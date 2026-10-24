package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestACLRulePayloadUsesScriptProfile(t *testing.T) {
	rule := testACLRule("payload", "accept", 42)
	payload, err := rule.dalPayload()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"Enable": true, "Name": "payload", "Interface": "ALL", "Order": int64(42),
		"Target": "Accept", "IPVersion": "IPv4", "SourceIP": "198.51.100.0", "SourceMask": "24",
		"MACAddress": "AnyMACAddress", "DestIP": "203.0.113.10", "DestMask": "32",
		"X_ZYXEL_ServiceIndex": 0, "Direction": "WAN_TO_LAN", "X_ZYXEL_ScheduleRule": "",
		"Protocol": "TCP", "SourcePort": int64(-1), "SourcePortRangeMax": int64(-1),
		"DestPort": int64(443), "DestPortRangeMax": int64(443), "IPv6header": "", "IPv6headertypes": "",
	}
	for key, expected := range want {
		if payload[key] != expected {
			t.Errorf("payload[%q] = %#v, want %#v", key, payload[key], expected)
		}
	}
	rule.Action = "drop"
	rule.SourcePortStart, rule.SourcePortEnd = int64Pointer(1024), int64Pointer(2048)
	payload, err = rule.dalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if payload["Target"] != "Drop" || payload["SourcePort"] != int64(1024) || payload["SourcePortRangeMax"] != int64(2048) {
		t.Fatalf("unexpected drop/source-port payload: %#v", payload)
	}
}

func TestACLRulePayloadRejectsInvalidCIDRsAndRanges(t *testing.T) {
	cases := []struct {
		name string
		edit func(*ACLRule)
	}{
		{"noncanonical source CIDR", func(r *ACLRule) { r.SourceCIDR = "198.51.100.1/24" }},
		{"IPv6 destination", func(r *ACLRule) { r.DestinationCIDR = "2001:db8::1/128" }},
		{"reversed destination ports", func(r *ACLRule) { r.DestinationPortStart, r.DestinationPortEnd = 5000, 4999 }},
		{"out of range destination port", func(r *ACLRule) { r.DestinationPortEnd = 65536 }},
		{"partial source port pair", func(r *ACLRule) { r.SourcePortStart = int64Pointer(1024) }},
		{"reversed source ports", func(r *ACLRule) { r.SourcePortStart, r.SourcePortEnd = int64Pointer(2048), int64Pointer(1024) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			rule := testACLRule("invalid", "accept", 5)
			test.edit(&rule)
			if _, err := rule.dalPayload(); err == nil {
				t.Fatal("expected invalid ACL rule to be rejected")
			}
		})
	}
}

func TestACLCreateRejectsUnknownPlannedInputsBeforeRouterAccess(t *testing.T) {
	model := aclRuleModel{
		Name: types.StringValue("acl"), Action: types.StringValue("accept"), Order: types.Int64Unknown(),
		SourceCIDR: types.StringValue("0.0.0.0/0"), DestinationCIDR: types.StringValue("203.0.113.10/32"),
		DestinationPortStart: types.Int64Value(443), DestinationPortEnd: types.Int64Value(443),
		SourcePortStart: types.Int64Unknown(), SourcePortEnd: types.Int64Null(), Enabled: types.BoolValue(true),
	}
	unknown := unknownACLPlanAttributes(model)
	for _, name := range []string{"order", "source_port_start"} {
		found := false
		for _, item := range unknown {
			if item == name {
				found = true
			}
		}
		if !found {
			t.Errorf("unknown input %q was not detected: %v", name, unknown)
		}
	}
}

func TestParseACLRuleNormalizesRouterRepresentations(t *testing.T) {
	for _, ipVersion := range []any{"IPv4", float64(4)} {
		row := fixtureACLRow("rule", 7, 10)
		row["IPVersion"] = ipVersion
		row["Order"] = "10"
		row["DestPort"] = float64(443)
		row["Enable"] = "1"
		row["SourceIP"] = "198.51.100.9"
		row["SourceMask"] = "24"
		rule, err := parseACLRule(row)
		if err != nil {
			t.Fatalf("parse ACL with IPVersion %#v: %v", ipVersion, err)
		}
		if rule.SourceCIDR != "198.51.100.0/24" || rule.DestinationCIDR != "203.0.113.10/32" || rule.Action != "accept" || rule.RouterIndex != 7 || rule.Order != 10 || !rule.Enabled {
			t.Fatalf("unexpected normalized ACL rule: %#v", rule)
		}
	}
	row := fixtureACLRow("any-source", 2, 20)
	row["SourceIP"] = ""
	row["SourceMask"] = nil
	rule, err := parseACLRule(row)
	if err != nil || rule.SourceCIDR != "0.0.0.0/0" {
		t.Fatalf("expected empty source to normalize to any, got %#v, %v", rule, err)
	}
}

func TestParseACLRuleRejectsUnsupportedSelectedProfile(t *testing.T) {
	row := fixtureACLRow("selected", 1, 1)
	row["Protocol"] = "UDP"
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "unsupported Protocol") {
		t.Fatalf("expected unsupported selected profile error, got %v", err)
	}
	// Listing and collision checks keep unrelated rules opaque; only a selected
	// managed row is decoded against the provider's fixed profile.
	unmanaged := map[string]any{"Name": "unmanaged", "Order": float64(1), "Protocol": "UDP", "Direction": "LAN_TO_WAN", "Interface": "LAN"}
	rows := []map[string]any{unmanaged, fixtureACLRow("selected", 2, 10)}
	found, err := findACLRow(rows, "selected")
	if err != nil || found == nil {
		t.Fatalf("unrelated unsupported profile should not block name lookup: %v", err)
	}
}

func TestParseACLRuleAcceptsStoredRowsWithoutInterface(t *testing.T) {
	// The router drops the submitted Interface value, so rows created through the
	// GUI payload or firewall_cf.py read back with no Interface field at all.
	row := fixtureACLRow("no-interface", 1, 1)
	delete(row, "Interface")
	rule, err := parseACLRule(row)
	if err != nil || rule.Name != "no-interface" {
		t.Fatalf("parse without Interface = %#v, %v", rule, err)
	}
	row["Interface"] = "ALL"
	if _, err := parseACLRule(row); err != nil {
		t.Fatalf("Interface ALL rejected: %v", err)
	}
	row["Interface"] = "LAN"
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "unsupported Interface") {
		t.Fatalf("expected unsupported Interface error, got %v", err)
	}
	// "No schedule" is submitted as "" and stored as 0.
	row = fixtureACLRow("stored-schedule", 1, 1)
	row["X_ZYXEL_ScheduleRule"] = float64(0)
	if _, err := parseACLRule(row); err != nil {
		t.Fatalf("schedule 0 rejected: %v", err)
	}
	row["X_ZYXEL_ScheduleRule"] = float64(2)
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "X_ZYXEL_ScheduleRule") {
		t.Fatalf("expected unsupported schedule error, got %v", err)
	}
}

func TestACLClientCRUDUsesDALAndReResolvesShiftedIndexes(t *testing.T) {
	fixture := newTerraformACLFixture(t)
	client, err := NewClient(fixture.server.URL, Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, second := testACLRule("acl-first", "accept", 10), testACLRule("acl-second", "drop", 20)
	for _, desired := range []ACLRule{first, second} {
		outcome, err := client.CreateACLRule(context.Background(), desired)
		if err != nil || !outcome.Applied || outcome.Ambiguous || outcome.Rule == nil {
			t.Fatalf("CreateACLRule(%q) outcome=%#v, err=%v", desired.Name, outcome, err)
		}
	}
	observed, err := client.ReadACLRule(context.Background(), second.Name)
	if err != nil || observed.RouterIndex != 3 {
		t.Fatalf("ReadACLRule got %#v, %v; want current index 3", observed, err)
	}
	if err := client.DeleteACLRule(context.Background(), first.Name); err != nil {
		t.Fatal(err)
	}
	// The second row shifts from index 3 to 2. Delete must re-read by Name.
	if err := client.DeleteACLRule(context.Background(), second.Name); err != nil {
		t.Fatal(err)
	}
	if err := fixture.check("unmanaged", true); err != nil {
		t.Fatal(err)
	}
	if err := fixture.check(first.Name, false); err != nil {
		t.Fatal(err)
	}
	if err := fixture.check(second.Name, false); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	posts, deletes := fixture.posts, fixture.deletes
	fixture.mu.Unlock()
	if posts != 2 || deletes != 2 {
		t.Fatalf("mock saw %d POST and %d DELETE operations; want 2 each", posts, deletes)
	}
}

func TestACLClientReadbackMismatchRetainsCreatedIdentity(t *testing.T) {
	fixture := newTerraformACLFixture(t)
	fixture.forceOrder = true
	client, err := NewClient(fixture.server.URL, Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rule := testACLRule("mismatched-order", "accept", 10)
	outcome, err := client.CreateACLRule(context.Background(), rule)
	if err == nil || !outcome.Applied || outcome.Ambiguous || outcome.Rule == nil || outcome.Rule.RouterIndex == 0 {
		t.Fatalf("expected tracked created rule with readback mismatch, got %#v, %v", outcome, err)
	}
	if outcome.Rule.Name != rule.Name || outcome.Rule.Order != 99 {
		t.Fatalf("readback did not preserve the actual created identity/order: %#v", outcome.Rule)
	}
	if !strings.Contains(err.Error(), "order") {
		t.Fatalf("expected order mismatch diagnostic, got %v", err)
	}
}

func TestACLClient5xxAfterCommitIsAnAmbiguousCreate(t *testing.T) {
	fixture := newTerraformACLFixture(t)
	fixture.failPostAfterCommit = true
	client, err := NewClient(fixture.server.URL, Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rule := testACLRule("committed-before-500", "accept", 10)
	outcome, err := client.CreateACLRule(context.Background(), rule)
	if err == nil || !outcome.Ambiguous || outcome.Applied {
		t.Fatalf("expected an ambiguous failed create after commit, got %#v, %v", outcome, err)
	}
	observed, readErr := client.ReadACLRule(context.Background(), rule.Name)
	if readErr != nil || observed.Name != rule.Name {
		t.Fatalf("ambiguous create did not leave the named object readable: %#v, %v", observed, readErr)
	}
}

func TestACLClientRejectsNameDuplicatesAndOrderConflicts(t *testing.T) {
	fixture := newTerraformACLFixture(t)
	fixture.rows = append(fixture.rows,
		map[string]any{"Name": "duplicate", "Order": 5},
		map[string]any{"Name": "duplicate", "Order": 6},
	)
	client, err := NewClient(fixture.server.URL, Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadACLRule(context.Background(), "duplicate"); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("expected duplicate-name read error, got %v", err)
	}
	if err := client.DeleteACLRule(context.Background(), "duplicate"); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("expected duplicate-name delete error, got %v", err)
	}
	collision := testACLRule("new-name", "accept", 1)
	if outcome, err := client.CreateACLRule(context.Background(), collision); err == nil || outcome.Applied || outcome.Ambiguous {
		t.Fatalf("expected preflight order collision, got %#v, %v", outcome, err)
	}
}

func TestACLClientMissingReadAndDeleteAreIdempotent(t *testing.T) {
	fixture := newTerraformACLFixture(t)
	client, err := NewClient(fixture.server.URL, Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadACLRule(context.Background(), "missing"); err != ErrACLRuleNotFound {
		t.Fatalf("ReadACLRule error = %v, want ErrACLRuleNotFound", err)
	}
	if err := client.DeleteACLRule(context.Background(), "missing"); err != nil {
		t.Fatalf("deleting a missing ACL rule should be a no-op: %v", err)
	}
}

func TestACLSessionGateHonorsCanceledContext(t *testing.T) {
	client, err := NewClient("http://127.0.0.1", Credentials{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.sessionGate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.withSession(ctx, func(*routerSession) error { return nil }); err == nil || err.Error() != "router operation canceled" {
		t.Fatalf("expected context-aware lock cancellation, got %v", err)
	}
	<-client.sessionGate
}

func testACLRule(name, action string, order int64) ACLRule {
	return ACLRule{Name: name, Action: action, Order: order, SourceCIDR: "198.51.100.0/24", DestinationCIDR: "203.0.113.10/32", DestinationPortStart: 443, DestinationPortEnd: 443, Enabled: true}
}

func fixtureACLRow(name string, index, order int) map[string]any {
	return map[string]any{
		"Name": name, "Index": float64(index), "Order": float64(order), "Target": "Accept",
		"IPVersion": "IPv4", "SourceIP": "198.51.100.0", "SourceMask": "24",
		"DestIP": "203.0.113.10", "DestMask": "32", "DestPort": float64(443), "DestPortRangeMax": float64(443),
		"SourcePort": float64(-1), "SourcePortRangeMax": float64(-1), "Enable": true,
		"Protocol": "TCP", "Direction": "WAN_TO_LAN", "Interface": "ALL", "MACAddress": "AnyMACAddress",
		"X_ZYXEL_ServiceIndex": float64(0), "X_ZYXEL_ScheduleRule": "", "IPv6header": "", "IPv6headertypes": "",
	}
}

func int64Pointer(value int64) *int64 { return &value }
