package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestACLCreateRejectsUnknownPlannedInputsBeforeRouterAccess(t *testing.T) {
	model := aclRuleModel{
		Name: types.StringValue("acl"), Action: types.StringValue("accept"), Order: types.Int64Unknown(),
		Protocol: types.StringValue("tcp"), IPVersion: types.StringUnknown(), Direction: types.StringUnknown(),
		MACAddress: types.StringUnknown(), Service: types.StringUnknown(), TCPFlag: types.StringUnknown(),
		SourceCIDR: types.StringValue("0.0.0.0/0"), DestinationCIDR: types.StringValue("203.0.113.10/32"),
		DestinationPortStart: types.Int64Value(443), DestinationPortEnd: types.Int64Value(443),
		SourcePortStart: types.Int64Unknown(), SourcePortEnd: types.Int64Null(), Enabled: types.BoolValue(true),
		PacketsPerUnit: types.Int64Unknown(), RateLimitUnit: types.StringValue("minute"),
	}
	unknown := unknownACLPlanAttributes(model)
	for _, name := range []string{"order", "source_port_start", "packets_per_unit", "ip_version", "direction", "mac_address", "service", "tcp_flag"} {
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

func TestACLModelMapsFilterFields(t *testing.T) {
	model := aclRuleModel{
		Name: types.StringValue("filters"), Action: types.StringValue("reject"), Order: types.Int64Value(5),
		Protocol: types.StringValue("tcp"), IPVersion: types.StringValue("ipv6"),
		Direction: types.StringValue("lan_to_wan"), MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"),
		Service: types.StringValue("custom-https"), TCPFlag: types.StringValue("syn"),
		SourceCIDR: types.StringValue("2001:db8::/32"), DestinationCIDR: types.StringValue("2001:db8:1::/64"),
		DestinationPortStart: types.Int64Value(443), DestinationPortEnd: types.Int64Value(443),
		SourcePortStart: types.Int64Null(), SourcePortEnd: types.Int64Null(), Enabled: types.BoolValue(true),
		RateLimitUnit: types.StringValue("minute"),
	}
	rule := modelACLRule(model)
	if rule.IPVersion != "ipv6" || rule.Direction != "lan_to_wan" || rule.MACAddress != "AA:BB:CC:DD:EE:FF" || rule.Service != "custom-https" || rule.TCPFlag != "syn" {
		t.Fatalf("model did not map filter fields: %#v", rule)
	}
	rounded := modelFromACLRule(rule)
	if rounded.IPVersion.ValueString() != "ipv6" || rounded.Direction.ValueString() != "lan_to_wan" ||
		rounded.MACAddress.ValueString() != "AA:BB:CC:DD:EE:FF" || rounded.Service.ValueString() != "custom-https" ||
		rounded.TCPFlag.ValueString() != "syn" {
		t.Fatalf("model round trip lost filter fields: %#v", rounded)
	}
	model.IPVersion, model.Direction = types.StringNull(), types.StringNull()
	model.MACAddress, model.Service, model.TCPFlag = types.StringNull(), types.StringNull(), types.StringNull()
	rule = modelACLRule(model)
	if rule.IPVersion != "ipv4" || rule.Direction != "wan_to_lan" || rule.MACAddress != "" || rule.Service != "" || rule.TCPFlag != "" {
		t.Fatalf("model did not apply filter defaults: %#v", rule)
	}
}

func TestACLClientCRUDUsesDALAndReResolvesShiftedIndexes(t *testing.T) {
	fixture := newTerraformACLFixture(t)
	client, err := zyxel.NewClient(fixture.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, second := testACLRule("acl-first", "accept", 10), testACLRule("acl-second", "drop", 20)
	for _, desired := range []zyxel.ACLRule{first, second} {
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
	client, err := zyxel.NewClient(fixture.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
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
	client, err := zyxel.NewClient(fixture.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
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
	client, err := zyxel.NewClient(fixture.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
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
	client, err := zyxel.NewClient(fixture.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadACLRule(context.Background(), "missing"); err != zyxel.ErrACLRuleNotFound {
		t.Fatalf("ReadACLRule error = %v, want zyxel.ErrACLRuleNotFound", err)
	}
	if err := client.DeleteACLRule(context.Background(), "missing"); err != nil {
		t.Fatalf("deleting a missing ACL rule should be a no-op: %v", err)
	}
}

func testACLRule(name, action string, order int64) zyxel.ACLRule {
	return zyxel.ACLRule{Name: name, Action: action, Order: order, Protocol: "tcp", SourceCIDR: "198.51.100.0/24", DestinationCIDR: "203.0.113.10/32", DestinationPortStart: int64Pointer(443), DestinationPortEnd: int64Pointer(443), Enabled: true}
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
