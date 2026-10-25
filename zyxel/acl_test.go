package zyxel

import (
	"context"
	"strings"
	"testing"
	"time"
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
	if _, exists := payload["LimitRate"]; exists {
		t.Fatalf("disabled rate limiting should omit LimitRate: %#v", payload)
	}
	rule.Action = "accept"
	rule.RateLimit, rule.RateLimitUnit = int64Pointer(100), "second"
	payload, err = rule.dalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if payload["LimitRate"] != int64(100) || payload["LimitRateUnit"] != "second" {
		t.Fatalf("unexpected rate limit payload: %#v", payload)
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
		{"zero rate limit", func(r *ACLRule) { r.RateLimit = int64Pointer(0) }},
		{"rate limit above maximum", func(r *ACLRule) { r.RateLimit = int64Pointer(513) }},
		{"invalid rate limit unit", func(r *ACLRule) { r.RateLimit, r.RateLimitUnit = int64Pointer(100), "hour" }},
		{"rate limit on drop action", func(r *ACLRule) { r.Action, r.RateLimit = "drop", int64Pointer(100) }},
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

func TestACLCreateValidatesDirectGoInputBeforeNetwork(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:1", Credentials{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rule := testACLRule("invalid", "accept", 1)
	rule.DestinationCIDR = "2001:db8::/32"
	outcome, err := client.CreateACLRule(context.Background(), rule)
	if err == nil || strings.Contains(err.Error(), "session") || outcome.Applied || outcome.Ambiguous || outcome.Rule != nil {
		t.Fatalf("invalid direct input reached network: outcome=%#v err=%v", outcome, err)
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

func TestParseACLRuleRateLimit(t *testing.T) {
	row := fixtureACLRow("rate", 1, 1)
	row["LimitRate"] = float64(120)
	row["LimitRateUnit"] = "Second"
	rule, err := parseACLRule(row)
	if err != nil || rule.RateLimit == nil || *rule.RateLimit != 120 || rule.RateLimitUnit != "second" {
		t.Fatalf("parse rate limit = %#v, %v", rule, err)
	}

	row = fixtureACLRow("disabled-rate", 1, 1)
	row["LimitRate"] = float64(0)
	row["LimitRateUnit"] = "second"
	rule, err = parseACLRule(row)
	if err != nil || rule.RateLimit != nil || rule.RateLimitUnit != "minute" {
		t.Fatalf("disabled rate limit should normalize to minute/nil: %#v, %v", rule, err)
	}

	row["LimitRate"] = float64(513)
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected invalid rate limit error, got %v", err)
	}
	row = fixtureACLRow("invalid-unit", 1, 1)
	row["LimitRate"] = float64(100)
	row["LimitRateUnit"] = "hour"
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "rate limit unit") {
		t.Fatalf("expected invalid rate limit unit error, got %v", err)
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
