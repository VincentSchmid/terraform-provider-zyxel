package zyxel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestACLRulePayloadUsesScriptProfile(t *testing.T) {
	rule := testACLRule("payload", "accept", 42)
	payload, err := rule.dalPayload(0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"Enable": true, "Name": "payload", "Interface": "ALL", "Order": int64(42),
		"Target": "Accept", "IPVersion": "IPv4", "SourceIP": "198.51.100.0", "SourceMask": "24",
		"MACAddress": "AnyMACAddress", "DestIP": "203.0.113.10", "DestMask": "32",
		"X_ZYXEL_ServiceIndex": int64(0), "Direction": "WAN_TO_LAN", "X_ZYXEL_ScheduleRule": "",
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
	payload, err = rule.dalPayload(0)
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
	payload, err = rule.dalPayload(0)
	if err != nil {
		t.Fatal(err)
	}
	if payload["LimitRate"] != int64(100) || payload["LimitRateUnit"] != "second" {
		t.Fatalf("unexpected rate limit payload: %#v", payload)
	}
}

func TestACLRulePayloadMapsProtocols(t *testing.T) {
	cases := map[string]string{
		"all": "ALL", "tcp_udp": "TCPUDP", "tcp": "TCP",
		"udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6",
	}
	for protocol, routerValue := range cases {
		t.Run(protocol, func(t *testing.T) {
			rule := testACLRule("protocol", "accept", 42)
			rule.Protocol = protocol
			if protocol != "tcp" && protocol != "udp" && protocol != "tcp_udp" {
				rule.DestinationPortStart, rule.DestinationPortEnd = nil, nil
			}
			payload, err := rule.dalPayload(0)
			if err != nil {
				t.Fatal(err)
			}
			if payload["Protocol"] != routerValue {
				t.Fatalf("payload Protocol = %#v, want %#v", payload["Protocol"], routerValue)
			}
			if protocol != "tcp" && protocol != "udp" && protocol != "tcp_udp" {
				if payload["SourcePort"] != int64(-1) || payload["DestPort"] != int64(-1) {
					t.Fatalf("portless protocol should send -1 ports: %#v", payload)
				}
			}
		})
	}
}

func TestACLRulePayloadMapsFilterFields(t *testing.T) {
	rule := testACLRule("filters", "reject", 42)
	rule.Service = "custom-https"
	rule.IPVersion = "ipv6"
	rule.SourceCIDR = "2001:db8::/32"
	rule.DestinationCIDR = "2001:db8:1::/64"
	rule.MACAddress = "aa:bb:cc:dd:ee:ff"
	rule.Direction = "lan_to_wan"
	rule.TCPFlag = "syn"
	payload, err := rule.dalPayload(3)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"Target": "Reject", "IPVersion": "IPv6",
		"SourceIP": "2001:db8::", "SourceMask": "32",
		"DestIP": "2001:db8:1::", "DestMask": "64",
		"MACAddress": "AA:BB:CC:DD:EE:FF", "Direction": "LAN_TO_WAN",
		"X_ZYXEL_ServiceIndex": int64(3), "TCPFlag": "SYN",
	}
	for key, expected := range want {
		if payload[key] != expected {
			t.Errorf("payload[%q] = %#v, want %#v", key, payload[key], expected)
		}
	}
	rule.MACAddress, rule.TCPFlag, rule.Service = "", "", ""
	rule.Action, rule.IPVersion, rule.Direction = "accept", "", ""
	rule.SourceCIDR, rule.DestinationCIDR = "0.0.0.0/0", "203.0.113.10/32"
	payload, err = rule.dalPayload(0)
	if err != nil {
		t.Fatal(err)
	}
	if payload["MACAddress"] != "AnyMACAddress" || payload["IPVersion"] != "IPv4" || payload["Direction"] != "WAN_TO_LAN" {
		t.Fatalf("unexpected default filter payload: %#v", payload)
	}
	if _, exists := payload["TCPFlag"]; exists {
		t.Fatalf("empty TCP flag must be omitted: %#v", payload)
	}
}

func TestACLRulePayloadRejectsInvalidCIDRsAndRanges(t *testing.T) {
	cases := []struct {
		name string
		edit func(*ACLRule)
	}{
		{"noncanonical source CIDR", func(r *ACLRule) { r.SourceCIDR = "198.51.100.1/24" }},
		{"IPv6 destination", func(r *ACLRule) { r.DestinationCIDR = "2001:db8::1/128" }},
		{"reversed destination ports", func(r *ACLRule) {
			r.DestinationPortStart, r.DestinationPortEnd = int64Pointer(5000), int64Pointer(4999)
		}},
		{"out of range destination port", func(r *ACLRule) { r.DestinationPortEnd = int64Pointer(65536) }},
		{"partial destination port pair", func(r *ACLRule) { r.DestinationPortEnd = nil }},
		{"unknown protocol", func(r *ACLRule) { r.Protocol = "sctp" }},
		{"destination ports on ICMP", func(r *ACLRule) { r.Protocol = "icmp" }},
		{"source ports on ALL", func(r *ACLRule) {
			r.Protocol = "all"
			r.SourcePortStart, r.SourcePortEnd = int64Pointer(1024), int64Pointer(2048)
		}},
		{"partial source port pair", func(r *ACLRule) { r.SourcePortStart = int64Pointer(1024) }},
		{"reversed source ports", func(r *ACLRule) { r.SourcePortStart, r.SourcePortEnd = int64Pointer(2048), int64Pointer(1024) }},
		{"zero rate limit", func(r *ACLRule) { r.RateLimit = int64Pointer(0) }},
		{"rate limit above maximum", func(r *ACLRule) { r.RateLimit = int64Pointer(513) }},
		{"invalid rate limit unit", func(r *ACLRule) { r.RateLimit, r.RateLimitUnit = int64Pointer(100), "hour" }},
		{"rate limit on drop action", func(r *ACLRule) { r.Action, r.RateLimit = "drop", int64Pointer(100) }},
		{"reject rate limit", func(r *ACLRule) { r.Action, r.RateLimit = "reject", int64Pointer(100) }},
		{"unknown action", func(r *ACLRule) { r.Action = "log" }},
		{"unknown direction", func(r *ACLRule) { r.Direction = "sideways" }},
		{"invalid IP version", func(r *ACLRule) { r.IPVersion = "ipx" }},
		{"IPv4 CIDR with IPv6 version", func(r *ACLRule) { r.IPVersion = "ipv6" }},
		{"malformed MAC address", func(r *ACLRule) { r.MACAddress = "AA:BB:CC:DD:EE" }},
		{"TCP flag on UDP", func(r *ACLRule) {
			r.Protocol = "udp"
			r.TCPFlag = "syn"
		}},
		{"unknown TCP flag", func(r *ACLRule) { r.TCPFlag = "ece" }},
		{"padded service name", func(r *ACLRule) { r.Service = " custom " }},
		{"service name without index", func(r *ACLRule) { r.Service = "custom" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			rule := testACLRule("invalid", "accept", 5)
			test.edit(&rule)
			if _, err := rule.dalPayload(0); err == nil {
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

func TestParseACLRuleMapsFilterFields(t *testing.T) {
	row := fixtureACLRow("filters", 1, 1)
	row["Target"] = "Reject"
	row["IPVersion"] = float64(6)
	row["SourceIP"], row["SourceMask"] = "2001:db8::", "32"
	row["DestIP"], row["DestMask"] = "2001:db8:1::", "64"
	row["MACAddress"] = "aa:bb:cc:dd:ee:ff"
	row["Direction"] = "LAN_TO_WAN"
	row["X_ZYXEL_ServiceIndex"] = float64(4)
	row["ServiceName"] = "custom-https"
	row["X_ZYXEL_TCPFlagMask"], row["X_ZYXEL_TCPFlagComp"] = "SYN", "SYN"
	rule, err := parseACLRule(row)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Action != "reject" || rule.IPVersion != "ipv6" || rule.Direction != "lan_to_wan" {
		t.Fatalf("unexpected action/version/direction: %#v", rule)
	}
	if rule.SourceCIDR != "2001:db8::/32" || rule.DestinationCIDR != "2001:db8:1::/64" {
		t.Fatalf("unexpected IPv6 CIDRs: %#v", rule)
	}
	if rule.MACAddress != "AA:BB:CC:DD:EE:FF" || rule.Service != "custom-https" || rule.TCPFlag != "syn" {
		t.Fatalf("unexpected filters: %#v", rule)
	}
}

func TestParseACLRuleRejectsUnsupportedFilterRepresentations(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"direction", func(row map[string]any) { row["Direction"] = "SIDEWAYS" }, "Direction"},
		{"MAC address", func(row map[string]any) { row["MACAddress"] = "not-a-mac" }, "MAC"},
		{"service without name", func(row map[string]any) { row["X_ZYXEL_ServiceIndex"] = float64(4) }, "service"},
		{"TCP flag mismatch", func(row map[string]any) {
			row["X_ZYXEL_TCPFlagMask"], row["X_ZYXEL_TCPFlagComp"] = "SYN", "ACK"
		}, "TCP flag"},
		{"unknown TCP flag", func(row map[string]any) {
			row["X_ZYXEL_TCPFlagMask"], row["X_ZYXEL_TCPFlagComp"] = "ECE", "ECE"
		}, "TCP flag"},
		{"TCP flag on ICMP", func(row map[string]any) {
			row["Protocol"], row["DestPort"], row["DestPortRangeMax"] = "ICMP", float64(-1), float64(-1)
			row["X_ZYXEL_TCPFlagMask"], row["X_ZYXEL_TCPFlagComp"] = "SYN", "SYN"
		}, "TCP flags"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			row := fixtureACLRow("unsupported", 1, 1)
			test.edit(row)
			if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q error, got %v", test.want, err)
			}
		})
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

func TestParseACLRuleNormalizesProtocols(t *testing.T) {
	cases := map[string]string{
		"ALL": "all", "TCPUDP": "tcp_udp", "TCP/UDP": "tcp_udp",
		"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ICMPv6": "icmpv6",
	}
	for routerValue, protocol := range cases {
		t.Run(routerValue, func(t *testing.T) {
			row := fixtureACLRow("protocol", 1, 1)
			row["Protocol"] = routerValue
			if protocol != "tcp" {
				row["DestPort"], row["DestPortRangeMax"] = float64(-1), float64(-1)
			}
			rule, err := parseACLRule(row)
			if err != nil {
				t.Fatal(err)
			}
			if rule.Protocol != protocol {
				t.Fatalf("Protocol = %q, want %q", rule.Protocol, protocol)
			}
		})
	}
}

func TestParseACLRuleRejectsUnsupportedSelectedProfile(t *testing.T) {
	row := fixtureACLRow("selected", 1, 1)
	row["Protocol"] = "SCTP"
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "unsupported Protocol") {
		t.Fatalf("expected unsupported selected profile error, got %v", err)
	}
	// Listing and collision checks keep unrelated rules opaque; only a selected
	// managed row is decoded against the provider's fixed profile.
	unmanaged := map[string]any{"Name": "unmanaged", "Order": float64(1), "Protocol": "SCTP", "Direction": "LAN_TO_WAN", "Interface": "LAN"}
	rows := []map[string]any{unmanaged, fixtureACLRow("selected", 2, 10)}
	found, err := findACLRow(rows, "selected")
	if err != nil || found == nil {
		t.Fatalf("unrelated unsupported profile should not block name lookup: %v", err)
	}
	// Ports are not accepted for protocols that do not use them.
	row = fixtureACLRow("icmp-with-ports", 2, 2)
	row["Protocol"] = "ICMP"
	if _, err := parseACLRule(row); err == nil || !strings.Contains(err.Error(), "destination ports") {
		t.Fatalf("expected portless protocol port error, got %v", err)
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
	return ACLRule{Name: name, Action: action, Order: order, Protocol: "tcp", SourceCIDR: "198.51.100.0/24", DestinationCIDR: "203.0.113.10/32", DestinationPortStart: int64Pointer(443), DestinationPortEnd: int64Pointer(443), Enabled: true}
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
