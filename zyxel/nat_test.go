package zyxel

import "testing"

func TestNATRuleParseFailsClosedForMalformedOrUnsupportedRows(t *testing.T) {
	base := natRow(1, "bad", "TCP", 80, 81, "192.0.2.1", 80, 81, true)
	for _, mutate := range []func(map[string]any){
		func(row map[string]any) { row["Protocol"] = "ICMP" },
		func(row map[string]any) { row["ExternalPortStart"] = 0 },
		func(row map[string]any) { row["Index"] = 1.5 },
		func(row map[string]any) { row["Index"] = float64(9007199254740992) },
		func(row map[string]any) { row["InternalClient"] = "::ffff:192.0.2.1" },
		func(row map[string]any) { row["InternalPortEnd"] = 83 },
	} {
		row := make(map[string]any, len(base))
		for key, value := range base {
			row[key] = value
		}
		mutate(row)
		if _, err := parseNATRule(row); err == nil {
			t.Fatalf("expected row rejection: %#v", row)
		}
	}
	row := natRow(1, "valid", "TCP+UDP", 80, 81, "192.0.2.1", 8080, 8081, false)
	row["FirmwareMetadata"] = "ignored"
	parsed, err := parseNATRule(row)
	if err != nil || parsed.Protocol != "both" || parsed.Enabled {
		t.Fatalf("metadata/protocol parse = %#v, %v", parsed, err)
	}
	allRow := natRow(1, "all-protocols", "ALL", 6690, 6690, "192.0.2.1", 6690, 6690, true)
	allParsed, err := parseNATRule(allRow)
	if err != nil || allParsed.Protocol != "all" {
		t.Fatalf("ALL protocol parse = %#v, %v", allParsed, err)
	}
}
func natRow(index int64, name, protocol string, externalStart, externalEnd int64, internal string, internalStart, internalEnd int64, enabled bool) map[string]any {
	return map[string]any{"Index": index, "Enable": enabled, "Description": name, "Protocol": protocol, "ExternalPortStart": externalStart, "ExternalPortEnd": externalEnd, "InternalClient": internal, "InternalPortStart": internalStart, "InternalPortEnd": internalEnd}
}
