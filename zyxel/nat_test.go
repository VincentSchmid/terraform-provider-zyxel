package zyxel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

func TestNATEncryptedListingFailsClosedForBlankPlaceholder(t *testing.T) {
	key := make([]byte, 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("oid") != "nat" {
			t.Error("NAT read attempted mutation or wrong OID")
		}
		writeEncrypted(t, w, key, map[string]any{"result": "ZCFG_SUCCESS", "ReplyMsg": "InternalClient", "Object": []any{
			natRow(1, "valid", "TCP", 8000, 8000, "192.0.2.80", 9000, 9000, true),
			natRow(2, "", "UDP", 0, 0, "", 0, 0, false),
		}})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, Credentials{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s := &routerSession{client: client, httpClient: client.httpClient, key: key, sessionKey: "test-key"}
	if rows, err := s.readNATRules(context.Background()); rows != nil || err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("listing concealed partial row: %v, %v", rows, err)
	}
}
