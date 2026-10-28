package zyxel

import (
	"strings"
	"testing"
)

func TestNormalizeHostname(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	longHostname := strings.Join([]string{longLabel, longLabel, longLabel, longLabel}, ".") // 255 characters
	for input, want := range map[string]string{
		"nas.home.arpa":     "nas.home.arpa",
		"NAS.Home.ARPA":     "nas.home.arpa",
		"a-b.c_d":           "a-b.c_d",
		"printer.lan":       "printer.lan",
		"1.2":               "1.2",
		"nas.home.arpa.lan": "nas.home.arpa.lan",
		longHostname:        longHostname,
	} {
		got, err := NormalizeHostname(input)
		if err != nil || got != want {
			t.Errorf("NormalizeHostname(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{
		"", " nas.home.arpa", "nas.home.arpa ", "nas.home.arpa\t",
		"localhost", "nas", ".home", "nas.", "nas..home",
		"-nas.home", "nas-.home", "nas.-home", "nas.home-", "na s.home",
		"nas/.home", "nas*.home", "nas.home.arpa.", "*", "nas.home.arpa#",
		strings.Join([]string{longLabel, longLabel, longLabel, strings.Repeat("a", 60), "abcd"}, "."), // 257 characters
		strings.Repeat("a", 64) + ".home",
	} {
		if got, err := NormalizeHostname(input); err == nil {
			t.Errorf("NormalizeHostname(%q) = %q, nil error", input, got)
		}
	}
}

func TestDNSEntryRowParsingFailsClosed(t *testing.T) {
	base := dnsRow(1, "nas.home.arpa", "192.0.2.20")
	for _, mutate := range []func(map[string]any){
		func(row map[string]any) { delete(row, "Index") },
		func(row map[string]any) { delete(row, "HostName") },
		func(row map[string]any) { delete(row, "IPv4Address") },
		func(row map[string]any) { row["Index"] = 0 },
		func(row map[string]any) { row["Index"] = 1.5 },
		func(row map[string]any) { row["Index"] = float64(9007199254740992) },
		func(row map[string]any) { row["HostName"] = "nas" },
		func(row map[string]any) { row["HostName"] = "" },
		func(row map[string]any) { row["HostName"] = 10 },
		func(row map[string]any) { row["IPv4Address"] = "2001:db8::20" },
		func(row map[string]any) { row["IPv4Address"] = "::ffff:192.0.2.20" },
		func(row map[string]any) { row["IPv4Address"] = "192.0.2.020" },
		func(row map[string]any) { row["IPv4Address"] = 20 },
	} {
		row := make(map[string]any, len(base))
		for key, value := range base {
			row[key] = value
		}
		mutate(row)
		if _, err := parseDNSEntry(row); err == nil {
			t.Fatalf("expected row rejection: %#v", row)
		}
	}
	row := dnsRow(3, "NAS.Home.ARPA", "192.0.2.20")
	row["FirmwareMetadata"] = "ignored"
	parsed, err := parseDNSEntry(row)
	if err != nil || parsed.Index != 3 || parsed.HostName != "nas.home.arpa" || parsed.IPv4Address != "192.0.2.20" {
		t.Fatalf("metadata/host name parse = %#v, %v", parsed, err)
	}
}

func TestFindDNSEntryIgnoresCaseAndRejectsDuplicates(t *testing.T) {
	rows := []DNSEntry{{Index: 1, HostName: "nas.home.arpa", IPv4Address: "192.0.2.20"}, {Index: 2, HostName: "printer.home.arpa", IPv4Address: "192.0.2.21"}}
	found, err := findDNSEntry(rows, "NAS.HOME.ARPA")
	if err != nil || found == nil || found.Index != 1 {
		t.Fatalf("case-insensitive lookup = %#v, %v", found, err)
	}
	if found, err := findDNSEntry(rows, "missing.home.arpa"); err != nil || found != nil {
		t.Fatalf("missing lookup = %#v, %v", found, err)
	}
	rows = append(rows, DNSEntry{Index: 3, HostName: "nas.home.arpa", IPv4Address: "192.0.2.99"})
	if found, err := findDNSEntry(rows, "nas.home.arpa"); err == nil || found != nil {
		t.Fatalf("duplicate lookup = %#v, %v", found, err)
	}
}

func dnsRow(index int64, hostname, ipv4 string) map[string]any {
	return map[string]any{"Index": index, "HostName": hostname, "IPv4Address": ipv4}
}
