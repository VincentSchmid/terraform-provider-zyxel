package zyxel_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/internal/routertest"
	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
)

func networkClient(t *testing.T) (*zyxel.Client, *routertest.NetworkFixture) {
	t.Helper()
	f := routertest.NewNetworkFixture(t)
	c, err := zyxel.NewClient(f.Server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, time.Second*3)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func validLAN() zyxel.LANSettings {
	return zyxel.LANSettings{InterfaceGroupID: "Default", IPAddress: "192.0.2.1", SubnetMask: "255.255.255.0", IGMPSnooping: "standard", DHCPMode: "server", BeginningIPAddress: "192.0.2.100", EndingIPAddress: "192.0.2.200", DNSMode: "proxy", DHCPLeaseTimeSeconds: 86400}
}

func TestLANLeaseTime(t *testing.T) {
	for input, want := range map[string]int64{"1d": 86400, "24h": 86400, "1440m": 86400, "1d5h12m": 105120, "1m": 60, "365d": 31536000, "0d25h60m": 93600} {
		got, err := zyxel.ParseLANLeaseTime(input)
		if err != nil || got != want {
			t.Errorf("%q: %d %v", input, got, err)
		}
		formatted := zyxel.FormatLANLeaseTime(got)
		if roundtrip, err := zyxel.ParseLANLeaseTime(formatted); err != nil || roundtrip != want {
			t.Errorf("round trip %q: %d %v", formatted, roundtrip, err)
		}
	}
	for _, input := range []string{"", "0m", "366d", "365d1m", "-1d", "1.5h", "60s", "1h1d", "1d1d", "1D", "1d 2h", "999999999999999999999999m"} {
		if _, err := zyxel.ParseLANLeaseTime(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestLANValidatesBeforeNetwork(t *testing.T) {
	c, _ := zyxel.NewClient("http://127.0.0.1:1", zyxel.Credentials{}, time.Second)
	for name, change := range map[string]func(*zyxel.LANSettings){
		"group":          func(v *zyxel.LANSettings) { v.InterfaceGroupID = "" },
		"ipv6":           func(v *zyxel.LANSettings) { v.IPAddress = "2001:db8::1" },
		"mapped":         func(v *zyxel.LANSettings) { v.IPAddress = "::ffff:192.0.2.1" },
		"mask":           func(v *zyxel.LANSettings) { v.SubnetMask = "255.0.255.0" },
		"network":        func(v *zyxel.LANSettings) { v.IPAddress = "192.0.2.0" },
		"broadcast":      func(v *zyxel.LANSettings) { v.IPAddress = "192.0.2.255" },
		"pool-order":     func(v *zyxel.LANSettings) { v.BeginningIPAddress = "192.0.2.220" },
		"pool-subnet":    func(v *zyxel.LANSettings) { v.EndingIPAddress = "198.51.100.200" },
		"pool-broadcast": func(v *zyxel.LANSettings) { v.EndingIPAddress = "192.0.2.255" },
		"pool-router":    func(v *zyxel.LANSettings) { v.BeginningIPAddress = "192.0.2.1" },
		"snooping":       func(v *zyxel.LANSettings) { v.IGMPSnooping = "unexpected" },
		"mode":           func(v *zyxel.LANSettings) { v.DHCPMode = "enable" },
		"relay-pool":     func(v *zyxel.LANSettings) { v.DHCPMode = "relay"; v.RelayServerAddress = "198.51.100.1" },
		"server-relay":   func(v *zyxel.LANSettings) { v.RelayServerAddress = "198.51.100.1" },
		"dns":            func(v *zyxel.LANSettings) { v.DNSMode = "static" },
		"lease-zero":     func(v *zyxel.LANSettings) { v.DHCPLeaseTimeSeconds = 0 },
		"lease-seconds":  func(v *zyxel.LANSettings) { v.DHCPLeaseTimeSeconds = 61 },
		"lease-large":    func(v *zyxel.LANSettings) { v.DHCPLeaseTimeSeconds = 31536060 },
	} {
		t.Run(name, func(t *testing.T) {
			v := validLAN()
			change(&v)
			applied, err := c.SetLAN(context.Background(), v)
			if applied || err == nil || strings.Contains(err.Error(), "session") {
				t.Fatalf("applied=%v err=%v", applied, err)
			}
		})
	}
}

func TestLANModesPreserveUnmanagedFields(t *testing.T) {
	c, f := networkClient(t)
	ctx := context.Background()
	v := validLAN()
	if applied, err := c.SetLAN(ctx, v); err != nil || !applied {
		t.Fatal(applied, err)
	}
	if f.Writes != 0 {
		t.Fatal("no-op wrote settings")
	}
	for _, mode := range []string{"relay", "disabled", "server"} {
		v.DHCPMode = mode
		v.BeginningIPAddress = ""
		v.EndingIPAddress = ""
		v.RelayServerAddress = ""
		v.DHCPLeaseTimeSeconds = 0
		v.DNSMode = "proxy"
		if mode == "relay" {
			v.RelayServerAddress = "198.51.100.10"
		}
		if mode == "server" {
			v.BeginningIPAddress = "192.0.2.50"
			v.EndingIPAddress = "192.0.2.150"
			v.AutoReserveIP = true
			v.DHCPLeaseTimeSeconds = 105120
			v.DNSMode = "isp"
		}
		v.IGMPSnooping = "blocking"
		if applied, err := c.SetLAN(ctx, v); err != nil || !applied {
			t.Fatal(applied, err)
		}
		got, err := c.ReadLAN(ctx, "Default")
		if err != nil || got == nil || *got != v {
			t.Fatalf("%#v %v", got, err)
		}
		f.Mu.Lock()
		fields := []string{"IPv6_LanEnable", "IPv6_Prefix", "DNS_Servers1", "DNS_Servers2"}
		if mode != "server" {
			fields = append(fields, "DNS_Type", "DHCP_LeaseTime")
		}
		for _, field := range fields {
			if _, ok := f.LastWrite[field]; ok {
				t.Errorf("wrote unmanaged field %s", field)
			}
		}
		if f.LANs[0]["IPv6_LanEnable"] != true {
			t.Error("changed unmanaged settings")
		}
		if mode == "server" && (f.LastWrite["DHCP_LeaseTime"] != float64(105120) || f.LastWrite["DNS_Type"] != "FromISP") {
			t.Error("wrong DNS/lease payload", f.LastWrite)
		}
		f.Mu.Unlock()
	}
}

func TestLANDNSAndLeaseReadback(t *testing.T) {
	c, f := networkClient(t)
	v := validLAN()
	v.DNSMode = "isp"
	v.DHCPLeaseTimeSeconds = 105120
	if applied, err := c.SetLAN(context.Background(), v); !applied || err != nil {
		t.Fatal(applied, err)
	}
	v.DNSMode = "proxy"
	if applied, err := c.SetLAN(context.Background(), v); !applied || err != nil {
		t.Fatal(applied, err)
	}
	if f.LastWrite["DNS_Type"] != "DNSProxy" {
		t.Fatal(f.LastWrite)
	}
	f.Mu.Lock()
	f.LANs[0]["DHCP_LeaseTime"] = "105120"
	f.Mu.Unlock()
	got, err := c.ReadLAN(context.Background(), "Default")
	if err != nil || got == nil || *got != v {
		t.Fatal(got, err)
	}
	// Neither lease nor DNS changes may be reported successful without readback.
	f.IgnoreWrite = true
	for _, change := range []func(*zyxel.LANSettings){
		func(v *zyxel.LANSettings) { v.DNSMode = "isp" },
		func(v *zyxel.LANSettings) { v.DHCPLeaseTimeSeconds = 60 },
	} {
		want := v
		change(&want)
		if applied, err := c.SetLAN(context.Background(), want); !applied || err == nil {
			t.Fatal(applied, err)
		}
	}
}

func TestLANReadMissingDuplicatesMalformed(t *testing.T) {
	for _, test := range []string{"missing", "duplicate", "malformed-enable", "malformed-pool", "malformed-mode", "malformed-dns", "malformed-lease", "missing-lease", "fractional-lease"} {
		t.Run(test, func(t *testing.T) {
			c, f := networkClient(t)
			f.Mu.Lock()
			switch test {
			case "missing":
				f.LANs = nil
			case "duplicate":
				f.LANs = append(f.LANs, f.LANs[0])
			case "malformed-enable":
				delete(f.LANs[0], "EnableDHCP")
			case "malformed-pool":
				f.LANs[0]["DHCP_MinAddress"] = "bad"
			case "malformed-mode":
				f.LANs[0]["DHCPType"] = "unknown"
			case "malformed-dns":
				f.LANs[0]["DNS_Type"] = "Static"
			case "malformed-lease":
				f.LANs[0]["DHCP_LeaseTime"] = 61
			case "missing-lease":
				delete(f.LANs[0], "DHCP_LeaseTime")
			case "fractional-lease":
				f.LANs[0]["DHCP_LeaseTime"] = 60.5
			}
			f.Mu.Unlock()
			got, err := c.ReadLAN(context.Background(), "Default")
			if test == "missing" {
				if err != nil || got != nil {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid settings")
			}
			if applied, err := c.SetLAN(context.Background(), validLAN()); applied || err == nil {
				t.Fatal("wrote invalid or missing LAN", applied, err)
			}
			if f.Writes != 0 {
				t.Fatal("unexpected write")
			}
		})
	}
}

func TestLANWriteFailuresAndAddressChange(t *testing.T) {
	for _, failure := range []string{"reject", "ignore", "readback", "after-commit", "address"} {
		t.Run(failure, func(t *testing.T) {
			c, f := networkClient(t)
			f.RejectWrite = failure == "reject"
			f.IgnoreWrite = failure == "ignore"
			f.FailReadback = failure == "readback"
			f.FailAfterWrite = failure == "after-commit"
			v := validLAN()
			v.IGMPSnooping = "disabled"
			if failure == "address" {
				v.IPAddress = "192.0.2.2"
			}
			applied, err := c.SetLAN(context.Background(), v)
			if failure == "address" {
				if !applied || err != nil || f.LastWrite["logout"] != float64(1) {
					t.Fatal(applied, err, f.LastWrite)
				}
				return
			}
			if err == nil || applied != (failure != "reject") {
				t.Fatal(applied, err)
			}
			if strings.Contains(err.Error(), "fixture-password") || strings.Contains(err.Error(), "network-token") {
				t.Fatal("error leaks response", err)
			}
			if f.Writes > 1 {
				t.Fatal("retried uncertain write")
			}
		})
	}
}
