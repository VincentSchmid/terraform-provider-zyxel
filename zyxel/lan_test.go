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
	return zyxel.LANSettings{InterfaceGroupID: "Default", IPAddress: "192.0.2.1", SubnetMask: "255.255.255.0", IGMPSnooping: "standard", DHCPMode: "server", BeginningIPAddress: "192.0.2.100", EndingIPAddress: "192.0.2.200"}
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
		if mode == "relay" {
			v.RelayServerAddress = "198.51.100.10"
		}
		if mode == "server" {
			v.BeginningIPAddress = "192.0.2.50"
			v.EndingIPAddress = "192.0.2.150"
			v.AutoReserveIP = true
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
		for _, field := range []string{"IPv6_LanEnable", "IPv6_Prefix", "DNS_Type", "DHCP_LeaseTime"} {
			if _, ok := f.LastWrite[field]; ok {
				t.Errorf("wrote unmanaged field %s", field)
			}
		}
		if f.LANs[0]["IPv6_LanEnable"] != true || f.LANs[0]["DHCP_LeaseTime"] != 86400 {
			t.Error("changed unmanaged settings")
		}
		f.Mu.Unlock()
	}
}

func TestLANReadMissingDuplicatesMalformed(t *testing.T) {
	for _, test := range []string{"missing", "duplicate", "malformed-enable", "malformed-pool", "malformed-mode"} {
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
