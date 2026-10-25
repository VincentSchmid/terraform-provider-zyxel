package zyxel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDHCPCreateValidatesDirectGoInputsBeforeNetwork(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:1", Credentials{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mac, ip string
	}{
		{"invalid", "192.0.2.1"},
		{"aa:bb:cc:dd:ee:ff", "192.0.2.1"},
		{"AA:BB:CC:DD:EE:FF", "invalid"},
		{"AA:BB:CC:DD:EE:FF", "::ffff:192.0.2.1"},
	} {
		created, err := client.CreateDHCPReservation(context.Background(), test.mac, test.ip, true)
		if created || err == nil || strings.Contains(err.Error(), "session") {
			t.Errorf("invalid direct input reached network: created=%v err=%v", created, err)
		}
	}
}

func TestDHCPReservationClientRejectsDuplicateAndMalformedRows(t *testing.T) {
	rows := []DHCPReservation{{Index: 1, MACAddr: "AA:BB:CC:DD:EE:FF", IPAddr: "192.0.2.1", Enabled: true}}
	if _, err := findDHCPReservation(rows, "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatalf("case-insensitive identity lookup failed: %v", err)
	}
	rows = append(rows, rows[0])
	if _, err := findDHCPReservation(rows, "AA:BB:CC:DD:EE:FF"); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("expected duplicate identity error, got %v", err)
	}
	if _, err := NormalizeMAC("not-a-mac"); err == nil {
		t.Fatal("expected invalid import ID rejection")
	}
	if mac, err := NormalizeMAC("aa-bb-cc-dd-ee-ff"); err != nil || mac != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("normalized import MAC = %q, %v", mac, err)
	}
}

func TestDHCPIndexValidation(t *testing.T) {
	for _, value := range []any{float64(0), float64(-1), float64(1.5), "2", nil} {
		if index, ok := integerValue(value); ok {
			t.Errorf("integerValue(%#v) = %d, true; want invalid", value, index)
		}
	}
	if index, ok := integerValue(float64(4)); !ok || index != 4 {
		t.Fatalf("integerValue(4) = %d, %t", index, ok)
	}
}
