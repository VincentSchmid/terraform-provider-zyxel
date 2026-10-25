package zyxel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFirewallDirectGoInputValidation(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:1", Credentials{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := client.SetFirewall(context.Background(), FirewallSettings{SecurityLevel: "invalid"})
	if applied || err == nil || strings.Contains(err.Error(), "session") {
		t.Fatalf("invalid security level reached network: applied=%v err=%v", applied, err)
	}
}

func TestFirewallBoolRejectsUnexpectedRepresentations(t *testing.T) {
	for _, value := range []any{"true", "false", float64(2), nil} {
		if _, ok := firewallBool(value); ok {
			t.Errorf("accepted unsupported firewall boolean: %#v", value)
		}
	}
	for _, value := range []any{true, false, float64(0), float64(1)} {
		if _, ok := firewallBool(value); !ok {
			t.Errorf("rejected supported firewall boolean: %#v", value)
		}
	}
}
