package zyxel

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestACLAppendInputValidation(t *testing.T) {
	c, err := NewClient("http://127.0.0.1:1", Credentials{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{ACLOrderAppend, "unknown"} {
		r := testACLRule("invalid", "accept", 1)
		r.OrderMode = mode
		outcome, err := c.CreateACLRule(context.Background(), r)
		if err == nil || strings.Contains(err.Error(), "session") || outcome.Applied || outcome.Ambiguous {
			t.Fatalf("invalid mode/order reached network: %#v %v", outcome, err)
		}
	}
}

func TestACLAppendVerification(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]map[string]any)
		fail bool
	}{
		{"compacted prefix", func([]map[string]any) {}, false},
		{"not last", func(rows []map[string]any) { rows[0]["Order"] = 3 }, true},
		{"duplicate order", func(rows []map[string]any) { rows[0]["Order"] = 2 }, true},
		{"invalid order", func(rows []map[string]any) { rows[0]["Order"] = nil }, true},
		{"drop", func(rows []map[string]any) { rows[0]["Target"] = "Drop" }, true},
		{"reject", func(rows []map[string]any) { rows[0]["Target"] = "Reject" }, true},
		{"unknown action", func(rows []map[string]any) { delete(rows[0], "Target") }, true},
		{"disabled drop", func(rows []map[string]any) { rows[0]["Target"], rows[0]["Enable"] = "Drop", false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := []map[string]any{fixtureACLRow("prefix", 1, 1), fixtureACLRow("new", 2, 2)}
			tc.edit(rows)
			err := verifyACLAppend(rows, testACLRule("new", "accept", 2))
			if (err != nil) != tc.fail {
				t.Fatalf("verification error = %v, want failure %v", err, tc.fail)
			}
		})
	}
}

func TestClientsShareEndpointSessionLock(t *testing.T) {
	a, _ := NewClient("http://127.0.0.1:1234", Credentials{}, time.Second)
	b, _ := NewClient("http://127.0.0.1:1234/", Credentials{}, time.Second)
	c, _ := NewClient("http://127.0.0.1:1235", Credentials{}, time.Second)
	if a.sessionGate != b.sessionGate || a.sessionGate == c.sessionGate {
		t.Fatal("session lock must be shared only for the same normalized endpoint")
	}
}
