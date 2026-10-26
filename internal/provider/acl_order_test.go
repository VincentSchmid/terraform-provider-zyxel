package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
)

func aclFixtureClient(t *testing.T, f *terraformACLFixture) *zyxel.Client {
	t.Helper()
	c, err := zyxel.NewClient(f.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func appendACLRule(name string) zyxel.ACLRule {
	r := testACLRule(name, "accept", 0)
	r.OrderMode = zyxel.ACLOrderAppend
	return r
}

func TestACLAppendConcurrentCreatesSelectFreshPositions(t *testing.T) {
	f := newTerraformACLFixture(t)
	f.rows[0]["Order"] = 20
	f.compactOrders, f.rejectOccupiedOrder = true, true
	// Two clients model provider aliases configured for the same endpoint.
	clients := []*zyxel.Client{aclFixtureClient(t, f), aclFixtureClient(t, f)}
	const count = 12
	start := make(chan struct{})
	errors := make(chan error, count)
	for i := range count {
		go func(i int) {
			<-start
			r := appendACLRule(fmt.Sprintf("equivalent-%02d", count-i))
			outcome, err := clients[i%2].CreateACLRule(context.Background(), r)
			if err == nil && (!outcome.Applied || outcome.Rule == nil || outcome.Rule.Order < 2) {
				err = fmt.Errorf("missing observed append position: %#v", outcome)
			}
			errors <- err
		}(i)
	}
	close(start)
	for range count {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != count || f.maxActiveSessions != 1 || f.rows[0]["Name"] != "unmanaged" {
		t.Fatalf("unsafe concurrent append: posts=%d sessions=%d", f.posts, f.maxActiveSessions)
	}
	for i, order := range f.requestedOrders {
		want := i + 2
		if i == 0 {
			want = 21
		}
		if order != want {
			t.Fatalf("stale selection %d: got %d want %d", i, order, want)
		}
	}
}

func TestACLAppendRefusesExistingTerminalRulesAndNames(t *testing.T) {
	for _, target := range []string{"Drop", "Reject", "unknown"} {
		t.Run(target, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.rows = append(f.rows, map[string]any{"Name": "trailing-https-drop", "Order": 2, "Target": target, "Enable": true})
			outcome, err := aclFixtureClient(t, f).CreateACLRule(context.Background(), appendACLRule("new-accept"))
			if err == nil || !strings.Contains(err.Error(), "insertion/reordering") || outcome.Applied || outcome.Ambiguous || f.posts != 0 {
				t.Fatalf("unsafe append: %#v %v", outcome, err)
			}
		})
	}
	for _, duplicates := range []int{1, 2} {
		t.Run(fmt.Sprintf("name matches %d", duplicates), func(t *testing.T) {
			f := newTerraformACLFixture(t)
			for i := range duplicates {
				f.rows = append(f.rows, fixtureACLRow("existing", i+2, i+2))
			}
			outcome, err := aclFixtureClient(t, f).CreateACLRule(context.Background(), appendACLRule("existing"))
			if err == nil || outcome.Applied || outcome.Ambiguous || f.posts != 0 {
				t.Fatalf("adopted existing row: %#v %v", outcome, err)
			}
		})
	}
}

func TestACLAppendStillVerifiesSecurityFields(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		want  string
	}{
		{"Target", "Drop", "action"}, {"Enable", false, "enabled"},
		{"SourceIP", "192.0.2.0", "source_cidr"}, {"DestIP", "192.0.2.1", "destination_cidr"},
		{"DestPort", 80, "destination_port_start"}, {"Protocol", "UDP", "protocol"},
		{"Direction", "LAN_TO_WAN", "direction"}, {"LimitRate", 1, "rate_limit"},
		{"Order", 1, "append verification"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.mutateCreate = func(row map[string]any) { row[tc.field] = tc.value }
			outcome, err := aclFixtureClient(t, f).CreateACLRule(context.Background(), appendACLRule("changed"))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !outcome.Applied || outcome.Ambiguous {
				t.Fatalf("security mismatch not reported: %#v %v", outcome, err)
			}
		})
	}
}
