package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
)

func fixtureACLPolicy(sources ...string) zyxel.ACLPolicy {
	p := zyxel.ACLPolicy{Name: "test-policy"}
	for i, source := range append(sources, "0.0.0.0/0") {
		r := testACLRule("logical-"+string(rune('a'+i)), "accept", 0)
		r.SourceCIDR = source
		if i == len(sources) {
			r.Action = "drop"
		}
		p.Rules = append(p.Rules, r)
	}
	return p
}

func TestACLPolicyStagesGrowthBehindExistingDrop(t *testing.T) {
	f := newTerraformACLFixture(t)
	f.rows[0]["Order"] = 40
	f.compactOrders, f.rejectOccupiedOrder = true, true
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	first, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("198.51.100.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || len(first.State.Names) != 2 || !strings.HasSuffix(first.State.Names[0], "-001") || first.State.Rules[0].Order != 2 {
		t.Fatalf("unexpected state: %#v", first)
	}
	beforeUpdate := len(f.history)
	second, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("192.0.2.0/24", "198.51.100.0/24"), &first.State)
	if err != nil {
		t.Fatal(err)
	}
	if second.State.Generation == first.State.Generation || len(second.State.Names) != 3 {
		t.Fatalf("generation not replaced: %#v", second)
	}
	for _, snapshot := range f.history[beforeUpdate:] {
		var drops int
		for _, row := range snapshot {
			if row["Target"] == "Drop" {
				drops++
			}
		}
		if drops == 0 {
			t.Fatal("policy update removed terminal protection")
		}
		if snapshot[0]["Name"] != "unmanaged" {
			t.Fatal("unrelated prefix mutated")
		}
	}
	// All new rows precede their drop; compaction is recorded, not rejected.
	for i, rule := range second.State.Rules {
		if rule.Order != int64(i+2) {
			t.Fatalf("bad observed order: %#v", rule)
		}
	}
	refreshed, err := c.ReadACLPolicy(ctx, second.State)
	if err != nil || len(refreshed.Names) != 3 {
		t.Fatalf("refresh: %#v %v", refreshed, err)
	}
	imported, err := c.ImportACLPolicy(ctx, second.State.Name, second.State.Generation)
	if err != nil || len(imported.Names) != 3 {
		t.Fatalf("explicit import: %#v %v", imported, err)
	}
	third, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("192.0.2.0/24"), &second.State)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteACLPolicy(ctx, third.State); err != nil {
		t.Fatal(err)
	}
	if len(f.rows) != 1 || f.rows[0]["Name"] != "unmanaged" {
		t.Fatal("destroy changed unrelated rules")
	}
}

func TestACLPolicyFailuresPreserveOwnershipAndOldDrop(t *testing.T) {
	for _, stage := range []string{"ambiguous-first", "ambiguous-drop", "readback", "security", "retirement"} {
		t.Run(stage, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders = true
			c := aclFixtureClient(t, f)
			ctx := context.Background()
			initial, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("198.51.100.0/24"), nil)
			if err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "ambiguous-first":
				f.failPostAt = f.posts + 1
			case "ambiguous-drop":
				f.failPostAt = f.posts + 3
			case "readback":
				f.failReadback = true
			case "security":
				f.mutateCreate = func(row map[string]any) { row["SourceIP"] = "203.0.113.0" }
			case "retirement":
				f.failDeleteAt = 1
			}
			out, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("198.51.100.0/24", "192.0.2.0/24"), &initial.State)
			if err == nil || !out.Changed || len(out.State.Names) <= len(initial.State.Names) {
				t.Fatalf("lost partial ledger: %#v %v", out, err)
			}
			if err := f.check(initial.State.Names[len(initial.State.Names)-1], true); err != nil {
				t.Fatal("old drop lost:", err)
			}
			posts := f.posts
			if _, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("192.0.2.0/24"), &out.State); err == nil || f.posts != posts {
				t.Fatal("automatically retried incomplete generation")
			}
			f.failDeleteAt = 0
			if err := c.DeleteACLPolicy(ctx, out.State); err != nil {
				t.Fatal("could not clean exact tracked rows:", err)
			}
		})
	}
}

func TestACLPolicyPreflightRejectsCollisionsDriftAndScopeChange(t *testing.T) {
	for _, kind := range []string{"untracked", "duplicate", "interleaved", "scope", "drift", "missing"} {
		t.Run(kind, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders = true
			c := aclFixtureClient(t, f)
			ctx := context.Background()
			initial, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("198.51.100.0/24"), nil)
			if err != nil {
				t.Fatal(err)
			}
			desired := fixtureACLPolicy("192.0.2.0/24")
			switch kind {
			case "untracked":
				f.rows = append(f.rows, fixtureACLRow("test-policy-guntracked-001", 4, 4))
			case "duplicate":
				f.rows = append(f.rows, fixtureACLRow(initial.State.Names[0], 4, 4))
			case "interleaved":
				f.rows = append(f.rows, fixtureACLRow("other", 4, 4))
			case "scope":
				for i := range desired.Rules {
					desired.Rules[i].DestinationCIDR = "192.0.2.1/32"
				}
			case "drift":
				f.rows[1]["Enable"] = false
			case "missing":
				f.rows = append(f.rows[:1], f.rows[2:]...)
			}
			posts := f.posts
			if _, err := c.ApplyACLPolicy(ctx, desired, &initial.State); err == nil || f.posts != posts {
				t.Fatal("unsafe policy reconciliation wrote rows")
			}
		})
	}
	f := newTerraformACLFixture(t)
	f.rows = append(f.rows, fixtureACLRow("test-policy-gexisting-001", 2, 2))
	if _, err := aclFixtureClient(t, f).ApplyACLPolicy(context.Background(), fixtureACLPolicy("192.0.2.0/24"), nil); err == nil || f.posts != 0 {
		t.Fatal("create adopted policy namespace")
	}
}
