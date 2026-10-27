package zyxel

import (
	"fmt"
	"testing"
)

func legacyPolicyRowName(prefix, generation string, i int) string {
	return fmt.Sprintf("%s-g%s-%02d", prefix, generation, i+1)
}

// recoveryFixture uses a released legacy generation so recovery keeps reading
// ACL-g<16hex>-NN rows. The legacy prefix is ignored; ownership is the ledger.
func recoveryFixture(t *testing.T) (ACLPolicyState, []map[string]any) {
	t.Helper()
	state := ACLPolicyState{Generation: "0123456789abcdef"}
	rows := []map[string]any{fixtureACLRow("prefix", 1, 1)}
	for i := 0; i < 2; i++ {
		name := legacyPolicyRowName("ACL", state.Generation, i)
		row := fixtureACLRow(name, i+2, i+2)
		if i == 1 {
			row["Target"] = "Drop"
		}
		rule, err := parseACLRule(row)
		if err != nil {
			t.Fatal(err)
		}
		state.Names = append(state.Names, name)
		state.Rules = append(state.Rules, rule)
		rows = append(rows, row)
	}
	return state, rows
}

func TestACLPolicyRecoveryInspection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*ACLPolicyState, *[]map[string]any)
		pending bool
		missing int
		fail    bool
	}{
		{name: "complete"},
		{name: "missing old accept", edit: func(s *ACLPolicyState, r *[]map[string]any) { *r = append((*r)[:1], (*r)[2:]...) }, pending: true, missing: 1},
		{name: "all absent", edit: func(s *ACLPolicyState, r *[]map[string]any) { *r = (*r)[:1] }, pending: true, missing: 2},
		{name: "mixed generation", edit: func(s *ACLPolicyState, r *[]map[string]any) {
			n := legacyPolicyRowName("ACL", "fedcba9876543210", 0)
			s.Names = append(s.Names, n)
			*r = append(*r, fixtureACLRow(n, 4, 4))
		}, pending: true},
		{name: "ambiguous absent write", edit: func(s *ACLPolicyState, r *[]map[string]any) {
			s.Names = append(s.Names, legacyPolicyRowName("ACL", "fedcba9876543210", 0))
		}, pending: true, missing: 1},
		{name: "untracked generation", edit: func(s *ACLPolicyState, r *[]map[string]any) {
			*r = append(*r, fixtureACLRow(legacyPolicyRowName("Other", s.Generation, 0), 4, 4))
		}, fail: true},
		{name: "unparseable ledger name", edit: func(s *ACLPolicyState, r *[]map[string]any) {
			s.Names = append(s.Names, "policy-gnot-a-generated-name")
		}, fail: true},
		{name: "duplicate ledger", edit: func(s *ACLPolicyState, r *[]map[string]any) { s.Names = append(s.Names, s.Names[0]) }, fail: true},
		{name: "duplicate router identity", edit: func(s *ACLPolicyState, r *[]map[string]any) { *r = append(*r, fixtureACLRow(s.Names[0], 4, 4)) }, fail: true},
		{name: "unrelated tail", edit: func(s *ACLPolicyState, r *[]map[string]any) { *r = append(*r, fixtureACLRow("unrelated", 4, 4)) }, fail: true},
		{name: "interleaved", edit: func(s *ACLPolicyState, r *[]map[string]any) {
			(*r)[2]["Order"] = 4
			*r = append(*r, fixtureACLRow("unrelated", 3, 3))
		}, fail: true},
		{name: "reordered", edit: func(s *ACLPolicyState, r *[]map[string]any) { (*r)[1]["Order"], (*r)[2]["Order"] = 3, 2 }, fail: true},
		{name: "unsupported row", edit: func(s *ACLPolicyState, r *[]map[string]any) { (*r)[1]["Target"] = "Unknown" }, fail: true},
		{name: "changed old row", edit: func(s *ACLPolicyState, r *[]map[string]any) { (*r)[1]["Enable"] = false }, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, rows := recoveryFixture(t)
			if tc.edit != nil {
				tc.edit(&state, &rows)
			}
			got, _, err := inspectACLPolicyRecovery(rows, state)
			if (err != nil) != tc.fail {
				t.Fatalf("error = %v, want failure %v", err, tc.fail)
			}
			if err != nil {
				return
			}
			if got.Pending != tc.pending || len(got.Missing) != tc.missing {
				t.Fatalf("unexpected recovery: %#v", got)
			}
			if len(got.State.Names) != len(state.Names) || len(got.State.Rules) != len(state.Rules) {
				t.Fatal("inspection discarded ledger")
			}
		})
	}
}

func TestACLPolicyRecoveryNamedAndUnnamedLedger(t *testing.T) {
	state := ACLPolicyState{Generation: "7f3d"}
	rows := []map[string]any{fixtureACLRow("prefix", 1, 1)}
	for i, label := range []string{"WebDAV", ""} {
		name := aclPolicyRowName(state.Generation, i, label)
		row := fixtureACLRow(name, i+2, i+2)
		if i == 1 {
			row["Target"] = "Drop"
		}
		rule, err := parseACLRule(row)
		if err != nil {
			t.Fatal(err)
		}
		state.Names = append(state.Names, name)
		state.Rules = append(state.Rules, rule)
		rows = append(rows, row)
	}
	if state.Names[0] != "WebDAV-g7f3d" || state.Names[1] != "g7f3d-02" {
		t.Fatalf("unexpected row names: %v", state.Names)
	}
	got, _, err := inspectACLPolicyRecovery(rows, state)
	if err != nil || got.Pending {
		t.Fatalf("recovery = %#v, %v", got, err)
	}
	if len(got.State.LogicalNames) != 2 || got.State.LogicalNames[0] != "WebDAV" || got.State.LogicalNames[1] != "" {
		t.Fatalf("logical names: %v", got.State.LogicalNames)
	}
}

func TestACLPolicyTrackedNames(t *testing.T) {
	for _, name := range []string{
		"WebDAV-g7f3d", "g7f3d-01", "g7f3d-999",
		"ACL-g0123456789abcdef-01", "ACL-g0123456789abcdef-001", "ACL-g0123456789abcdef-999",
	} {
		if !validACLPolicyTrackedName(name) {
			t.Fatalf("rejected %s", name)
		}
	}
	for _, name := range []string{
		"g7f3d-00", "g7f3d-1", "g7f3d-0001", "g7f3d-1000",
		"policy-g0123456789abcdef-00", "policy-g0123456789abcdef-1",
		"policy-g0123456789abcdef-0001", "policy-g0123456789abcdef-1000",
		"policy-g0123456789abcdeF-01", "policy-g0123456789abcdef-+1",
		"other", "",
	} {
		if validACLPolicyTrackedName(name) {
			t.Fatalf("accepted %s", name)
		}
	}
}
