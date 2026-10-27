package provider

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestACLPolicyManagementUpdateOperations(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders, f.maxACLRows = true, 32
			c := aclFixtureClient(t, f)
			ctx := context.Background()
			p := fixtureACLPolicy("198.51.100.0/24")
			initial, err := c.ApplyACLPolicy(ctx, p, nil)
			if err != nil {
				t.Fatal(err)
			}
			before := len(f.history)
			p.Rules[0].SourceCIDR = "192.0.2.0/24"
			if changed {
				p.ManagementRules[0].SourceCIDR = "192.0.2.128/25"
			}
			out, err := c.ApplyACLPolicy(ctx, p, &initial.State)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"delete:" + initial.State.Names[2], "delete:" + initial.State.Names[1]}
			if changed {
				want = append(want, "create:"+out.State.Names[0], "delete:"+initial.State.Names[0])
			}
			want = append(want, "create:"+out.State.Names[1], "create:"+out.State.Names[2])
			var got []string
			last := f.history[before-1]
			for _, snapshot := range f.history[before:] {
				old, current := map[string]bool{}, map[string]bool{}
				for _, row := range last {
					old[row["Name"].(string)] = true
				}
				for _, row := range snapshot {
					current[row["Name"].(string)] = true
				}
				for name := range old {
					if !current[name] {
						got = append(got, "delete:"+name)
					}
				}
				for name := range current {
					if !old[name] {
						got = append(got, "create:"+name)
					}
				}
				if snapshot[0]["Name"] != "unmanaged" {
					t.Fatal("unmanaged prefix changed")
				}
				last = snapshot
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("operations = %v, want %v", got, want)
			}
			if !changed && out.State.Names[0] != initial.State.Names[0] {
				t.Fatal("unchanged management replaced")
			}
			if _, err := c.ReadACLPolicy(ctx, out.State); err != nil {
				t.Fatal(err)
			}
			if _, err := c.ImportACLPolicy(ctx, policyImportID(out.State)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestACLPolicyManagementCapacityPreflight(t *testing.T) {
	for _, kind := range []string{"final", "transitional", "service", "fits32"} {
		t.Run(kind, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders, f.maxACLRows = true, 32
			c := aclFixtureClient(t, f)
			ctx := context.Background()
			p := fixtureACLPolicy("198.51.100.0/24")
			if kind == "transitional" {
				for len(p.ManagementRules) < 16 {
					r := p.ManagementRules[0]
					r.Name = fmt.Sprint("M", len(p.ManagementRules))
					p.ManagementRules = append(p.ManagementRules, r)
				}
			}
			initial, err := c.ApplyACLPolicy(ctx, p, nil)
			if err != nil {
				t.Fatal(err)
			}
			posts, deletes := f.posts, f.deletes
			switch kind {
			case "final", "fits32":
				count := 31
				if kind == "fits32" {
					count = 30
				}
				for len(p.Rules) < count {
					r := p.Rules[len(p.Rules)-1]
					r.Name = ""
					p.Rules = append(p.Rules, r)
				}
			case "transitional":
				p.ManagementRules[0].SourceCIDR = "192.0.2.0/24"
			case "service":
				p.Rules[len(p.Rules)-1].ServiceID = "404"
				p.Rules[len(p.Rules)-1].Protocol = "all"
				p.Rules[len(p.Rules)-1].DestinationPortStart = nil
				p.Rules[len(p.Rules)-1].DestinationPortEnd = nil
			}
			out, err := c.ApplyACLPolicy(ctx, p, &initial.State)
			if kind == "fits32" {
				if err != nil || len(f.rows) != 32 {
					t.Fatalf("32 rows should fit: %v (%d)", err, len(f.rows))
				}
				return
			}
			if err == nil || out.Changed || f.posts != posts || f.deletes != deletes {
				t.Fatalf("preflight mutated router: %#v %v", out, err)
			}
		})
	}
}

func TestACLPolicyManagementRetryAtTransitionalLimit(t *testing.T) {
	f := newTerraformACLFixture(t)
	f.compactOrders, f.maxACLRows = true, 32
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	p := fixtureACLPolicy("198.51.100.0/24")
	for len(p.ManagementRules) < 15 {
		r := p.ManagementRules[0]
		r.Name = fmt.Sprint("M", len(p.ManagementRules))
		p.ManagementRules = append(p.ManagementRules, r)
	}
	initial, err := c.ApplyACLPolicy(ctx, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.ManagementRules {
		p.ManagementRules[i].SourceCIDR = "192.0.2.0/24"
	}
	f.failDeleteAt = f.deletes + 3 // All replacements verified; first management retirement fails.
	partial, err := c.ApplyACLPolicy(ctx, p, &initial.State)
	if err == nil || len(f.rows) != 31 {
		t.Fatalf("expected both management sets: %d %v", len(f.rows), err)
	}
	posts := f.posts
	f.failDeleteAt = 0
	out, err := c.ApplyACLPolicy(ctx, p, &partial.State)
	if err != nil {
		t.Fatal(err)
	}
	if f.posts != posts+2 {
		t.Fatal("retry recreated already verified management")
	}
	if _, err := c.ReadACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
	}
}

func TestACLPolicyManagementPartialRecovery(t *testing.T) {
	for _, failure := range []string{"deny-delete", "normal-delete", "management-create", "management-readback", "management-mismatch", "management-delete", "normal-create", "deny-create", "final-readback"} {
		t.Run(failure, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders = true
			c := aclFixtureClient(t, f)
			ctx := context.Background()
			p := fixtureACLPolicy("198.51.100.0/24")
			initial, err := c.ApplyACLPolicy(ctx, p, nil)
			if err != nil {
				t.Fatal(err)
			}
			p.ManagementRules[0].SourceCIDR = "192.0.2.0/24"
			switch failure {
			case "deny-delete":
				f.failDeleteAt = f.deletes + 1
			case "normal-delete":
				f.failDeleteAt = f.deletes + 2
			case "management-delete":
				f.failDeleteAt = f.deletes + 3
			case "management-create":
				f.failPostAt = f.posts + 1
			case "management-readback":
				f.failReadback = true
			case "management-mismatch":
				f.mutateCreate = func(row map[string]any) { row["SourceIP"] = "203.0.113.0" }
			case "normal-create":
				f.failPostAt = f.posts + 2
			case "deny-create":
				f.failPostAt = f.posts + 3
			case "final-readback":
				f.mutateCreate = func(row map[string]any) {
					if row["Target"] == "Drop" {
						f.failACLReadAt = f.aclReads + 3
					}
				}
			}
			out, err := c.ApplyACLPolicy(ctx, p, &initial.State)
			if err == nil || !out.Changed {
				t.Fatalf("expected partial failure: %#v %v", out, err)
			}
			if strings.HasPrefix(failure, "management-") && failure != "management-delete" {
				if err := f.check(initial.State.Names[0], true); err != nil {
					t.Fatal("old management lost before replacement verification")
				}
			}
			for _, row := range f.rows {
				name := row["Name"].(string)
				if name != "unmanaged" && !containsPolicyName(out.State.Names, name) {
					t.Fatalf("untracked write: %s", name)
				}
			}
			f.failDeleteAt, f.failPostAt, f.failReadback, f.failNextRead, f.mutateCreate = 0, 0, false, false, nil
			f.failACLReadAt = 0
			if failure == "management-mismatch" {
				// Security drift requires explicit operator reconciliation, not
				// automatic adoption of a misconfigured replacement.
				if _, err := c.InspectACLPolicyRecovery(ctx, out.State); err == nil {
					t.Fatal("security mismatch silently adopted")
				}
				return
			}
			recovery, err := c.InspectACLPolicyRecovery(ctx, out.State)
			if err != nil || !recovery.Pending {
				t.Fatalf("recovery inspection: %#v %v", recovery, err)
			}
			retried, err := c.ApplyACLPolicy(ctx, p, &out.State)
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			if _, err := c.ReadACLPolicy(ctx, retried.State); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func containsPolicyName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func TestACLPolicyManagementAdapterValidation(t *testing.T) {
	ctx := context.Background()
	var schemaResp resource.SchemaResponse
	r := &ACLPolicyResource{}
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if !schemaResp.Schema.Attributes["management_rules"].IsRequired() {
		t.Fatal("management list not required")
	}
	for _, action := range []string{"accept", "drop", "reject", "missing", "duplicate"} {
		m := testManagementModel()
		d := m
		d.Name = types.StringValue("Deny")
		d.Action = types.StringValue("drop")
		model := aclPolicyModel{ManagementRules: []aclPolicyRuleModel{m}, DropRules: []aclPolicyRuleModel{d}, RowNames: types.ListNull(types.StringType), ObservedOrders: types.ListNull(types.Int64Type)}
		if action == "missing" {
			model.ManagementRules = nil
		} else if action == "duplicate" {
			model.DropRules[0].Name = m.Name
		} else {
			model.ManagementRules[0].Action = types.StringValue(action)
		}
		plan := tfsdk.Plan{Schema: schemaResp.Schema}
		if d := plan.Set(ctx, model); d.HasError() {
			t.Fatal(d)
		}
		var resp resource.ValidateConfigResponse
		r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: plan.Raw}}, &resp)
		if resp.Diagnostics.HasError() != (action != "accept") {
			t.Fatalf("%s: %v", action, resp.Diagnostics)
		}
	}
}

type testPolicyPrivate map[string][]byte

func (p testPolicyPrivate) GetKey(_ context.Context, key string) ([]byte, diag.Diagnostics) {
	return p[key], nil
}
func (p testPolicyPrivate) SetKey(_ context.Context, key string, value []byte) diag.Diagnostics {
	p[key] = value
	return nil
}

func TestACLPolicyPrivateLedgerPreservesActualConfiguration(t *testing.T) {
	ctx := context.Background()
	private := testPolicyPrivate{}
	ledger := zyxel.ACLPolicyState{Generation: "7f", Names: []string{"M-g7f"}, ManagementNames: []string{"M-g7f"}, Rules: []zyxel.ACLRule{testACLRule("M-g7f", "accept", 2)}, Pending: true}
	if d := storePolicyLedger(ctx, private, ledger); d.HasError() {
		t.Fatal(d)
	}
	got, d := loadPolicyLedger(ctx, aclPolicyModel{}, private)
	if d.HasError() || !reflect.DeepEqual(got, ledger) {
		t.Fatalf("ledger lost: %#v %v", got, d)
	}
}

func TestACLPolicyV1UpgradePreservesOwnershipWithoutInventingManagement(t *testing.T) {
	ctx := context.Background()
	r := &ACLPolicyResource{}
	u := r.UpgradeState(ctx)[1]
	raw, err := tftypes.ValueFromJSON([]byte(`{
		"rules":[], "drop_rules":[], "generation":"7f",
		"row_names":["g7f-01","g7f-02"], "observed_orders":[2,3]
	}`), u.PriorSchema.Type().TerraformType(ctx))
	if err != nil {
		t.Fatal(err)
	}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	prior := tfsdk.State{Schema: *u.PriorSchema, Raw: raw}
	resp := resource.UpgradeStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	u.StateUpgrader(ctx, resource.UpgradeStateRequest{State: &prior}, &resp)
	var model aclPolicyModel
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if d := resp.State.Get(ctx, &model); d.HasError() {
		t.Fatal(d)
	}
	var names []string
	if d := model.RowNames.ElementsAs(ctx, &names, false); d.HasError() {
		t.Fatal(d)
	}
	if len(model.ManagementRules) != 0 || model.Generation.ValueString() != "7f" || !reflect.DeepEqual(names, []string{"g7f-01", "g7f-02"}) {
		t.Fatalf("upgrade changed ownership or invented management: %#v", model)
	}
}
