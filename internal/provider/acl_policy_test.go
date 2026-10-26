package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// serviceACLPolicy swaps the inline filters for a custom service, exactly as
// the adapter does when a rule sets service_id.
func serviceACLPolicy(service string, sources ...string) zyxel.ACLPolicy {
	p := fixtureACLPolicy(sources...)
	for i := range p.Rules {
		p.Rules[i].Protocol, p.Rules[i].ServiceID = "all", service
		p.Rules[i].DestinationPortStart, p.Rules[i].DestinationPortEnd = nil, nil
	}
	return p
}

func TestACLPolicyModelPassesServiceRuleParameters(t *testing.T) {
	rule := func(action, source string) aclPolicyRuleModel {
		return aclPolicyRuleModel{
			Action: types.StringValue(action), Protocol: types.StringNull(), ServiceID: types.StringValue("101"),
			IPVersion: types.StringValue("ipv4"), Direction: types.StringValue("wan_to_lan"),
			SourceCIDR: types.StringValue(source), DestinationCIDR: types.StringValue("203.0.113.10/32"),
			SourcePorts: types.StringNull(), DestinationPorts: types.StringNull(),
		}
	}
	model := aclPolicyModel{
		Name:      types.StringValue("policy"),
		Rules:     []aclPolicyRuleModel{rule("accept", "198.51.100.0/24")},
		DropRules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")},
	}
	p, known := modelACLPolicy(model)
	if !known {
		t.Fatal("service policy rules must be known before writes")
	}
	for _, got := range p.Rules {
		if got.ServiceID != "101" || got.Protocol != "all" || got.DestinationPorts != "" || got.SourcePorts != "" {
			t.Fatalf("service_id was not passed to the ACL rule: %#v", got)
		}
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	model.Rules[0].ServiceID = types.StringUnknown()
	if _, known := modelACLPolicy(model); known {
		t.Fatal("unknown service_id must block the write")
	}
}

func TestACLPolicyModelDefaultsProtocolForBothServiceForms(t *testing.T) {
	base := func(action, source string) aclPolicyRuleModel {
		return aclPolicyRuleModel{
			Action: types.StringValue(action), Protocol: types.StringNull(),
			Service: types.StringNull(), ServiceID: types.StringNull(),
			IPVersion: types.StringValue("ipv4"), Direction: types.StringValue("wan_to_lan"),
			SourceCIDR: types.StringValue(source), DestinationCIDR: types.StringValue("203.0.113.10/32"),
			SourcePorts: types.StringNull(), DestinationPorts: types.StringNull(),
			MACAddress: types.StringNull(), TCPFlag: types.StringNull(),
			PacketsPerUnit: types.Int64Null(), RateLimitUnit: types.StringNull(),
		}
	}
	byName := base("accept", "198.51.100.0/24")
	byName.Service = types.StringValue("https")
	byID := base("accept", "192.0.2.0/24")
	byID.ServiceID = types.StringValue("101")
	inline := base("drop", "0.0.0.0/0")
	inline.Protocol = types.StringValue("udp")
	inline.DestinationPorts = types.StringValue("1194")

	model := aclPolicyModel{
		Name:      types.StringValue("policy"),
		Rules:     []aclPolicyRuleModel{byName, byID},
		DropRules: []aclPolicyRuleModel{inline},
	}
	p, known := modelACLPolicy(model)
	if !known {
		t.Fatal("policy with known service rules reported unknown")
	}
	if got := []string{p.Rules[0].Protocol, p.Rules[1].Protocol, p.Rules[2].Protocol}; got[0] != "all" || got[1] != "all" || got[2] != "udp" {
		t.Fatalf("service rules must compute all: %v", got)
	}
	if p.Rules[0].Service != "https" || p.Rules[1].ServiceID != "101" {
		t.Fatalf("per-rule service selection lost: %#v", p.Rules)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestACLPolicyModelKeepsAcceptsBeforeDrops(t *testing.T) {
	base := func(action string) aclPolicyRuleModel {
		return aclPolicyRuleModel{
			Action: types.StringValue(action), Protocol: types.StringValue("udp"),
			IPVersion: types.StringValue("ipv4"), Direction: types.StringValue("wan_to_lan"),
			SourceCIDR: types.StringValue("0.0.0.0/0"), DestinationCIDR: types.StringValue("203.0.113.10/32"),
			Service: types.StringNull(), ServiceID: types.StringNull(),
			SourcePorts: types.StringNull(), DestinationPorts: types.StringValue("1194"),
			MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), TCPFlag: types.StringNull(),
			PacketsPerUnit: types.Int64Value(10), RateLimitUnit: types.StringValue("second"),
		}
	}
	accept := base("accept")
	drop := base("drop")
	drop.PacketsPerUnit, drop.RateLimitUnit = types.Int64Null(), types.StringNull()
	model := aclPolicyModel{
		Name:      types.StringValue("policy"),
		Rules:     []aclPolicyRuleModel{accept},
		DropRules: []aclPolicyRuleModel{drop},
	}
	p, known := modelACLPolicy(model)
	if !known {
		t.Fatal("known policy reported unknown")
	}
	if len(p.Rules) != 2 || p.Rules[0].Action != "accept" || p.Rules[1].Action != "drop" {
		t.Fatalf("accepts must precede drops: %#v", p.Rules)
	}
	if p.Rules[0].MACAddress != "AA:BB:CC:DD:EE:FF" || p.Rules[0].RateLimit == nil || *p.Rules[0].RateLimit != 10 || p.Rules[0].RateLimitUnit != "second" {
		t.Fatalf("per-rule filters lost: %#v", p.Rules[0])
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestACLPolicyValidateConfigAcceptsSeparateRuleLists(t *testing.T) {
	ctx := context.Background()
	var schemaResp resource.SchemaResponse
	(&ACLPolicyResource{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}
	rule := func(action, source string) aclPolicyRuleModel {
		return aclPolicyRuleModel{
			Action: types.StringValue(action), Protocol: types.StringValue("tcp"),
			Service: types.StringNull(), ServiceID: types.StringNull(),
			IPVersion: types.StringValue("ipv4"), Direction: types.StringValue("wan_to_lan"),
			SourceCIDR: types.StringValue(source), DestinationCIDR: types.StringValue("203.0.113.10/32"),
			SourcePorts: types.StringNull(), DestinationPorts: types.StringValue("443"),
			MACAddress: types.StringNull(), TCPFlag: types.StringNull(),
			PacketsPerUnit: types.Int64Null(), RateLimitUnit: types.StringNull(),
		}
	}
	for _, test := range []struct {
		name      string
		rules     []aclPolicyRuleModel
		dropRules []aclPolicyRuleModel
		invalid   bool
	}{
		{name: "accepts then drops", rules: []aclPolicyRuleModel{rule("accept", "198.51.100.0/24")}, dropRules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")}},
		{name: "drops only", dropRules: []aclPolicyRuleModel{rule("reject", "0.0.0.0/0")}},
		{name: "drop in rules", rules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")}, dropRules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")}, invalid: true},
		{name: "accept in drop_rules", rules: []aclPolicyRuleModel{rule("accept", "198.51.100.0/24")}, dropRules: []aclPolicyRuleModel{rule("accept", "0.0.0.0/0")}, invalid: true},
		{name: "no drop", rules: []aclPolicyRuleModel{rule("accept", "198.51.100.0/24")}, invalid: true},
		{name: "inline without protocol", rules: []aclPolicyRuleModel{func() aclPolicyRuleModel {
			r := rule("accept", "198.51.100.0/24")
			r.Protocol = types.StringNull()
			return r
		}()}, dropRules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")}, invalid: true},
		{name: "service without protocol", rules: []aclPolicyRuleModel{func() aclPolicyRuleModel {
			r := rule("accept", "198.51.100.0/24")
			r.Protocol, r.DestinationPorts, r.Service = types.StringNull(), types.StringNull(), types.StringValue("https")
			return r
		}()}, dropRules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")}},
		{name: "service_id without protocol", rules: []aclPolicyRuleModel{func() aclPolicyRuleModel {
			r := rule("accept", "198.51.100.0/24")
			r.Protocol, r.DestinationPorts, r.ServiceID = types.StringNull(), types.StringNull(), types.StringValue("101")
			return r
		}()}, dropRules: []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := aclPolicyModel{
				Name: types.StringValue("policy"), Rules: test.rules, DropRules: test.dropRules,
				Generation: types.StringNull(), RowNames: types.ListNull(types.StringType), ObservedOrders: types.ListNull(types.Int64Type),
			}
			plan := tfsdk.Plan{Schema: schemaResp.Schema}
			if diags := plan.Set(ctx, model); diags.HasError() {
				t.Fatal(diags)
			}
			var resp resource.ValidateConfigResponse
			(&ACLPolicyResource{}).ValidateConfig(ctx, resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: plan.Raw}}, &resp)
			if resp.Diagnostics.HasError() != test.invalid {
				t.Fatalf("diagnostics=%v", resp.Diagnostics)
			}
		})
	}
}

func TestACLPolicyCreatesServiceRulesThroughACLRulePath(t *testing.T) {
	f := newTerraformACLFixture(t)
	f.addService("https", 7)
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	out, err := c.ApplyACLPolicy(ctx, serviceACLPolicy("7", "198.51.100.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.State.Rules) != 2 {
		t.Fatalf("unexpected ledger: %#v", out.State)
	}
	for _, rule := range out.State.Rules {
		if rule.ServiceID != "7" || rule.Protocol != "all" || rule.DestinationPortStart != nil {
			t.Fatalf("service filters not preserved through the ACL rule path: %#v", rule)
		}
	}
	grown, err := c.ApplyACLPolicy(ctx, serviceACLPolicy("7", "198.51.100.0/24", "192.0.2.0/24"), &out.State)
	if err != nil {
		t.Fatal(err)
	}
	f.addService("https-2", 8)
	changed, err := c.ApplyACLPolicy(ctx, serviceACLPolicy("8", "198.51.100.0/24"), &grown.State)
	if err != nil {
		t.Fatalf("per-rule service change was rejected: %v", err)
	}
	if changed.State.Generation == grown.State.Generation {
		t.Fatal("service change did not stage a new generation")
	}
	if _, err := c.ImportACLPolicy(ctx, changed.State.Name, changed.State.Generation); err != nil {
		t.Fatalf("import of a service-backed policy: %v", err)
	}
	if err := c.DeleteACLPolicy(ctx, changed.State); err != nil {
		t.Fatal(err)
	}
}

func TestACLPolicyRejectsUnknownServiceBeforeWrites(t *testing.T) {
	f := newTerraformACLFixture(t)
	c := aclFixtureClient(t, f)
	if _, err := c.ApplyACLPolicy(context.Background(), serviceACLPolicy("404", "198.51.100.0/24"), nil); err == nil || f.posts != 0 {
		t.Fatal("policy with a missing service wrote ACL rows")
	}
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

func TestACLPolicyPreflightRejectsCollisionsDriftAndMissingRows(t *testing.T) {
	for _, kind := range []string{"untracked", "duplicate", "interleaved", "drift", "missing"} {
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
