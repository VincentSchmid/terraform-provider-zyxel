package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func fixtureACLPolicy(sources ...string) zyxel.ACLPolicy {
	p := zyxel.ACLPolicy{ManagementRules: []zyxel.ACLRule{testACLRule("Management", "accept", 0)}}
	for i, source := range append(sources, "0.0.0.0/0") {
		r := testACLRule("", "accept", 0)
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
		ManagementRules: []aclPolicyRuleModel{testManagementModel()},
		Rules:           []aclPolicyRuleModel{rule("accept", "198.51.100.0/24")},
		DropRules:       []aclPolicyRuleModel{rule("drop", "0.0.0.0/0")},
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
		ManagementRules: []aclPolicyRuleModel{testManagementModel()},
		Rules:           []aclPolicyRuleModel{byName, byID},
		DropRules:       []aclPolicyRuleModel{inline},
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
		ManagementRules: []aclPolicyRuleModel{testManagementModel()},
		Rules:           []aclPolicyRuleModel{accept},
		DropRules:       []aclPolicyRuleModel{drop},
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
				ManagementRules: []aclPolicyRuleModel{testManagementModel()},
				Rules:           test.rules, DropRules: test.dropRules,
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
	if len(out.State.Rules) != 3 {
		t.Fatalf("unexpected ledger: %#v", out.State)
	}
	for _, rule := range out.State.Rules[1:] {
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
	if _, err := c.ImportACLPolicy(ctx, policyImportID(changed.State)); err != nil {
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

func TestACLPolicyReadsLegacyThreeDigitGeneration(t *testing.T) {
	f := newTerraformACLFixture(t)
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	initial, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("198.51.100.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.State.Names) != 3 || !strings.HasSuffix(initial.State.Names[1], "-02") || !strings.HasSuffix(initial.State.Names[2], "-03") {
		t.Fatalf("new generation did not use two-digit suffixes: %v", initial.State.Names)
	}

	// Rewrite the generation as a released v2 provider would have named it.
	legacy := initial.State
	legacy.Names = nil
	legacy.Generation = "0123456789abcdef"
	legacy.ManagementNames = nil
	for i, name := range initial.State.Names {
		legacyName := fmt.Sprintf("ACL-g%s-%03d", legacy.Generation, i+1)
		for _, row := range f.rows {
			if row["Name"] == name {
				row["Name"] = legacyName
			}
		}
		legacy.Names = append(legacy.Names, legacyName)
		legacy.Rules[i].Name = legacyName
	}
	if _, err := c.ReadACLPolicy(ctx, legacy); err != nil {
		t.Fatalf("read of a three-digit generation: %v", err)
	}
	imported, err := c.ImportACLPolicy(ctx, legacy.Generation)
	if err != nil {
		t.Fatalf("import of a three-digit generation: %v", err)
	}
	if len(imported.Names) != len(legacy.Names) || imported.Names[0] != legacy.Names[0] {
		t.Fatalf("legacy import ledger: %#v", imported.Names)
	}
	out, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy("198.51.100.0/24", "192.0.2.0/24"), &legacy)
	if err != nil {
		t.Fatalf("update from a three-digit generation: %v", err)
	}
	for i, name := range out.State.Names[1:] {
		if !strings.HasSuffix(name, fmt.Sprintf("-%02d", i+2)) {
			t.Fatalf("replacement generation did not use two-digit suffixes: %v", out.State.Names)
		}
	}
	if err := c.DeleteACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
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
				f.rows = append(f.rows, fixtureACLRow(fmt.Sprintf("g%s-03", initial.State.Generation), 4, 4))
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
			out, err := c.ApplyACLPolicy(ctx, desired, &initial.State)
			if kind == "missing" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.ReadACLPolicy(ctx, out.State); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || f.posts != posts {
				t.Fatal("unsafe policy reconciliation wrote rows")
			}
		})
	}
	f := newTerraformACLFixture(t)
	f.rows = append(f.rows, fixtureACLRow("Other-g7f3d", 2, 2))
	out, err := aclFixtureClient(t, f).ApplyACLPolicy(context.Background(), fixtureACLPolicy("192.0.2.0/24"), nil)
	if err != nil || len(out.State.Names) != 3 || out.State.Generation == "7f3d" {
		t.Fatalf("create did not treat the unrelated row as an unowned prefix: %#v %v", out, err)
	}
	for _, name := range out.State.Names {
		if name == "Other-g7f3d" {
			t.Fatal("create adopted an unrelated row")
		}
	}
}

func TestACLPolicyNamedAndUnnamedRowFormats(t *testing.T) {
	f := newTerraformACLFixture(t)
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	p := fixtureACLPolicy("198.51.100.0/24")
	p.Rules[0].Name, p.Rules[1].Name = "Web-DAV_2", "Deny"
	created, err := c.ApplyACLPolicy(ctx, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(created.State.Names) != 3 ||
		created.State.Names[1] != "Web-DAV_2-g"+created.State.Generation ||
		created.State.Names[2] != "Deny-g"+created.State.Generation {
		t.Fatalf("named rows: %v (generation %s)", created.State.Names, created.State.Generation)
	}
	unnamed := fixtureACLPolicy("192.0.2.0/24", "198.51.100.0/24")
	out, err := c.ApplyACLPolicy(ctx, unnamed, &created.State)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.State.Names) != 4 ||
		out.State.Names[0] != created.State.Names[0] ||
		out.State.Names[1] != "g"+out.State.Generation+"-02" ||
		out.State.Names[3] != "g"+out.State.Generation+"-04" {
		t.Fatalf("unnamed rows: %v (generation %s)", out.State.Names, out.State.Generation)
	}
	if _, err := c.ReadACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
	}
	imported, err := c.ImportACLPolicy(ctx, policyImportID(out.State))
	if err != nil || len(imported.Names) != 4 || imported.Names[0] != out.State.Names[0] {
		t.Fatalf("import by bare generation: %#v %v", imported, err)
	}
	if err := c.DeleteACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
	}
}

func TestACLPolicyStateUpgradeDropsNameAndRefreshesLegacyRows(t *testing.T) {
	ctx := context.Background()
	r := &ACLPolicyResource{}
	upgrade := r.UpgradeState(ctx)[0]
	data := []byte(`{
		"name":"ACL",
		"generation":"0123456789abcdef",
		"row_names":["ACL-g0123456789abcdef-01"],
		"observed_orders":[2],
		"rules":[],
		"drop_rules":[{
			"action":"drop",
			"protocol":"tcp",
			"ip_version":"ipv4",
			"direction":"wan_to_lan",
			"source_cidr":"198.51.100.0/24",
			"destination_cidr":"203.0.113.10/32",
			"source_ports":"*",
			"destination_ports":"443"
		}]
	}`)
	raw, err := tftypes.ValueFromJSON(data, upgrade.PriorSchema.Type().TerraformType(ctx))
	if err != nil {
		t.Fatal(err)
	}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatal(schemaResp.Diagnostics)
	}
	prior := tfsdk.State{Schema: *upgrade.PriorSchema, Raw: raw}
	resp := resource.UpgradeStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	upgrade.StateUpgrader(ctx, resource.UpgradeStateRequest{State: &prior}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var upgraded aclPolicyModel
	if diags := resp.State.Get(ctx, &upgraded); diags.HasError() {
		t.Fatal(diags)
	}
	if upgraded.Generation.ValueString() != "0123456789abcdef" || len(upgraded.DropRules) != 1 || len(upgraded.Rules) != 0 {
		t.Fatalf("upgraded state: %#v", upgraded)
	}
	var names []string
	if diags := upgraded.RowNames.ElementsAs(ctx, &names, false); diags.HasError() || len(names) != 1 || names[0] != "ACL-g0123456789abcdef-01" {
		t.Fatalf("row_names not copied verbatim: %v %v", names, diags)
	}

	f := newTerraformACLFixture(t)
	row := fixtureACLRow("ACL-g0123456789abcdef-01", 2, 2)
	row["Target"] = "Drop"
	f.rows = append(f.rows, row)
	c := aclFixtureClient(t, f)
	ledger, diags := policyLedger(ctx, upgraded)
	if diags.HasError() {
		t.Fatal(diags)
	}
	refreshed, err := c.ReadACLPolicy(ctx, ledger)
	if err != nil {
		t.Fatalf("refresh after upgrade rejected legacy row names: %v", err)
	}
	if len(refreshed.Names) != 1 || refreshed.Names[0] != "ACL-g0123456789abcdef-01" {
		t.Fatalf("refreshed ledger: %#v", refreshed.Names)
	}
}

func testManagementModel() aclPolicyRuleModel {
	return aclPolicyRuleModel{
		Name: types.StringValue("Management"), Action: types.StringValue("accept"), Protocol: types.StringValue("tcp"),
		IPVersion: types.StringValue("ipv4"), Direction: types.StringValue("lan_to_router"),
		SourceCIDR: types.StringValue("192.168.1.0/24"), DestinationCIDR: types.StringValue("192.168.1.1/32"), DestinationPorts: types.StringValue("443"),
	}
}

func policyImportID(state zyxel.ACLPolicyState) string {
	return fmt.Sprintf("%s:%d:%s", state.Generation, len(state.ManagementNames), strings.Join(state.Names, ","))
}
