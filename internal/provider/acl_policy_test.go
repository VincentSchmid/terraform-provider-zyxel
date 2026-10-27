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
	p := zyxel.ACLPolicy{}
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
				Rules: test.rules, DropRules: test.dropRules,
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
	if _, err := c.ImportACLPolicy(ctx, changed.State.Generation); err != nil {
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
	if len(initial.State.Names) != 2 || !strings.HasSuffix(initial.State.Names[0], "-01") || !strings.HasSuffix(initial.State.Names[1], "-02") {
		t.Fatalf("new generation did not use two-digit suffixes: %v", initial.State.Names)
	}

	// Rewrite the generation as a released v2 provider would have named it.
	legacy := initial.State
	legacy.Names = nil
	legacy.Generation = "0123456789abcdef"
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
	for i, name := range out.State.Names {
		if !strings.HasSuffix(name, fmt.Sprintf("-%02d", i+1)) {
			t.Fatalf("replacement generation did not use two-digit suffixes: %v", out.State.Names)
		}
	}
	if err := c.DeleteACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
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
	if !first.Changed || len(first.State.Names) != 2 || !strings.HasSuffix(first.State.Names[0], "-01") || first.State.Rules[0].Order != 2 {
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
	imported, err := c.ImportACLPolicy(ctx, second.State.Generation)
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

func TestACLPolicyNamedMigrationAtCapacity(t *testing.T) {
	f := newTerraformACLFixture(t)
	f.compactOrders, f.rejectOccupiedOrder, f.maxACLRows = true, true, 32
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	sources := make([]string, 18)
	for i := range sources {
		sources[i] = fmt.Sprintf("192.0.2.%d/32", i+1)
	}
	initial, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy(sources...), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Replace every unnamed row with a named rule, as a live legacy migration would.
	named := fixtureACLPolicy(sources...)
	for i := range named.Rules {
		named.Rules[i].Name = fmt.Sprintf("Rule_%d", i+1)
	}
	out, err := c.ApplyACLPolicy(ctx, named, &initial.State)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range out.State.Names {
		if want := fmt.Sprintf("Rule_%d-g%s", i+1, out.State.Generation); name != want {
			t.Fatalf("row %d is %q, want %q", i, name, want)
		}
	}
	refreshed, err := c.ReadACLPolicy(ctx, out.State)
	if err != nil || len(refreshed.Names) != len(out.State.Names) {
		t.Fatalf("refresh: %#v %v", refreshed, err)
	}
	if len(f.rows) != 20 { // 19 policy rows plus the unrelated prefix row.
		t.Fatalf("retired rows were not removed: %d rows", len(f.rows))
	}
}

func TestACLPolicyCapacityFallback(t *testing.T) {
	for _, result := range []string{"ZCFG_INVALID_PARAM_VALUE", "ZCFG_EXCEED_MAX_INS_NUM"} {
		for _, count := range []int{17, 18, 30, 31} {
			t.Run(fmt.Sprint(result, "/", count), func(t *testing.T) {
				testACLPolicyCapacityFallback(t, result, count)
			})
		}
	}
}

func testACLPolicyCapacityFallback(t *testing.T, result string, count int) {
	t.Helper()
	f := newTerraformACLFixture(t)
	f.compactOrders, f.rejectOccupiedOrder, f.maxACLRows, f.capacityResult = true, true, 32, result
	c := aclFixtureClient(t, f)
	ctx := context.Background()
	sources := make([]string, 18)
	for i := range sources {
		sources[i] = fmt.Sprintf("192.0.2.%d/32", i+1)
	}
	initial, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy(sources...), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.history)
	sources = make([]string, count)
	for i := range sources {
		sources[i] = fmt.Sprintf("198.51.100.%d/32", i+1)
	}
	out, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy(sources...), &initial.State)
	if count == 31 { // The unrelated prefix also consumes a slot.
		if err == nil || !strings.Contains(err.Error(), result) || f.deletes != 0 {
			t.Fatalf("oversized policy retired protection: %v, deletes=%d", err, f.deletes)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	window := false
	for _, snapshot := range f.history[before:] {
		drops := 0
		for _, row := range snapshot {
			if row["Target"] == "Drop" {
				drops++
			}
		}
		window = window || drops == 0
		if len(snapshot) > 32 || snapshot[0]["Name"] != "unmanaged" {
			t.Fatal("capacity or prefix changed")
		}
	}
	if window != (count == 30) {
		t.Fatalf("unexpected protection window: %v", window)
	}
	if _, err := c.ReadACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportACLPolicy(ctx, out.State.Generation); err != nil {
		t.Fatal(err)
	}
}

func TestACLPolicyCapacityFailureLedger(t *testing.T) {
	for _, failure := range []string{"delete", "ambiguous-retry", "below-capacity"} {
		t.Run(failure, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders, f.maxACLRows = true, 32
			c := aclFixtureClient(t, f)
			ctx := context.Background()
			sources := make([]string, 18)
			for i := range sources {
				sources[i] = fmt.Sprintf("192.0.2.%d/32", i+1)
			}
			initial, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy(sources...), nil)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "delete":
				f.failDeleteAt = 1
			case "ambiguous-retry":
				f.failPostAt = f.posts + 13 // Twelve creates fill the table.
			case "below-capacity":
				f.maxACLRows = 24
			}
			out, err := c.ApplyACLPolicy(ctx, fixtureACLPolicy(sources[:17]...), &initial.State)
			if err == nil || !out.Changed {
				t.Fatalf("expected recoverable failure: %#v %v", out, err)
			}
			if failure == "below-capacity" && f.deletes != 0 {
				t.Fatal("generic rejection triggered retirement below known capacity")
			}
			tracked := map[string]bool{}
			for _, name := range out.State.Names {
				tracked[name] = true
			}
			for _, row := range f.rows {
				name := row["Name"].(string)
				if name != "unmanaged" && !tracked[name] {
					t.Fatalf("untracked write: %s", name)
				}
			}
			f.failDeleteAt, f.failPostAt = 0, 0
			if err := c.DeleteACLPolicy(ctx, out.State); err != nil {
				t.Fatal(err)
			}
		})
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
	if err != nil || len(out.State.Names) != 2 || out.State.Generation == "7f3d" {
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
	if len(created.State.Names) != 2 ||
		created.State.Names[0] != "Web-DAV_2-g"+created.State.Generation ||
		created.State.Names[1] != "Deny-g"+created.State.Generation {
		t.Fatalf("named rows: %v (generation %s)", created.State.Names, created.State.Generation)
	}
	unnamed := fixtureACLPolicy("192.0.2.0/24", "198.51.100.0/24")
	out, err := c.ApplyACLPolicy(ctx, unnamed, &created.State)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.State.Names) != 3 ||
		out.State.Names[0] != "g"+out.State.Generation+"-01" ||
		out.State.Names[2] != "g"+out.State.Generation+"-03" {
		t.Fatalf("unnamed rows: %v (generation %s)", out.State.Names, out.State.Generation)
	}
	if _, err := c.ReadACLPolicy(ctx, out.State); err != nil {
		t.Fatal(err)
	}
	imported, err := c.ImportACLPolicy(ctx, out.State.Generation)
	if err != nil || len(imported.Names) != 3 || imported.Names[0] != out.State.Names[0] {
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
