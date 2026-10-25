package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func natSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	(&NATRuleResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	return resp
}

func TestNATPortsSchemaAndValidation(t *testing.T) {
	ctx := context.Background()
	s := natSchema(t).Schema
	if s.Version != 1 {
		t.Fatalf("schema version = %d", s.Version)
	}
	for _, name := range []string{"external_port_start", "external_port_end", "internal_port_start", "internal_port_end"} {
		if _, ok := s.Attributes[name]; ok {
			t.Fatalf("legacy attribute %s remains in current schema", name)
		}
	}
	for _, tc := range []struct {
		value   types.String
		invalid bool
	}{{types.StringValue("5006"), false}, {types.StringValue("5006-5007"), false}, {types.StringNull(), false}, {types.StringUnknown(), false}, {types.StringValue("*"), true}, {types.StringValue(""), true}, {types.StringValue("5007-5006"), true}} {
		var resp validator.StringResponse
		natPortsValidator{}.ValidateString(ctx, validator.StringRequest{Path: path.Root("external_ports"), ConfigValue: tc.value}, &resp)
		if resp.Diagnostics.HasError() != tc.invalid {
			t.Fatalf("validation of %s: %s", tc.value, resp.Diagnostics)
		}
	}
	for _, tc := range []struct {
		ext, translation types.String
		invalid          bool
	}{{types.StringValue("5006"), types.StringValue("80"), false}, {types.StringValue("5006-5007"), types.StringValue("80-81"), false}, {types.StringValue("5006-5007"), types.StringValue("80"), true}, {types.StringUnknown(), types.StringValue("80"), false}, {types.StringNull(), types.StringValue("80"), false}} {
		config := tfsdk.Config{Schema: s}
		plan := tfsdk.Plan{Schema: s}
		model := natRuleModel{Name: types.StringValue("test"), Protocol: types.StringValue("tcp"), InternalClient: types.StringValue("192.0.2.1"), ExternalPorts: tc.ext, TranslationPorts: tc.translation}
		if diags := plan.Set(ctx, model); diags.HasError() {
			t.Fatal(diags)
		}
		config.Raw = plan.Raw
		var resp resource.ValidateConfigResponse
		(&NATRuleResource{}).ValidateConfig(ctx, resource.ValidateConfigRequest{Config: config}, &resp)
		if resp.Diagnostics.HasError() != tc.invalid {
			t.Fatalf("range length validation: %s", resp.Diagnostics)
		}
	}
}

func TestNATStateUpgrade(t *testing.T) {
	ctx := context.Background()
	r := &NATRuleResource{}
	upgrade := r.UpgradeState(ctx)[0]
	for _, tc := range []struct {
		name, bounds, external, translation string
		invalid                             bool
	}{
		{"single", `5006,5006,80,80`, "5006", "80", false},
		{"range", `5006,5007,80,81`, "5006-5007", "80-81", false},
		{"import", `null,null,null,null`, "", "", false},
		{"invalid", `0,5006,80,80`, "", "", true},
		{"partial", `5006,null,80,80`, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Build the exact version-0 representation, including legacy fields.
			bounds := strings.Split(tc.bounds, ",")
			data := []byte(fmt.Sprintf(`{"name":"existing","protocol":"tcp","external_port_start":%s,"external_port_end":%s,"internal_client":"192.0.2.1","internal_port_start":%s,"internal_port_end":%s,"enabled":true,"router_index":7}`, bounds[0], bounds[1], bounds[2], bounds[3]))
			raw, err := tftypes.ValueFromJSON(data, upgrade.PriorSchema.Type().TerraformType(ctx))
			if err != nil {
				t.Fatal(err)
			}
			prior := tfsdk.State{Schema: *upgrade.PriorSchema, Raw: raw}
			resp := resource.UpgradeStateResponse{State: tfsdk.State{Schema: natSchema(t).Schema}}
			upgrade.StateUpgrader(ctx, resource.UpgradeStateRequest{State: &prior}, &resp)
			if resp.Diagnostics.HasError() != tc.invalid {
				t.Fatalf("upgrade diagnostics: %s", resp.Diagnostics)
			}
			if tc.invalid {
				return
			}
			var saved natRuleModel
			if diags := resp.State.Get(ctx, &saved); diags.HasError() {
				t.Fatal(diags)
			}
			if saved.Name.ValueString() != "existing" || saved.RouterIndex.ValueInt64() != 7 || !saved.Enabled.ValueBool() || saved.ExternalPorts.ValueString() != tc.external || saved.TranslationPorts.ValueString() != tc.translation {
				t.Fatalf("upgraded state: %#v", saved)
			}
			if tc.name == "import" && (!saved.ExternalPorts.IsNull() || !saved.TranslationPorts.IsNull()) {
				t.Fatal("import-only state must retain null ports until refresh")
			}
		})
	}
}

func TestNATPortsReadRoundTrip(t *testing.T) {
	ctx := context.Background()
	client, fixture, closeServer := newNATMockClient(t, []map[string]any{natRow(1, "existing", "TCP", 5006, 5007, "192.0.2.1", 80, 81, true)})
	defer closeServer()
	r := &NATRuleResource{client: client}
	s := natSchema(t).Schema
	state := tfsdk.State{Schema: s}
	if diags := state.Set(ctx, &natRuleModel{Name: types.StringValue("existing")}); diags.HasError() {
		t.Fatal(diags)
	}
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var saved natRuleModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatal(diags)
	}
	if saved.ExternalPorts.ValueString() != "5006-5007" || saved.TranslationPorts.ValueString() != "80-81" || fixture.writes != 0 {
		t.Fatalf("read state: %#v, writes: %d", saved, fixture.writes)
	}
	if got := observedNATPorts(types.StringValue("5006-5006"), 5006, 5006); got.ValueString() != "5006-5006" {
		t.Fatalf("equivalent syntax not preserved: %s", got)
	}
	for _, bad := range []natRuleModel{{ExternalPorts: types.StringValue("*"), TranslationPorts: types.StringValue("80")}, {ExternalPorts: types.StringValue("80"), TranslationPorts: types.StringValue("*")}} {
		if _, err := modelNATRule(bad); err == nil {
			t.Fatal("conversion must reject invalid resolved ports")
		}
	}
}
