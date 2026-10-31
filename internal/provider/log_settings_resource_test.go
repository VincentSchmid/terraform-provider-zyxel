package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/internal/routertest"
	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	testresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func logSettingsTestClient(t *testing.T) (*zyxel.Client, *routertest.LogSettingsFixture) {
	t.Helper()
	f := routertest.NewLogSettingsFixture(t)
	c, err := zyxel.NewClient(f.Server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestLogSettingsCreateRetainsUncertainIdentity(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(fmt.Sprint(afterCommit), func(t *testing.T) {
			client, f := logSettingsTestClient(t)
			f.Mu.Lock()
			f.FailReadback, f.ServerError = !afterCommit, afterCommit
			f.Mu.Unlock()
			r := &LogSettingsResource{client: client}
			ctx := context.Background()
			var s resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &s)
			plan := tfsdk.Plan{Schema: s.Schema}
			m := logSettingsModel{ID: types.StringUnknown(), Enabled: types.BoolValue(true), Mode: types.StringValue("local")}
			if d := plan.Set(ctx, &m); d.HasError() {
				t.Fatal(d)
			}
			resp := resource.CreateResponse{State: tfsdk.State{Schema: s.Schema}}
			r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
			var id string
			if d := resp.State.GetAttribute(ctx, path.Root("id"), &id); d.HasError() || !resp.Diagnostics.HasError() || id != "router" {
				t.Fatal(id, d, resp.Diagnostics)
			}
			if !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "inspect the router before retrying") {
				t.Fatal("missing uncertain-write recovery guidance")
			}
		})
	}
}

func TestLogSettingsUnknownAndNullValues(t *testing.T) {
	client, f := logSettingsTestClient(t)
	r := &LogSettingsResource{client: client}
	for _, m := range []logSettingsModel{
		{Enabled: types.BoolUnknown(), Mode: types.StringValue("local")},
		{Enabled: types.BoolNull(), Mode: types.StringValue("local")},
		{Enabled: types.BoolValue(true), Mode: types.StringUnknown()},
		{Enabled: types.BoolValue(true), Mode: types.StringNull()},
	} {
		var d diag.Diagnostics
		if r.apply(context.Background(), &m, &d) || !d.HasError() {
			t.Fatal("unknown/null values accepted", d)
		}
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Reads != 0 || f.Writes != 0 {
		t.Fatal("unknown/null values reached router")
	}
}

func TestLogSettingsModeValidator(t *testing.T) {
	for _, value := range []types.String{types.StringNull(), types.StringUnknown(), types.StringValue("local"), types.StringValue("remote"), types.StringValue("local_remote"), types.StringValue("Local"), types.StringValue("")} {
		var resp validator.StringResponse
		logModeValidator{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("mode"), ConfigValue: value}, &resp)
		invalid := value == types.StringValue("Local") || value == types.StringValue("")
		if resp.Diagnostics.HasError() != invalid {
			t.Fatalf("value=%v diagnostics=%v", value, resp.Diagnostics)
		}
	}
}

func TestLogSettingsReadAndDestroy(t *testing.T) {
	client, f := logSettingsTestClient(t)
	r := &LogSettingsResource{client: client}
	ctx := context.Background()
	var s resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &s)
	resp := resource.ReadResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Read(ctx, resource.ReadRequest{}, &resp)
	var m logSettingsModel
	if d := resp.State.Get(ctx, &m); d.HasError() || resp.Diagnostics.HasError() || m.ID.ValueString() != "router" || m.Enabled.ValueBool() || m.Mode.ValueString() != "local" {
		t.Fatal(m, d, resp.Diagnostics)
	}
	f.Mu.Lock()
	f.ReadResult = "DENIED"
	f.Mu.Unlock()
	r.Read(ctx, resource.ReadRequest{State: resp.State}, &resp)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatal("failed read lost recoverable state", resp.Diagnostics)
	}
	var del resource.DeleteResponse
	r.Delete(ctx, resource.DeleteRequest{State: resp.State}, &del)
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if del.Diagnostics.HasError() || f.Writes != 0 {
		t.Fatal("destroy mutated logging", del.Diagnostics, f.Writes)
	}
}

func logSettingsTestHCL(endpoint string, enabled bool, mode string) string {
	return networkProviderHCL(endpoint) + fmt.Sprintf(`
resource "zyxel_log_settings" "router" {
  enabled = %t
  mode = %q
}
`, enabled, mode)
}

func TestAccLogSettingsLifecycle(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := logSettingsTestClient(t)
	address := "zyxel_log_settings.router"
	check := func(enabled, mode string) testresource.TestCheckFunc {
		return testresource.ComposeTestCheckFunc(
			testresource.TestCheckResourceAttr(address, "id", "router"),
			testresource.TestCheckResourceAttr(address, "enabled", enabled),
			testresource.TestCheckResourceAttr(address, "mode", mode),
		)
	}
	update := testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}
	testresource.Test(t, testresource.TestCase{
		ProtoV6ProviderFactories: natTestFactories,
		CheckDestroy: func(*terraform.State) error {
			f.Mu.Lock()
			defer f.Mu.Unlock()
			if f.Settings["Enable"] != true || f.Settings["LogMode"] != "Local" || f.Settings["Server"] != "syslog.example.test" || f.Writes != 6 {
				return fmt.Errorf("destroy changed logging or unexpected writes: settings=%+v writes=%d", f.Settings, f.Writes)
			}
			return nil
		},
		Steps: []testresource.TestStep{
			{Config: logSettingsTestHCL(f.Server.URL, true, "local"), Check: check("true", "local")},
			{ResourceName: address, ImportState: true, ImportStateId: "router", ImportStateVerify: true},
			{Config: logSettingsTestHCL(f.Server.URL, false, "local"), ConfigPlanChecks: update, Check: check("false", "local")},
			{Config: logSettingsTestHCL(f.Server.URL, true, "remote"), ConfigPlanChecks: update, Check: check("true", "remote")},
			{Config: logSettingsTestHCL(f.Server.URL, true, "local_remote"), ConfigPlanChecks: update, Check: check("true", "local_remote")},
			{Config: logSettingsTestHCL(f.Server.URL, true, "local"), ConfigPlanChecks: update, Check: check("true", "local")},
			{PreConfig: func() { f.Mu.Lock(); f.Settings["Enable"] = false; f.Mu.Unlock() }, Config: logSettingsTestHCL(f.Server.URL, true, "local"), ConfigPlanChecks: update},
			{ResourceName: address, ImportState: true, ImportStateId: "invalid", ExpectError: regexp.MustCompile("import ID must be router")},
		},
	})
}

func TestAccLogSettingsInvalidMode(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := logSettingsTestClient(t)
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: []testresource.TestStep{
		{Config: logSettingsTestHCL(f.Server.URL, true, "invalid"), ExpectError: regexp.MustCompile("Invalid logging mode")},
	}})
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Reads != 0 || f.Writes != 0 {
		t.Fatal("invalid configuration reached router")
	}
}
