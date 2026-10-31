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
			m := logSettingsModel{ID: types.StringUnknown(), Enabled: types.BoolValue(true)}
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
		{Enabled: types.BoolUnknown()},
		{Enabled: types.BoolNull()},
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

func TestLogSettingsReadAndDestroy(t *testing.T) {
	client, f := logSettingsTestClient(t)
	r := &LogSettingsResource{client: client}
	ctx := context.Background()
	var s resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &s)
	resp := resource.ReadResponse{State: tfsdk.State{Schema: s.Schema}}
	r.Read(ctx, resource.ReadRequest{}, &resp)
	var m logSettingsModel
	if d := resp.State.Get(ctx, &m); d.HasError() || resp.Diagnostics.HasError() || m.ID.ValueString() != "router" || m.Enabled.ValueBool() {
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

func logSettingsTestHCL(endpoint string, enabled bool) string {
	return networkProviderHCL(endpoint) + fmt.Sprintf(`
resource "zyxel_log_settings" "router" {
  enabled = %t
}
`, enabled)
}

func TestAccLogSettingsLifecycle(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := logSettingsTestClient(t)
	address := "zyxel_log_settings.router"
	check := func(enabled string) testresource.TestCheckFunc {
		return testresource.ComposeTestCheckFunc(
			testresource.TestCheckResourceAttr(address, "id", "router"),
			testresource.TestCheckResourceAttr(address, "enabled", enabled),
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
			{Config: logSettingsTestHCL(f.Server.URL, true), Check: check("true")},
			{ResourceName: address, ImportState: true, ImportStateId: "router", ImportStateVerify: true},
			{Config: logSettingsTestHCL(f.Server.URL, false), ConfigPlanChecks: update, Check: check("false")},
			{Config: logSettingsTestHCL(f.Server.URL, true), ConfigPlanChecks: update, Check: check("true")},
			{PreConfig: func() { f.Mu.Lock(); f.Settings["Enable"] = false; f.Mu.Unlock() }, Config: logSettingsTestHCL(f.Server.URL, true), ConfigPlanChecks: update},
			{PreConfig: func() { f.Mu.Lock(); f.Settings["LogMode"] = "Remote"; f.Mu.Unlock() }, Config: logSettingsTestHCL(f.Server.URL, true), ConfigPlanChecks: update, Check: check("true")},
			{PreConfig: func() { f.Mu.Lock(); f.Settings["LogMode"] = "LocalRemote"; f.Mu.Unlock() }, Config: logSettingsTestHCL(f.Server.URL, true), ConfigPlanChecks: update, Check: check("true")},
			{ResourceName: address, ImportState: true, ImportStateId: "invalid", ExpectError: regexp.MustCompile("import ID must be router")},
		},
	})
}

func TestAccLogSettingsRejectsModeAttribute(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := logSettingsTestClient(t)
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: []testresource.TestStep{
		{Config: networkProviderHCL(f.Server.URL) + `
resource "zyxel_log_settings" "router" {
  enabled = true
  mode = "remote"
}
`, ExpectError: regexp.MustCompile("Unsupported argument")},
	}})
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Reads != 0 || f.Writes != 0 {
		t.Fatal("invalid configuration reached router")
	}
}
