package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	testresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestInterfaceGroupCreateRetainsRecoverableIdentity(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(fmt.Sprint(afterCommit), func(t *testing.T) {
			client, f := networkTestClient(t)
			f.FailAfterWrite = afterCommit
			f.FailReadback = !afterCommit
			ctx := context.Background()
			r := &InterfaceGroupResource{client: client}
			var s resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &s)
			m := interfaceGroupObservedModel(ctx, zyxel.InterfaceGroup{Name: "test", WANInterfaces: []string{"IP.Interface.2"}, LANInterfaces: []string{"Ethernet.Interface.2"}})
			m.ID = types.StringUnknown()
			m.RouterIndex = types.Int64Unknown()
			plan := tfsdk.Plan{Schema: s.Schema}
			if d := plan.Set(ctx, &m); d.HasError() {
				t.Fatal(d)
			}
			resp := resource.CreateResponse{State: tfsdk.State{Schema: s.Schema}}
			r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
			var id string
			if d := resp.State.GetAttribute(ctx, path.Root("id"), &id); d.HasError() || !resp.Diagnostics.HasError() || id != "test" {
				t.Fatal(id, d, resp.Diagnostics)
			}
		})
	}
}
func interfaceGroupTestHCL(name string) string {
	return fmt.Sprintf(`
resource "zyxel_interface_group" "test" {
  name = %q
  wan_interfaces = ["IP.Interface.2"]
  lan_interfaces = ["Ethernet.Interface.2", "WiFi.SSID.3"]
}
`, name)
}

func TestAccInterfaceGroupLANReference(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := networkTestClient(t)
	config := lanTestHCL(f.Server.URL, "zyxel_interface_group.test.id", "server") + interfaceGroupTestHCL("Guests")
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: []testresource.TestStep{
		{Config: config, Check: testresource.ComposeTestCheckFunc(testresource.TestCheckResourceAttr("zyxel_interface_group.test", "id", "Guests"), testresource.TestCheckResourceAttr("zyxel_lan.test", "interface_group_id", "Guests"), testresource.TestCheckResourceAttr("zyxel_lan.test", "dhcp.beginning_ip_address", "192.0.2.50"))},
		{ResourceName: "zyxel_interface_group.test", ImportState: true, ImportStateId: "Guests", ImportStateVerify: true},
		{ResourceName: "zyxel_lan.test", ImportState: true, ImportStateId: "Guests", ImportStateVerify: true},
	}, CheckDestroy: func(*terraform.State) error {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		if len(f.Groups) != 1 || f.Groups[0]["Group_Name"] != "Default" || len(f.LANs) != 1 {
			return fmt.Errorf("did not delete only the managed group")
		}
		return nil
	}})
}
func TestAccInterfaceGroupReplacementAndDisappearance(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := networkTestClient(t)
	address := "zyxel_interface_group.test"
	config := func(name string) string { return networkProviderHCL(f.Server.URL) + interfaceGroupTestHCL(name) }
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: []testresource.TestStep{
		{Config: config("first")},
		{Config: config("second"), ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionDestroyBeforeCreate)}}, Check: testresource.TestCheckResourceAttr(address, "id", "second")},
		{PreConfig: func() { f.Mu.Lock(); f.Groups = f.Groups[:1]; f.LANs = f.LANs[:1]; f.Mu.Unlock() }, Config: config("second"), ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionCreate)}}},
	}})
}
