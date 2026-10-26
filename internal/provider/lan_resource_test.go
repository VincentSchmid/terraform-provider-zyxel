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
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	testresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func networkTestClient(t *testing.T) (*zyxel.Client, *routertest.NetworkFixture) {
	t.Helper()
	f := routertest.NewNetworkFixture(t)
	c, err := zyxel.NewClient(f.Server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func testLANModel() lanModel {
	return lanObservedModel(zyxel.LANSettings{InterfaceGroupID: "Default", IPAddress: "192.0.2.1", SubnetMask: "255.255.255.0", IGMPSnooping: "disabled", DHCPMode: "disabled", DNSMode: "proxy"})
}
func TestLANCreatePreservesIdentityAfterUncertainWrite(t *testing.T) {
	for _, afterCommit := range []bool{false, true} {
		t.Run(fmt.Sprint(afterCommit), func(t *testing.T) {
			client, f := networkTestClient(t)
			f.FailReadback = !afterCommit
			f.FailAfterWrite = afterCommit
			r := &LANResource{client: client}
			ctx := context.Background()
			var s resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &s)
			plan := tfsdk.Plan{Schema: s.Schema}
			m := testLANModel()
			m.ID = types.StringUnknown()
			if d := plan.Set(ctx, &m); d.HasError() {
				t.Fatal(d)
			}
			resp := resource.CreateResponse{State: tfsdk.State{Schema: s.Schema}}
			r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
			var id string
			if d := resp.State.GetAttribute(ctx, path.Root("id"), &id); d.HasError() || !resp.Diagnostics.HasError() || id != "Default" {
				t.Fatal(id, d, resp.Diagnostics)
			}
		})
	}
}

func TestLANReadMissingRemovesStateAndDestroyIsNoOp(t *testing.T) {
	client, f := networkTestClient(t)
	r := &LANResource{client: client}
	ctx := context.Background()
	var s resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &s)
	state := tfsdk.State{Schema: s.Schema}
	m := testLANModel()
	if d := state.Set(ctx, &m); d.HasError() {
		t.Fatal(d)
	}
	f.Mu.Lock()
	f.LANs = nil
	f.Mu.Unlock()
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Fatal(resp.Diagnostics, resp.State.Raw)
	}
	var del resource.DeleteResponse
	r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
	if del.Diagnostics.HasError() || f.Writes != 0 {
		t.Fatal(del.Diagnostics, f.Writes)
	}
}

func networkProviderHCL(endpoint string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
`, endpoint)
}
func lanTestHCL(endpoint, group, mode string) string {
	extra := ""
	if mode == "server" {
		extra = `beginning_ip_address = "192.0.2.50"
  ending_ip_address = "192.0.2.150"
	  auto_reserve_ip = true
  dhcp_lease_time = "1d"`
	}
	if mode == "relay" {
		extra = `relay_server_address = "198.51.100.10"`
	}
	return networkProviderHCL(endpoint) + fmt.Sprintf(`
resource "zyxel_lan" "test" {
  interface_group_id = %s
  ip_address = "192.0.2.1"
  subnet_mask = "255.255.255.0"
  igmp_snooping = "blocking"
  dhcp = {
  mode = %q
  %s
  }
}
`, group, mode, extra)
}
func TestAccLANModesImportDriftAndDestroy(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := networkTestClient(t)
	address := "zyxel_lan.test"
	var steps []testresource.TestStep
	for i, mode := range []string{"server", "relay", "disabled", "server"} {
		step := testresource.TestStep{Config: lanTestHCL(f.Server.URL, `"Default"`, mode), Check: testresource.ComposeTestCheckFunc(testresource.TestCheckResourceAttr(address, "dhcp.mode", mode), testresource.TestCheckResourceAttr(address, "dns_mode", "proxy"), testresource.TestCheckResourceAttr(address, "id", "Default"))}
		if i > 0 {
			step.ConfigPlanChecks = testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}
		}
		steps = append(steps, step, testresource.TestStep{ResourceName: address, ImportState: true, ImportStateId: "Default", ImportStateVerify: true})
	}
	steps = append(steps, testresource.TestStep{PreConfig: func() { f.Mu.Lock(); f.LANs[0]["IGMPSnoopingMode"] = "Disabled"; f.Mu.Unlock() }, Config: lanTestHCL(f.Server.URL, `"Default"`, "server"), ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}})
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: steps, CheckDestroy: func(*terraform.State) error {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		if len(f.LANs) != 1 || f.LANs[0]["DHCP_MinAddress"] != "192.0.2.50" || f.LANs[0]["IPv6_LanEnable"] != true {
			return fmt.Errorf("destroy changed LAN or unmanaged settings")
		}
		return nil
	}})
}
func TestAccLANInvalidConfiguration(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := networkTestClient(t)
	config := networkProviderHCL(f.Server.URL) + `
resource "zyxel_lan" "test" {
  interface_group_id = "Default"
  ip_address = "192.0.2.1"
  subnet_mask = "255.255.255.0"
  dhcp = { mode = "server" }
}
`
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: []testresource.TestStep{{Config: config, ExpectError: regexp.MustCompile("Invalid LAN settings")}}})
	if f.Writes != 0 {
		t.Fatal("invalid plan mutated router")
	}
}

func TestLANConfigValidation(t *testing.T) {
	ctx := context.Background()
	r := &LANResource{}
	var schema resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schema)
	for _, test := range []struct {
		name    string
		change  func(*lanModel)
		invalid bool
	}{
		{"disabled", func(*lanModel) {}, false},
		{"null dhcp", func(m *lanModel) { m.DHCP = types.ObjectNull(lanDHCPTypes) }, true},
		{"unknown dhcp", func(m *lanModel) { m.DHCP = types.ObjectUnknown(lanDHCPTypes) }, false},
		{"default dns", func(m *lanModel) { m.DNSMode = types.StringNull() }, false},
		{"invalid dns", func(m *lanModel) { m.DNSMode = types.StringValue("static") }, true},
		{"inactive isp", func(m *lanModel) { m.DNSMode = types.StringValue("isp") }, true},
		{"unknown child", func(m *lanModel) {
			a := m.DHCP.Attributes()
			a["mode"] = types.StringUnknown()
			m.DHCP = types.ObjectValueMust(lanDHCPTypes, a)
		}, false},
		{"server missing lease", func(m *lanModel) {
			a := m.DHCP.Attributes()
			a["mode"] = types.StringValue("server")
			m.DHCP = types.ObjectValueMust(lanDHCPTypes, a)
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := testLANModel()
			test.change(&m)
			config := tfsdk.Config{Schema: schema.Schema}
			plan := tfsdk.Plan{Schema: schema.Schema}
			if d := plan.Set(ctx, &m); d.HasError() {
				t.Fatal(d)
			}
			config.Raw = plan.Raw
			var resp resource.ValidateConfigResponse
			r.ValidateConfig(ctx, resource.ValidateConfigRequest{Config: config}, &resp)
			if resp.Diagnostics.HasError() != test.invalid {
				t.Fatal(resp.Diagnostics)
			}
		})
	}
}

func TestAccLANLeaseSpellingsAndDNS(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := networkTestClient(t)
	var steps []testresource.TestStep
	for _, lease := range []string{"24h", "1440m", "1d5h12m", "1m", "365d"} {
		config := strings.Replace(lanTestHCL(f.Server.URL, `"Default"`, "server"), `dhcp_lease_time = "1d"`, fmt.Sprintf("dhcp_lease_time = %q", lease), 1)
		config = strings.Replace(config, `igmp_snooping = "blocking"`, "igmp_snooping = \"blocking\"\n dns_mode = \"isp\"", 1)
		steps = append(steps, testresource.TestStep{Config: config, Check: testresource.ComposeTestCheckFunc(testresource.TestCheckResourceAttr("zyxel_lan.test", "dhcp.dhcp_lease_time", lease), testresource.TestCheckResourceAttr("zyxel_lan.test", "dns_mode", "isp"))})
	}
	steps = append(steps, testresource.TestStep{
		PreConfig: func() {
			f.Mu.Lock()
			defer f.Mu.Unlock()
			f.LANs[0]["DHCP_LeaseTime"] = 120
			f.LANs[0]["DNS_Type"] = "FromISP"
		},
		Config:           lanTestHCL(f.Server.URL, `"Default"`, "server"),
		ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction("zyxel_lan.test", plancheck.ResourceActionUpdate)}},
		Check:            testresource.ComposeTestCheckFunc(testresource.TestCheckResourceAttr("zyxel_lan.test", "dhcp.dhcp_lease_time", "1d"), testresource.TestCheckResourceAttr("zyxel_lan.test", "dns_mode", "proxy")),
	})
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: steps})
}

func TestAccLANInvalidLeaseAndInactiveSettings(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock Terraform tests")
	}
	_, f := networkTestClient(t)
	var steps []testresource.TestStep
	for _, value := range []string{"0m", "366d", "1.5h", "1h30s", "999999999999999999999999h"} {
		config := strings.Replace(lanTestHCL(f.Server.URL, `"Default"`, "server"), `dhcp_lease_time = "1d"`, fmt.Sprintf("dhcp_lease_time = %q", value), 1)
		steps = append(steps, testresource.TestStep{Config: config, ExpectError: regexp.MustCompile("Invalid DHCP lease time")})
	}
	for _, mode := range []string{"relay", "disabled"} {
		config := strings.Replace(lanTestHCL(f.Server.URL, `"Default"`, mode), `igmp_snooping = "blocking"`, "igmp_snooping = \"blocking\"\n dns_mode = \"isp\"", 1)
		steps = append(steps, testresource.TestStep{Config: config, ExpectError: regexp.MustCompile("Invalid LAN settings")})
		config = strings.Replace(lanTestHCL(f.Server.URL, `"Default"`, mode), "dhcp = {", "dhcp = {\n dhcp_lease_time = \"1d\"", 1)
		steps = append(steps, testresource.TestStep{Config: config, ExpectError: regexp.MustCompile("Invalid LAN settings")})
	}
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: steps})
	if f.Writes != 0 {
		t.Fatal("invalid settings mutated router")
	}
}
