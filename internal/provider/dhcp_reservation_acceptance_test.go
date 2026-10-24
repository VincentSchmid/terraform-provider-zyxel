package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const dhcpTestAddress = "zyxel_dhcp_reservation.test"

var dhcpTestFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"zyxel": providerserver.NewProtocol6WithError(New("test")()),
}

type dhcpTestConfig struct {
	mac, ip string
}

func (c dhcpTestConfig) hcl(endpoint string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %[1]q
  username = "fixture-user"
  password = "fixture-password"
}

resource "zyxel_dhcp_reservation" "test" {
  mac_address  = %[2]q
  ipv4_address = %[3]q
}
`, endpoint, c.mac, c.ip)
}

func TestAccDHCPReservation_basic(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	fixture := newDHCPMockRouter(t)
	c := dhcpTestConfig{mac: "AA:BB:CC:DD:EE:21", ip: "192.0.2.21"}
	steps := []resource.TestStep{{
		Config: c.hcl(fixture.server.URL),
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(dhcpTestAddress, tfjsonpath.New("mac_address"), knownvalue.StringExact(c.mac)),
			statecheck.ExpectKnownValue(dhcpTestAddress, tfjsonpath.New("ipv4_address"), knownvalue.StringExact(c.ip)),
			statecheck.ExpectKnownValue(dhcpTestAddress, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
			dhcpFixtureStateCheck{fixture: fixture, mac: c.mac},
		},
	}, {
		ResourceName: dhcpTestAddress, ImportState: true, ImportStateVerify: true,
		ImportStateId: c.mac, ImportStateVerifyIdentifierAttribute: "mac_address",
	}}
	c.ip = "192.0.2.22"
	steps = append(steps, resource.TestStep{
		Config: c.hcl(fixture.server.URL),
		ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(dhcpTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}},
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(dhcpTestAddress, tfjsonpath.New("ipv4_address"), knownvalue.StringExact(c.ip)),
			dhcpFixtureStateCheck{fixture: fixture, mac: c.mac},
		},
	})
	c.mac = "AA:BB:CC:DD:EE:22"
	steps = append(steps, resource.TestStep{
		Config: c.hcl(fixture.server.URL),
		ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(dhcpTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}},
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(dhcpTestAddress, tfjsonpath.New("mac_address"), knownvalue.StringExact(c.mac)),
			dhcpFixtureStateCheck{fixture: fixture, mac: c.mac},
		},
	})
	steps = append(steps, resource.TestStep{
		ResourceName: dhcpTestAddress, ImportState: true, ImportStateVerify: true,
		ImportStateId: c.mac, ImportStateVerifyIdentifierAttribute: "mac_address",
	})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: dhcpTestFactories,
		Steps:                    steps,
		CheckDestroy:             func(*terraform.State) error { return fixture.check(c.mac, false) },
	})
}

func TestAccDHCPReservation_disappears(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	fixture := newDHCPMockRouter(t)
	c := dhcpTestConfig{mac: "AA:BB:CC:DD:EE:31", ip: "192.0.2.31"}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: dhcpTestFactories,
		CheckDestroy:             func(*terraform.State) error { return fixture.check(c.mac, false) },
		Steps: []resource.TestStep{{
			Config:             c.hcl(fixture.server.URL),
			ConfigStateChecks:  []statecheck.StateCheck{dhcpFixtureStateCheck{fixture: fixture, mac: c.mac, remove: true}},
			ExpectNonEmptyPlan: true,
		}, {
			Config: c.hcl(fixture.server.URL),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(dhcpTestAddress, plancheck.ResourceActionCreate),
			}},
			ConfigStateChecks: []statecheck.StateCheck{dhcpFixtureStateCheck{fixture: fixture, mac: c.mac}},
		}, {
			PreConfig: func() { fixture.remove(c.mac) },
			Config:    c.hcl(fixture.server.URL),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(dhcpTestAddress, plancheck.ResourceActionCreate),
			}},
		}},
	})
}

type dhcpFixtureStateCheck struct {
	fixture *dhcpMockRouter
	mac     string
	remove  bool
}

func (c dhcpFixtureStateCheck) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	resp.Error = c.fixture.check(c.mac, true)
	if resp.Error == nil && c.remove {
		c.fixture.remove(c.mac)
	}
}

func (f *dhcpMockRouter) remove(mac string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, row := range f.rows {
		if row["MACAddr"] == mac {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			for next, remaining := range f.rows {
				remaining["Index"] = next + 1
			}
			return
		}
	}
}

func (f *dhcpMockRouter) check(mac string, exists bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.rows {
		if row["MACAddr"] == mac {
			if !exists {
				return fmt.Errorf("DHCP reservation %q still exists in mock router", mac)
			}
			return nil
		}
	}
	if exists {
		return fmt.Errorf("DHCP reservation %q not found in mock router", mac)
	}
	return nil
}
