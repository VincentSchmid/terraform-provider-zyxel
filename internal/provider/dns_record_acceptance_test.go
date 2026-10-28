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

const dnsTestAddress = "zyxel_dns_record.test"

var dnsTestFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"zyxel": providerserver.NewProtocol6WithError(New("test")()),
}

type dnsTestConfig struct {
	hostname, ip string
}

func (c dnsTestConfig) hcl(endpoint string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %[1]q
  username = "fixture-user"
  password = "fixture-password"
}

resource "zyxel_dns_record" "test" {
  hostname     = %[2]q
  ipv4_address = %[3]q
}
`, endpoint, c.hostname, c.ip)
}

func TestAccDNSRecord_basicImportReplacement(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	_, fixture, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	c := dnsTestConfig{hostname: "nas.home.arpa", ip: "192.0.2.20"}
	importStep := resource.TestStep{ResourceName: dnsTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.hostname, ImportStateVerifyIdentifierAttribute: "hostname"}
	steps := []resource.TestStep{{
		Config: c.hcl(fixture.endpoint),
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(dnsTestAddress, tfjsonpath.New("hostname"), knownvalue.StringExact(c.hostname)),
			statecheck.ExpectKnownValue(dnsTestAddress, tfjsonpath.New("ipv4_address"), knownvalue.StringExact(c.ip)),
			statecheck.ExpectKnownValue(dnsTestAddress, tfjsonpath.New("router_index"), knownvalue.Int64Exact(1)),
			dnsFixtureStateCheck{fixture: fixture, hostname: c.hostname},
		},
	}, importStep}
	c.ip = "192.0.2.21"
	steps = append(steps, resource.TestStep{
		Config: c.hcl(fixture.endpoint),
		ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(dnsTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}},
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(dnsTestAddress, tfjsonpath.New("ipv4_address"), knownvalue.StringExact(c.ip)),
			dnsFixtureStateCheck{fixture: fixture, hostname: c.hostname},
		},
	}, importStep)
	c.hostname = "nas2.home.arpa"
	steps = append(steps, resource.TestStep{
		Config: c.hcl(fixture.endpoint),
		ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(dnsTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}},
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(dnsTestAddress, tfjsonpath.New("hostname"), knownvalue.StringExact(c.hostname)),
			dnsFixtureStateCheck{fixture: fixture, hostname: c.hostname},
		},
	}, resource.TestStep{ResourceName: dnsTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.hostname, ImportStateVerifyIdentifierAttribute: "hostname"})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: dnsTestFactories,
		Steps:                    steps,
		CheckDestroy:             func(*terraform.State) error { return fixture.check(c.hostname, false) },
	})
}

func TestAccDNSRecord_disappearsAndIndexShift(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	_, fixture, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	c := dnsTestConfig{hostname: "media.home.arpa", ip: "192.0.2.30"}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: dnsTestFactories,
		CheckDestroy:             func(*terraform.State) error { return fixture.check(c.hostname, false) },
		Steps: []resource.TestStep{{
			Config:             c.hcl(fixture.endpoint),
			ConfigStateChecks:  []statecheck.StateCheck{dnsFixtureStateCheck{fixture: fixture, hostname: c.hostname, remove: true}},
			ExpectNonEmptyPlan: true,
		}, {
			Config: c.hcl(fixture.endpoint),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(dnsTestAddress, plancheck.ResourceActionCreate),
			}},
			ConfigStateChecks: []statecheck.StateCheck{dnsFixtureStateCheck{fixture: fixture, hostname: c.hostname}},
		}, {
			// Unrelated entries shift the managed record's index; deletion still
			// resolves the current index by host name.
			PreConfig: func() { fixture.shift(c.hostname) },
			Config:    c.hcl(fixture.endpoint),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(dnsTestAddress, tfjsonpath.New("router_index"), knownvalue.Int64Exact(3)),
			},
		}},
	})
}

type dnsFixtureStateCheck struct {
	fixture  *dnsMockState
	hostname string
	remove   bool
}

func (c dnsFixtureStateCheck) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	resp.Error = c.fixture.check(c.hostname, true)
	if resp.Error == nil && c.remove {
		c.fixture.remove(c.hostname)
	}
}

func (f *dnsMockState) remove(hostname string) {
	f.rebuild(hostname, 0, false)
}

// shift places two unrelated entries ahead of the tracked record.
func (f *dnsMockState) shift(hostname string) {
	f.rebuild(hostname, 2, true)
}

func (f *dnsMockState) rebuild(hostname string, prefix int, keep bool) {
	var tracked map[string]any
	rows := make([]map[string]any, 0, len(f.rows)+prefix)
	for _, row := range f.rows {
		if row["HostName"] == hostname {
			tracked = row
			continue
		}
		rows = append(rows, row)
	}
	for i := 0; i < prefix; i++ {
		rows = append(rows, dnsMockRow(0, fmt.Sprintf("unrelated%d.home.arpa", i+1), fmt.Sprintf("192.0.2.%d", 200+i)))
	}
	if keep {
		rows = append(rows, tracked)
	}
	for i, row := range rows {
		row["Index"] = int64(i + 1)
	}
	f.rows = rows
}

func (f *dnsMockState) check(hostname string, exists bool) error {
	for _, row := range f.rows {
		if row["HostName"] == hostname {
			if !exists {
				return fmt.Errorf("DNS record %q still exists in mock router", hostname)
			}
			return nil
		}
	}
	if exists {
		return fmt.Errorf("DNS record %q not found in mock router", hostname)
	}
	return nil
}
