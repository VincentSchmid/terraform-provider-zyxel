package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	testresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const natTestAddress = "zyxel_nat_rule.test"

var natTestFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"zyxel": providerserver.NewProtocol6WithError(New("test")()),
}

type natTestConfig struct {
	name, protocol, internalClient     string
	extStart, extEnd, intStart, intEnd int
}

func defaultNATTestConfig() natTestConfig {
	return natTestConfig{name: "fixture-nat", protocol: "tcp", internalClient: "192.0.2.80", extStart: 8080, extEnd: 8080, intStart: 80, intEnd: 80}
}

func (c natTestConfig) hcl(endpoint string) string {
	extStart, extEnd, intStart, intEnd := int64(c.extStart), int64(c.extEnd), int64(c.intStart), int64(c.intEnd)
	return fmt.Sprintf(`
provider "zyxel" {
  host = %[1]q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_nat_rule" "test" {
  name = %[2]q
  protocol = %[3]q
  external_ports = %[4]q
  internal_client = %[5]q
  translation_ports = %[6]q
}
`, endpoint, c.name, c.protocol, zyxel.FormatPorts(&extStart, &extEnd), c.internalClient, zyxel.FormatPorts(&intStart, &intEnd))
}

func TestAccNATRule_basicImportReplacement(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	_, fixture, closeServer := newNATMockClient(t, nil)
	defer closeServer()
	c := defaultNATTestConfig()
	steps := []testresource.TestStep{{Config: c.hcl(fixture.endpoint), ConfigStateChecks: []statecheck.StateCheck{
		statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("name"), knownvalue.StringExact(c.name)),
		statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("protocol"), knownvalue.StringExact("tcp")),
		statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
		statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("router_index"), knownvalue.Int64Exact(1)),
	}}, {
		ResourceName: natTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.name, ImportStateVerifyIdentifierAttribute: "name",
	}}
	c.extStart, c.extEnd = 8081, 8081
	steps = append(steps, testresource.TestStep{
		Config: c.hcl(fixture.endpoint),
		ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(natTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}},
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("external_ports"), knownvalue.StringExact("8081")),
			natFixtureStateCheck{fixture: fixture, name: c.name},
		},
	})
	steps = append(steps, testresource.TestStep{ResourceName: natTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.name, ImportStateVerifyIdentifierAttribute: "name"})
	c.extEnd, c.intEnd = 8082, 81
	steps = append(steps, testresource.TestStep{
		Config: c.hcl(fixture.endpoint),
		ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(natTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}},
		ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("external_ports"), knownvalue.StringExact("8081-8082")),
			statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("translation_ports"), knownvalue.StringExact("80-81")),
		},
	}, testresource.TestStep{ResourceName: natTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.name, ImportStateVerifyIdentifierAttribute: "name"})
	testresource.Test(t, testresource.TestCase{
		ProtoV6ProviderFactories: natTestFactories,
		Steps:                    steps,
		CheckDestroy:             func(*terraform.State) error { return fixture.check(c.name, false) },
	})
}

func TestAccNATRule_disappearsAndIndexShift(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	_, fixture, closeServer := newNATMockClient(t, nil)
	defer closeServer()
	c := defaultNATTestConfig()
	testresource.Test(t, testresource.TestCase{
		ProtoV6ProviderFactories: natTestFactories,
		CheckDestroy:             func(*terraform.State) error { return fixture.check(c.name, false) },
		Steps: []testresource.TestStep{{Config: c.hcl(fixture.endpoint), ConfigStateChecks: []statecheck.StateCheck{
			natFixtureStateCheck{fixture: fixture, name: c.name, remove: true},
		}, ExpectNonEmptyPlan: true}, {
			Config: c.hcl(fixture.endpoint),
			ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(natTestAddress, plancheck.ResourceActionCreate),
			}},
		}, {
			PreConfig: func() { fixture.remove(c.name) },
			Config:    c.hcl(fixture.endpoint),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(natTestAddress, tfjsonpath.New("router_index"), knownvalue.Int64Exact(1)),
			},
		}},
	})
}

type natFixtureStateCheck struct {
	fixture *natMockState
	name    string
	remove  bool
}

func (c natFixtureStateCheck) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	resp.Error = c.fixture.check(c.name, true)
	if resp.Error == nil && c.remove {
		c.fixture.remove(c.name)
	}
}

func (f *natMockState) remove(name string) {
	for i, row := range f.rows {
		if row["Description"] == name {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			for nextIndex, remaining := range f.rows {
				remaining["Index"] = nextIndex + 1
			}
			return
		}
	}
}

func (f *natMockState) check(name string, exists bool) error {
	for _, row := range f.rows {
		if row["Description"] == name {
			if !exists {
				return fmt.Errorf("NAT rule %q still exists", name)
			}
			return nil
		}
	}
	if exists {
		return fmt.Errorf("NAT rule %q not found in mock router", name)
	}
	return nil
}
