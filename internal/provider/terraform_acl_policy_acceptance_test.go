package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func policyTestConfig(endpoint, sources string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_acl_policy" "https" {
  name = "policy-https"
  rules = concat([
    for cidr in %s : {
      action = "accept"
      protocol = "tcp"
      ip_version = "ipv4"
      direction = "wan_to_lan"
      source_cidr = cidr
      destination_cidr = "203.0.113.10/32"
      destination_ports = "443"
    }
  ], [{
    action = "drop"
    protocol = "tcp"
    ip_version = "ipv4"
    direction = "wan_to_lan"
    source_cidr = "0.0.0.0/0"
    destination_cidr = "203.0.113.10/32"
    destination_ports = "443"
  }])
}
`, endpoint, sources)
}

func TestAccACLPolicy_growthShrinkRefreshAndImport(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.rows[0]["Order"] = 20
	f.compactOrders, f.rejectOccupiedOrder = true, true
	initial := policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)
	grown := policyTestConfig(f.server.URL, `["192.0.2.0/24", "198.51.100.0/24"]`)
	empty := policyTestConfig(f.server.URL, `[]`)
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: initial, ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue("zyxel_acl_policy.https", tfjsonpath.New("observed_orders"), knownvalue.ListExact([]knownvalue.Check{knownvalue.Int64Exact(2), knownvalue.Int64Exact(3)})),
		}},
		{Config: initial, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: grown, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("zyxel_acl_policy.https", plancheck.ResourceActionUpdate),
		}}},
		{Config: grown, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{ResourceName: "zyxel_acl_policy.https", ImportState: true, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "name", ImportStateIdFunc: func(*terraform.State) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, row := range f.rows {
				if name, ok := row["Name"].(string); ok && strings.HasPrefix(name, "policy-https-g") {
					return "policy-https/" + strings.TrimSuffix(strings.TrimPrefix(name, "policy-https-g"), "-001"), nil
				}
			}
			return "", fmt.Errorf("no policy generation found")
		}},
		{Config: empty},
		{Config: empty, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}})
	if len(f.rows) != 1 || f.rows[0]["Name"] != "unmanaged" {
		t.Fatal("policy cleanup changed unrelated prefix")
	}
}

func TestAccACLPolicy_partialCreateRetainsAllRows(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.failPostAt = 2
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`), ExpectError: regexp.MustCompile("500|ambiguous")},
	}})
	if len(f.rows) != 1 {
		t.Fatal("partial policy create lost ownership of router rows")
	}
}

func TestAccACLPolicy_partialUpdateRetainsBothGenerations(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.compactOrders = true
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)},
		{PreConfig: func() { f.mu.Lock(); defer f.mu.Unlock(); f.failPostAt = f.posts + 1 }, Config: policyTestConfig(f.server.URL, `["192.0.2.0/24", "198.51.100.0/24"]`), ExpectError: regexp.MustCompile("500|ambiguous")},
	}})
	if len(f.rows) != 1 {
		t.Fatal("partial policy update lost ownership of router rows")
	}
}
