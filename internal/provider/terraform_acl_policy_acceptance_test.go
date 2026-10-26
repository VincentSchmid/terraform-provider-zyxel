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
  rules = [
    for cidr in %s : {
      action = "accept"
      protocol = "tcp"
      ip_version = "ipv4"
      direction = "wan_to_lan"
      source_cidr = cidr
      destination_cidr = "203.0.113.10/32"
      destination_ports = "443"
    }
  ]
  drop_rules = [{
    action = "drop"
    protocol = "tcp"
    ip_version = "ipv4"
    direction = "wan_to_lan"
    source_cidr = "0.0.0.0/0"
    destination_cidr = "203.0.113.10/32"
    destination_ports = "443"
  }]
}
`, endpoint, sources)
}

func policyServiceTestConfig(endpoint, sources string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_service" "https" {
  name = "policy-https"
  protocol = "tcp"
  source_ports = "*"
  destination_ports = "443"
}
resource "zyxel_acl_policy" "service" {
  name = "policy-service"
  rules = [
    for cidr in %s : {
      action = "accept"
      ip_version = "ipv4"
      direction = "wan_to_lan"
      source_cidr = cidr
      destination_cidr = "203.0.113.10/32"
      service_id = zyxel_service.https.id
    }
  ]
  drop_rules = [{
    action = "drop"
    ip_version = "ipv4"
    direction = "wan_to_lan"
    source_cidr = "0.0.0.0/0"
    destination_cidr = "203.0.113.10/32"
    service_id = zyxel_service.https.id
  }]
}
`, endpoint, sources)
}

func TestAccACLPolicy_serviceRules(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	config := policyServiceTestConfig(f.server.URL, `["198.51.100.0/24"]`)
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: config, ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue("zyxel_acl_policy.service", tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("protocol"), knownvalue.StringExact("all")),
			statecheck.ExpectKnownValue("zyxel_acl_policy.service", tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("service_id"), knownvalue.StringExact("101")),
			statecheck.ExpectKnownValue("zyxel_acl_policy.service", tfjsonpath.New("drop_rules").AtSliceIndex(0).AtMapKey("destination_ports"), knownvalue.Null()),
		}},
		{Config: config, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{ResourceName: "zyxel_acl_policy.service", ImportState: true, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "name", ImportStateIdFunc: func(*terraform.State) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, row := range f.rows {
				name, ok := row["Name"].(string)
				if !ok || !strings.HasPrefix(name, "policy-service-g") {
					continue
				}
				if index := fixtureInt(row["X_ZYXEL_ServiceIndex"]); index != 101 {
					return "", fmt.Errorf("policy row %q does not reference the service: %d", name, index)
				}
				return "policy-service/" + strings.TrimSuffix(strings.TrimPrefix(name, "policy-service-g"), "-001"), nil
			}
			return "", fmt.Errorf("no policy generation found")
		}},
	}})
	if len(f.rows) != 1 || f.rows[0]["Name"] != "unmanaged" {
		t.Fatal("policy cleanup changed unrelated prefix")
	}
}

func policyFilterTestConfig(endpoint, fields string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_acl_policy" "filters" {
  name = "policy-filters"
  rules = [
    {
      action = "accept"
      ip_version = "ipv4"
      direction = "wan_to_lan"
      source_cidr = "198.51.100.0/24"
      destination_cidr = "203.0.113.10/32"
      %s
    },
  ]
  drop_rules = [
    {
      action = "drop"
      ip_version = "ipv4"
      direction = "wan_to_lan"
      source_cidr = "0.0.0.0/0"
      destination_cidr = "203.0.113.10/32"
      %s
    },
  ]
}
`, endpoint, fields, fields)
}

func TestAccACLPolicy_serviceFiltersReplaceInlineFilters(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	for _, step := range []struct {
		fields string
		error  string
	}{
		{`protocol = "tcp"
      service_id = "101"`, "cannot be combined with an inline protocol"},
		{`service_id = "101"
      destination_ports = "443"`, "cannot be combined with inline ports"},
		{`service_id = "101"
      source_ports = "*"`, "cannot be combined with inline ports"},
		{"", "Missing inline protocol"},
	} {
		step := step
		resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
			{Config: policyFilterTestConfig(f.server.URL, step.fields), PlanOnly: true, ExpectError: regexp.MustCompile(step.error)},
		}})
	}
	if f.posts != 0 {
		t.Fatal("invalid policy configurations reached the router")
	}
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
