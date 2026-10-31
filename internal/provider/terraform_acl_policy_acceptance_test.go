package provider

import (
	"context"
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
  management_rules = [{
    action = "accept"
    protocol = "tcp"
    ip_version = "ipv4"
    direction = "lan_to_router"
    source_cidr = "192.168.1.0/24"
    destination_cidr = "192.168.1.1/32"
    destination_ports = "443"
  }]
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
  management_rules = [{
    action = "accept"
    protocol = "tcp"
    ip_version = "ipv4"
    direction = "lan_to_router"
    source_cidr = "192.168.1.0/24"
    destination_cidr = "192.168.1.1/32"
    destination_ports = "443"
  }]
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
		{ResourceName: "zyxel_acl_policy.service", ImportState: true, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "generation", ImportStateIdFunc: func(s *terraform.State) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, row := range f.rows {
				name, ok := row["Name"].(string)
				if !ok || name == "unmanaged" {
					continue
				}
				if row["Direction"] == "LAN_TO_ROUTER" {
					continue
				}
				if index := fixtureInt(row["X_ZYXEL_ServiceIndex"]); index != 101 {
					return "", fmt.Errorf("policy row %q does not reference the service: %d", name, index)
				}
			}
			return policyStateImportID(s, "zyxel_acl_policy.service"), nil
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
  management_rules = [{
    action = "accept"
    protocol = "tcp"
    ip_version = "ipv4"
    direction = "lan_to_router"
    source_cidr = "192.168.1.0/24"
    destination_cidr = "192.168.1.1/32"
    destination_ports = "443"
  }]
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
			statecheck.ExpectKnownValue("zyxel_acl_policy.https", tfjsonpath.New("observed_orders"), knownvalue.ListExact([]knownvalue.Check{knownvalue.Int64Exact(2), knownvalue.Int64Exact(3), knownvalue.Int64Exact(4)})),
		}},
		{Config: initial, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: grown, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("zyxel_acl_policy.https", plancheck.ResourceActionUpdate),
		}}},
		{Config: grown, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{ResourceName: "zyxel_acl_policy.https", ImportState: true, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "generation", ImportStateIdFunc: func(s *terraform.State) (string, error) {
			return policyStateImportID(s, "zyxel_acl_policy.https"), nil
		}},
		{Config: empty},
		{Config: empty, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}})
	if len(f.rows) != 1 || f.rows[0]["Name"] != "unmanaged" {
		t.Fatal("policy cleanup changed unrelated prefix")
	}
}

func TestAccACLPolicy_wildcardRefreshPreservesLedger(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	config := policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)
	var ledger string
	var posts, deletes, history int
	check := func(s *terraform.State) error {
		if got := policyStateImportID(s, "zyxel_acl_policy.https"); got != ledger {
			return fmt.Errorf("wildcard refresh changed ownership ledger: %q != %q", got, ledger)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.posts != posts || f.deletes != deletes || len(f.history) != history {
			return fmt.Errorf("wildcard refresh wrote router rows")
		}
		return nil
	}
	steps := []resource.TestStep{{Config: config, Check: func(s *terraform.State) error {
		ledger = policyStateImportID(s, "zyxel_acl_policy.https")
		f.mu.Lock()
		defer f.mu.Unlock()
		posts, deletes, history = f.posts, f.deletes, len(f.history)
		return nil
	}}}
	for _, address := range []string{"Any", ""} {
		steps = append(steps, resource.TestStep{
			PreConfig: func() {
				f.mu.Lock()
				defer f.mu.Unlock()
				for _, row := range f.rows {
					if row["Target"] == "Drop" {
						row["SourceIP"], row["SourceMask"] = address, "32"
					}
				}
			},
			Config: config, Check: check,
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("zyxel_acl_policy.https", tfjsonpath.New("drop_rules").AtSliceIndex(0).AtMapKey("source_cidr"), knownvalue.StringExact("0.0.0.0/0")),
			},
		})
	}
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: steps})
}

func TestAccACLPolicy_partialCreateRetainsAllRows(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.failPostAt = 2
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`), ExpectError: regexp.MustCompile("500|ambiguous")},
		{PreConfig: func() { f.mu.Lock(); defer f.mu.Unlock(); f.failPostAt = 0 }, Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)},
		{Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
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
		// Returning to the original configuration must still schedule recovery:
		// the failed update retained that configuration alongside both generations.
		{PreConfig: func() { f.mu.Lock(); defer f.mu.Unlock(); f.failPostAt = 0 }, Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction("zyxel_acl_policy.https", plancheck.ResourceActionUpdate),
		}}},
		{Config: policyTestConfig(f.server.URL, `["198.51.100.0/24"]`), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}})
	if len(f.rows) != 1 {
		t.Fatal("partial policy update lost ownership of router rows")
	}
}

func TestAccACLPolicy_capacityUpdateConverges(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	for _, result := range []string{"ZCFG_INVALID_PARAM_VALUE", "ZCFG_EXCEED_MAX_INS_NUM"} {
		t.Run(result, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.compactOrders, f.maxACLRows, f.capacityResult = true, 32, result
			initial := policyTestConfig(f.server.URL, `[for n in range(18) : "192.0.2.${n + 1}/32"]`)
			shrunk := policyTestConfig(f.server.URL, `[for n in range(17) : "192.0.2.${n + 1}/32"]`)
			resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
				{Config: initial},
				{Config: shrunk, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("zyxel_acl_policy.https", plancheck.ResourceActionUpdate),
				}}},
				{Config: shrunk, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			}})
		})
	}
}

func TestAccACLPolicy_managementReplacementRecovery(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.compactOrders = true
	initial := policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)
	changed := strings.Replace(initial, "192.168.1.0/24", "192.168.2.0/24", 1)
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: initial},
		{PreConfig: func() { f.mu.Lock(); defer f.mu.Unlock(); f.failDeleteAt = f.deletes + 3 }, Config: changed, ExpectError: regexp.MustCompile("delete failure|503")},
		{PreConfig: func() { f.mu.Lock(); defer f.mu.Unlock(); f.failDeleteAt = 0 }, Config: changed},
		{Config: changed, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{ResourceName: "zyxel_acl_policy.https", ImportState: true, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "generation", ImportStateIdFunc: func(s *terraform.State) (string, error) { return policyStateImportID(s, "zyxel_acl_policy.https"), nil }},
	}})
	if len(f.rows) != 1 {
		t.Fatal("management recovery lost ownership")
	}
}

func TestAccACLPolicy_namedRenameRefreshImport(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	config := policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)
	named := strings.Replace(config, "for cidr in [\"198.51.100.0/24\"] : {", "for cidr in [\"198.51.100.0/24\"] : {\n name = \"WebDAV\"", 1)
	named = strings.Replace(named, `action = "drop"`, "name = \"Deny\"\n action = \"drop\"", 1)
	renamed := strings.Replace(named, "WebDAV", "WebDAV-New", 1)
	check := func(label string) resource.TestCheckFunc {
		return resource.ComposeTestCheckFunc(
			resource.TestCheckResourceAttr("zyxel_acl_policy.https", "rules.0.name", label),
			resource.TestCheckResourceAttr("zyxel_acl_policy.https", "drop_rules.0.name", "Deny"),
			resource.TestMatchResourceAttr("zyxel_acl_policy.https", "generation", regexp.MustCompile(`^[0-9a-f]{2}$`)),
			resource.TestMatchResourceAttr("zyxel_acl_policy.https", "row_names.1", regexp.MustCompile(`^`+label+`-g[0-9a-f]{2}$`)),
		)
	}
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: named, Check: check("WebDAV")},
		{Config: named, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: renamed, Check: check("WebDAV-New")},
		{Config: renamed, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{ResourceName: "zyxel_acl_policy.https", ImportState: true, ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "generation", ImportStateIdFunc: func(s *terraform.State) (string, error) {
			return policyStateImportID(s, "zyxel_acl_policy.https"), nil
		}},
		{Config: config, ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue("zyxel_acl_policy.https", tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.Null()),
			statecheck.ExpectKnownValue("zyxel_acl_policy.https", tfjsonpath.New("drop_rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.Null()),
		}},
		{Config: config, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
	}})
}

func TestAccACLPolicy_legacyImport(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	for _, width := range []int{2, 3} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			f := newTerraformACLFixture(t)
			c := aclFixtureClient(t, f)
			p := fixtureACLPolicy("198.51.100.0/24")
			out, err := c.ApplyACLPolicy(context.Background(), p, nil)
			if err != nil {
				t.Fatal(err)
			}
			f.remove(out.State.Names[0])
			out.State.Names = out.State.Names[1:]
			const generation = "0123456789abcdef"
			f.mu.Lock()
			for i, name := range out.State.Names {
				for _, row := range f.rows {
					if row["Name"] == name {
						row["Name"] = fmt.Sprintf("ACL-g%s-%0*d", generation, width, i+1)
					}
				}
			}
			f.mu.Unlock()
			config := policyTestConfig(f.server.URL, `["198.51.100.0/24"]`)
			resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
				{Config: config, ResourceName: "zyxel_acl_policy.https", ImportState: true, ImportStateId: generation, ImportStatePersist: true},
				{Config: config, ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("zyxel_acl_policy.https", tfjsonpath.New("rules").AtSliceIndex(0).AtMapKey("name"), knownvalue.Null()),
				}},
			}})
			if len(f.rows) != 1 {
				t.Fatal("legacy rows were not deleted")
			}
		})
	}
}

func policyStateImportID(s *terraform.State, address string) string {
	a := s.RootModule().Resources[address].Primary.Attributes
	count := 0
	fmt.Sscan(a["row_names.#"], &count)
	names := make([]string, count)
	for i := range names {
		names[i] = a[fmt.Sprintf("row_names.%d", i)]
	}
	return a["generation"] + ":" + a["management_rules.#"] + ":" + strings.Join(names, ",")
}
