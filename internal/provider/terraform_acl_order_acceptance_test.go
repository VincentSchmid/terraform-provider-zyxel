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
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func appendACLConfig(endpoint, members string) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_acl_rule" "ranges" {
  count = length(%s)
  name = "range-${count.index}"
  action = "accept"
  source_cidr = "198.51.100.0/24"
  destination_cidr = "203.0.113.10/32"
  destination_ports = "443"
}
`, endpoint, members)
}

func TestAccACLRule_appendCollectionRefreshAndGrowth(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.rows[0]["Order"] = 30
	f.compactOrders, f.rejectOccupiedOrder = true, true
	initial := appendACLConfig(f.server.URL, `["z", "a", "m"]`)
	grown := appendACLConfig(f.server.URL, `["z", "a", "m", "b"]`)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: aclTestFactories,
		Steps: []resource.TestStep{
			{Config: initial},
			{Config: initial, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			{Config: grown, ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(`zyxel_acl_rule.ranges[3]`, tfjsonpath.New("order"), knownvalue.Int64Exact(5)),
			}},
			{Config: grown, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			// Removing a prefix compacts every managed position on refresh.
			{PreConfig: func() {
				f.remove("unmanaged")
				f.mu.Lock()
				defer f.mu.Unlock()
				for i, row := range f.rows {
					row["Order"] = i + 1
				}
			}, Config: grown, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		},
	})
}

func TestAccACLRule_appendFailuresRetainIdentity(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	for _, tc := range []struct {
		name    string
		setup   func(*terraformACLFixture)
		pattern string
	}{
		{"readback", func(f *terraformACLFixture) { f.failReadback = true }, "readback"},
		{"ambiguous", func(f *terraformACLFixture) { f.failPostAfterCommit = true }, "ambiguous|500"},
		{"security mismatch", func(f *terraformACLFixture) { f.mutateCreate = func(row map[string]any) { row["Target"] = "Drop" } }, "action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTerraformACLFixture(t)
			tc.setup(f)
			resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
				{Config: appendACLConfig(f.server.URL, `["a"]`), ExpectError: regexp.MustCompile(tc.pattern)},
			}})
			if err := f.check("range-0", false); err != nil {
				t.Fatal("failed create lost recoverable state:", err)
			}
		})
	}
}

func TestAccACLRule_appendRejectsGrowthBehindExistingDrop(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.compactOrders = true
	policy := func(members string) string {
		return appendACLConfig(f.server.URL, members) + `
resource "zyxel_acl_rule" "drop" {
  name = "trailing-drop"
  action = "drop"
  destination_cidr = "203.0.113.10/32"
  destination_ports = "443"
  depends_on = [zyxel_acl_rule.ranges]
}
`
	}
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: policy(`["a"]`)},
		{Config: policy(`["a", "b"]`), ExpectError: regexp.MustCompile("insertion/reordering")},
	}})
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 2 {
		t.Fatalf("unsupported growth wrote a rule: posts=%d", f.posts)
	}
}

func TestAccACLRule_switchToAppendAndStrictReplacement(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for local mock acceptance tests")
	}
	f := newTerraformACLFixture(t)
	c := defaultACLTestConfig()
	strict := c.hcl(f.server.URL)
	appendConfig := strings.Replace(strict, "order = 10", "", 1)
	changed := strings.Replace(appendConfig, `action = "accept"`, `action = "drop"`, 1)
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: strict},
		{Config: appendConfig, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: changed, ConfigStateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("order"), knownvalue.Int64Exact(2)),
		}},
		{Config: changed, ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		{Config: strings.Replace(changed, `action = "drop"`, "action = \"drop\"\norder = 20", 1), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(aclTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
		}}},
	}})
}
