package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
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

const aclTestAddress = "zyxel_acl_rule.test"

var aclTestFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"zyxel": providerserver.NewProtocol6WithError(New("test")()),
}

func testingAcceptanceEnabled() bool { return os.Getenv("TF_ACC") != "" }

type aclTestConfig struct {
	name, action, protocol, source, destination string
	order, destStart, destEnd                   int
	sourceStart, sourceEnd                      int
	packetsPerUnit                              int
	rateLimitUnit                               string
	ipVersion, direction, macAddress            string
	service, tcpFlag                            string
	enabled                                     bool
}

func defaultACLTestConfig() aclTestConfig {
	return aclTestConfig{name: "fixture-managed", action: "accept", protocol: "tcp", source: "0.0.0.0/0", destination: "203.0.113.10/32", order: 10, destStart: 443, destEnd: 443, enabled: true}
}

func (c aclTestConfig) hcl(endpoint string) string {
	sourcePorts := ""
	if c.sourceStart != 0 {
		sourcePorts = fmt.Sprintf("source_port_start = %d\nsource_port_end = %d", c.sourceStart, c.sourceEnd)
	}
	sourceCIDR := ""
	if c.source != "0.0.0.0/0" {
		sourceCIDR = fmt.Sprintf("source_cidr = %q", c.source)
	}
	protocol := ""
	if c.protocol != "" && c.protocol != "tcp" {
		protocol = fmt.Sprintf("protocol = %q", c.protocol)
	}
	destinationPorts := ""
	if c.destStart != 0 {
		destinationPorts = fmt.Sprintf("destination_port_start = %d\ndestination_port_end = %d", c.destStart, c.destEnd)
	}
	enabled := ""
	if !c.enabled {
		enabled = "enabled = false"
	}
	packetsPerUnit := ""
	if c.packetsPerUnit != 0 {
		packetsPerUnit = fmt.Sprintf("packets_per_unit = %d\nrate_limit_unit = %q", c.packetsPerUnit, c.rateLimitUnit)
	}
	extra := ""
	if c.ipVersion != "" && c.ipVersion != "ipv4" {
		extra += fmt.Sprintf("ip_version = %q\n", c.ipVersion)
	}
	if c.direction != "" && c.direction != "wan_to_lan" {
		extra += fmt.Sprintf("direction = %q\n", c.direction)
	}
	if c.macAddress != "" {
		extra += fmt.Sprintf("mac_address = %q\n", c.macAddress)
	}
	if c.service != "" {
		extra += fmt.Sprintf("service = %q\n", c.service)
	}
	if c.tcpFlag != "" {
		extra += fmt.Sprintf("tcp_flag = %q\n", c.tcpFlag)
	}
	return fmt.Sprintf(`
provider "zyxel" {
  host = %[1]q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_acl_rule" "test" {
  name = %[2]q
  action = %[3]q
  order = %[4]d
  %[5]s
  %[6]s
  destination_cidr = %[7]q
  %[8]s
  %[9]s
  %[10]s
  %[11]s
  %[12]s
}
`, endpoint, c.name, c.action, c.order, sourceCIDR, protocol, c.destination, destinationPorts, enabled, sourcePorts, packetsPerUnit, extra)
}

func TestAccACLRule_basicImportReplacement(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 to run local mock Terraform acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.addService("custom-https", 7)
	c := defaultACLTestConfig()
	steps := []resource.TestStep{{Config: c.hcl(f.server.URL), ConfigStateChecks: []statecheck.StateCheck{
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("name"), knownvalue.StringExact(c.name)),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("protocol"), knownvalue.StringExact("tcp")),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("source_port_start"), knownvalue.Null()),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("source_cidr"), knownvalue.StringExact("0.0.0.0/0")),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("packets_per_unit"), knownvalue.Null()),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("rate_limit_unit"), knownvalue.StringExact("minute")),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("ip_version"), knownvalue.StringExact("ipv4")),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("direction"), knownvalue.StringExact("wan_to_lan")),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("mac_address"), knownvalue.Null()),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("service"), knownvalue.Null()),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("tcp_flag"), knownvalue.Null()),
		statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("router_index"), knownvalue.Int64Exact(2)),
		aclFixtureStateCheck{fixture: f, name: c.name},
	}}, {
		ResourceName: aclTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.name, ImportStateVerifyIdentifierAttribute: "name",
	}}
	changes := []func(*aclTestConfig){
		func(c *aclTestConfig) { c.action = "drop" },
		func(c *aclTestConfig) { c.order = 20 },
		func(c *aclTestConfig) { c.source = "198.51.100.0/24" },
		func(c *aclTestConfig) { c.destination = "203.0.113.11/32" },
		func(c *aclTestConfig) { c.destEnd = 444 },
		func(c *aclTestConfig) { c.destStart = 444 },
		func(c *aclTestConfig) { c.sourceStart, c.sourceEnd = 1024, 2048 },
		func(c *aclTestConfig) { c.sourceEnd = 4096 },
		func(c *aclTestConfig) { c.sourceStart = 2048 },
		func(c *aclTestConfig) { c.enabled = false },
		func(c *aclTestConfig) { c.name = "fixture-renamed" },
		func(c *aclTestConfig) { c.action, c.packetsPerUnit, c.rateLimitUnit = "accept", 120, "minute" },
		func(c *aclTestConfig) { c.packetsPerUnit, c.rateLimitUnit = 512, "second" },
		func(c *aclTestConfig) { c.packetsPerUnit, c.rateLimitUnit = 0, "minute" },
		func(c *aclTestConfig) { c.protocol = "udp" },
		func(c *aclTestConfig) { c.protocol = "tcp_udp" },
		func(c *aclTestConfig) {
			c.protocol, c.destStart, c.destEnd, c.sourceStart, c.sourceEnd = "icmp", 0, 0, 0, 0
		},
		func(c *aclTestConfig) { c.protocol = "all" },
		func(c *aclTestConfig) { c.protocol = "icmpv6" },
		func(c *aclTestConfig) {
			c.protocol, c.destStart, c.destEnd = "tcp", 443, 443
			c.tcpFlag = "syn"
		},
		func(c *aclTestConfig) { c.direction = "lan_to_wan" },
		func(c *aclTestConfig) { c.macAddress = "AA:BB:CC:DD:EE:FF" },
		func(c *aclTestConfig) { c.service = "custom-https" },
		func(c *aclTestConfig) { c.action = "reject" },
		func(c *aclTestConfig) {
			c.action, c.service, c.tcpFlag, c.macAddress, c.direction = "accept", "", "", "", ""
			c.ipVersion, c.source, c.destination = "ipv6", "2001:db8::/32", "2001:db8:1::/64"
		},
		func(c *aclTestConfig) {
			c.ipVersion, c.source, c.destination = "ipv4", "0.0.0.0/0", "203.0.113.10/32"
		},
	}
	for _, change := range changes {
		change(&c)
		packetsPerUnitCheck := statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("packets_per_unit"), knownvalue.Null())
		unit := c.rateLimitUnit
		if c.packetsPerUnit != 0 {
			packetsPerUnitCheck = statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("packets_per_unit"), knownvalue.Int64Exact(int64(c.packetsPerUnit)))
		} else if unit == "" {
			unit = "minute"
		}
		ipVersion := c.ipVersion
		if ipVersion == "" {
			ipVersion = "ipv4"
		}
		direction := c.direction
		if direction == "" {
			direction = "wan_to_lan"
		}
		optionalCheck := func(attribute, value string) statecheck.StateCheck {
			if value == "" {
				return statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New(attribute), knownvalue.Null())
			}
			return statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New(attribute), knownvalue.StringExact(value))
		}
		steps = append(steps, resource.TestStep{
			Config: c.hcl(f.server.URL),
			ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(aclTestAddress, plancheck.ResourceActionDestroyBeforeCreate),
			}},
			ConfigStateChecks: []statecheck.StateCheck{
				aclFixtureStateCheck{fixture: f, name: c.name},
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("protocol"), knownvalue.StringExact(c.protocol)),
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("action"), knownvalue.StringExact(c.action)),
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("enabled"), knownvalue.Bool(c.enabled)),
				packetsPerUnitCheck,
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("rate_limit_unit"), knownvalue.StringExact(unit)),
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("ip_version"), knownvalue.StringExact(ipVersion)),
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("direction"), knownvalue.StringExact(direction)),
				optionalCheck("mac_address", c.macAddress),
				optionalCheck("service", c.service),
				optionalCheck("tcp_flag", c.tcpFlag),
			},
		})
	}
	steps = append(steps, resource.TestStep{ResourceName: aclTestAddress, ImportState: true, ImportStateVerify: true, ImportStateId: c.name, ImportStateVerifyIdentifierAttribute: "name"})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: aclTestFactories, Steps: steps,
		CheckDestroy: func(*terraform.State) error {
			if err := f.check(c.name, false); err != nil {
				return err
			}
			return f.check("unmanaged", true)
		},
	})
}

func TestAccACLRule_disappearsAndIndexShift(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 to run local mock Terraform acceptance tests")
	}
	f := newTerraformACLFixture(t)
	c := defaultACLTestConfig()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: aclTestFactories,
		CheckDestroy:             func(*terraform.State) error { return f.check(c.name, false) },
		Steps: []resource.TestStep{
			{Config: c.hcl(f.server.URL), ConfigStateChecks: []statecheck.StateCheck{
				aclFixtureStateCheck{fixture: f, name: c.name, remove: true},
			}, ExpectNonEmptyPlan: true},
			{Config: c.hcl(f.server.URL), ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
				plancheck.ExpectResourceAction(aclTestAddress, plancheck.ResourceActionCreate),
			}}},
			{PreConfig: func() { f.remove("unmanaged") }, Config: c.hcl(f.server.URL), ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(aclTestAddress, tfjsonpath.New("router_index"), knownvalue.Int64Exact(1)),
			}},
		},
	})
}

func TestAccACLRule_createdOrderMismatchRetainsState(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 to run local mock Terraform acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.forceOrder = true
	c := defaultACLTestConfig()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: aclTestFactories,
		CheckDestroy:             func(*terraform.State) error { return f.check(c.name, false) },
		Steps:                    []resource.TestStep{{Config: c.hcl(f.server.URL), ExpectError: regexp.MustCompile(`(?i)order|readback`)}},
	})
	if err := f.check(c.name, false); err != nil {
		t.Fatal("failed create left an untracked rule:", err)
	}
}

func TestAccACLRule_readbackFailureRetainsState(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 to run local mock Terraform acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.failReadback = true
	c := defaultACLTestConfig()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: aclTestFactories,
		CheckDestroy:             func(*terraform.State) error { return f.check(c.name, false) },
		Steps:                    []resource.TestStep{{Config: c.hcl(f.server.URL), ExpectError: regexp.MustCompile(`(?i)readback`)}},
	})
	if err := f.check(c.name, false); err != nil {
		t.Fatal("post-write read failure left an untracked rule:", err)
	}
}

func TestAccACLRule_ambiguousPostRetainsState(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 to run local mock Terraform acceptance tests")
	}
	f := newTerraformACLFixture(t)
	f.failPostAfterCommit = true
	c := defaultACLTestConfig()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: aclTestFactories,
		CheckDestroy:             func(*terraform.State) error { return f.check(c.name, false) },
		Steps:                    []resource.TestStep{{Config: c.hcl(f.server.URL), ExpectError: regexp.MustCompile(`(?i)ambiguous|500`)}},
	})
	if err := f.check(c.name, false); err != nil {
		t.Fatal("ambiguous POST left an untracked rule:", err)
	}
}

func TestAccACLRule_invalidConfiguration(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 to run local mock Terraform acceptance tests")
	}
	f := newTerraformACLFixture(t)
	var steps []resource.TestStep
	for _, mutate := range []func(*aclTestConfig){
		func(c *aclTestConfig) { c.name = " " },
		func(c *aclTestConfig) { c.action = "log" },
		func(c *aclTestConfig) { c.order = 0 },
		func(c *aclTestConfig) { c.destination = "2001:db8::/64" },
		func(c *aclTestConfig) { c.destination = "203.0.113.11/24" },
		func(c *aclTestConfig) { c.destEnd = 442 },
		func(c *aclTestConfig) { c.sourceStart, c.sourceEnd = 2048, 1024 },
		func(c *aclTestConfig) { c.protocol = "sctp" },
		func(c *aclTestConfig) { c.protocol = "icmp" },
		func(c *aclTestConfig) { c.ipVersion = "ipv5" },
		func(c *aclTestConfig) { c.ipVersion = "ipv6" },
		func(c *aclTestConfig) { c.direction = "sideways" },
		func(c *aclTestConfig) { c.macAddress = "AA:BB:CC:DD:EE" },
		func(c *aclTestConfig) {
			c.protocol, c.destStart, c.destEnd = "icmp", 0, 0
			c.tcpFlag = "syn"
		},
		func(c *aclTestConfig) { c.service = " custom " },
	} {
		c := defaultACLTestConfig()
		mutate(&c)
		steps = append(steps, resource.TestStep{Config: c.hcl(f.server.URL), PlanOnly: true, ExpectError: regexp.MustCompile(`(?i)Invalid|must be|does not use|does not match|required`)})
	}
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: steps})
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 0 || f.deletes != 0 {
		t.Fatal("invalid configuration wrote to the mock router")
	}
}

type aclFixtureStateCheck struct {
	fixture *terraformACLFixture
	name    string
	remove  bool
}

func (c aclFixtureStateCheck) CheckState(_ context.Context, _ statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	resp.Error = c.fixture.check(c.name, true)
	if resp.Error == nil && c.remove {
		c.fixture.remove(c.name)
	}
}
