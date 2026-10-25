package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestServiceClientLifecycleAndSafeACLReferences(t *testing.T) {
	f := newTerraformACLFixture(t)
	client, err := zyxel.NewClient(f.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first := zyxel.Service{Name: "first", Protocol: "tcp", DestinationPorts: "443"}
	second := zyxel.Service{Name: "second", Protocol: "udp", SourcePorts: "1024-2048", DestinationPorts: "53"}
	if _, err := client.CreateService(ctx, first); err != nil {
		t.Fatal(err)
	}
	out, err := client.CreateService(ctx, second)
	if err != nil || out.Service == nil {
		t.Fatalf("%#v %v", out, err)
	}
	id := out.Service.ID
	if id == "2" || out.Service.RouterIndex != 2 {
		t.Fatal("native ID must be separate from display index")
	}
	if _, err := client.CreateService(ctx, second); err == nil {
		t.Fatal("adopted existing service")
	}
	if err := client.DeleteService(ctx, "first"); err != nil {
		t.Fatal(err)
	}
	observed, err := client.ReadService(ctx, "second")
	if err != nil || observed.ID != id || observed.RouterIndex != 1 {
		t.Fatalf("%#v %v", observed, err)
	}
	rule := testACLRule("uses-service", "accept", 10)
	rule.Protocol = "all"
	rule.ServiceID = id
	rule.DestinationPortStart, rule.DestinationPortEnd = nil, nil
	acl, err := client.CreateACLRule(ctx, rule)
	if err != nil || acl.Rule == nil || acl.Rule.ServiceID != id {
		t.Fatalf("%#v %v", acl, err)
	}
	if err := client.DeleteService(ctx, "second"); err == nil || !strings.Contains(err.Error(), "referenced") {
		t.Fatalf("must prevent cascade: %v", err)
	}
	if err := f.check(rule.Name, true); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteACLRule(ctx, rule.Name); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteService(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteService(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadService(ctx, "second"); !errors.Is(err, zyxel.ErrServiceNotFound) {
		t.Fatal(err)
	}
}

func TestServiceReferenceFailuresDoNotMutateACLs(t *testing.T) {
	f := newTerraformACLFixture(t)
	client, _ := zyxel.NewClient(f.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	rule := testACLRule("missing-service", "accept", 10)
	rule.Protocol, rule.ServiceID = "all", "999"
	rule.DestinationPortStart, rule.DestinationPortEnd = nil, nil
	if _, err := client.CreateACLRule(context.Background(), rule); err == nil {
		t.Fatal("accepted nonexistent service ID")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 0 {
		t.Fatal("wrote an ACL for an unresolved service")
	}
}

func TestServiceDeletionRejectsUnmanagedReferencesAndDuplicateNames(t *testing.T) {
	f := newTerraformACLFixture(t)
	client, _ := zyxel.NewClient(f.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	outcome, err := client.CreateService(context.Background(), zyxel.Service{Name: "test", Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rows[0]["X_ZYXEL_ServiceIndex"] = outcome.Service.ID
	f.mu.Unlock()
	if err := client.DeleteService(context.Background(), "test"); err == nil {
		t.Fatal("deleted a service referenced by an unmanaged ACL")
	}
	f.mu.Lock()
	f.rows[0]["X_ZYXEL_ServiceIndex"] = 0
	f.services = append(f.services, f.services[0])
	f.mu.Unlock()
	if _, err := client.ReadService(context.Background(), "test"); err == nil {
		t.Fatal("read ambiguous duplicate service")
	}
	if err := client.DeleteService(context.Background(), "test"); err == nil {
		t.Fatal("deleted ambiguous duplicate service")
	}
}

func TestACLCompactPortStateRoundTrip(t *testing.T) {
	rule := testACLRule("compact", "accept", 10)
	old := modelFromACLRule(rule)
	old.SourcePorts = types.StringValue("*")
	old.DestinationPorts = types.StringValue("443-443")
	state := aclObservedModel(rule, old)
	if state.DestinationPorts.ValueString() != "443-443" || !state.DestinationPortStart.IsNull() || state.SourcePorts.ValueString() != "*" {
		t.Fatalf("%#v", state)
	}
	start, end := int64(444), int64(445)
	rule.DestinationPortStart, rule.DestinationPortEnd = &start, &end
	state = aclObservedModel(rule, old)
	if state.DestinationPorts.ValueString() != "444-445" {
		t.Fatal("must expose port drift")
	}
}

func TestServiceUncertainWritesRetainIdentity(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint(ambiguous), func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.failReadback = !ambiguous
			f.failPostAfterCommit = ambiguous
			client, _ := zyxel.NewClient(f.server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
			outcome, err := client.CreateService(context.Background(), zyxel.Service{Name: "uncertain", Protocol: "tcp"})
			if err == nil || (ambiguous && !outcome.Ambiguous) || (!ambiguous && !outcome.Applied) {
				t.Fatalf("%#v %v", outcome, err)
			}
			observed, err := client.ReadService(context.Background(), "uncertain")
			if err != nil || observed.Name != "uncertain" {
				t.Fatalf("cannot reconcile: %#v %v", observed, err)
			}
		})
	}
}

func TestAccServiceProtocolsAndReplacement(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for mock Terraform tests")
	}
	f := newTerraformACLFixture(t)
	config := func(protocol, extra string) string {
		return fmt.Sprintf(`
provider "zyxel" {
 host = %q
 username = "fixture-user"
 password = "fixture-password"
}

resource "zyxel_service" "test" {
 name = "test"
 protocol = %q
 %s
}
`, f.server.URL, protocol, extra)
	}
	var steps []resource.TestStep
	for _, item := range [][2]string{{"tcp", `source_ports = "443-445"`}, {"udp", `destination_ports = "53"`}, {"icmp", `icmp_type = 8`}, {"icmpv6", `icmpv6_type = 128`}, {"other", `protocol_number = 47`}} {
		steps = append(steps, resource.TestStep{Config: config(item[0], item[1]), Check: resource.TestCheckResourceAttr("zyxel_service.test", "protocol", item[0])})
	}
	steps = append(steps, resource.TestStep{Config: config("icmp", `source_ports = "*"`), PlanOnly: true, ExpectError: regexp.MustCompile("Protocol does not use ports")})
	steps = append(steps, resource.TestStep{Config: config("other", `protocol_number = 47`)})
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: steps})
}

func TestAccServiceAndACLReference(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for mock Terraform tests")
	}
	f := newTerraformACLFixture(t)
	config := fmt.Sprintf(`
provider "zyxel" {
 host = %q
 username = "fixture-user"
 password = "fixture-password"
}
resource "zyxel_service" "test" {
 name = "https"
 protocol = "tcp"
 source_ports = "*"
 destination_ports = "443"
}
resource "zyxel_acl_rule" "test" {
 name = "service-acl"
 action = "accept"
 order = 10
 destination_cidr = "203.0.113.10/32"
 service_id = zyxel_service.test.id
}
`, f.server.URL)
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: []resource.TestStep{
		{Config: config, Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("zyxel_service.test", "id", "101"), resource.TestCheckResourceAttr("zyxel_acl_rule.test", "service_id", "101"), resource.TestCheckResourceAttr("zyxel_acl_rule.test", "protocol", "all"))},
		{ResourceName: "zyxel_service.test", ImportState: true, ImportStateId: "https", ImportStateVerify: true, ImportStateVerifyIdentifierAttribute: "name", ImportStateVerifyIgnore: []string{"source_ports"}},
		{Config: config, PlanOnly: true},
	}})
}

func TestAccACLCompactPorts(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for mock Terraform tests")
	}
	f := newTerraformACLFixture(t)
	config := func(source, destination string) string {
		return fmt.Sprintf(`
provider "zyxel" {
 host = %q
 username = "fixture-user"
 password = "fixture-password"
}
resource "zyxel_acl_rule" "test" {
 name = "compact"
 action = "accept"
 order = 10
 destination_cidr = "203.0.113.10/32"
 source_ports = %q
 destination_ports = %q
}
`, f.server.URL, source, destination)
	}
	var steps []resource.TestStep
	for _, ports := range [][2]string{{"*", "443"}, {"443", "443-445"}, {"443-445", "*"}, {"*", "443-443"}} {
		steps = append(steps, resource.TestStep{Config: config(ports[0], ports[1]), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr(aclTestAddress, "source_ports", ports[0]), resource.TestCheckResourceAttr(aclTestAddress, "destination_ports", ports[1]))})
	}
	for _, bad := range []string{"445-443", "65536", ""} {
		steps = append(steps, resource.TestStep{Config: config("*", bad), PlanOnly: true, ExpectError: regexp.MustCompile("Invalid ports")})
	}
	conflict := strings.Replace(config("*", "443"), `source_ports = "*"`, `source_ports = "*"
 source_port_start = 1
 source_port_end = 1`, 1)
	steps = append(steps, resource.TestStep{Config: conflict, PlanOnly: true, ExpectError: regexp.MustCompile("Conflicting port syntax")}, resource.TestStep{Config: config("*", "443-443")})
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories, Steps: steps})
}

func TestAccServiceUncertainWriteRetainsState(t *testing.T) {
	if !testingAcceptanceEnabled() {
		t.Skip("set TF_ACC=1 for mock Terraform tests")
	}
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint(ambiguous), func(t *testing.T) {
			f := newTerraformACLFixture(t)
			f.failReadback = !ambiguous
			f.failPostAfterCommit = ambiguous
			config := fmt.Sprintf(`
provider "zyxel" {
 host = %q
 username = "fixture-user"
 password = "fixture-password"
}
resource "zyxel_service" "test" {
 name = "uncertain"
 protocol = "tcp"
}
`, f.server.URL)
			resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: aclTestFactories,
				CheckDestroy: func(*terraform.State) error {
					f.mu.Lock()
					defer f.mu.Unlock()
					if len(f.services) != 0 {
						return fmt.Errorf("uncertain write left an untracked service")
					}
					return nil
				},
				Steps: []resource.TestStep{{Config: config, ExpectError: regexp.MustCompile("(?i)readback|500")}},
			})
		})
	}
}
