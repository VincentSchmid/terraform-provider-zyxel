package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	testresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type firewallFixture struct {
	peer                                                *terraformACLFixture
	endpoint                                            string
	enabled                                             bool
	ipv4, ipv6                                          bool
	level                                               string
	rejectDoS                                           bool
	reads, writes                                       int
	readValue                                           any
	readObject                                          any
	readResult                                          string
	writeResult                                         string
	failReadback, ignoreWrite, brokenWrite, serverError bool
}

func newFirewallFixture(t *testing.T) (*zyxel.Client, *firewallFixture) {
	t.Helper()
	f := &firewallFixture{peer: newTerraformACLFixture(t), readResult: "ZCFG_SUCCESS", writeResult: "ZCFG_SUCCESS", ipv4: true, ipv6: true, level: "Low"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/DAL" {
			f.peer.serveHTTP(w, r)
			return
		}
		f.peer.mu.Lock()
		defer f.peer.mu.Unlock()
		cookie, err := r.Cookie("fixture-session")
		if err != nil || f.peer.sessions[cookie.Value] == nil {
			http.Error(w, "missing session", http.StatusForbidden)
			return
		}
		s := f.peer.sessions[cookie.Value]
		if r.URL.Query().Get("oid") != "firewall" || r.URL.Query().Get("sessionkey") != s.token || r.URL.Query().Has("Index") {
			t.Error("unexpected OID, stale session key, or indexed singleton request")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			f.reads++
			if f.failReadback && f.writes > 0 {
				http.Error(w, "readback failed", http.StatusServiceUnavailable)
				return
			}
			value := f.readValue
			if value == nil {
				value = f.enabled
			}
			object := f.readObject
			if object == nil {
				object = []any{map[string]any{"enableDos": value, "IPv4_Enable": f.ipv4, "IPv6_Enable": f.ipv6, "Level_GUI": f.level, "secret": "not-for-state"}}
			}
			f.peer.reply(w, s, map[string]any{"result": f.readResult, "Object": object})
		case http.MethodPut:
			if r.Header.Get("CSRFToken") != s.token || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("missing write headers")
			}
			var envelope struct{ IV, Content string }
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Error(err)
				return
			}
			plain, err := fixtureDecrypt(s.key, envelope.IV, envelope.Content)
			var body map[string]any
			if err != nil || json.Unmarshal(plain, &body) != nil {
				t.Error("invalid encrypted write")
				return
			}

			if _, dos := body["enableDos"]; dos {
				enabled, ok := body["enableDos"].(bool)
				if !ok || len(body) != 1 {
					t.Errorf("invalid DoS payload: %v", body)
					return
				}
				if f.rejectDoS {
					f.peer.reply(w, s, map[string]any{"result": "DENIED"})
					return
				}
				if f.writeResult == "ZCFG_SUCCESS" && !f.ignoreWrite {
					f.enabled = enabled
				}
			} else {
				ipv4, ok4 := body["IPv4_Enable"].(bool)
				ipv6, ok6 := body["IPv6_Enable"].(bool)
				master, okMaster := body["Firewall_Enable"].(bool)
				level, okLevel := body["Level_GUI"].(string)
				if !ok4 || !ok6 || !okMaster || !okLevel || len(body) != 4 || master != (ipv4 || ipv6) || (level != "Off" && level != "Low" && level != "High") {
					t.Errorf("invalid General payload: %v", body)
					return
				}
				if f.writeResult == "ZCFG_SUCCESS" && !f.ignoreWrite {
					f.ipv4, f.ipv6, f.level = ipv4, ipv6, level
				}
			}
			f.writes++
			f.peer.rotate(s)
			if f.serverError {
				http.Error(w, "failure after commit", http.StatusInternalServerError)
				return
			}
			if f.brokenWrite {
				_, _ = w.Write([]byte(`{}`))
				return
			}
			f.peer.reply(w, s, map[string]any{"result": f.writeResult, "sessionkey": s.token})
		default:
			t.Errorf("unexpected singleton method %s", r.Method)
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	f.endpoint = server.URL
	client, err := zyxel.NewClient(server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client, f
}

func TestFirewallClient(t *testing.T) {
	client, f := newFirewallFixture(t)
	for _, enabled := range []bool{true, false, false, true} {
		applied, err := client.SetFirewall(context.Background(), testFirewallSettings(enabled))
		if err != nil || !applied || f.enabled != enabled {
			t.Fatalf("set %t: applied=%t, err=%v", enabled, applied, err)
		}
		got, err := client.ReadFirewall(context.Background())
		if err != nil || got != testFirewallSettings(enabled) {
			t.Fatalf("read: %+v, %v", got, err)
		}
	}
	if f.writes != 3 {
		t.Fatalf("expected three targeted writes, got %d", f.writes)
	}
	f.peer.mu.Lock()
	defer f.peer.mu.Unlock()
	if len(f.peer.sessions) != 0 {
		t.Fatal("successful sessions were not logged out with the rotated token")
	}
}

func TestFirewallReadValues(t *testing.T) {
	for _, tc := range []struct {
		value   any
		want    bool
		invalid bool
	}{
		{true, true, false}, {false, false, false}, {1, true, false}, {0, false, false},
		{"false", false, true}, {2, false, true}, {map[string]any{}, false, true},
	} {
		t.Run(fmt.Sprint(tc.value), func(t *testing.T) {
			client, f := newFirewallFixture(t)
			f.readValue = tc.value
			got, err := client.ReadFirewall(context.Background())
			if (err != nil) != tc.invalid || got.DoSProtectionEnabled != tc.want {
				t.Fatalf("read=%+v, err=%v", got, err)
			}
		})
	}
}

func TestFirewallFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(*firewallFixture)
		applied bool
		writes  int
	}{
		{"read rejection", func(f *firewallFixture) { f.readResult = "DENIED" }, false, 0},
		{"malformed read", func(f *firewallFixture) { f.readValue = "secret-invalid" }, false, 0},
		{"write rejection", func(f *firewallFixture) { f.writeResult = "DENIED" }, false, 1},
		{"readback failure", func(f *firewallFixture) { f.failReadback = true }, true, 1},
		{"readback mismatch", func(f *firewallFixture) { f.ignoreWrite = true }, true, 1},
		{"ambiguous response", func(f *firewallFixture) { f.brokenWrite = true }, true, 1},
		{"server error after commit", func(f *firewallFixture) { f.serverError = true }, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, f := newFirewallFixture(t)
			tc.setup(f)
			applied, err := client.SetFirewall(context.Background(), testFirewallSettings(true))
			if err == nil || applied != tc.applied || f.writes != tc.writes {
				t.Fatalf("applied=%t, writes=%d, err=%v", applied, f.writes, err)
			}
		})
	}
}

func TestFirewallRejectsIncompleteSettings(t *testing.T) {
	for _, object := range []any{
		"invalid", []any{}, []any{"invalid"}, []any{map[string]any{}},
		[]any{map[string]any{"enableDos": nil}},
		[]any{map[string]any{"enableDos": true}, map[string]any{"enableDos": false}},
	} {
		t.Run(fmt.Sprint(object), func(t *testing.T) {
			client, f := newFirewallFixture(t)
			f.readObject = object
			if applied, err := client.SetFirewall(context.Background(), testFirewallSettings(true)); err == nil || applied || f.writes != 0 {
				t.Fatalf("malformed settings allowed mutation: applied=%t err=%v writes=%d", applied, err, f.writes)
			}
		})
	}
}

func TestFirewallAdoptsExistingValueWithoutWrite(t *testing.T) {
	client, f := newFirewallFixture(t)
	f.enabled = true
	if applied, err := client.SetFirewall(context.Background(), testFirewallSettings(true)); err != nil || !applied || f.writes != 0 {
		t.Fatalf("adoption should not write: applied=%t err=%v writes=%d", applied, err, f.writes)
	}
}

func TestFirewallCreateRetainsIdentityAfterUnconfirmedWrite(t *testing.T) {
	client, f := newFirewallFixture(t)
	f.failReadback = true
	r := &FirewallResource{client: client}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := plan.Set(context.Background(), &firewallModel{ID: types.StringUnknown(), IPv4Enabled: types.BoolValue(true), IPv6Enabled: types.BoolValue(true), SecurityLevel: types.StringValue("medium"), DoSProtectionEnabled: types.BoolValue(true)}); diags.HasError() {
		t.Fatal(diags)
	}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, &resp)
	var id string
	diags := resp.State.GetAttribute(context.Background(), path.Root("id"), &id)
	if !resp.Diagnostics.HasError() || diags.HasError() || id != "router" {
		t.Fatalf("identity lost after unconfirmed write: id=%q diagnostics=%v %v", id, resp.Diagnostics, diags)
	}
}

func firewallTestHCL(endpoint string, enabled bool) string {
	return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_firewall" "router" {
  ipv4_enabled = true
  ipv6_enabled = true
  security_level = "medium"
  dos_protection_enabled = %t
}
`, endpoint, enabled)
}

func TestAccFirewallLifecycle(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	_, f := newFirewallFixture(t)
	address := "zyxel_firewall.router"
	testresource.Test(t, testresource.TestCase{
		ProtoV6ProviderFactories: natTestFactories,
		CheckDestroy: func(*terraform.State) error {
			f.peer.mu.Lock()
			defer f.peer.mu.Unlock()
			if !f.enabled || f.writes != 4 {
				return fmt.Errorf("destroy changed protection or unexpected writes: enabled=%t writes=%d", f.enabled, f.writes)
			}
			return nil
		},
		Steps: []testresource.TestStep{
			{Config: firewallTestHCL(f.endpoint, true), Check: testresource.ComposeTestCheckFunc(testresource.TestCheckResourceAttr(address, "dos_protection_enabled", "true"), testresource.TestCheckResourceAttr(address, "id", "router"))},
			{ResourceName: address, ImportState: true, ImportStateId: "router", ImportStateVerify: true},
			{Config: firewallTestHCL(f.endpoint, false), ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}, Check: testresource.TestCheckResourceAttr(address, "dos_protection_enabled", "false")},
			{Config: firewallTestHCL(f.endpoint, true), Check: testresource.TestCheckResourceAttr(address, "dos_protection_enabled", "true")},
			{PreConfig: func() { f.peer.mu.Lock(); f.enabled = false; f.peer.mu.Unlock() }, Config: firewallTestHCL(f.endpoint, true), ConfigPlanChecks: testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}},
			{ResourceName: address, ImportState: true, ImportStateId: "invalid", ExpectError: regexp.MustCompile("import ID must be router")},
		},
	})
}

func testFirewallSettings(dos bool) zyxel.FirewallSettings {
	return zyxel.FirewallSettings{IPv4Enabled: true, IPv6Enabled: true, SecurityLevel: "medium", DoSProtectionEnabled: dos}
}

func TestFirewallGeneralSettings(t *testing.T) {
	client, f := newFirewallFixture(t)
	for _, settings := range []zyxel.FirewallSettings{
		{IPv4Enabled: true, IPv6Enabled: false, SecurityLevel: "low", DoSProtectionEnabled: true},
		{IPv4Enabled: false, IPv6Enabled: true, SecurityLevel: "medium", DoSProtectionEnabled: true},
		{IPv4Enabled: false, IPv6Enabled: false, SecurityLevel: "high", DoSProtectionEnabled: false},
		{IPv4Enabled: true, IPv6Enabled: true, SecurityLevel: "medium", DoSProtectionEnabled: true},
	} {
		applied, err := client.SetFirewall(context.Background(), settings)
		if err != nil || !applied {
			t.Fatalf("set %+v: applied=%t err=%v", settings, applied, err)
		}
		got, err := client.ReadFirewall(context.Background())
		if err != nil || got != settings {
			t.Fatalf("read: %+v err=%v; want %+v", got, err, settings)
		}
	}
	if f.writes != 7 {
		t.Fatalf("expected four General and three DoS writes, got %d", f.writes)
	}
	if applied, err := client.SetFirewall(context.Background(), zyxel.FirewallSettings{SecurityLevel: "invalid"}); applied || err == nil || f.writes != 7 {
		t.Fatal("invalid security level should fail before accessing the router")
	}
}

func TestFirewallPartialUpdate(t *testing.T) {
	client, f := newFirewallFixture(t)
	f.rejectDoS = true
	settings := testFirewallSettings(true)
	settings.SecurityLevel = "high"
	applied, err := client.SetFirewall(context.Background(), settings)
	if err == nil || !applied || f.level != "High" || f.enabled {
		t.Fatalf("expected partial success to remain recoverable: applied=%t err=%v", applied, err)
	}
}

func TestFirewallRejectsMalformedGeneralFields(t *testing.T) {
	for _, field := range []string{"IPv4_Enable", "IPv6_Enable", "Level_GUI"} {
		t.Run(field, func(t *testing.T) {
			client, f := newFirewallFixture(t)
			object := map[string]any{"IPv4_Enable": true, "IPv6_Enable": true, "Level_GUI": "Low", "enableDos": false}
			delete(object, field)
			f.readObject = []any{object}
			if applied, err := client.SetFirewall(context.Background(), testFirewallSettings(true)); applied || err == nil || f.writes != 0 {
				t.Fatal("missing General setting must fail without writing")
			}
			object[field] = "unexpected"
			if _, err := client.ReadFirewall(context.Background()); err == nil {
				t.Fatal("malformed General setting must fail")
			}
		})
	}
}

func TestAccFirewallGeneralUpdate(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run local mock Terraform lifecycle tests")
	}
	_, f := newFirewallFixture(t)
	address := "zyxel_firewall.router"
	config := func(ipv4, ipv6 bool, level string) string {
		return fmt.Sprintf(`
provider "zyxel" {
  host = %q
  username = "fixture-user"
  password = "fixture-password"
}
resource "zyxel_firewall" "router" {
  ipv4_enabled = %t
  ipv6_enabled = %t
  security_level = %q
  dos_protection_enabled = true
}`, f.endpoint, ipv4, ipv6, level)
	}
	var steps []testresource.TestStep
	for _, settings := range []zyxel.FirewallSettings{{IPv4Enabled: true, IPv6Enabled: false, SecurityLevel: "low", DoSProtectionEnabled: true}, {IPv4Enabled: false, IPv6Enabled: true, SecurityLevel: "medium", DoSProtectionEnabled: true}, {IPv4Enabled: false, IPv6Enabled: false, SecurityLevel: "high", DoSProtectionEnabled: true}, {IPv4Enabled: true, IPv6Enabled: true, SecurityLevel: "medium", DoSProtectionEnabled: true}} {
		step := testresource.TestStep{Config: config(settings.IPv4Enabled, settings.IPv6Enabled, settings.SecurityLevel), Check: testresource.ComposeTestCheckFunc(
			testresource.TestCheckResourceAttr(address, "ipv4_enabled", fmt.Sprint(settings.IPv4Enabled)),
			testresource.TestCheckResourceAttr(address, "ipv6_enabled", fmt.Sprint(settings.IPv6Enabled)),
			testresource.TestCheckResourceAttr(address, "security_level", settings.SecurityLevel),
		)}
		if len(steps) > 0 {
			step.ConfigPlanChecks = testresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate)}}
		}
		steps = append(steps, step)
	}
	steps = append(steps, testresource.TestStep{Config: config(true, true, "invalid"), ExpectError: regexp.MustCompile("Invalid firewall security level")})
	steps = append(steps, testresource.TestStep{Config: config(true, true, "medium")})
	testresource.Test(t, testresource.TestCase{ProtoV6ProviderFactories: natTestFactories, Steps: steps})
}
