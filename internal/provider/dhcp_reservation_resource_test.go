package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/internal/routertest"
	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestDHCPReservationCreateDeleteEncryptedLifecycle(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var key []byte
	var sessionKey string
	var mu sync.Mutex
	rows := []map[string]any{{"Index": float64(1), "MACAddr": "AA:BB:CC:DD:EE:01", "IPAddr": "192.0.2.1", "Enable": true}}
	var deleteIndex string
	var posted map[string]any
	var logoutKey string
	mux := http.NewServeMux()
	mux.HandleFunc("/GetInfoNoLogin", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "router", Value: "session", Path: "/"})
	})
	mux.HandleFunc("/getRSAPublickKey", func(w http.ResponseWriter, _ *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]string{"RSAPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	})
	mux.HandleFunc("/UserLogin", func(w http.ResponseWriter, r *http.Request) {
		var payload routertest.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		wrapped, _ := base64.StdEncoding.DecodeString(payload.Key)
		keyBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, wrapped)
		if err != nil {
			t.Error(err)
			return
		}
		key, err = base64.StdEncoding.DecodeString(string(keyBytes))
		if err != nil {
			t.Error(err)
			return
		}
		sessionKey = "token-1"
		routertest.WriteEncrypted(t, w, key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": sessionKey})
	})
	mux.HandleFunc("/cgi-bin/DAL", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if got := r.URL.Query().Get("sessionkey"); got != sessionKey {
			t.Errorf("session key = %q, want %q", got, sessionKey)
		}
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("oid") != "static_dhcp" {
				t.Errorf("unexpected oid %q", r.URL.Query().Get("oid"))
			}
			routertest.WriteEncrypted(t, w, key, map[string]any{"result": "ZCFG_SUCCESS", "Object": rows})
		case http.MethodPost:
			assertWriteHeaders(t, r, sessionKey)
			var payload routertest.Payload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
				return
			}
			ciphertext, _ := base64.StdEncoding.DecodeString(payload.Content)
			iv, _ := base64.StdEncoding.DecodeString(payload.IV)
			plain, err := routertest.DecryptCBC(key, iv[:16], ciphertext)
			if err != nil {
				t.Error(err)
				return
			}
			if err := json.Unmarshal(plain, &posted); err != nil {
				t.Error(err)
				return
			}
			if posted["BrWan"] != "Default" || posted["MACAddr"] != "AA:BB:CC:DD:EE:02" || posted["IPAddr"] != "192.0.2.22" || posted["Enable"] != true {
				t.Errorf("unexpected create payload: %#v", posted)
			}
			rows = append(rows, map[string]any{"Index": float64(4), "MACAddr": posted["MACAddr"], "IPAddr": posted["IPAddr"], "Enable": posted["Enable"]})
			sessionKey = "token-2"
			routertest.WriteEncrypted(t, w, key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": sessionKey})
		case http.MethodDelete:
			assertWriteHeaders(t, r, sessionKey)
			deleteIndex = r.URL.Query().Get("Index")
			if deleteIndex != "4" {
				t.Errorf("delete Index = %q, want freshly read index 4", deleteIndex)
			}
			var payload routertest.Payload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
				return
			}
			ciphertext, _ := base64.StdEncoding.DecodeString(payload.Content)
			iv, _ := base64.StdEncoding.DecodeString(payload.IV)
			plain, err := routertest.DecryptCBC(key, iv[:16], ciphertext)
			if err != nil {
				t.Error(err)
				return
			}
			if string(plain) != "{}" {
				t.Errorf("DELETE body = %s, want encrypted empty object", plain)
			}
			rows = rows[:1]
			sessionKey = "token-3"
			routertest.WriteEncrypted(t, w, key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": sessionKey})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	mux.HandleFunc("/cgi-bin/UserLogout", func(w http.ResponseWriter, r *http.Request) { logoutKey = r.URL.Query().Get("sessionkey") })
	server := httptest.NewServer(mux)
	defer server.Close()
	client, err := zyxel.NewClient(server.URL, zyxel.Credentials{Username: "user", Password: "not-printed"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateDHCPReservation(context.Background(), "AA:BB:CC:DD:EE:02", "192.0.2.22", true)
	if err != nil || !created {
		t.Fatalf("create = %t, %v", created, err)
	}
	if err := client.DeleteDHCPReservation(context.Background(), "AA:BB:CC:DD:EE:02"); err != nil {
		t.Fatal(err)
	}
	if posted == nil || deleteIndex != "4" {
		t.Fatalf("create/delete were not observed: %#v, index %q", posted, deleteIndex)
	}
	if logoutKey != "token-3" {
		t.Fatalf("logout key = %q, want rotated token-3", logoutKey)
	}
}

func assertWriteHeaders(t *testing.T, r *http.Request, token string) {
	t.Helper()
	if r.Header.Get("CSRFToken") != token {
		t.Errorf("CSRFToken = %q, want %q", r.Header.Get("CSRFToken"), token)
	}
	if r.Header.Get("If-Modified-Since") != "Thu, 01 Jun 1970 00:00:00 GMT" {
		t.Errorf("missing If-Modified-Since header")
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("unexpected Content-Type %q", r.Header.Get("Content-Type"))
	}
}

func TestDHCPReservationSchemaAndValidators(t *testing.T) {
	var schemaResponse resource.SchemaResponse
	NewDHCPReservationResource().Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	if diagnostics := schemaResponse.Schema.Validate(); diagnostics.HasError() {
		t.Fatalf("invalid resource schema: %v", diagnostics)
	}
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"02:00:5E:10:00:01", true}, {"02:00:5e:10:00:01", false}, {"02-00-5E-10-00-01", false}, {"02:00:5E:10:00", false},
	} {
		response := validator.StringResponse{}
		macValidator{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("mac_address"), ConfigValue: types.StringValue(test.value)}, &response)
		if response.Diagnostics.HasError() == test.valid {
			t.Errorf("MAC validator for %q diagnostics error=%t", test.value, response.Diagnostics.HasError())
		}
	}
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"192.0.2.10", true}, {"::ffff:192.0.2.10", false}, {"192.0.2.10/24", false}, {"not-an-ip", false},
	} {
		response := validator.StringResponse{}
		ipv4Validator{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("ipv4_address"), ConfigValue: types.StringValue(test.value)}, &response)
		if response.Diagnostics.HasError() == test.valid {
			t.Errorf("IPv4 validator for %q diagnostics error=%t", test.value, response.Diagnostics.HasError())
		}
	}
	schema := dhcpFrameworkSchema(t)
	for _, test := range []struct {
		name       string
		plan       dhcpReservationModel
		state      dhcpReservationModel
		modifiers  []planmodifier.String
		planValue  types.String
		stateValue types.String
	}{
		{name: "mac_address", plan: dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:01"), IPv4: types.StringValue("192.0.2.10"), Enabled: types.BoolValue(true)}, state: dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), IPv4: types.StringValue("192.0.2.10"), Enabled: types.BoolValue(true)}, modifiers: schema.Attributes["mac_address"].(resourceschema.StringAttribute).PlanModifiers, planValue: types.StringValue("AA:BB:CC:DD:EE:01"), stateValue: types.StringValue("AA:BB:CC:DD:EE:FF")},
		{name: "ipv4_address", plan: dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), IPv4: types.StringValue("192.0.2.11"), Enabled: types.BoolValue(true)}, state: dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), IPv4: types.StringValue("192.0.2.10"), Enabled: types.BoolValue(true)}, modifiers: schema.Attributes["ipv4_address"].(resourceschema.StringAttribute).PlanModifiers, planValue: types.StringValue("192.0.2.11"), stateValue: types.StringValue("192.0.2.10")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if len(test.modifiers) == 0 {
				t.Fatal("schema has no replacement plan modifier")
			}
			response := planmodifier.StringResponse{PlanValue: test.planValue}
			test.modifiers[0].PlanModifyString(context.Background(), planmodifier.StringRequest{Plan: dhcpPlan(t, schema, test.plan), PlanValue: test.planValue, State: dhcpState(t, schema, test.state), StateValue: test.stateValue}, &response)
			if !response.RequiresReplace {
				t.Fatal("configured schema modifier did not require replacement")
			}
		})
	}
	enabledModifiers := schema.Attributes["enabled"].(resourceschema.BoolAttribute).PlanModifiers
	if len(enabledModifiers) == 0 {
		t.Fatal("enabled schema has no replacement plan modifier")
	}
	enabledPlan := dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), IPv4: types.StringValue("192.0.2.10"), Enabled: types.BoolValue(true)}
	enabledState := dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), IPv4: types.StringValue("192.0.2.10"), Enabled: types.BoolValue(false)}
	enabledResponse := planmodifier.BoolResponse{PlanValue: enabledPlan.Enabled}
	enabledModifiers[0].PlanModifyBool(context.Background(), planmodifier.BoolRequest{Plan: dhcpPlan(t, schema, enabledPlan), PlanValue: enabledPlan.Enabled, State: dhcpState(t, schema, enabledState), StateValue: enabledState.Enabled}, &enabledResponse)
	if !enabledResponse.RequiresReplace {
		t.Fatal("configured enabled modifier did not require replacement")
	}
}

func TestDHCPValidateConfigEnabled(t *testing.T) {
	schema := dhcpFrameworkSchema(t)
	r := NewDHCPReservationResource().(*DHCPReservationResource)
	for _, test := range []struct {
		name    string
		enabled types.Bool
		invalid bool
	}{
		{name: "false", enabled: types.BoolValue(false), invalid: true},
		{name: "null", enabled: types.BoolNull()},
		{name: "unknown", enabled: types.BoolUnknown()},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:FF"), IPv4: types.StringValue("192.0.2.10"), Enabled: test.enabled}
			configPlan := dhcpPlan(t, schema, model)
			response := resource.ValidateConfigResponse{}
			r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: schema, Raw: configPlan.Raw}}, &response)
			if response.Diagnostics.HasError() != test.invalid {
				t.Fatalf("enabled=%v diagnostics=%v", test.enabled, response.Diagnostics)
			}
		})
	}
}

type dhcpMockRouter struct {
	client                 *zyxel.Client
	server                 *httptest.Server
	mu                     sync.Mutex
	key                    []byte
	token                  string
	rows                   []map[string]any
	writeCount             int
	readCount              int
	activeSessions         int
	maxActiveSessions      int
	lastDeleteIndex        string
	malformedRead          bool
	readbackIPOverride     string
	writeHTTPStatus        int
	malformedWriteResponse bool
}

func newDHCPMockRouter(t *testing.T) *dhcpMockRouter {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mock := &dhcpMockRouter{}
	mux := http.NewServeMux()
	mux.HandleFunc("/GetInfoNoLogin", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "router", Value: "session", Path: "/"})
	})
	mux.HandleFunc("/getRSAPublickKey", func(w http.ResponseWriter, _ *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]string{"RSAPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	})
	mux.HandleFunc("/UserLogin", func(w http.ResponseWriter, r *http.Request) {
		var payload routertest.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		wrapped, _ := base64.StdEncoding.DecodeString(payload.Key)
		keyBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, wrapped)
		if err != nil {
			t.Error(err)
			return
		}
		mock.key, err = base64.StdEncoding.DecodeString(string(keyBytes))
		if err != nil {
			t.Error(err)
			return
		}
		mock.mu.Lock()
		mock.token = "mock-token-1"
		mock.activeSessions++
		if mock.activeSessions > mock.maxActiveSessions {
			mock.maxActiveSessions = mock.activeSessions
		}
		mock.mu.Unlock()
		routertest.WriteEncrypted(t, w, mock.key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": mock.token})
	})
	mux.HandleFunc("/cgi-bin/DAL", func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if r.URL.Query().Get("sessionkey") != mock.token {
			t.Errorf("DAL session token mismatch")
		}
		switch r.Method {
		case http.MethodGet:
			mock.readCount++
			if mock.malformedRead {
				routertest.WriteEncrypted(t, w, mock.key, map[string]any{"result": "ZCFG_SUCCESS", "Object": "malformed"})
				return
			}
			rows := mock.rows
			if rows == nil {
				rows = []map[string]any{}
			}
			if mock.readbackIPOverride != "" && len(rows) > 0 {
				rows = append([]map[string]any(nil), rows...)
				last := make(map[string]any, len(rows[len(rows)-1]))
				for k, v := range rows[len(rows)-1] {
					last[k] = v
				}
				last["IPAddr"] = mock.readbackIPOverride
				rows[len(rows)-1] = last
			}
			routertest.WriteEncrypted(t, w, mock.key, map[string]any{"result": "ZCFG_SUCCESS", "Object": rows})
		case http.MethodPost, http.MethodDelete:
			mock.writeCount++
			if mock.writeHTTPStatus != 0 {
				http.Error(w, "private body content", mock.writeHTTPStatus)
				return
			}
			if r.Header.Get("CSRFToken") != mock.token || r.Header.Get("If-Modified-Since") != "Thu, 01 Jun 1970 00:00:00 GMT" {
				t.Errorf("write headers missing current token")
			}
			if r.Method == http.MethodPost {
				var payload routertest.Payload
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					return
				}
				ciphertext, _ := base64.StdEncoding.DecodeString(payload.Content)
				iv, _ := base64.StdEncoding.DecodeString(payload.IV)
				plain, err := routertest.DecryptCBC(mock.key, iv[:16], ciphertext)
				if err != nil {
					t.Error(err)
					return
				}
				var row map[string]any
				if err := json.Unmarshal(plain, &row); err != nil {
					t.Error(err)
					return
				}
				ip := row["IPAddr"].(string)
				if mock.readbackIPOverride != "" {
					ip = mock.readbackIPOverride
				}
				mock.rows = append(mock.rows, map[string]any{"Index": float64(len(mock.rows) + 1), "MACAddr": row["MACAddr"], "IPAddr": ip, "Enable": row["Enable"]})
			} else {
				mock.lastDeleteIndex = r.URL.Query().Get("Index")
				index, _ := fixtureInteger(parseIndex(mock.lastDeleteIndex))
				for i := range mock.rows {
					if n, ok := fixtureInteger(mock.rows[i]["Index"]); ok && n == index {
						mock.rows = append(mock.rows[:i], mock.rows[i+1:]...)
						break
					}
				}
			}
			mock.token = fmt.Sprintf("mock-token-%d", mock.writeCount+1)
			if mock.malformedWriteResponse {
				_, _ = w.Write([]byte("not-encrypted-json"))
				return
			}
			routertest.WriteEncrypted(t, w, mock.key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": mock.token})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	mux.HandleFunc("/cgi-bin/UserLogout", func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		if !mock.malformedWriteResponse && r.URL.Query().Get("sessionkey") != mock.token {
			t.Errorf("logout did not use rotated session key")
		}
		mock.activeSessions--
	})
	mock.server = httptest.NewServer(mux)
	mock.client, err = zyxel.NewClient(mock.server.URL, zyxel.Credentials{Username: "test-user", Password: "test-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mock.server.Close)
	return mock
}

func parseIndex(value string) float64 {
	var result float64
	_, _ = fmt.Sscan(value, &result)
	return result
}

func dhcpFrameworkSchema(t *testing.T) resourceschema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	NewDHCPReservationResource().Schema(context.Background(), resource.SchemaRequest{}, &response)
	return response.Schema
}

func dhcpPlan(t *testing.T, schema resourceschema.Schema, model dhcpReservationModel) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: schema}
	if diags := plan.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("setting plan: %v", diags)
	}
	return plan
}

func dhcpState(t *testing.T, schema resourceschema.Schema, model dhcpReservationModel) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: schema}
	if diags := state.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("setting state: %v", diags)
	}
	return state
}

func emptyDHCPState(schema resourceschema.Schema) tfsdk.State {
	ctx := context.Background()
	return tfsdk.State{Schema: schema, Raw: tftypes.NewValue(schema.Type().TerraformType(ctx), nil)}
}

func TestDHCPFrameworkImportReadDriftAndMissing(t *testing.T) {
	ctx := context.Background()
	schema := dhcpFrameworkSchema(t)
	r := NewDHCPReservationResource().(*DHCPReservationResource)
	mock := newDHCPMockRouter(t)
	r.client = mock.client
	mac := "AA:BB:CC:DD:EE:FF"
	mock.rows = []map[string]any{{"Index": float64(2), "MACAddr": mac, "IPAddr": "192.0.2.88", "Enable": false}}
	importResp := resource.ImportStateResponse{State: emptyDHCPState(schema)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "aa-bb-cc-dd-ee-ff"}, &importResp)
	if importResp.Diagnostics.HasError() {
		t.Fatalf("import failed: %v", importResp.Diagnostics)
	}
	var imported dhcpReservationModel
	if diags := importResp.State.Get(ctx, &imported); diags.HasError() {
		t.Fatal(diags)
	}
	if imported.MACAddress.ValueString() != mac {
		t.Fatalf("import key = %q", imported.MACAddress.ValueString())
	}
	readResp := resource.ReadResponse{State: importResp.State}
	r.Read(ctx, resource.ReadRequest{State: importResp.State}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("read failed: %v", readResp.Diagnostics)
	}
	var state dhcpReservationModel
	if diags := readResp.State.Get(ctx, &state); diags.HasError() {
		t.Fatal(diags)
	}
	if state.IPv4.ValueString() != "192.0.2.88" || state.Enabled.ValueBool() {
		t.Fatalf("observed drift not reported: %#v", state)
	}
	mock.rows = nil
	missingResp := resource.ReadResponse{State: readResp.State}
	r.Read(ctx, resource.ReadRequest{State: readResp.State}, &missingResp)
	if missingResp.Diagnostics.HasError() || !missingResp.State.Raw.IsNull() {
		t.Fatalf("missing reservation was not removed: %v", missingResp.Diagnostics)
	}
}

func TestDHCPFrameworkCreateReadbackFailurePreservesIdentity(t *testing.T) {
	ctx := context.Background()
	schema := dhcpFrameworkSchema(t)
	r := NewDHCPReservationResource().(*DHCPReservationResource)
	mock := newDHCPMockRouter(t)
	r.client = mock.client
	mock.readbackIPOverride = "192.0.2.99"
	model := dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:11"), IPv4: types.StringValue("192.0.2.11"), Enabled: types.BoolValue(true)}
	response := resource.CreateResponse{State: dhcpState(t, schema, model)}
	r.Create(ctx, resource.CreateRequest{Plan: dhcpPlan(t, schema, model)}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("expected readback mismatch to fail")
	}
	var saved dhcpReservationModel
	if diags := response.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("identity was not retained: %v", diags)
	}
	if saved.MACAddress != model.MACAddress || saved.IPv4 != model.IPv4 {
		t.Fatalf("created identity lost: %#v", saved)
	}
}

func TestDHCPDuplicateCollisionsNeverWrite(t *testing.T) {
	mock := newDHCPMockRouter(t)
	mac := "AA:BB:CC:DD:EE:12"
	mock.rows = []map[string]any{{"Index": float64(1), "MACAddr": mac, "IPAddr": "192.0.2.12", "Enable": true}, {"Index": float64(2), "MACAddr": mac, "IPAddr": "192.0.2.12", "Enable": true}}
	if found, err := mock.client.ReadDHCPReservation(context.Background(), mac); err == nil || found != nil {
		t.Fatalf("duplicate public read = %#v, %v", found, err)
	}
	if found, err := mock.client.ReadDHCPReservation(context.Background(), "AA:BB:CC:DD:EE:99"); err != nil || found != nil {
		t.Fatalf("missing public read = %#v, %v", found, err)
	}
	created, err := mock.client.CreateDHCPReservation(context.Background(), mac, "192.0.2.12", true)
	if err == nil || created || mock.writeCount != 0 {
		t.Fatalf("duplicate create created=%t writes=%d err=%v", created, mock.writeCount, err)
	}
	if err := mock.client.DeleteDHCPReservation(context.Background(), mac); err == nil || mock.writeCount != 0 {
		t.Fatalf("duplicate delete writes=%d err=%v", mock.writeCount, err)
	}
}

func TestDHCPWriteHTTPFailureDoesNotLeakBody(t *testing.T) {
	mock := newDHCPMockRouter(t)
	mock.writeHTTPStatus = http.StatusInternalServerError
	created, err := mock.client.CreateDHCPReservation(context.Background(), "AA:BB:CC:DD:EE:13", "192.0.2.13", true)
	if err == nil || created || strings.Contains(err.Error(), "private body content") || strings.Contains(err.Error(), "test-password") {
		t.Fatalf("unsafe HTTP failure: created=%t err=%v", created, err)
	}
}

func TestDHCPAmbiguousCreateRetainsIdentity(t *testing.T) {
	ctx := context.Background()
	schema := dhcpFrameworkSchema(t)
	r := NewDHCPReservationResource().(*DHCPReservationResource)
	mock := newDHCPMockRouter(t)
	r.client = mock.client
	mock.malformedWriteResponse = true
	model := dhcpReservationModel{MACAddress: types.StringValue("AA:BB:CC:DD:EE:14"), IPv4: types.StringValue("192.0.2.14"), Enabled: types.BoolValue(true)}
	response := resource.CreateResponse{State: dhcpState(t, schema, model)}
	r.Create(ctx, resource.CreateRequest{Plan: dhcpPlan(t, schema, model)}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("expected ambiguous write diagnostic")
	}
	var saved dhcpReservationModel
	if diags := response.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("ambiguous write lost identity: %v", diags)
	}
	if saved.MACAddress != model.MACAddress || mock.writeCount != 1 {
		t.Fatalf("ambiguous create state=%#v writes=%d", saved, mock.writeCount)
	}
}

func TestDHCPReadRejectsMalformedRowsAndCreateRejectsDisabled(t *testing.T) {
	mock := newDHCPMockRouter(t)
	mock.malformedRead = true
	if _, err := mock.client.DHCPReservations(context.Background()); err == nil {
		t.Fatal("malformed list was accepted")
	}
	mock.malformedRead = false
	mock.rows = []map[string]any{{"Index": float64(1), "MACAddr": "AA:BB:CC:DD:EE:15", "IPAddr": "::ffff:192.0.2.15", "Enable": true}}
	if _, err := mock.client.DHCPReservations(context.Background()); err == nil {
		t.Fatal("IPv4-mapped IPv6 router value was accepted")
	}
	reads := mock.readCount
	created, err := mock.client.CreateDHCPReservation(context.Background(), "AA:BB:CC:DD:EE:16", "192.0.2.16", false)
	if err == nil || created || mock.readCount != reads {
		t.Fatalf("disabled create reached router: created=%t reads=%d err=%v", created, mock.readCount-reads, err)
	}
}

func TestDHCPCreateRejectsUnknownPlanBeforeRouterCall(t *testing.T) {
	ctx := context.Background()
	schema := dhcpFrameworkSchema(t)
	r := NewDHCPReservationResource().(*DHCPReservationResource)
	mock := newDHCPMockRouter(t)
	r.client = mock.client
	model := dhcpReservationModel{MACAddress: types.StringUnknown(), IPv4: types.StringValue("192.0.2.17"), Enabled: types.BoolValue(true)}
	response := resource.CreateResponse{State: tfsdk.State{Schema: schema}}
	r.Create(ctx, resource.CreateRequest{Plan: dhcpPlan(t, schema, model)}, &response)
	if !response.Diagnostics.HasError() || mock.readCount != 0 {
		t.Fatalf("unknown plan reached router: diagnostics=%v reads=%d", response.Diagnostics, mock.readCount)
	}
}

func TestDHCPClientSerializesConcurrentSessions(t *testing.T) {
	mock := newDHCPMockRouter(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mock.client.DHCPReservations(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if mock.maxActiveSessions != 1 || mock.activeSessions != 0 {
		t.Fatalf("session overlap max=%d active=%d", mock.maxActiveSessions, mock.activeSessions)
	}
}

func fixtureInteger(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), v == float64(int64(v)) && v >= 1
	case int64:
		return v, v >= 1
	}
	return 0, false
}
