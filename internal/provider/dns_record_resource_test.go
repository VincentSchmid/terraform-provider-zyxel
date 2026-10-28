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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestDNSRecordCreateDeleteUsesCurrentIndexesAndRotatedSession(t *testing.T) {
	rows := []map[string]any{dnsMockRow(1, "printer.home.arpa", "192.0.2.21"), dnsMockRow(2, "nas.home.arpa", "192.0.2.22")}
	client, state, closeServer := newDNSMockClient(t, rows)
	defer closeServer()
	created, err := client.CreateDNSEntry(context.Background(), "media.home.arpa", "192.0.2.23")
	if err != nil || !created {
		t.Fatalf("CreateDNSEntry() = %v, %v", created, err)
	}
	if state.writes != 1 {
		t.Fatalf("expected one POST, got %d", state.writes)
	}
	if state.lastBody["HostName"] != "media.home.arpa" || state.lastBody["IPv4Address"] != "192.0.2.23" || len(state.lastBody) != 2 {
		t.Fatalf("unexpected POST body: %#v", state.lastBody)
	}
	found, err := client.ReadDNSEntry(context.Background(), "media.home.arpa")
	if err != nil || found == nil || found.Index != 3 || found.IPv4Address != "192.0.2.23" {
		t.Fatalf("readback entry = %#v, %v", found, err)
	}
	// An unrelated deletion can shift the target index. Delete resolves by host
	// name twice and uses the current returned index, not the saved router_index.
	state.rows = []map[string]any{state.rows[2]}
	state.rows[0]["Index"] = int64(1)
	if err := client.DeleteDNSEntry(context.Background(), "media.home.arpa"); err != nil {
		t.Fatal(err)
	}
	if state.deletedIndex != 1 {
		t.Fatalf("delete used index %d, want current index 1", state.deletedIndex)
	}
	if state.sessionKey != "rotated-2" || !state.logoutHadCurrentKey {
		t.Fatalf("write session rotation/logout not honored: %#v", state)
	}
}

func TestDNSRecordCreateRejectsDuplicateHostnameBeforeWrite(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, []map[string]any{dnsMockRow(1, "NAS.Home.ARPA", "192.0.2.20")})
	defer closeServer()
	created, err := client.CreateDNSEntry(context.Background(), "nas.home.arpa", "192.0.2.99")
	if err == nil || created {
		t.Fatalf("expected a case-insensitive duplicate to be rejected, got created=%t err=%v", created, err)
	}
	if state.writes != 0 {
		t.Fatalf("duplicate create sent %d writes", state.writes)
	}
	// Several host names may resolve to the same address; only the name is unique.
	created, err = client.CreateDNSEntry(context.Background(), "alias.home.arpa", "192.0.2.20")
	if err != nil || !created || state.writes != 1 {
		t.Fatalf("shared-address create = %t, %v (writes %d)", created, err, state.writes)
	}
}

func TestDNSRecordDeleteRejectsAmbiguousHostnameAndMissingIsIdempotent(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, []map[string]any{
		dnsMockRow(1, "duplicate.home.arpa", "192.0.2.20"),
		dnsMockRow(2, "duplicate.home.arpa", "192.0.2.21"),
	})
	if err := client.DeleteDNSEntry(context.Background(), "duplicate.home.arpa"); err == nil {
		t.Fatal("expected duplicate host name delete to fail")
	}
	if state.writes != 0 {
		t.Fatalf("ambiguous delete sent %d writes", state.writes)
	}
	closeServer()

	client, state, closeServer = newDNSMockClient(t, nil)
	defer closeServer()
	if err := client.DeleteDNSEntry(context.Background(), "already-missing.home.arpa"); err != nil {
		t.Fatalf("deleting missing DNS record failed: %v", err)
	}
	if state.writes != 0 {
		t.Fatalf("deleting missing DNS record sent %d writes", state.writes)
	}
}

func TestDNSRecordCreateRejectsInvalidInputBeforeOpeningSession(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	for _, test := range [][2]string{
		{" nas.home.arpa", "192.0.2.1"},
		{"NAS.home.arpa", "192.0.2.1"},
		{"localhost", "192.0.2.1"},
		{"nas..home", "192.0.2.1"},
		{"nas.home.arpa", ""},
		{"nas.home.arpa", "192.0.2.300"},
		{"nas.home.arpa", "::ffff:192.0.2.1"},
		{"nas.home.arpa", "2001:db8::1"},
	} {
		if _, err := client.CreateDNSEntry(context.Background(), test[0], test[1]); err == nil {
			t.Fatalf("invalid input %q/%q was accepted", test[0], test[1])
		}
	}
	if state.logins != 0 || state.writes != 0 {
		t.Fatalf("invalid input opened %d sessions and sent %d writes", state.logins, state.writes)
	}
}

func TestDNSRecordCreateAmbiguousWritePreservesCreatedIdentity(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	state.badWriteResponse = true
	created, err := client.CreateDNSEntry(context.Background(), "recoverable.home.arpa", "192.0.2.80")
	if err == nil || !created {
		t.Fatalf("expected ambiguous applied create, got created=%v err=%v", created, err)
	}
	if state.writes != 1 || len(state.rows) != 1 || state.rows[0]["HostName"] != "recoverable.home.arpa" {
		t.Fatalf("ambiguous POST did not leave recoverable entry: writes=%d rows=%#v", state.writes, state.rows)
	}
}

func TestDNSRecordCreateFailsWhenReadbackDiffers(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	state.storedIPv4Override = "192.0.2.99"
	created, err := client.CreateDNSEntry(context.Background(), "unconfirmed.home.arpa", "192.0.2.80")
	if err == nil || !created {
		t.Fatalf("unconfirmed readback = created %t, err %v", created, err)
	}
	if state.writes != 1 {
		t.Fatalf("expected one applied POST, got %d", state.writes)
	}
}

func TestDNSRecordCreateRejectsRejectedWrite(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	state.rejectWrite = true
	created, err := client.CreateDNSEntry(context.Background(), "denied.home.arpa", "192.0.2.80")
	if err == nil || created {
		t.Fatalf("rejected write = created %t, err %v", created, err)
	}
	if len(state.rows) != 0 {
		t.Fatalf("rejected write changed rows: %#v", state.rows)
	}
}

func TestDNSRecordPublicReadRejectsDuplicatesAndReportsMissing(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, []map[string]any{
		dnsMockRow(1, "duplicate.home.arpa", "192.0.2.20"),
		dnsMockRow(2, "duplicate.home.arpa", "192.0.2.21"),
	})
	defer closeServer()
	if found, err := client.ReadDNSEntry(context.Background(), "duplicate.home.arpa"); err == nil || found != nil {
		t.Fatalf("duplicate read = %#v, %v", found, err)
	}
	if found, err := client.ReadDNSEntry(context.Background(), "missing.home.arpa"); err != nil || found != nil {
		t.Fatalf("missing read = %#v, %v", found, err)
	}
	if state.writes != 0 {
		t.Fatal("reads must not mutate the router")
	}
}

func TestDNSRecordListRejectsMalformedRows(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	state.malformedRead = true
	if _, err := client.DNSEntries(context.Background()); err == nil {
		t.Fatal("malformed list was accepted")
	}
	state.malformedRead = false
	for _, row := range []map[string]any{
		dnsMockRow(1, "single-label", "192.0.2.20"),
		dnsMockRow(1, "nas.home.arpa", "2001:db8::20"),
		dnsMockRow(1, "nas.home.arpa", "::ffff:192.0.2.20"),
		{"Index": 0, "HostName": "nas.home.arpa", "IPv4Address": "192.0.2.20"},
		{"HostName": "nas.home.arpa", "IPv4Address": "192.0.2.20"},
	} {
		state.rows = []map[string]any{row}
		if _, err := client.DNSEntries(context.Background()); err == nil {
			t.Fatalf("router row was accepted: %#v", row)
		}
	}
}

func TestDNSRecordResourceCreateKeepsKnownStateAfterAmbiguousPOST(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	state.badWriteResponse = true
	r := &DNSRecordResource{client: client}
	ctx := context.Background()
	schema := dnsFrameworkSchema(t)
	planned := dnsRecordModel{Hostname: types.StringValue("recoverable.home.arpa"), IPv4Address: types.StringValue("192.0.2.80"), RouterIndex: types.Int64Unknown()}
	plan := dnsPlan(t, schema, planned)
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schema, Raw: plan.Raw}}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected ambiguous write diagnostic")
	}
	var saved dnsRecordModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("recoverable state is invalid: %s", diags)
	}
	if saved.Hostname.ValueString() != planned.Hostname.ValueString() || saved.IPv4Address.ValueString() != planned.IPv4Address.ValueString() || !saved.RouterIndex.IsNull() {
		t.Fatalf("ambiguous POST did not retain known recoverable state: %#v", saved)
	}
}

func TestDNSRecordCreateRejectsUnknownPlanBeforeRouterCall(t *testing.T) {
	client, state, closeServer := newDNSMockClient(t, nil)
	defer closeServer()
	r := &DNSRecordResource{client: client}
	schema := dnsFrameworkSchema(t)
	model := dnsRecordModel{Hostname: types.StringUnknown(), IPv4Address: types.StringValue("192.0.2.10"), RouterIndex: types.Int64Null()}
	resp := resource.CreateResponse{State: emptyDNSState(schema)}
	r.Create(context.Background(), resource.CreateRequest{Plan: dnsPlan(t, schema, model)}, &resp)
	if !resp.Diagnostics.HasError() || state.logins != 0 {
		t.Fatalf("unknown plan reached router: diagnostics=%v logins=%d", resp.Diagnostics, state.logins)
	}
}

func TestDNSRecordSchemaReplacementAndValidators(t *testing.T) {
	schema := dnsFrameworkSchema(t)
	if diagnostics := schema.Validate(); diagnostics.HasError() {
		t.Fatalf("invalid resource schema: %v", diagnostics)
	}
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"nas.home.arpa", true}, {"NAS.home.arpa", false}, {"localhost", false}, {"nas..home", false},
		{"-nas.home", false}, {"nas.home arpa", false},
	} {
		response := validator.StringResponse{}
		dnsHostnameValidator{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("hostname"), ConfigValue: types.StringValue(test.value)}, &response)
		if response.Diagnostics.HasError() == test.valid {
			t.Errorf("host name validator for %q diagnostics error=%t", test.value, response.Diagnostics.HasError())
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
	for _, test := range []struct {
		name      string
		plan      dnsRecordModel
		state     dnsRecordModel
		planValue types.String
		stateVal  types.String
	}{
		{
			name:      "hostname",
			plan:      dnsRecordModel{Hostname: types.StringValue("nas.home.arpa"), IPv4Address: types.StringValue("192.0.2.10")},
			state:     dnsRecordModel{Hostname: types.StringValue("old.home.arpa"), IPv4Address: types.StringValue("192.0.2.10")},
			planValue: types.StringValue("nas.home.arpa"), stateVal: types.StringValue("old.home.arpa"),
		},
		{
			name:      "ipv4_address",
			plan:      dnsRecordModel{Hostname: types.StringValue("nas.home.arpa"), IPv4Address: types.StringValue("192.0.2.11")},
			state:     dnsRecordModel{Hostname: types.StringValue("nas.home.arpa"), IPv4Address: types.StringValue("192.0.2.10")},
			planValue: types.StringValue("192.0.2.11"), stateVal: types.StringValue("192.0.2.10"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			modifiers := schema.Attributes[test.name].(resourceschema.StringAttribute).PlanModifiers
			if len(modifiers) == 0 {
				t.Fatal("schema has no replacement plan modifier")
			}
			response := planmodifier.StringResponse{PlanValue: test.planValue}
			modifiers[0].PlanModifyString(context.Background(), planmodifier.StringRequest{Plan: dnsPlan(t, schema, test.plan), PlanValue: test.planValue, State: dnsState(t, schema, test.state), StateValue: test.stateVal}, &response)
			if !response.RequiresReplace {
				t.Fatal("configured schema modifier did not require replacement")
			}
		})
	}
}

func TestDNSRecordFrameworkImportReadDriftAndMissing(t *testing.T) {
	ctx := context.Background()
	schema := dnsFrameworkSchema(t)
	r := NewDNSRecordResource().(*DNSRecordResource)
	client, state, closeServer := newDNSMockClient(t, []map[string]any{dnsMockRow(2, "NAS.Home.ARPA", "192.0.2.88")})
	defer closeServer()
	r.client = client

	importResp := resource.ImportStateResponse{State: emptyDNSState(schema)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "NAS.Home.ARPA"}, &importResp)
	if importResp.Diagnostics.HasError() {
		t.Fatalf("import failed: %v", importResp.Diagnostics)
	}
	var imported dnsRecordModel
	if diags := importResp.State.Get(ctx, &imported); diags.HasError() {
		t.Fatal(diags)
	}
	if imported.Hostname.ValueString() != "nas.home.arpa" {
		t.Fatalf("import key = %q", imported.Hostname.ValueString())
	}
	readResp := resource.ReadResponse{State: importResp.State}
	r.Read(ctx, resource.ReadRequest{State: importResp.State}, &readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("read failed: %v", readResp.Diagnostics)
	}
	var observed dnsRecordModel
	if diags := readResp.State.Get(ctx, &observed); diags.HasError() {
		t.Fatal(diags)
	}
	if observed.Hostname.ValueString() != "nas.home.arpa" || observed.IPv4Address.ValueString() != "192.0.2.88" || observed.RouterIndex.ValueInt64() != 2 {
		t.Fatalf("observed entry not reported: %#v", observed)
	}
	state.rows = nil
	missingResp := resource.ReadResponse{State: readResp.State}
	r.Read(ctx, resource.ReadRequest{State: readResp.State}, &missingResp)
	if missingResp.Diagnostics.HasError() || !missingResp.State.Raw.IsNull() {
		t.Fatalf("missing record was not removed: %v", missingResp.Diagnostics)
	}

	invalidImport := resource.ImportStateResponse{State: emptyDNSState(schema)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "localhost"}, &invalidImport)
	if !invalidImport.Diagnostics.HasError() {
		t.Fatal("invalid import ID was accepted")
	}
}

func TestDNSRecordDeleteUsesStateIdentity(t *testing.T) {
	ctx := context.Background()
	schema := dnsFrameworkSchema(t)
	r := NewDNSRecordResource().(*DNSRecordResource)
	client, state, closeServer := newDNSMockClient(t, []map[string]any{dnsMockRow(1, "nas.home.arpa", "192.0.2.20"), dnsMockRow(2, "media.home.arpa", "192.0.2.21")})
	defer closeServer()
	r.client = client
	resp := resource.DeleteResponse{State: dnsState(t, schema, dnsRecordModel{Hostname: types.StringValue("media.home.arpa"), IPv4Address: types.StringValue("192.0.2.21"), RouterIndex: types.Int64Value(1)})}
	r.Delete(ctx, resource.DeleteRequest{State: dnsState(t, schema, dnsRecordModel{Hostname: types.StringValue("media.home.arpa"), IPv4Address: types.StringValue("192.0.2.21"), RouterIndex: types.Int64Value(1)})}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete failed: %v", resp.Diagnostics)
	}
	if state.deletedIndex != 2 || len(state.rows) != 1 || state.rows[0]["HostName"] != "nas.home.arpa" {
		t.Fatalf("delete used stale index or removed the wrong row: index=%d rows=%#v", state.deletedIndex, state.rows)
	}
}

func TestDNSRecordUpdateRequiresReplacement(t *testing.T) {
	schema := dnsFrameworkSchema(t)
	resp := resource.UpdateResponse{}
	NewDNSRecordResource().(*DNSRecordResource).Update(context.Background(), resource.UpdateRequest{Plan: dnsPlan(t, schema, dnsRecordModel{Hostname: types.StringValue("nas.home.arpa"), IPv4Address: types.StringValue("192.0.2.21")})}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("in-place update was accepted")
	}
}

type dnsMockState struct {
	endpoint            string
	rows                []map[string]any
	key                 []byte
	sessionKey          string
	writes              int
	logins              int
	lastBody            map[string]any
	deletedIndex        int
	logoutHadCurrentKey bool
	badWriteResponse    bool
	malformedRead       bool
	rejectWrite         bool
	storedIPv4Override  string
}

func newDNSMockClient(t *testing.T, rows []map[string]any) (*zyxel.Client, *dnsMockState, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	state := &dnsMockState{rows: rows}
	mux := http.NewServeMux()
	mux.HandleFunc("/GetInfoNoLogin", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "router", Value: "session", Path: "/"})
	})
	mux.HandleFunc("/getRSAPublickKey", func(w http.ResponseWriter, _ *http.Request) {
		der, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]string{"RSAPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	})
	mux.HandleFunc("/UserLogin", func(w http.ResponseWriter, r *http.Request) {
		state.logins++
		var payload routertest.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		encryptedKey, _ := base64.StdEncoding.DecodeString(payload.Key)
		key, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedKey)
		if err != nil {
			t.Error(err)
			return
		}
		state.key, err = base64.StdEncoding.DecodeString(string(key))
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := dnsWriteBody(state.key, payload); err != nil {
			t.Error(err)
			return
		}
		state.sessionKey = "session-1"
		writeDNSEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": state.sessionKey})
	})
	mux.HandleFunc("/cgi-bin/DAL", func(w http.ResponseWriter, r *http.Request) {
		if oid := r.URL.Query().Get("oid"); oid != "dns" {
			t.Errorf("unexpected oid %q", oid)
		}
		if r.URL.Query().Get("sessionkey") != state.sessionKey {
			t.Errorf("request used stale session key")
		}
		if r.Method == http.MethodGet {
			if state.malformedRead {
				writeDNSEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "Object": "malformed"})
				return
			}
			cloned := make([]any, len(state.rows))
			for i, row := range state.rows {
				cloned[i] = row
			}
			writeDNSEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "Object": cloned})
			return
		}
		if r.Header.Get("CSRFToken") != state.sessionKey || r.Header.Get("If-Modified-Since") != "Thu, 01 Jun 1970 00:00:00 GMT" {
			t.Errorf("write headers missing current token")
		}
		var payload routertest.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		body, err := dnsWriteBody(state.key, payload)
		if err != nil {
			t.Error(err)
			return
		}
		state.lastBody = body
		if state.rejectWrite {
			writeDNSEncrypted(t, w, state.key, map[string]any{"result": "DENIED"})
			return
		}
		state.writes++
		if r.Method == http.MethodPost {
			ipv4 := state.lastBody["IPv4Address"].(string)
			if state.storedIPv4Override != "" {
				ipv4 = state.storedIPv4Override
			}
			state.rows = append(state.rows, dnsMockRow(int64(len(state.rows)+1), state.lastBody["HostName"].(string), ipv4))
		} else {
			index, _ := strconv.Atoi(r.URL.Query().Get("Index"))
			state.deletedIndex = index
			for i, row := range state.rows {
				if int(row["Index"].(int64)) == index {
					state.rows = append(state.rows[:i], state.rows[i+1:]...)
					break
				}
			}
		}
		state.sessionKey = fmt.Sprintf("rotated-%d", state.writes)
		if state.badWriteResponse {
			_, _ = w.Write([]byte("malformed encrypted write response"))
			return
		}
		writeDNSEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": state.sessionKey})
	})
	mux.HandleFunc("/cgi-bin/UserLogout", func(w http.ResponseWriter, r *http.Request) {
		state.logoutHadCurrentKey = r.URL.Query().Get("sessionkey") == state.sessionKey
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	state.endpoint = server.URL
	client, err := zyxel.NewClient(server.URL, zyxel.Credentials{Username: "mock", Password: "mock"}, 2*time.Second)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, state, server.Close
}

func dnsWriteBody(key []byte, payload routertest.Payload) (map[string]any, error) {
	iv, ivErr := base64.StdEncoding.DecodeString(payload.IV)
	ciphertext, contentErr := base64.StdEncoding.DecodeString(payload.Content)
	if ivErr != nil || contentErr != nil || len(iv) < 16 {
		return nil, fmt.Errorf("malformed payload envelope")
	}
	plain, err := routertest.DecryptCBC(key, iv[:16], ciphertext)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	err = json.Unmarshal(plain, &body)
	return body, err
}

func dnsMockRow(index int64, hostname, ipv4 string) map[string]any {
	return map[string]any{"Index": index, "HostName": hostname, "IPv4Address": ipv4}
}

func writeDNSEncrypted(t *testing.T, w http.ResponseWriter, key []byte, value any) {
	t.Helper()
	plain, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := routertest.EncryptCBC(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(routertest.Payload{IV: base64.StdEncoding.EncodeToString(iv), Content: base64.StdEncoding.EncodeToString(ciphertext)})
}

func dnsFrameworkSchema(t *testing.T) resourceschema.Schema {
	t.Helper()
	var response resource.SchemaResponse
	NewDNSRecordResource().Schema(context.Background(), resource.SchemaRequest{}, &response)
	return response.Schema
}

func dnsPlan(t *testing.T, schema resourceschema.Schema, model dnsRecordModel) tfsdk.Plan {
	t.Helper()
	plan := tfsdk.Plan{Schema: schema}
	if diags := plan.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("setting plan: %v", diags)
	}
	return plan
}

func dnsState(t *testing.T, schema resourceschema.Schema, model dnsRecordModel) tfsdk.State {
	t.Helper()
	state := tfsdk.State{Schema: schema}
	if diags := state.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("setting state: %v", diags)
	}
	return state
}

func emptyDNSState(schema resourceschema.Schema) tfsdk.State {
	ctx := context.Background()
	return tfsdk.State{Schema: schema, Raw: tftypes.NewValue(schema.Type().TerraformType(ctx), nil)}
}
