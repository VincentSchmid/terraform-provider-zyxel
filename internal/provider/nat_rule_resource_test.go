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

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestNATRuleCreateDeleteUsesCurrentIndexesAndRotatedSession(t *testing.T) {
	rows := []map[string]any{natRow(3, "older", "UDP", 4000, 4000, "192.0.2.30", 4000, 4000, true), natRow(8, "later", "TCP", 5000, 5000, "192.0.2.40", 5000, 5000, true)}
	client, state, closeServer := newNATMockClient(t, rows)
	defer closeServer()
	rule := NATRule{Name: "web", Protocol: "both", ExternalPortStart: 8080, ExternalPortEnd: 8081, InternalClient: "192.0.2.80", InternalPortStart: 80, InternalPortEnd: 81}
	created, err := client.CreateNATRule(context.Background(), rule)
	if err != nil || !created {
		t.Fatalf("CreateNATRule() = %v, %v", created, err)
	}
	if got := state.writes; got != 1 {
		t.Fatalf("expected one POST, got %d", got)
	}
	if state.lastBody["Protocol"] != "TCP+UDP" || state.lastBody["Description"] != "web" {
		t.Fatalf("unexpected POST body: %#v", state.lastBody)
	}
	got, err := client.NATRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found, err := findNATRule(got, "web")
	if err != nil || found == nil || found.Protocol != "both" || found.Index != 3 {
		t.Fatalf("readback rule = %#v, %v", found, err)
	}
	// An unrelated deletion can shift the target index. Delete resolves by name
	// twice and uses the current returned index, not the saved router_index.
	state.rows = []map[string]any{state.rows[2]}
	state.rows[0]["Index"] = int64(1)
	if err := client.DeleteNATRule(context.Background(), "web"); err != nil {
		t.Fatal(err)
	}
	if state.deletedIndex != 1 {
		t.Fatalf("delete used index %d, want current index 1", state.deletedIndex)
	}
	if state.sessionKey != "rotated-2" || !state.logoutHadCurrentKey {
		t.Fatalf("write session rotation/logout not honored: %#v", state)
	}
}

func TestNATRuleCreateRejectsDuplicateAndOverlappingRulesBeforeWrite(t *testing.T) {
	rows := []map[string]any{natRow(1, "existing", "TCP+UDP", 80, 90, "192.0.2.1", 8080, 8090, true)}
	client, state, closeServer := newNATMockClient(t, rows)
	defer closeServer()
	_, err := client.CreateNATRule(context.Background(), NATRule{Name: "new", Protocol: "tcp", ExternalPortStart: 90, ExternalPortEnd: 90, InternalClient: "192.0.2.2", InternalPortStart: 90, InternalPortEnd: 90})
	if err == nil {
		t.Fatal("expected overlapping TCP rule to be rejected")
	}
	if state.writes != 0 {
		t.Fatalf("conflicting create sent %d writes", state.writes)
	}
	_, err = client.CreateNATRule(context.Background(), NATRule{Name: "existing", Protocol: "udp", ExternalPortStart: 100, ExternalPortEnd: 100, InternalClient: "192.0.2.2", InternalPortStart: 100, InternalPortEnd: 100})
	if err == nil {
		t.Fatal("expected duplicate name to be rejected")
	}
	if state.writes != 0 {
		t.Fatalf("duplicate create sent %d writes", state.writes)
	}
}

func TestNATRuleDeleteRejectsAmbiguousNameAndMissingIsIdempotent(t *testing.T) {
	duplicateRows := []map[string]any{
		natRow(1, "duplicate", "TCP", 80, 80, "192.0.2.1", 80, 80, true),
		natRow(2, "duplicate", "UDP", 81, 81, "192.0.2.2", 81, 81, true),
	}
	client, state, closeServer := newNATMockClient(t, duplicateRows)
	if err := client.DeleteNATRule(context.Background(), "duplicate"); err == nil {
		t.Fatal("expected duplicate name delete to fail")
	}
	if state.writes != 0 {
		t.Fatalf("ambiguous delete sent %d writes", state.writes)
	}
	closeServer()

	client, state, closeServer = newNATMockClient(t, nil)
	defer closeServer()
	if err := client.DeleteNATRule(context.Background(), "already-missing"); err != nil {
		t.Fatalf("deleting missing NAT rule failed: %v", err)
	}
	if state.writes != 0 {
		t.Fatalf("deleting missing NAT rule sent %d writes", state.writes)
	}
}

func TestNATRuleCreateRejectsInvalidResolvedInputBeforeOpeningSession(t *testing.T) {
	client, state, closeServer := newNATMockClient(t, nil)
	defer closeServer()
	valid := NATRule{Name: "rule", Protocol: "tcp", ExternalPortStart: 80, ExternalPortEnd: 80, InternalClient: "192.0.2.1", InternalPortStart: 8080, InternalPortEnd: 8080}
	invalid := []NATRule{
		{Name: " ", Protocol: "tcp", ExternalPortStart: 80, ExternalPortEnd: 80, InternalClient: "192.0.2.1", InternalPortStart: 80, InternalPortEnd: 80},
		{Name: "rule", Protocol: "TCP", ExternalPortStart: 80, ExternalPortEnd: 80, InternalClient: "192.0.2.1", InternalPortStart: 80, InternalPortEnd: 80},
		{Name: "rule", Protocol: "tcp", ExternalPortStart: 0, ExternalPortEnd: 0, InternalClient: "192.0.2.1", InternalPortStart: 1, InternalPortEnd: 1},
		{Name: "rule", Protocol: "tcp", ExternalPortStart: 80, ExternalPortEnd: 81, InternalClient: "192.0.2.1", InternalPortStart: 80, InternalPortEnd: 82},
		{Name: "rule", Protocol: "tcp", ExternalPortStart: 80, ExternalPortEnd: 80, InternalClient: "::ffff:192.0.2.1", InternalPortStart: 80, InternalPortEnd: 80},
	}
	for i, rule := range invalid {
		if i == 0 {
			rule = valid
			rule.Name = " rule "
		}
		if _, err := client.CreateNATRule(context.Background(), rule); err == nil {
			t.Fatalf("invalid input %d was accepted", i)
		}
	}
	if state.logins != 0 || state.writes != 0 {
		t.Fatalf("invalid input opened %d sessions and sent %d writes", state.logins, state.writes)
	}
}

func TestNATRuleCreateAmbiguousWritePreservesCreatedIdentity(t *testing.T) {
	client, state, closeServer := newNATMockClient(t, nil)
	defer closeServer()
	state.badWriteResponse = true
	rule := NATRule{Name: "recovery-rule", Protocol: "tcp", ExternalPortStart: 8080, ExternalPortEnd: 8080, InternalClient: "192.0.2.80", InternalPortStart: 80, InternalPortEnd: 80}
	created, err := client.CreateNATRule(context.Background(), rule)
	if err == nil || !created {
		t.Fatalf("expected ambiguous applied create, got created=%v err=%v", created, err)
	}
	if state.writes != 1 || len(state.rows) != 1 || state.rows[0]["Description"] != rule.Name {
		t.Fatalf("ambiguous POST did not leave recoverable rule: writes=%d rows=%#v", state.writes, state.rows)
	}
}

func TestNATResourceCreateKeepsKnownStateAfterAmbiguousPOST(t *testing.T) {
	client, state, closeServer := newNATMockClient(t, nil)
	defer closeServer()
	state.badWriteResponse = true
	r := &NATRuleResource{client: client}
	ctx := context.Background()
	var schemaResponse resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatal(schemaResponse.Diagnostics)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	planned := natRuleModel{
		Name: types.StringValue("recoverable"), Protocol: types.StringValue("tcp"),
		ExternalPortStart: types.Int64Value(8080), ExternalPortEnd: types.Int64Value(8080),
		InternalClient: types.StringValue("192.0.2.80"), InternalPortStart: types.Int64Value(80),
		InternalPortEnd: types.Int64Value(80), Enabled: types.BoolUnknown(), RouterIndex: types.Int64Unknown(),
	}
	if diags := plan.Set(ctx, &planned); diags.HasError() {
		t.Fatal(diags)
	}
	req := resource.CreateRequest{Plan: plan}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: schemaResponse.Schema, Raw: plan.Raw}}
	r.Create(ctx, req, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected ambiguous write diagnostic")
	}
	var saved natRuleModel
	if diags := resp.State.Get(ctx, &saved); diags.HasError() {
		t.Fatalf("recoverable state is invalid: %s", diags)
	}
	if saved.Name.ValueString() != planned.Name.ValueString() || saved.Enabled.IsUnknown() || !saved.Enabled.ValueBool() || !saved.RouterIndex.IsNull() {
		t.Fatalf("ambiguous POST did not retain known recoverable state: %#v", saved)
	}
}

func TestNATRuleParseFailsClosedForMalformedOrUnsupportedRows(t *testing.T) {
	base := natRow(1, "bad", "TCP", 80, 81, "192.0.2.1", 80, 81, true)
	for _, mutate := range []func(map[string]any){
		func(row map[string]any) { row["Protocol"] = "ICMP" },
		func(row map[string]any) { row["ExternalPortStart"] = 0 },
		func(row map[string]any) { row["Index"] = 1.5 },
		func(row map[string]any) { row["Index"] = float64(9007199254740992) },
		func(row map[string]any) { row["InternalClient"] = "::ffff:192.0.2.1" },
		func(row map[string]any) { row["InternalPortEnd"] = 83 },
	} {
		row := make(map[string]any, len(base))
		for key, value := range base {
			row[key] = value
		}
		mutate(row)
		if _, err := parseNATRule(row); err == nil {
			t.Fatalf("expected row rejection: %#v", row)
		}
	}
	row := natRow(1, "valid", "TCP+UDP", 80, 81, "192.0.2.1", 8080, 8081, false)
	row["FirmwareMetadata"] = "ignored"
	parsed, err := parseNATRule(row)
	if err != nil || parsed.Protocol != "both" || parsed.Enabled {
		t.Fatalf("metadata/protocol parse = %#v, %v", parsed, err)
	}
	allRow := natRow(1, "all-protocols", "ALL", 6690, 6690, "192.0.2.1", 6690, 6690, true)
	allParsed, err := parseNATRule(allRow)
	if err != nil || allParsed.Protocol != "all" {
		t.Fatalf("ALL protocol parse = %#v, %v", allParsed, err)
	}
}

func TestNATRuleAllProtocolRoundTripsAndBlocksEveryPort(t *testing.T) {
	rows := []map[string]any{natRow(1, "all-protocols", "ALL", 6690, 6690, "192.0.2.1", 6690, 6690, true)}
	client, state, closeServer := newNATMockClient(t, rows)
	defer closeServer()
	if _, err := client.CreateNATRule(context.Background(), NATRule{Name: "tcp-clash", Protocol: "tcp", ExternalPortStart: 6690, ExternalPortEnd: 6690, InternalClient: "192.0.2.2", InternalPortStart: 6690, InternalPortEnd: 6690}); err == nil {
		t.Fatal("expected an all-protocol rule to block any overlapping protocol")
	}
	if state.writes != 0 {
		t.Fatalf("conflicting create sent %d writes", state.writes)
	}
	created, err := client.CreateNATRule(context.Background(), NATRule{Name: "webdav", Protocol: "all", ExternalPortStart: 5006, ExternalPortEnd: 5006, InternalClient: "192.0.2.3", InternalPortStart: 5006, InternalPortEnd: 5006})
	if err != nil || !created {
		t.Fatalf("CreateNATRule() = %v, %v", created, err)
	}
	if state.lastBody["Protocol"] != "ALL" {
		t.Fatalf("unexpected POST body: %#v", state.lastBody)
	}
	got, err := client.NATRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found, err := findNATRule(got, "webdav")
	if err != nil || found == nil || found.Protocol != "all" {
		t.Fatalf("readback rule = %#v, %v", found, err)
	}
}

type natMockState struct {
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
}

func newNATMockClient(t *testing.T, rows []map[string]any) (*Client, *natMockState, func()) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	state := &natMockState{rows: rows}
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
		var payload encryptedPayload
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
		iv, _ := base64.StdEncoding.DecodeString(payload.IV)
		ciphertext, _ := base64.StdEncoding.DecodeString(payload.Content)
		plain, err := decryptCBC(state.key, iv[:16], ciphertext)
		if err != nil {
			t.Error(err)
			return
		}
		var login map[string]any
		if err := json.Unmarshal(plain, &login); err != nil {
			t.Error(err)
			return
		}
		state.sessionKey = "session-1"
		writeNATEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": state.sessionKey})
	})
	mux.HandleFunc("/cgi-bin/DAL", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sessionkey") != state.sessionKey {
			t.Errorf("request used stale session key")
		}
		if r.Method == http.MethodGet {
			cloned := make([]any, len(state.rows))
			for i, row := range state.rows {
				cloned[i] = row
			}
			writeNATEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "Object": cloned})
			return
		}
		if r.Header.Get("CSRFToken") != state.sessionKey {
			t.Errorf("write omitted current CSRF token")
		}
		var payload encryptedPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		iv, _ := base64.StdEncoding.DecodeString(payload.IV)
		ciphertext, _ := base64.StdEncoding.DecodeString(payload.Content)
		plain, err := decryptCBC(state.key, iv[:16], ciphertext)
		if err != nil {
			t.Error(err)
			return
		}
		if err := json.Unmarshal(plain, &state.lastBody); err != nil {
			t.Error(err)
			return
		}
		state.writes++
		if r.Method == http.MethodPost {
			state.rows = append(state.rows, natRow(int64(len(state.rows)+1), state.lastBody["Description"].(string), state.lastBody["Protocol"].(string), int64(state.lastBody["ExternalPortStart"].(float64)), int64(state.lastBody["ExternalPortEnd"].(float64)), state.lastBody["InternalClient"].(string), int64(state.lastBody["InternalPortStart"].(float64)), int64(state.lastBody["InternalPortEnd"].(float64)), true))
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
		writeNATEncrypted(t, w, state.key, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": state.sessionKey})
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
	client, err := NewClient(server.URL, Credentials{Username: "mock", Password: "mock"}, 2*time.Second)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, state, server.Close
}

func natRow(index int64, name, protocol string, externalStart, externalEnd int64, internal string, internalStart, internalEnd int64, enabled bool) map[string]any {
	return map[string]any{"Index": index, "Enable": enabled, "Description": name, "Protocol": protocol, "ExternalPortStart": externalStart, "ExternalPortEnd": externalEnd, "InternalClient": internal, "InternalPortStart": internalStart, "InternalPortEnd": internalEnd}
}

func writeNATEncrypted(t *testing.T, w http.ResponseWriter, key []byte, value any) {
	t.Helper()
	plain, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptCBC(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(encryptedPayload{IV: base64.StdEncoding.EncodeToString(iv), Content: base64.StdEncoding.EncodeToString(ciphertext)})
}
