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
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestReadStatusUsesHybridLoginAndLogsOut(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var sessionKey string
	var loggedOut bool
	var aesKey []byte
	dalResult := "ZCFG_SUCCESS"
	mux := http.NewServeMux()
	mux.HandleFunc("/GetInfoNoLogin", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "router", Value: "session", Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/getRSAPublickKey", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("router"); err != nil || cookie.Value != "session" {
			t.Errorf("session cookie missing on key request")
		}
		publicDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]string{"RSAPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))})
	})
	mux.HandleFunc("/UserLogin", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("router"); err != nil || cookie.Value != "session" {
			t.Errorf("session cookie missing on login")
		}
		var payload encryptedPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		encryptedKey, err := base64.StdEncoding.DecodeString(payload.Key)
		if err != nil {
			t.Fatal(err)
		}
		key, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedKey)
		if err != nil {
			t.Fatal(err)
		}
		aesKey, err = base64.StdEncoding.DecodeString(string(key))
		if err != nil {
			t.Fatal(err)
		}
		iv, _ := base64.StdEncoding.DecodeString(payload.IV)
		content, _ := base64.StdEncoding.DecodeString(payload.Content)
		plain, err := decryptCBC(aesKey, iv[:16], content)
		if err != nil {
			t.Fatal(err)
		}
		var login map[string]any
		if err := json.Unmarshal(plain, &login); err != nil {
			t.Fatal(err)
		}
		if login["Input_Account"] != "router-user" || login["Input_Passwd"] != base64.StdEncoding.EncodeToString([]byte("secret")) {
			t.Errorf("unexpected login payload")
		}
		sessionKey = "session-123"
		writeEncrypted(t, w, aesKey, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": sessionKey})
	})
	mux.HandleFunc("/cgi-bin/DAL", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("oid") != "status" || r.URL.Query().Get("sessionkey") != sessionKey {
			t.Errorf("unexpected DAL request")
		}
		if cookie, err := r.Cookie("router"); err != nil || cookie.Value != "session" {
			t.Errorf("session cookie missing on status read")
		}
		writeEncrypted(t, w, aesKey, map[string]any{"result": dalResult, "Object": []any{map[string]any{"DeviceInfo": map[string]any{"ModelName": "Zyxel-Test", "SoftwareVersion": "test-firmware"}, "SystemInfo": map[string]any{"HostName": "router"}}}})
	})
	mux.HandleFunc("/cgi-bin/UserLogout", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sessionkey") != sessionKey {
			t.Errorf("logout omitted current session key")
		}
		loggedOut = true
		http.Error(w, "logout failed", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint, err := normalizeHost(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(endpoint, Credentials{Username: "router-user", Password: "secret"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.ReadStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status["DeviceInfo"].(map[string]any)["ModelName"] != "Zyxel-Test" {
		t.Fatalf("unexpected status: %#v", status)
	}
	if !loggedOut {
		t.Fatal("expected best-effort logout")
	}
	dalResult = "ACCESS_DENIED"
	_, err = client.ReadStatus(context.Background())
	if err == nil || err.Error() != "router rejected the status request" {
		t.Fatalf("expected sanitized DAL failure, got %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "session-123") {
		t.Fatalf("error leaked sensitive data: %v", err)
	}
}

func TestDecryptRejectsBadPadding(t *testing.T) {
	if _, err := decryptCBC(make([]byte, 32), make([]byte, 16), make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "padding") {
		t.Fatalf("expected padding error, got %v", err)
	}
}

func TestDecryptRejectsMalformedEncryptedResponse(t *testing.T) {
	session := &routerSession{key: make([]byte, 32)}
	for _, payload := range []string{
		`{"iv":"AQID","content":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		`{"iv":"AAAAAAAAAAAAAAAAAAAAAA==","content":"not-base64"}`,
		`{"iv":"AAAAAAAAAAAAAAAAAAAAAA==","content":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
	} {
		if _, err := session.decryptResponse([]byte(payload)); err == nil {
			t.Errorf("expected malformed response to be rejected: %s", payload)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for _, test := range []struct {
		input, want string
		invalid     bool
	}{
		{"192.0.2.10", "http://192.0.2.10", false},
		{"https://router.example", "https://router.example", false},
		{"http://user:pass@router", "", true},
		{"http://router/admin", "", true},
	} {
		got, err := normalizeHost(test.input)
		if test.invalid && err == nil {
			t.Errorf("normalizeHost(%q) succeeded", test.input)
		}
		if !test.invalid && (err != nil || got != test.want) {
			t.Errorf("normalizeHost(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
}

func TestResolveCredentialsRequiresCompletePair(t *testing.T) {
	t.Setenv("ZYXEL_USER", "env-user")
	t.Setenv("ZYXEL_PASS", "env-pass")
	user, pass := resolveCredentials(types.StringValue("config-user"), types.StringNull())
	if user != "env-user" || pass != "env-pass" {
		t.Fatalf("partial config should fall back to a complete environment pair")
	}
	user, pass = resolveCredentials(types.StringValue("config-user"), types.StringValue("config-pass"))
	if user != "config-user" || pass != "config-pass" {
		t.Fatalf("complete config pair should take precedence")
	}
	_, pass = resolveCredentials(types.StringValue("config-user"), types.StringValue(" pass "))
	if pass != " pass " {
		t.Fatal("configured password whitespace must be preserved")
	}
	t.Setenv("ZYXEL_USER", "")
	t.Setenv("ZYXEL_PASS", "")
	user, pass = resolveCredentials(types.StringValue("only-user"), types.StringNull())
	if user != "only-user" || pass != "" {
		t.Fatalf("incomplete credentials should not be combined")
	}
}

func TestUnknownProviderSettings(t *testing.T) {
	got := unknownSettings(providerModel{Host: types.StringUnknown(), Username: types.StringNull(), Password: types.StringUnknown(), TimeoutSeconds: types.Int64Unknown()})
	if len(got) != 3 {
		t.Fatalf("expected unknown host, password, and timeout, got %v", got)
	}
	seen := map[string]bool{}
	for _, name := range got {
		seen[name] = true
	}
	for _, name := range []string{"host", "password", "timeout_seconds"} {
		if !seen[name] {
			t.Errorf("unknown setting %q was not detected", name)
		}
	}
}

func TestMissingAndIncompleteConfigurationDiagnostics(t *testing.T) {
	issues := validateConnectionSettings("", "", "")
	if len(issues) != 2 || issues[0].summary != "Missing router host" || issues[1].summary != "Missing router credentials" {
		t.Fatalf("unexpected missing configuration diagnostics: %#v", issues)
	}
	issues = validateConnectionSettings("router", "admin", "")
	if len(issues) != 1 || issues[0].summary != "Incomplete router credentials" {
		t.Fatalf("unexpected partial credentials diagnostic: %#v", issues)
	}
	for _, issue := range append(issues, validateConnectionSettings("", "", "")...) {
		if strings.Contains(issue.detail, "admin") || strings.Contains(issue.detail, "secret") {
			t.Fatalf("configuration diagnostic leaked a credential: %#v", issue)
		}
	}
}

func TestCredentialsRedactValues(t *testing.T) {
	creds := Credentials{Username: "admin-name", Password: "top-secret"}
	for _, formatted := range []string{fmt.Sprintf("%v", creds), fmt.Sprintf("%+v", creds), fmt.Sprintf("%#v", creds)} {
		if strings.Contains(formatted, "admin-name") || strings.Contains(formatted, "top-secret") {
			t.Fatalf("credential formatting leaked a secret: %s", formatted)
		}
	}
}

func TestReadStatusHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := NewClient(server.URL, Credentials{Username: "user", Password: "secret"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.ReadStatus(ctx)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("cancellation error leaked password: %v", err)
	}
}

func writeEncrypted(t *testing.T, w http.ResponseWriter, key []byte, value any) {
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
