package provider

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// This fixture is an independent protocol peer for real Terraform tests. All
// provider credentials point to this loopback server, never to the real router.
type terraformACLFixture struct {
	mu                  sync.Mutex
	server              *httptest.Server
	key                 *rsa.PrivateKey
	sessions            map[string]*terraformACLSession
	rows                []map[string]any
	sequence            int
	posts               int
	deletes             int
	forceOrder          bool
	brokenReads         bool
	failReadback        bool
	failNextRead        bool
	failPostAfterCommit bool
}

type terraformACLSession struct {
	key   []byte
	token string
}

func newTerraformACLFixture(t *testing.T) *terraformACLFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &terraformACLFixture{key: key, sessions: map[string]*terraformACLSession{}}
	// Deliberately outside the managed profile: CRUD must leave it alone.
	f.rows = []map[string]any{{"Name": "unmanaged", "Order": 1, "Protocol": "UDP", "Direction": "LAN_TO_WAN", "Interface": "LAN"}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *terraformACLFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/GetInfoNoLogin" {
		f.sequence++
		id := strconv.Itoa(f.sequence)
		f.sessions[id] = &terraformACLSession{}
		http.SetCookie(w, &http.Cookie{Name: "fixture-session", Value: id, Path: "/"})
		_, _ = io.WriteString(w, `{}`)
		return
	}
	cookie, err := r.Cookie("fixture-session")
	if err != nil || f.sessions[cookie.Value] == nil {
		http.Error(w, "missing cookie", http.StatusForbidden)
		return
	}
	s := f.sessions[cookie.Value]
	switch r.URL.Path {
	case "/getRSAPublickKey":
		der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]string{"RSAPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	case "/UserLogin":
		var envelope struct{ Key, IV, Content string }
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&envelope) != nil {
			http.Error(w, "bad login", http.StatusBadRequest)
			return
		}
		wrapped, _ := base64.StdEncoding.DecodeString(envelope.Key)
		encoded, err := rsa.DecryptPKCS1v15(rand.Reader, f.key, wrapped)
		if err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		s.key, err = base64.StdEncoding.DecodeString(string(encoded))
		body, decodeErr := fixtureDecrypt(s.key, envelope.IV, envelope.Content)
		var login map[string]any
		if err != nil || decodeErr != nil || json.Unmarshal(body, &login) != nil || login["Input_Account"] != "fixture-user" || login["Input_Passwd"] != base64.StdEncoding.EncodeToString([]byte("fixture-password")) {
			http.Error(w, "invalid fixture credentials", http.StatusForbidden)
			return
		}
		f.rotate(s)
		f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": s.token})
	case "/cgi-bin/UserLogout":
		if r.URL.Query().Get("sessionkey") != s.token {
			http.Error(w, "stale token", http.StatusForbidden)
			return
		}
		delete(f.sessions, cookie.Value)
		_, _ = io.WriteString(w, `{}`)
	case "/cgi-bin/DAL":
		if r.URL.Query().Get("sessionkey") != s.token || r.URL.Query().Get("oid") != "firewall_acl" {
			http.Error(w, "stale token or OID", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			if f.brokenReads || f.failNextRead {
				f.failNextRead = false
				http.Error(w, "fixture read failure", http.StatusServiceUnavailable)
				return
			}
			rows := make([]map[string]any, len(f.rows))
			for i, row := range f.rows {
				rows[i] = map[string]any{}
				for k, v := range row {
					rows[i][k] = v
				}
				rows[i]["Index"] = i + 1
			}
			f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "Object": rows})
			return
		}
		if r.Header.Get("CSRFToken") != s.token || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("If-Modified-Since") == "" {
			http.Error(w, "missing write headers", http.StatusForbidden)
			return
		}
		var envelope struct{ IV, Content string }
		if json.NewDecoder(r.Body).Decode(&envelope) != nil {
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		plain, err := fixtureDecrypt(s.key, envelope.IV, envelope.Content)
		var body map[string]any
		if err != nil || json.Unmarshal(plain, &body) != nil {
			http.Error(w, "bad ciphertext", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPost:
			body["IPVersion"] = 4 // Typical firmware read normalization.
			if f.forceOrder {
				body["Order"] = 99
			}
			f.rows = append(f.rows, body)
			f.posts++
			f.failNextRead = f.failReadback
		case http.MethodDelete:
			index, err := strconv.Atoi(r.URL.Query().Get("Index"))
			if err != nil || index < 1 || index > len(f.rows) || len(body) != 0 {
				http.Error(w, "invalid current index", http.StatusBadRequest)
				return
			}
			f.rows = append(f.rows[:index-1], f.rows[index:]...)
			f.deletes++
		default:
			http.Error(w, "unsupported write method", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodPost && f.failPostAfterCommit {
			f.rotate(s)
			http.Error(w, "fixture failure after commit", http.StatusInternalServerError)
			return
		}
		f.rotate(s) // Includes DELETE: the next read/logout must use this token.
		f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": s.token})
	default:
		http.NotFound(w, r)
	}
}

func (f *terraformACLFixture) rotate(s *terraformACLSession) {
	f.sequence++
	s.token = fmt.Sprintf("fixture-token-%d", f.sequence)
}

func (f *terraformACLFixture) reply(w http.ResponseWriter, s *terraformACLSession, value any) {
	plain, _ := json.Marshal(value)
	block, _ := aes.NewCipher(s.key)
	iv := make([]byte, 32)
	_, _ = rand.Read(iv)
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv[:aes.BlockSize]).CryptBlocks(plain, plain)
	_ = json.NewEncoder(w).Encode(map[string]string{"iv": base64.StdEncoding.EncodeToString(iv), "content": base64.StdEncoding.EncodeToString(plain)})
}

func fixtureDecrypt(key []byte, encodedIV, encodedContent string) ([]byte, error) {
	iv, err := base64.StdEncoding.DecodeString(encodedIV)
	if err != nil || len(iv) < aes.BlockSize {
		return nil, fmt.Errorf("invalid IV")
	}
	content, err := base64.StdEncoding.DecodeString(encodedContent)
	if err != nil || len(content) == 0 || len(content)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(content, content)
	padding := int(content[len(content)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(content) || !bytes.Equal(content[len(content)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		return nil, fmt.Errorf("invalid padding")
	}
	return content[:len(content)-padding], nil
}

func (f *terraformACLFixture) remove(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, row := range f.rows {
		if row["Name"] == name {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			return
		}
	}
}

func (f *terraformACLFixture) check(name string, exists bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.rows {
		if row["Name"] == name {
			if !exists {
				return fmt.Errorf("ACL %q still exists", name)
			}
			return nil
		}
	}
	if exists {
		return fmt.Errorf("ACL %q not found in mock router", name)
	}
	return nil
}
