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
	services            []map[string]any
	serviceSequence     int
	sequence            int
	posts               int
	deletes             int
	forceOrder          bool
	compactOrders       bool
	rejectOccupiedOrder bool
	maxACLRows          int
	// capacityResult is the rejection the firmware returns for a create at
	// capacity. Empty means the generic parameter rejection.
	capacityResult      string
	mutateCreate        func(map[string]any)
	activeSessions      int
	maxActiveSessions   int
	requestedOrders     []int
	failPostAt          int
	failDeleteAt        int
	history             [][]map[string]any
	brokenReads         bool
	failReadback        bool
	failNextRead        bool
	failPostAfterCommit bool
	aclReads            int
	failACLReadAt       int
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
	f.rows = []map[string]any{{"Name": "unmanaged", "Order": 1, "Target": "Accept", "Protocol": "UDP", "Direction": "LAN_TO_WAN", "Interface": "LAN", "X_ZYXEL_ServiceIndex": 0}}
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
		f.activeSessions++
		if f.activeSessions > f.maxActiveSessions {
			f.maxActiveSessions = f.activeSessions
		}
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
		f.activeSessions--
		_, _ = io.WriteString(w, `{}`)
	case "/cgi-bin/DAL":
		oid := r.URL.Query().Get("oid")
		if r.URL.Query().Get("sessionkey") != s.token || (oid != "firewall_acl" && oid != "firewall_proto") {
			http.Error(w, "stale token or OID", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			if oid == "firewall_acl" {
				f.aclReads++
				if f.failACLReadAt != 0 && f.aclReads == f.failACLReadAt {
					http.Error(w, "fixture final read failure", http.StatusServiceUnavailable)
					return
				}
			}
			if f.brokenReads || f.failNextRead {
				f.failNextRead = false
				http.Error(w, "fixture read failure", http.StatusServiceUnavailable)
				return
			}
			if oid == "firewall_proto" {
				services := make([]map[string]any, len(f.services))
				for i, service := range f.services {
					services[i] = map[string]any{}
					for key, value := range service {
						services[i][key] = value
					}
					services[i]["Index"] = i + 1
				}
				f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "Object": services})
				return
			}
			rows := make([]map[string]any, len(f.rows))
			for i, row := range f.rows {
				rows[i] = map[string]any{}
				for k, v := range row {
					rows[i][k] = v
				}
				rows[i]["Index"] = i + 1
				if mac, _ := rows[i]["MACAddress"].(string); mac == "" {
					rows[i]["MACAddress"] = "AnyMACAddress"
				}
				if index := fixtureInt(rows[i]["X_ZYXEL_ServiceIndex"]); index != 0 {
					for _, service := range f.services {
						if fixtureInt(service["Iid"]) == index {
							rows[i]["ServiceName"] = service["Name"]
						}
					}
				}
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
		if oid == "firewall_proto" {
			switch r.Method {
			case http.MethodPost:
				f.serviceSequence++
				body["Iid"] = 100 + f.serviceSequence
				switch body["Protocol"] {
				case "TCP":
					body["Protocol"] = 6
				case "UDP":
					body["Protocol"] = 17
				case "ICMP":
					body["Protocol"] = 1
				case "ICMPv6":
					body["Protocol"] = 58
				case "Other":
					body["Protocol"] = body["ProtocolNumber"]
				}
				f.services = append(f.services, body)
				f.failNextRead = f.failReadback
			case http.MethodDelete:
				index, _ := strconv.Atoi(r.URL.Query().Get("Index"))
				if index < 1 || index > len(f.services) {
					http.Error(w, "invalid service index", 400)
					return
				}
				f.services = append(f.services[:index-1], f.services[index:]...)
			default:
				http.Error(w, "unsupported service write", 405)
				return
			}
			f.rotate(s)
			if r.Method == http.MethodPost && f.failPostAfterCommit {
				http.Error(w, "fixture service failure after commit", http.StatusInternalServerError)
				return
			}
			f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": s.token})
			return
		}
		switch r.Method {
		case http.MethodPost:
			f.requestedOrders = append(f.requestedOrders, fixtureInt(body["Order"]))
			if f.maxACLRows > 0 && len(f.rows) >= f.maxACLRows {
				// Both codes were observed from V5.17 hardware at the 32-row
				// limit; policy preflight must avoid either rejection.
				result := f.capacityResult
				if result == "" {
					result = "ZCFG_INVALID_PARAM_VALUE"
				}
				f.reply(w, s, map[string]any{"result": result})
				return
			}
			if f.rejectOccupiedOrder {
				for _, row := range f.rows {
					if fixtureInt(row["Order"]) == fixtureInt(body["Order"]) {
						f.reply(w, s, map[string]any{"result": "ZCFG_INVALID_PARAM_VALUE"})
						return
					}
				}
			}
			// Typical firmware read normalization: the write accepts display
			// values while the stored row uses router-native values.
			switch body["IPVersion"] {
			case "IPv4":
				body["IPVersion"] = 4
			case "IPv6":
				body["IPVersion"] = 6
			}
			if body["Protocol"] == "TCPUDP" {
				body["Protocol"] = "TCP/UDP"
			}
			if flag, ok := body["TCPFlag"]; ok {
				body["X_ZYXEL_TCPFlagMask"], body["X_ZYXEL_TCPFlagComp"] = flag, flag
				delete(body, "TCPFlag")
			}
			if body["MACAddress"] == "AnyMACAddress" {
				body["MACAddress"] = ""
			}
			if ordinal := fixtureInt(body["X_ZYXEL_ServiceIndex"]); ordinal != 0 {
				if ordinal < 1 || ordinal > len(f.services) {
					http.Error(w, "unknown service index", http.StatusBadRequest)
					return
				}
				body["X_ZYXEL_ServiceIndex"] = f.services[ordinal-1]["Iid"]
			}
			if f.forceOrder {
				body["Order"] = 99
			}
			if f.mutateCreate != nil {
				f.mutateCreate(body)
			}
			f.rows = append(f.rows, body)
			f.posts++
			f.failNextRead = f.failReadback
		case http.MethodDelete:
			if f.failDeleteAt != 0 && f.deletes+1 == f.failDeleteAt {
				http.Error(w, "fixture delete failure", http.StatusServiceUnavailable)
				return
			}
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
		if f.compactOrders {
			for i, row := range f.rows {
				row["Order"] = i + 1
			}
		}
		snapshot := make([]map[string]any, len(f.rows))
		for i, row := range f.rows {
			snapshot[i] = map[string]any{}
			for k, v := range row {
				snapshot[i][k] = v
			}
		}
		f.history = append(f.history, snapshot)
		if r.Method == http.MethodPost && (f.failPostAfterCommit || f.failPostAt != 0 && f.posts == f.failPostAt) {
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

// addService registers a custom service group. iid is the stored object index
// the router keeps in ACL rows; the display index is the list position.
func (f *terraformACLFixture) addService(name string, iid int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.services = append(f.services, map[string]any{"Name": name, "Iid": iid})
}

func fixtureInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
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
