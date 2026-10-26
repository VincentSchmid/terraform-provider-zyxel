package routertest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// NetworkFixture is an independent encrypted peer for LAN/interface-group tests.
// Public test controls must be accessed while holding Mu.
type NetworkFixture struct {
	Mu                                                     sync.Mutex
	Server                                                 *httptest.Server
	Groups                                                 []map[string]any
	LANs                                                   []map[string]any
	Writes                                                 int
	LastWrite                                              map[string]any
	FailAfterWrite, FailReadback, IgnoreWrite, RejectWrite bool
	key                                                    *rsa.PrivateKey
	sessions                                               map[string]*networkSession
	sequence                                               int
	t                                                      *testing.T
}
type networkSession struct {
	key   []byte
	token string
}

func NewNetworkFixture(t *testing.T) *NetworkFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &NetworkFixture{key: key, sessions: map[string]*networkSession{}, t: t}
	f.Groups = []map[string]any{{"Group_Name": "Default", "Index": 1, "wanIntf": "", "lanIntf": "Ethernet.Interface.1,Ethernet.Interface.2,WiFi.SSID.3", "Criteria": ""}}
	f.LANs = []map[string]any{NetworkLAN("Default")}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

func NetworkLAN(name string) map[string]any {
	return map[string]any{"Name": name, "IPAddress": "192.0.2.1", "SubnetMask": "255.255.255.0", "IGMPSnoopingMode": "Standard", "EnableDHCP": true, "DHCPType": "DHCPServer", "DHCP_MinAddress": "192.0.2.100", "DHCP_MaxAddress": "192.0.2.200", "DHCP_AutoReserveLanIp": false, "DHCP_RelayAddr": "", "DHCP_LeaseTime": 86400, "DNS_Type": "DNSProxy", "IPv6_LanEnable": true, "IPv6_Prefix": "2001:db8::/64", "secret": "not-for-state"}
}

func (f *NetworkFixture) reply(w http.ResponseWriter, s *networkSession, value any) {
	WriteEncrypted(f.t, w, s.key, value)
}
func (f *NetworkFixture) rotate(s *networkSession) {
	f.sequence++
	s.token = fmt.Sprintf("network-token-%d", f.sequence)
}
func (f *NetworkFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if r.URL.Path == "/GetInfoNoLogin" {
		f.sequence++
		id := strconv.Itoa(f.sequence)
		f.sessions[id] = &networkSession{}
		http.SetCookie(w, &http.Cookie{Name: "network-session", Value: id, Path: "/"})
		_, _ = w.Write([]byte(`{}`))
		return
	}
	cookie, err := r.Cookie("network-session")
	if err != nil || f.sessions[cookie.Value] == nil {
		http.Error(w, "missing session", 403)
		return
	}
	s := f.sessions[cookie.Value]
	switch r.URL.Path {
	case "/getRSAPublickKey":
		der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]string{"RSAPublicKey": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	case "/UserLogin":
		var p Payload
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			http.Error(w, "bad login", 400)
			return
		}
		wrapped, _ := base64.StdEncoding.DecodeString(p.Key)
		encoded, err := rsa.DecryptPKCS1v15(rand.Reader, f.key, wrapped)
		if err != nil {
			http.Error(w, "bad key", 400)
			return
		}
		s.key, err = base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			http.Error(w, "bad key", 400)
			return
		}
		body, err := networkDecrypt(s.key, p)
		if err != nil || body["Input_Account"] != "fixture-user" || body["Input_Passwd"] != base64.StdEncoding.EncodeToString([]byte("fixture-password")) {
			http.Error(w, "bad credentials", 403)
			return
		}
		f.rotate(s)
		f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": s.token})
	case "/cgi-bin/UserLogout":
		if r.URL.Query().Get("sessionkey") != s.token {
			http.Error(w, "stale logout token", 403)
			return
		}
		delete(f.sessions, cookie.Value)
		_, _ = w.Write([]byte(`{}`))
	case "/cgi-bin/LAN_PORT_LIST_Get", "/cgi-bin/DAL":
		if r.URL.Query().Get("sessionkey") != s.token {
			http.Error(w, "stale token", 403)
			return
		}
		oid := r.URL.Query().Get("oid")
		if r.URL.Path == "/cgi-bin/LAN_PORT_LIST_Get" {
			oid = "ports"
		}
		if r.Method == http.MethodGet {
			if f.FailReadback && f.Writes > 0 {
				http.Error(w, "read failure fixture-password network-token", 503)
				return
			}
			var rows []map[string]any
			switch oid {
			case "intf_group":
				rows = make([]map[string]any, len(f.Groups))
				for i, row := range f.Groups {
					rows[i] = map[string]any{}
					for k, v := range row {
						rows[i][k] = v
					}
					rows[i]["Index"] = i + 1
				}
			case "lan":
				rows = f.LANs
			case "wan":
				rows = []map[string]any{{"Type": "WAN", "IpIfacePath": "IP.Interface.2"}, {"Type": "WAN", "IpIfacePath": "IP.Interface.3"}}
			case "ports":
				rows = []map[string]any{{"IntfPath": "Ethernet.Interface.1", "BrPortPath": "Bridging.Bridge.1.Port.2"}, {"IntfPath": "Ethernet.Interface.2", "BrPortPath": "Bridging.Bridge.1.Port.3"}, {"IntfPath": "WiFi.SSID.3", "BrPortPath": "Bridging.Bridge.1.Port.7"}}
			default:
				http.Error(w, "unsupported read", 400)
				return
			}
			f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "Object": rows})
			return
		}
		if r.Header.Get("CSRFToken") != s.token || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "bad write headers", 403)
			return
		}
		var p Payload
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			http.Error(w, "bad envelope", 400)
			return
		}
		body, err := networkDecrypt(s.key, p)
		if err != nil {
			http.Error(w, "bad payload", 400)
			return
		}
		f.LastWrite = body
		if f.RejectWrite {
			f.reply(w, s, map[string]any{"result": "DENIED: fixture-password"})
			return
		}
		f.Writes++
		if !f.IgnoreWrite {
			switch {
			case oid == "lan" && r.Method == http.MethodPut:
				allowed := map[string]bool{"Name": true, "IPAddress": true, "SubnetMask": true, "IGMPSnoopingMode": true, "DHCPType": true, "EnableDHCP": true, "logout": true, "DHCP_MinAddress": true, "DHCP_MaxAddress": true, "DHCP_AutoReserveLanIp": true, "DHCP_RelayAddr": true}
				for key := range body {
					if !allowed[key] {
						f.t.Errorf("unexpected LAN write field %s", key)
					}
				}
				for _, row := range f.LANs {
					if row["Name"] == body["Name"] {
						for k, v := range body {
							if k != "logout" {
								row[k] = v
							}
						}
					}
				}
			case oid == "intf_group" && r.Method == http.MethodPost:
				paths, _ := body["lanIntf"].(string)
				paths = strings.NewReplacer("Bridging.Bridge.1.Port.2", "Ethernet.Interface.1", "Bridging.Bridge.1.Port.3", "Ethernet.Interface.2", "Bridging.Bridge.1.Port.7", "WiFi.SSID.3").Replace(paths)
				f.Groups = append(f.Groups, map[string]any{"Group_Name": body["Name"], "wanIntf": body["wanIntf"], "lanIntf": paths, "Criteria": ""})
				f.LANs = append(f.LANs, NetworkLAN(body["Name"].(string)))
			case oid == "intf_group" && r.Method == http.MethodDelete:
				index, _ := strconv.Atoi(r.URL.Query().Get("Index"))
				if index <= 1 || index > len(f.Groups) || body["Index"] != float64(index) {
					f.t.Error("unsafe group deletion index")
					http.Error(w, "invalid index", 400)
					return
				}
				name := f.Groups[index-1]["Group_Name"]
				f.Groups = append(f.Groups[:index-1], f.Groups[index:]...)
				for i, row := range f.LANs {
					if row["Name"] == name {
						f.LANs = append(f.LANs[:i], f.LANs[i+1:]...)
						break
					}
				}
			default:
				http.Error(w, "unsupported write", 405)
				return
			}
		}
		f.rotate(s)
		if f.FailAfterWrite {
			http.Error(w, "failure after commit fixture-password", 500)
			return
		}
		f.reply(w, s, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": s.token})
	default:
		http.NotFound(w, r)
	}
}

func networkDecrypt(key []byte, p Payload) (map[string]any, error) {
	iv, e1 := base64.StdEncoding.DecodeString(p.IV)
	ct, e2 := base64.StdEncoding.DecodeString(p.Content)
	if e1 != nil || e2 != nil || len(iv) < 16 || len(ct) == 0 || len(ct)%16 != 0 {
		return nil, fmt.Errorf("bad envelope")
	}
	plain, err := DecryptCBC(key, iv[:16], ct)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	err = json.Unmarshal(plain, &body)
	return body, err
}
