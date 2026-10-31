package routertest

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// LogSettingsFixture reuses the encrypted test peer's authentication protocol.
// Access controls while holding Mu; only the logset singleton is served here.
type LogSettingsFixture struct {
	*NetworkFixture
	Settings                                                   map[string]any
	ReadObject                                                 any
	Reads                                                      int
	ReadResult, WriteResult                                    string
	BrokenWrite, ServerError, ChangeUnmanaged, RemoveUnmanaged bool
}

func NewLogSettingsFixture(t *testing.T) *LogSettingsFixture {
	t.Helper()
	f := &LogSettingsFixture{
		NetworkFixture: NewNetworkFixture(t),
		ReadResult:     "ZCFG_SUCCESS", WriteResult: "ZCFG_SUCCESS",
		Settings: map[string]any{
			"Enable": false, "LogMode": "Local", "Server": "syslog.example.test",
			"Port": float64(514), "Email": false, "Categories": []any{"system", "security"}, "Nullable": nil,
		},
	}
	protocol := f.Server.Config.Handler
	f.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/DAL" || r.URL.Query().Get("oid") != "logset" {
			protocol.ServeHTTP(w, r)
			return
		}
		f.Mu.Lock()
		defer f.Mu.Unlock()
		cookie, err := r.Cookie("network-session")
		if err != nil || f.sessions[cookie.Value] == nil {
			http.Error(w, "missing session", http.StatusForbidden)
			return
		}
		s := f.sessions[cookie.Value]
		if r.URL.Query().Get("sessionkey") != s.token || r.URL.Query().Has("Index") {
			t.Error("stale token or indexed logging singleton")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			f.Reads++
			if f.FailReadback && f.Writes > 0 {
				http.Error(w, "fixture-password network-token readback failure", http.StatusServiceUnavailable)
				return
			}
			object := f.ReadObject
			if object == nil {
				object = []any{f.Settings}
			}
			f.reply(w, s, map[string]any{"result": f.ReadResult, "Object": object})
		case http.MethodPut:
			if r.Header.Get("CSRFToken") != s.token || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("missing logging write headers")
			}
			var p Payload
			if json.NewDecoder(r.Body).Decode(&p) != nil {
				t.Error("invalid logging envelope")
				return
			}
			body, err := networkDecrypt(s.key, p)
			if err != nil {
				t.Error("invalid logging encrypted payload")
				return
			}
			f.LastWrite = body
			if len(body) != len(f.Settings) {
				t.Error("logging write did not preserve the current object")
			}
			for key, value := range f.Settings {
				if key != "Enable" && key != "LogMode" && !reflect.DeepEqual(body[key], value) {
					t.Errorf("logging write changed unrelated field %s", key)
				}
			}
			if _, ok := body["Enable"].(bool); !ok {
				t.Error("invalid logging Enable")
			}
			if mode := body["LogMode"]; mode != "Local" && mode != "Remote" && mode != "LocalRemote" {
				t.Error("invalid logging LogMode")
			}
			f.Writes++
			if f.WriteResult == "ZCFG_SUCCESS" && !f.IgnoreWrite {
				f.Settings = body
				if f.ChangeUnmanaged {
					f.Settings["Server"] = "changed.example.test"
				}
				if f.RemoveUnmanaged {
					delete(f.Settings, "Nullable")
				}
			}
			f.rotate(s)
			if f.ServerError {
				http.Error(w, "fixture-password network-token failure after commit", http.StatusInternalServerError)
				return
			}
			if f.BrokenWrite {
				_, _ = w.Write([]byte(`{}`))
				return
			}
			f.reply(w, s, map[string]any{"result": f.WriteResult, "sessionkey": s.token})
		default:
			t.Errorf("unexpected logging method %s", r.Method)
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		}
	})
	return f
}
