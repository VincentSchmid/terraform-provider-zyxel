package zyxel_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/internal/routertest"
	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
)

func logSettingsClient(t *testing.T) (*zyxel.Client, *routertest.LogSettingsFixture) {
	t.Helper()
	f := routertest.NewLogSettingsFixture(t)
	c, err := zyxel.NewClient(f.Server.URL, zyxel.Credentials{Username: "fixture-user", Password: "fixture-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestLogSettingsLocalAndAdoption(t *testing.T) {
	c, f := logSettingsClient(t)
	ctx := context.Background()
	for _, settings := range []zyxel.LogSettings{
		{Enabled: false}, {Enabled: true}, {Enabled: false}, {Enabled: true},
	} {
		if applied, err := c.SetLogSettings(ctx, settings); !applied || err != nil {
			t.Fatal(applied, err)
		}
		if got, err := c.ReadLogSettings(ctx); err != nil || got != settings {
			t.Fatalf("read=%+v err=%v want=%+v", got, err, settings)
		}
		f.Mu.Lock()
		writes := f.Writes
		f.Mu.Unlock()
		if applied, err := c.SetLogSettings(ctx, settings); !applied || err != nil {
			t.Fatal(applied, err)
		}
		f.Mu.Lock()
		if f.Writes != writes {
			t.Error("adoption issued a redundant write")
		}
		f.Mu.Unlock()
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.Writes != 3 || f.Settings["LogMode"] != "Local" || f.Settings["Server"] != "syslog.example.test" || f.Settings["Email"] != false {
		t.Fatalf("unexpected writes or unmanaged settings: %d %+v", f.Writes, f.Settings)
	}
}

func TestLogSettingsRemoteDrift(t *testing.T) {
	for _, mode := range []string{"Remote", "LocalRemote"} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", mode, enabled), func(t *testing.T) {
				c, f := logSettingsClient(t)
				f.Mu.Lock()
				f.Settings["Enable"], f.Settings["LogMode"] = true, mode
				f.Mu.Unlock()
				got, err := c.ReadLogSettings(context.Background())
				if err != nil || got.Enabled {
					t.Fatal("remote mode must not appear as enabled local-only logging", got, err)
				}
				if applied, err := c.SetLogSettings(context.Background(), zyxel.LogSettings{Enabled: enabled}); !applied || err != nil {
					t.Fatal(applied, err)
				}
				f.Mu.Lock()
				defer f.Mu.Unlock()
				if f.Writes != 1 || f.Settings["Enable"] != enabled || f.Settings["LogMode"] != "Local" {
					t.Fatal("apply did not select Local mode", f.Writes, f.Settings)
				}
			})
		}
	}
}

func TestLogSettingsRejectsMalformedReads(t *testing.T) {
	for i, object := range []any{
		"invalid", []any{}, []any{"invalid"}, []any{nil},
		[]any{map[string]any{"Enable": true, "LogMode": "Local"}, map[string]any{"Enable": false, "LogMode": "Local"}},
		[]any{map[string]any{"LogMode": "Local"}},
		[]any{map[string]any{"Enable": true}},
		[]any{map[string]any{"Enable": "true", "LogMode": "Local"}},
		[]any{map[string]any{"Enable": 1, "LogMode": "Local"}},
		[]any{map[string]any{"Enable": nil, "LogMode": "Local"}},
		[]any{map[string]any{"Enable": true, "LogMode": "secret-unsupported"}},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, f := logSettingsClient(t)
			f.Mu.Lock()
			f.ReadObject = object
			f.Mu.Unlock()
			if _, err := c.ReadLogSettings(context.Background()); err == nil {
				t.Fatal("accepted malformed read")
			}
			applied, err := c.SetLogSettings(context.Background(), zyxel.LogSettings{Enabled: true})
			f.Mu.Lock()
			defer f.Mu.Unlock()
			if applied || err == nil || f.Writes != 0 || strings.Contains(err.Error(), "secret-unsupported") {
				t.Fatalf("applied=%t writes=%d err=%v", applied, f.Writes, err)
			}
		})
	}
}

func TestLogSettingsWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(*routertest.LogSettingsFixture)
		applied bool
		writes  int
	}{
		{"read rejection", func(f *routertest.LogSettingsFixture) { f.ReadResult = "DENIED fixture-password" }, false, 0},
		{"write rejection", func(f *routertest.LogSettingsFixture) { f.WriteResult = "DENIED fixture-password" }, false, 1},
		{"failed readback", func(f *routertest.LogSettingsFixture) { f.FailReadback = true }, true, 1},
		{"ignored write", func(f *routertest.LogSettingsFixture) { f.IgnoreWrite = true }, true, 1},
		{"unmanaged setting changed", func(f *routertest.LogSettingsFixture) { f.ChangeUnmanaged = true }, true, 1},
		{"null setting removed", func(f *routertest.LogSettingsFixture) { f.RemoveUnmanaged = true }, true, 1},
		{"ambiguous response", func(f *routertest.LogSettingsFixture) { f.BrokenWrite = true }, true, 1},
		{"server error after commit", func(f *routertest.LogSettingsFixture) { f.ServerError = true }, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f := logSettingsClient(t)
			f.Mu.Lock()
			tc.setup(f)
			f.Mu.Unlock()
			applied, err := c.SetLogSettings(context.Background(), zyxel.LogSettings{Enabled: true})
			f.Mu.Lock()
			defer f.Mu.Unlock()
			if err == nil || applied != tc.applied || f.Writes != tc.writes {
				t.Fatalf("applied=%t writes=%d err=%v", applied, f.Writes, err)
			}
			for _, secret := range []string{"fixture-password", "network-token", "sessionkey", f.Server.URL} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaked sensitive data: %v", err)
				}
			}
		})
	}
}
