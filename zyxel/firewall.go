package zyxel

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// FirewallSettings contains the supported router-wide General and DoS settings.
type FirewallSettings struct {
	IPv4Enabled          bool
	IPv6Enabled          bool
	SecurityLevel        string
	DoSProtectionEnabled bool
}

var firewallLevels = map[string]string{"low": "Off", "medium": "Low", "high": "High"}

func (c *Client) ReadFirewall(ctx context.Context) (FirewallSettings, error) {
	var settings FirewallSettings
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		settings, err = s.readFirewall(ctx)
		return err
	})
	return settings, err
}

// SetFirewall reports whether any requested change succeeded or may have applied.
func (c *Client) SetFirewall(ctx context.Context, settings FirewallSettings) (bool, error) {
	level, ok := firewallLevels[settings.SecurityLevel]
	if !ok {
		return false, errors.New("firewall security_level must be low, medium, or high")
	}
	applied := false
	err := c.withSession(ctx, func(s *routerSession) error {
		current, err := s.readFirewall(ctx)
		if err != nil {
			return err
		}
		var payloads []map[string]any
		if current.IPv4Enabled != settings.IPv4Enabled || current.IPv6Enabled != settings.IPv6Enabled || current.SecurityLevel != settings.SecurityLevel {
			payloads = append(payloads, map[string]any{
				"IPv4_Enable": settings.IPv4Enabled, "IPv6_Enable": settings.IPv6Enabled,
				"Level_GUI": level, "Firewall_Enable": settings.IPv4Enabled || settings.IPv6Enabled,
			})
		}
		if current.DoSProtectionEnabled != settings.DoSProtectionEnabled {
			payloads = append(payloads, map[string]any{"enableDos": settings.DoSProtectionEnabled})
		}
		// Match the General and DoS screens' separate, allowlisted PUT payloads.
		for _, payload := range payloads {
			result, err := s.writeDAL(ctx, http.MethodPut, "firewall", "", payload)
			if err != nil {
				var ambiguous *AmbiguousWriteError
				var status *responseStatusError
				applied = applied || errors.As(err, &ambiguous) || (errors.As(err, &status) && status.status >= 500)
				return err
			}
			if result["result"] != "ZCFG_SUCCESS" {
				return errors.New("router rejected the firewall update request")
			}
			applied = true
		}
		if len(payloads) == 0 {
			applied = true
			return nil
		}
		current, err = s.readFirewall(ctx)
		if err != nil {
			return err
		}
		if current != settings {
			return errors.New("firewall update could not be confirmed by readback")
		}
		return nil
	})
	return applied, err
}

func (s *routerSession) readFirewall(ctx context.Context) (FirewallSettings, error) {
	var settings FirewallSettings
	response, err := s.get(ctx, "/cgi-bin/DAL?oid=firewall&sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return settings, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return settings, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return settings, errors.New("router rejected the firewall read request")
	}
	objects, ok := value["Object"].([]any)
	if !ok || len(objects) != 1 {
		return settings, errors.New("router firewall response did not contain exactly one settings object")
	}
	object, ok := objects[0].(map[string]any)
	if !ok {
		return settings, errors.New("router returned malformed firewall settings")
	}
	for _, field := range []struct {
		name   string
		target *bool
	}{
		{"IPv4_Enable", &settings.IPv4Enabled}, {"IPv6_Enable", &settings.IPv6Enabled}, {"enableDos", &settings.DoSProtectionEnabled},
	} {
		parsed, ok := firewallBool(object[field.name])
		if !ok {
			return settings, errors.New("router firewall settings did not contain a valid " + field.name + " boolean")
		}
		*field.target = parsed
	}
	for name, level := range firewallLevels {
		if object["Level_GUI"] == level {
			settings.SecurityLevel = name
			return settings, nil
		}
	}
	return settings, errors.New("router returned an unsupported firewall Level_GUI")
}

func firewallBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case float64:
		if v == 0 || v == 1 {
			return v == 1, true
		}
	}
	return false, false
}
