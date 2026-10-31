package zyxel

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
)

// LogSettings controls local-only logging under Maintenance > Log Setting.
// Remote destinations, TLS, email, and log categories are left unchanged.
type LogSettings struct {
	// Enabled reports whether logging is enabled in Local mode, not a remote mode.
	Enabled bool
}

func (c *Client) ReadLogSettings(ctx context.Context) (LogSettings, error) {
	var settings LogSettings
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		settings, _, err = s.readLogSettings(ctx)
		return err
	})
	return settings, err
}

// SetLogSettings adopts the built-in settings and always selects Local mode.
// This stops remote forwarding if a remote mode was previously selected. The boolean
// reports success or possible application; reconcile before retrying on error.
func (c *Client) SetLogSettings(ctx context.Context, settings LogSettings) (bool, error) {
	applied := false
	err := c.withSession(ctx, func(s *routerSession) error {
		current, before, err := s.readLogSettings(ctx)
		if err != nil {
			return err
		}
		if current == settings && before["LogMode"] == "Local" {
			applied = true
			return nil
		}
		// Match the supplied logset workflow: copy the current object, changing
		// only Enable and LogMode, rather than resetting other logging controls.
		payload := make(map[string]any, len(before))
		for key, value := range before {
			payload[key] = value
		}
		payload["Enable"], payload["LogMode"] = settings.Enabled, "Local"
		result, err := s.writeDAL(ctx, http.MethodPut, "logset", "", payload)
		if err != nil {
			var ambiguous *AmbiguousWriteError
			var status *responseStatusError
			applied = errors.As(err, &ambiguous) || (errors.As(err, &status) && status.status >= 500)
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the logging update request")
		}
		applied = true
		current, after, err := s.readLogSettings(ctx)
		if err != nil {
			return err
		}
		if current != settings || after["LogMode"] != "Local" || after["Enable"] != settings.Enabled {
			return errors.New("logging update could not be confirmed by readback")
		}
		for key, value := range before {
			if key == "Enable" || key == "LogMode" {
				continue
			}
			if observed, exists := after[key]; !exists || !reflect.DeepEqual(observed, value) {
				return errors.New("logging readback differs in an unrelated setting; inspect the router manually")
			}
		}
		return nil
	})
	return applied, err
}

func (s *routerSession) readLogSettings(ctx context.Context) (LogSettings, map[string]any, error) {
	var settings LogSettings
	response, err := s.get(ctx, "/cgi-bin/DAL?oid=logset&sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return settings, nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return settings, nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return settings, nil, errors.New("router rejected the logging read request")
	}
	objects, ok := value["Object"].([]any)
	if !ok || len(objects) != 1 {
		return settings, nil, errors.New("router logging response did not contain exactly one settings object")
	}
	object, ok := objects[0].(map[string]any)
	if !ok {
		return settings, nil, errors.New("router returned malformed logging settings")
	}
	settings.Enabled, ok = object["Enable"].(bool)
	if !ok {
		return settings, nil, errors.New("router logging settings did not contain a valid Enable boolean")
	}
	switch object["LogMode"] {
	case "Local":
		return settings, object, nil
	case "Remote", "LocalRemote":
		settings.Enabled = false
		return settings, object, nil
	}
	return settings, nil, errors.New("router returned an unsupported logging LogMode")
}
