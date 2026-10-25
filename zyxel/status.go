package zyxel

import (
	"context"
	"errors"
	"net/url"
)

// Status contains the supported status fields. Nil means a field was not reported.
type Status struct {
	ModelName       *string
	FirmwareVersion *string
	Hostname        *string
}

// ReadStatus reads the supported router status fields.
func (c *Client) ReadStatus(ctx context.Context) (Status, error) {
	var status Status
	err := c.withSession(ctx, func(s *routerSession) error {
		response, err := s.get(ctx, "/cgi-bin/DAL?oid=status&sessionkey="+url.QueryEscape(s.sessionKey))
		if err != nil {
			return err
		}
		value, err := s.decryptResponse(response)
		if err != nil {
			return err
		}
		if result, ok := value["result"].(string); ok && result != "ZCFG_SUCCESS" {
			return errors.New("router rejected the status request")
		}
		objects, ok := value["Object"].([]any)
		if !ok || len(objects) == 0 {
			return errors.New("router status response did not contain a status object")
		}
		object, ok := objects[0].(map[string]any)
		if !ok || len(object) == 0 {
			return errors.New("router status response contained an empty status object")
		}
		status = Status{
			ModelName:       statusString(object, "DeviceInfo", "ModelName"),
			FirmwareVersion: statusString(object, "DeviceInfo", "SoftwareVersion"),
			Hostname:        statusString(object, "SystemInfo", "HostName"),
		}
		return nil
	})
	return status, err
}

func statusString(object map[string]any, parent, key string) *string {
	child, ok := object[parent].(map[string]any)
	if !ok {
		return nil
	}
	value, ok := child[key].(string)
	if !ok {
		return nil
	}
	return &value
}
