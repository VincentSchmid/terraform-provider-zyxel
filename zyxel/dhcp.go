package zyxel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

type DHCPReservation struct {
	Index   int64
	MACAddr string
	IPAddr  string
	Enabled bool
}

// ReadDHCPReservation resolves a MAC address and rejects duplicate identities.
// A nil reservation with no error means the reservation is absent.
func (c *Client) ReadDHCPReservation(ctx context.Context, mac string) (*DHCPReservation, error) {
	rows, err := c.DHCPReservations(ctx)
	if err != nil {
		return nil, err
	}
	return findDHCPReservation(rows, mac)
}

func (c *Client) DHCPReservations(ctx context.Context) ([]DHCPReservation, error) {
	var reservations []DHCPReservation
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		reservations, err = s.readDHCPReservations(ctx)
		return err
	})
	return reservations, err
}

// CreateDHCPReservation creates an enabled reservation on the default LAN bridge.
// The boolean is true if creation succeeded or may have succeeded, including
// when an error prevents confirmation. Reconcile by MAC before retrying.
func (c *Client) CreateDHCPReservation(ctx context.Context, mac, ip string, enabled bool) (bool, error) {
	canonicalMAC, err := NormalizeMAC(mac)
	if err != nil || canonicalMAC != mac {
		return false, errors.New("MAC address must use canonical uppercase colon notation")
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() {
		return false, errors.New("DHCP reservation must use an IPv4 address")
	}
	if !enabled {
		return false, errors.New("DHCP reservations can only be created enabled")
	}
	created := false
	err = c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if sameDHCPMAC(row.MACAddr, mac) {
				return errors.New("a DHCP reservation for this MAC already exists; import it before managing it")
			}
		}
		result, err := s.writeDAL(ctx, http.MethodPost, "static_dhcp", "", map[string]any{
			"Enable": enabled, "MACAddr": mac, "IPAddr": ip, "BrWan": "Default",
		})
		if err != nil {
			var ambiguous *AmbiguousWriteError
			if errors.As(err, &ambiguous) {
				created = true
			}
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the DHCP reservation create request")
		}
		created = true
		rows, err = s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		found, err := findDHCPReservation(rows, mac)
		if err != nil {
			return err
		}
		if found == nil || found.IPAddr != ip || found.Enabled != enabled {
			return errors.New("DHCP reservation create could not be confirmed by readback")
		}
		return nil
	})
	return created, err
}

func (c *Client) DeleteDHCPReservation(ctx context.Context, mac string) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		found, err := findDHCPReservation(rows, mac)
		if err != nil {
			return err
		}
		if found == nil {
			return nil
		}
		if found.Index < 1 {
			return errors.New("router returned an invalid DHCP reservation index")
		}
		result, err := s.writeDAL(ctx, http.MethodDelete, "static_dhcp", fmt.Sprint(found.Index), map[string]any{})
		if err != nil {
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the DHCP reservation delete request")
		}
		rows, err = s.readDHCPReservations(ctx)
		if err != nil {
			return err
		}
		remaining, err := findDHCPReservation(rows, mac)
		if err != nil {
			return err
		}
		if remaining != nil {
			return errors.New("DHCP reservation delete could not be confirmed by readback")
		}
		return nil
	})
}

func findDHCPReservation(rows []DHCPReservation, mac string) (*DHCPReservation, error) {
	var found *DHCPReservation
	for i := range rows {
		if sameDHCPMAC(rows[i].MACAddr, mac) {
			if found != nil {
				return nil, errors.New("router returned multiple DHCP reservations for this MAC")
			}
			found = &rows[i]
		}
	}
	return found, nil
}

func sameDHCPMAC(left, right string) bool {
	canonicalLeft, leftErr := NormalizeMAC(left)
	canonicalRight, rightErr := NormalizeMAC(right)
	return leftErr == nil && rightErr == nil && canonicalLeft == canonicalRight
}

func (s *routerSession) readDHCPReservations(ctx context.Context) ([]DHCPReservation, error) {
	response, err := s.get(ctx, "/cgi-bin/DAL?oid=static_dhcp&sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, errors.New("router rejected the DHCP reservation read request")
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, errors.New("router DHCP response did not contain a reservation list")
	}
	rows := make([]DHCPReservation, 0, len(objects))
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("router returned a malformed DHCP reservation")
		}
		index, ok := integerValue(row["Index"])
		if !ok || index < 1 {
			return nil, errors.New("router returned an invalid DHCP reservation index")
		}
		mac, macOK := row["MACAddr"].(string)
		ip, ipOK := row["IPAddr"].(string)
		enabled, enabledOK := row["Enable"].(bool)
		if !macOK || !ipOK || !enabledOK {
			return nil, errors.New("router returned an incomplete DHCP reservation")
		}
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil || !parsedIP.Is4() {
			return nil, errors.New("router returned a DHCP reservation with an invalid IPv4 address")
		}
		canonicalMAC, err := NormalizeMAC(mac)
		if err != nil {
			return nil, errors.New("router returned an invalid DHCP reservation MAC address")
		}
		rows = append(rows, DHCPReservation{Index: index, MACAddr: canonicalMAC, IPAddr: ip, Enabled: enabled})
	}
	return rows, nil
}

func integerValue(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		if v >= 1 && v == float64(int64(v)) {
			return int64(v), true
		}
	case json.Number:
		parsed, err := v.Int64()
		return parsed, err == nil && parsed >= 1
	case int64:
		return v, v >= 1
	case int:
		return int64(v), v >= 1
	}
	return 0, false
}

// NormalizeMAC accepts colon or hyphen notation and returns an uppercase MAC.
func NormalizeMAC(value string) (string, error) {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "-", ":")
	value = strings.ToUpper(value)
	if !regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`).MatchString(value) {
		return "", fmt.Errorf("invalid MAC")
	}
	return value, nil
}
