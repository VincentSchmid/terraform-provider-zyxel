package zyxel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
)

// LANSettings manages only IPv4 LAN Setup fields for an exact interface-group
// name. Empty pool/relay addresses mean those fields are inactive, not cleared.
type LANSettings struct {
	InterfaceGroupID                    string
	IPAddress, SubnetMask               string
	IGMPSnooping                        string
	DHCPMode                            string
	BeginningIPAddress, EndingIPAddress string
	AutoReserveIP                       bool
	RelayServerAddress                  string
}

// Validate checks inputs independently of Terraform, without contacting a router.
func (v LANSettings) Validate() error {
	if err := validateInterfaceGroupName(v.InterfaceGroupID); err != nil {
		return err
	}
	ip, err := lanIPv4(v.IPAddress)
	if err != nil {
		return errors.New("ip_address must be a usable IPv4 address")
	}
	mask, err := netip.ParseAddr(v.SubnetMask)
	if err != nil || !mask.Is4() {
		return errors.New("subnet_mask must be a contiguous IPv4 mask")
	}
	m := mask.As4()
	ones, bits := net.IPMask(m[:]).Size()
	if bits != 32 || ones < 1 || ones > 30 {
		return errors.New("subnet_mask must be contiguous with a prefix length from 1 through 30")
	}
	prefix := netip.PrefixFrom(ip, ones).Masked()
	if !lanUsableHost(ip, prefix) {
		return errors.New("ip_address must not be the subnet or broadcast address")
	}
	if v.IGMPSnooping != "disabled" && v.IGMPSnooping != "standard" && v.IGMPSnooping != "blocking" {
		return errors.New("igmp_snooping must be disabled, standard, or blocking")
	}
	switch v.DHCPMode {
	case "server":
		start, e1 := lanIPv4(v.BeginningIPAddress)
		end, e2 := lanIPv4(v.EndingIPAddress)
		if e1 != nil || e2 != nil || !lanUsableHost(start, prefix) || !lanUsableHost(end, prefix) || start.Compare(end) > 0 {
			return errors.New("DHCP beginning/ending IP addresses must be ordered usable hosts in the LAN subnet")
		}
		if start.Compare(ip) <= 0 && ip.Compare(end) <= 0 {
			return errors.New("DHCP pool must not contain the router LAN IP address")
		}
		if v.RelayServerAddress != "" {
			return errors.New("relay_server_address is only valid in relay mode")
		}
	case "relay", "disabled":
		if v.BeginningIPAddress != "" || v.EndingIPAddress != "" || v.AutoReserveIP {
			return errors.New("DHCP pool and auto_reserve_ip are only valid in server mode")
		}
		if v.DHCPMode == "relay" {
			relay, err := lanIPv4(v.RelayServerAddress)
			if err != nil || relay == ip {
				return errors.New("relay_server_address must be a usable IPv4 address other than the router LAN IP")
			}
		} else if v.RelayServerAddress != "" {
			return errors.New("relay_server_address is only valid in relay mode")
		}
	default:
		return errors.New("dhcp_mode must be server, disabled, or relay")
	}
	return nil
}

func lanIPv4(value string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip == netip.MustParseAddr("255.255.255.255") {
		return netip.Addr{}, errors.New("invalid IPv4 host")
	}
	return ip, nil
}

func lanUsableHost(ip netip.Addr, prefix netip.Prefix) bool {
	if !prefix.Contains(ip) || ip == prefix.Addr() {
		return false
	}
	b := ip.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	hostMask := uint32(1)<<(32-prefix.Bits()) - 1
	return n&hostMask != hostMask
}

// ReadLAN returns nil when the named LAN no longer exists. Duplicate names and
// malformed active settings are errors, never silently interpreted as disabled.
func (c *Client) ReadLAN(ctx context.Context, groupID string) (*LANSettings, error) {
	if err := validateInterfaceGroupName(groupID); err != nil {
		return nil, err
	}
	var result *LANSettings
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		result, err = s.readLAN(ctx, groupID)
		return err
	})
	return result, err
}

// SetLAN adopts and updates an existing group's built-in LAN settings. The bool
// reports success or possible application; reconcile before retrying on error.
// A management-address change may disconnect the client; no write is retried.
func (c *Client) SetLAN(ctx context.Context, v LANSettings) (bool, error) {
	if err := v.Validate(); err != nil {
		return false, err
	}
	applied := false
	err := c.withSession(ctx, func(s *routerSession) error {
		current, err := s.readLAN(ctx, v.InterfaceGroupID)
		if err != nil {
			return err
		}
		if current == nil {
			return errors.New("LAN interface group not found; create the interface group first")
		}
		if *current == v {
			applied = true
			return nil
		}
		payload := map[string]any{
			"Name": v.InterfaceGroupID, "IPAddress": v.IPAddress, "SubnetMask": v.SubnetMask,
			"IGMPSnoopingMode": map[string]string{"disabled": "Disabled", "standard": "Standard", "blocking": "Blocking"}[v.IGMPSnooping],
			"DHCPType":         "DHCPServer", "EnableDHCP": v.DHCPMode != "disabled", "logout": 0,
		}
		if current.IPAddress != v.IPAddress || current.SubnetMask != v.SubnetMask {
			payload["logout"] = 1
		}
		switch v.DHCPMode {
		case "server":
			payload["DHCP_MinAddress"], payload["DHCP_MaxAddress"], payload["DHCP_AutoReserveLanIp"] = v.BeginningIPAddress, v.EndingIPAddress, v.AutoReserveIP
		case "relay":
			payload["DHCPType"], payload["DHCP_RelayAddr"] = "DHCPRelay", v.RelayServerAddress
		}
		response, err := s.writeDAL(ctx, http.MethodPut, "lan", "", payload)
		if err != nil {
			applied = interfaceGroupWriteUncertain(err)
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected LAN update")
		}
		applied = true
		observed, err := s.readLAN(ctx, v.InterfaceGroupID)
		if err != nil {
			return err
		}
		if observed == nil || *observed != v {
			return errors.New("LAN update could not be confirmed by readback")
		}
		return nil
	})
	return applied, err
}

func (s *routerSession) readLAN(ctx context.Context, groupID string) (*LANSettings, error) {
	rows, err := s.readDALObjects(ctx, "lan")
	if err != nil {
		return nil, err
	}
	var found map[string]any
	for _, row := range rows {
		name, ok := row["Name"].(string)
		if !ok || name == "" {
			return nil, errors.New("router returned LAN settings without a group name")
		}
		if name == groupID {
			if found != nil {
				return nil, errors.New("router returned duplicate LAN group names")
			}
			found = row
		}
	}
	if found == nil {
		return nil, nil
	}
	v := LANSettings{InterfaceGroupID: groupID}
	v.IPAddress, _ = found["IPAddress"].(string)
	v.SubnetMask, _ = found["SubnetMask"].(string)
	mode, _ := found["IGMPSnoopingMode"].(string)
	v.IGMPSnooping = map[string]string{"Disabled": "disabled", "Standard": "standard", "Blocking": "blocking"}[mode]
	enabled, ok := firewallBool(found["EnableDHCP"])
	if !ok {
		return nil, errors.New("router returned invalid LAN DHCP enable state")
	}
	switch found["DHCPType"] {
	case "DHCPServer":
		v.DHCPMode = "disabled"
		if enabled {
			v.DHCPMode = "server"
			v.BeginningIPAddress, _ = found["DHCP_MinAddress"].(string)
			v.EndingIPAddress, _ = found["DHCP_MaxAddress"].(string)
			v.AutoReserveIP, ok = firewallBool(found["DHCP_AutoReserveLanIp"])
			if !ok {
				return nil, errors.New("router returned invalid LAN auto-reserve state")
			}
		}
	case "DHCPRelay":
		if !enabled {
			return nil, errors.New("router returned unsupported disabled DHCP relay")
		}
		v.DHCPMode = "relay"
		v.RelayServerAddress, _ = found["DHCP_RelayAddr"].(string)
	default:
		return nil, errors.New("router returned unsupported LAN DHCP type")
	}
	if err := v.Validate(); err != nil {
		return nil, errors.New("router returned invalid LAN settings: " + err.Error())
	}
	return &v, nil
}
