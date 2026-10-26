package zyxel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// InterfaceGroup is a port-based Network Setting > Interface Grouping entry.
// The exact name is its stable ID. RouterIndex is only a current locator.
// Interface paths are IP.Interface.N, Ethernet.Interface.N, or WiFi.SSID.N.
type InterfaceGroup struct {
	Name                         string
	WANInterfaces, LANInterfaces []string
	RouterIndex                  int64
}

func validateInterfaceGroupName(name string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name || strings.ContainsFunc(name, unicode.IsControl) {
		return errors.New("interface group name must be nonempty without surrounding whitespace or control characters")
	}
	return nil
}

func (v InterfaceGroup) Validate() error {
	if err := validateInterfaceGroupName(v.Name); err != nil {
		return err
	}
	if v.Name == "Default" {
		return errors.New("the built-in Default interface group cannot be created or deleted")
	}
	for _, field := range []struct {
		values        []string
		pattern, name string
	}{
		{v.WANInterfaces, `^IP\.Interface\.[1-9][0-9]*$`, "wan_interfaces"},
		{v.LANInterfaces, `^(Ethernet\.Interface|WiFi\.SSID)\.[1-9][0-9]*$`, "lan_interfaces"},
	} {
		if len(field.values) == 0 {
			return fmt.Errorf("%s must contain at least one interface path", field.name)
		}
		seen := map[string]bool{}
		pattern := regexp.MustCompile(field.pattern)
		for _, value := range field.values {
			if !pattern.MatchString(value) || seen[value] {
				return fmt.Errorf("%s must contain unique supported interface paths", field.name)
			}
			seen[value] = true
		}
	}
	return nil
}

// ReadInterfaceGroup returns nil for absence and rejects duplicate names. Only
// port-based groups are supported; DHCP/VLAN classification criteria are not.
func (c *Client) ReadInterfaceGroup(ctx context.Context, name string) (*InterfaceGroup, error) {
	if err := validateInterfaceGroupName(name); err != nil {
		return nil, err
	}
	var group *InterfaceGroup
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDALObjects(ctx, "intf_group")
		if err != nil {
			return err
		}
		group, err = findInterfaceGroup(rows, name)
		return err
	})
	return group, err
}

// CreateInterfaceGroup returns true after a successful or uncertain write, even
// when readback fails, so callers can retain the name for recovery.
func (c *Client) CreateInterfaceGroup(ctx context.Context, v InterfaceGroup) (bool, error) {
	if err := v.Validate(); err != nil {
		return false, err
	}
	applied := false
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDALObjects(ctx, "intf_group")
		if err != nil {
			return err
		}
		for _, row := range rows {
			name, ok := row["Group_Name"].(string)
			if !ok || validateInterfaceGroupName(name) != nil {
				return errors.New("cannot safely check interface group memberships: invalid group name")
			}
			if row["Group_Name"] == v.Name {
				return errors.New("interface group name already exists; import it before managing it")
			}
			if row["Group_Name"] == "Default" {
				continue
			}
			for _, pair := range []struct {
				field string
				paths []string
			}{{"wanIntf", v.WANInterfaces}, {"lanIntf", v.LANInterfaces}} {
				if _, ok := row[pair.field].(string); !ok {
					return errors.New("cannot safely check interface group memberships: invalid interface list")
				}
				for _, path := range splitInterfacePaths(row[pair.field]) {
					if slices.Contains(pair.paths, path) {
						return errors.New("interface is already assigned to a non-default group")
					}
				}
			}
		}
		wan, err := s.readDALObjects(ctx, "wan")
		if err != nil {
			return err
		}
		for _, path := range v.WANInterfaces {
			matches := 0
			for _, row := range wan {
				if row["IpIfacePath"] == path && row["Type"] == "WAN" {
					matches++
				}
			}
			if matches != 1 {
				return errors.New("WAN interface path does not resolve uniquely to a WAN interface")
			}
		}
		// The UI displays lower-layer interface paths, but POST requires current
		// bridge-port paths. Resolve within the same locked session, never in state.
		ports, err := s.readLANPorts(ctx)
		if err != nil {
			return err
		}
		var bridgePorts []string
		for _, path := range v.LANInterfaces {
			matches := 0
			for _, row := range ports {
				if row["IntfPath"] == path {
					port, ok := row["BrPortPath"].(string)
					if !ok || !regexp.MustCompile(`^Bridging\.Bridge\.[1-9][0-9]*\.Port\.[1-9][0-9]*$`).MatchString(port) {
						return errors.New("invalid LAN bridge-port path")
					}
					bridgePorts = append(bridgePorts, port)
					matches++
				}
			}
			if matches != 1 {
				return errors.New("LAN interface path does not resolve uniquely to a bridge port")
			}
		}
		response, err := s.writeDAL(ctx, http.MethodPost, "intf_group", "", map[string]any{"Name": v.Name, "wanIntf": strings.Join(v.WANInterfaces, ","), "lanIntf": strings.Join(bridgePorts, ","), "critInfo": map[string]any{}})
		if err != nil {
			applied = interfaceGroupWriteUncertain(err)
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected interface group creation")
		}
		applied = true
		rows, err = s.readDALObjects(ctx, "intf_group")
		if err != nil {
			return err
		}
		observed, err := findInterfaceGroup(rows, v.Name)
		if err != nil {
			return err
		}
		if observed == nil || !sameInterfacePaths(v.WANInterfaces, observed.WANInterfaces) || !sameInterfacePaths(v.LANInterfaces, observed.LANInterfaces) {
			return errors.New("interface group creation could not be confirmed by readback")
		}
		return nil
	})
	return applied, err
}

// DeleteInterfaceGroup resolves the current display index by exact name. The
// firmware returns member interfaces to Default; it also removes this group's LAN.
func (c *Client) DeleteInterfaceGroup(ctx context.Context, name string) error {
	if err := validateInterfaceGroupName(name); err != nil {
		return err
	}
	if name == "Default" {
		return errors.New("cannot delete the built-in Default interface group")
	}
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDALObjects(ctx, "intf_group")
		if err != nil {
			return err
		}
		group, err := findInterfaceGroup(rows, name)
		if err != nil || group == nil {
			return err
		}
		response, err := s.writeDAL(ctx, http.MethodDelete, "intf_group", strconv.FormatInt(group.RouterIndex, 10), map[string]any{"Index": group.RouterIndex})
		if err != nil {
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected interface group deletion")
		}
		rows, err = s.readDALObjects(ctx, "intf_group")
		if err != nil {
			return err
		}
		group, err = findInterfaceGroup(rows, name)
		if err != nil {
			return err
		}
		if group != nil {
			return errors.New("interface group deletion could not be confirmed by readback")
		}
		return nil
	})
}

func findInterfaceGroup(rows []map[string]any, name string) (*InterfaceGroup, error) {
	var found map[string]any
	for _, row := range rows {
		if row["Group_Name"] == name {
			if found != nil {
				return nil, errors.New("router returned duplicate interface group names")
			}
			found = row
		}
	}
	if found == nil {
		return nil, nil
	}
	index, ok := aclInt64(found["Index"])
	if !ok || index < 1 {
		return nil, errors.New("interface group has invalid display index")
	}
	criteria, ok := found["Criteria"].(string)
	if !ok || criteria != "" {
		return nil, errors.New("interface group classification criteria are not supported")
	}
	group := &InterfaceGroup{Name: name, RouterIndex: index, WANInterfaces: splitInterfacePaths(found["wanIntf"]), LANInterfaces: splitInterfacePaths(found["lanIntf"])}
	if err := group.Validate(); err != nil {
		return nil, err
	}
	return group, nil
}

func splitInterfacePaths(value any) []string {
	s, _ := value.(string)
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func sameInterfacePaths(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func interfaceGroupWriteUncertain(err error) bool {
	var ambiguous *AmbiguousWriteError
	var status *responseStatusError
	return errors.As(err, &ambiguous) || (errors.As(err, &status) && status.status >= 500)
}

func (s *routerSession) readLANPorts(ctx context.Context) ([]map[string]any, error) {
	response, err := s.get(ctx, "/cgi-bin/LAN_PORT_LIST_Get?sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, errors.New("router rejected LAN port list request")
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, errors.New("router returned invalid LAN port list")
	}
	var rows []map[string]any
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("router returned invalid LAN port")
		}
		rows = append(rows, row)
	}
	return rows, nil
}
