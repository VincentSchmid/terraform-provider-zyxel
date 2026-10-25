package zyxel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var ErrServiceNotFound = errors.New("service not found")

// Service is a reusable Firewall > Protocol object. ID is the router's native
// Iid, not its shifting display index. Name is the identity for CRUD and import.
type Service struct {
	Name, Description, Protocol          string
	SourcePorts, DestinationPorts        string
	ICMPType, ICMPv6Type, ProtocolNumber *int64
	ID                                   string
	RouterIndex                          int64
}

// ServiceCreateOutcome preserves enough identity to reconcile uncertain writes.
type ServiceCreateOutcome struct {
	Applied, Ambiguous bool
	Service            *Service
}

// ParsePorts accepts *, a single port, or an inclusive range. Empty means any.
// Bounds use the ACL API convention: nil/nil for any and equal bounds for single.
func ParsePorts(value string) (*int64, *int64, error) {
	if value == "" || value == "*" {
		return nil, nil, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return nil, nil, errors.New("ports must be *, a port, or start-end")
	}
	values := make([]int64, len(parts))
	for i, part := range parts {
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n < 1 || n > 65535 || strconv.FormatInt(n, 10) != part {
			return nil, nil, errors.New("ports must use canonical decimal numbers from 1 through 65535")
		}
		values[i] = n
	}
	start, end := values[0], values[0]
	if len(values) == 2 {
		end = values[1]
	}
	if end < start {
		return nil, nil, errors.New("port range end must be at least its start")
	}
	return &start, &end, nil
}

// FormatPorts is the compact representation of an observed ACL port range.
func FormatPorts(start, end *int64) string {
	if start == nil {
		return "*"
	}
	if end == nil || *start == *end {
		return strconv.FormatInt(*start, 10)
	}
	return fmt.Sprintf("%d-%d", *start, *end)
}

func (s Service) dalPayload() (map[string]any, error) {
	if strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Name) != s.Name {
		return nil, errors.New("service name must be non-empty without surrounding whitespace")
	}
	protocol := map[string]string{"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6", "other": "Other"}[s.Protocol]
	if protocol == "" {
		return nil, errors.New("service protocol must be tcp, udp, icmp, icmpv6, or other")
	}
	ports := s.Protocol == "tcp" || s.Protocol == "udp"
	if !ports && (s.SourcePorts != "" || s.DestinationPorts != "") {
		return nil, errors.New("service ports are only valid for tcp or udp")
	}
	if (s.Protocol != "icmp" && s.ICMPType != nil) || (s.Protocol != "icmpv6" && s.ICMPv6Type != nil) || (s.Protocol != "other" && s.ProtocolNumber != nil) {
		return nil, errors.New("service type fields must match the selected protocol")
	}
	payload := map[string]any{"Name": s.Name, "Description": s.Description, "Protocol": protocol}
	if ports {
		for _, pair := range []struct{ value, start, end string }{{s.SourcePorts, "SourcePort", "SourcePortEnd"}, {s.DestinationPorts, "DestPort", "DestPortEnd"}} {
			start, end, err := ParsePorts(pair.value)
			if err != nil {
				return nil, err
			}
			payload[pair.start], payload[pair.end] = int64(-1), int64(-1)
			if start != nil {
				payload[pair.start] = *start
				if *end != *start {
					payload[pair.end] = *end
				}
			}
		}
	}
	if s.Protocol == "icmp" || s.Protocol == "icmpv6" {
		typeValue := s.ICMPType
		if s.Protocol == "icmpv6" {
			typeValue = s.ICMPv6Type
		}
		n := int64(-1)
		if typeValue != nil {
			n = *typeValue
		}
		if n < -1 || n > 143 {
			return nil, errors.New("ICMP type must be -1 (any) through 143")
		}
		payload["ICMPType"], payload["ICMPTypeCode"] = n, int64(-1)
	}
	if s.Protocol == "other" {
		if s.ProtocolNumber == nil || *s.ProtocolNumber < 0 || *s.ProtocolNumber > 255 {
			return nil, errors.New("other requires protocol_number from 0 through 255")
		}
		switch *s.ProtocolNumber {
		case 1, 6, 17, 58:
			return nil, errors.New("use the named service protocol for protocol numbers 1, 6, 17, and 58")
		}
		payload["ProtocolNumber"] = *s.ProtocolNumber
	}
	return payload, nil
}

func parseService(row map[string]any) (Service, error) {
	var s Service
	var ok bool
	s.Name, ok = row["Name"].(string)
	if !ok || strings.TrimSpace(s.Name) == "" {
		return s, errors.New("service has invalid name")
	}
	s.Description, ok = row["Description"].(string)
	if !ok {
		return s, errors.New("service has invalid description")
	}
	s.RouterIndex, ok = aclInt64(row["Index"])
	if !ok || s.RouterIndex < 1 {
		return s, errors.New("service has invalid display index")
	}
	iid, ok := aclInt64(row["Iid"])
	if !ok || iid < 1 {
		return s, errors.New("service has invalid native ID")
	}
	s.ID = strconv.FormatInt(iid, 10)
	n, ok := aclInt64(row["Protocol"])
	if !ok || n < 0 || n > 255 {
		return s, errors.New("service has invalid protocol number")
	}
	switch n {
	case 6:
		s.Protocol = "tcp"
	case 17:
		s.Protocol = "udp"
	case 1:
		s.Protocol = "icmp"
	case 58:
		s.Protocol = "icmpv6"
	default:
		s.Protocol = "other"
		s.ProtocolNumber = &n
	}
	if s.Protocol == "tcp" || s.Protocol == "udp" {
		for _, pair := range []struct {
			start, end string
			target     *string
		}{{"SourcePort", "SourcePortEnd", &s.SourcePorts}, {"DestPort", "DestPortEnd", &s.DestinationPorts}} {
			if _, ok := row[pair.start]; !ok {
				return s, errors.New("service is missing port bounds")
			}
			if _, ok := row[pair.end]; !ok {
				return s, errors.New("service is missing port bounds")
			}
			start, end, err := aclPortRange(row, pair.start, pair.end)
			if err != nil {
				return s, err
			}
			*pair.target = FormatPorts(start, end)
		}
	}
	if s.Protocol == "icmp" || s.Protocol == "icmpv6" {
		n, ok := aclInt64(row["ICMPType"])
		if !ok || n < -1 || n > 143 {
			return s, errors.New("service has invalid ICMP type")
		}
		code, ok := aclInt64(row["ICMPTypeCode"])
		if !ok || code != -1 {
			return s, errors.New("service ICMP code filters are not supported")
		}
		if s.Protocol == "icmp" {
			s.ICMPType = &n
		} else {
			s.ICMPv6Type = &n
		}
	}
	return s, nil
}

func findServiceRow(rows []map[string]any, name string) (map[string]any, error) {
	var found map[string]any
	for _, row := range rows {
		if row["Name"] == name {
			if found != nil {
				return nil, errors.New("router returned duplicate service names")
			}
			found = row
		}
	}
	return found, nil
}

func (c *Client) ReadService(ctx context.Context, name string) (Service, error) {
	var result Service
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDALObjects(ctx, firewallProtocolOID)
		if err != nil {
			return err
		}
		row, err := findServiceRow(rows, name)
		if err != nil {
			return err
		}
		if row == nil {
			return ErrServiceNotFound
		}
		result, err = parseService(row)
		return err
	})
	return result, err
}

func (c *Client) CreateService(ctx context.Context, service Service) (ServiceCreateOutcome, error) {
	var outcome ServiceCreateOutcome
	payload, err := service.dalPayload()
	if err != nil {
		return outcome, err
	}
	err = c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDALObjects(ctx, firewallProtocolOID)
		if err != nil {
			return err
		}
		row, err := findServiceRow(rows, service.Name)
		if err != nil {
			return err
		}
		if row != nil {
			return errors.New("service name already exists; import it before managing it")
		}
		response, err := s.writeDAL(ctx, http.MethodPost, firewallProtocolOID, "", payload)
		if err != nil {
			var ambiguous *AmbiguousWriteError
			var status *responseStatusError
			outcome.Ambiguous = errors.As(err, &ambiguous) || (errors.As(err, &status) && status.status >= 500)
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected service creation")
		}
		outcome.Applied = true
		rows, err = s.readDALObjects(ctx, firewallProtocolOID)
		if err != nil {
			return fmt.Errorf("service created but readback failed: %w", err)
		}
		row, err = findServiceRow(rows, service.Name)
		if err != nil {
			return err
		}
		if row == nil {
			return errors.New("created service missing from readback")
		}
		observed, err := parseService(row)
		if err != nil {
			return err
		}
		outcome.Service = &observed
		want, _ := service.dalPayload()
		got, _ := observed.dalPayload()
		for key, value := range want {
			if got[key] != value {
				return fmt.Errorf("created service readback differs in %s", key)
			}
		}
		return nil
	})
	return outcome, err
}

// DeleteService refuses to cascade-delete ACL rules, including unmanaged rules.
func (c *Client) DeleteService(ctx context.Context, name string) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readDALObjects(ctx, firewallProtocolOID)
		if err != nil {
			return err
		}
		row, err := findServiceRow(rows, name)
		if err != nil {
			return err
		}
		if row == nil {
			return nil
		}
		index, ok := aclInt64(row["Index"])
		if !ok || index < 1 {
			return errors.New("service has invalid display index")
		}
		iid, ok := aclInt64(row["Iid"])
		if !ok || iid < 1 {
			return errors.New("service has invalid native ID")
		}
		acls, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		for _, acl := range acls {
			ref, ok := aclInt64(acl["X_ZYXEL_ServiceIndex"])
			if !ok || ref < 0 {
				return errors.New("cannot safely check ACL service references")
			}
			if ref == iid {
				return errors.New("service is still referenced by an ACL rule; remove associated ACL rules first to prevent cascading deletion")
			}
		}
		response, err := s.writeDAL(ctx, http.MethodDelete, firewallProtocolOID, strconv.FormatInt(index, 10), map[string]any{})
		if err != nil {
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected service deletion")
		}
		rows, err = s.readDALObjects(ctx, firewallProtocolOID)
		if err != nil {
			return err
		}
		row, err = findServiceRow(rows, name)
		if err != nil {
			return err
		}
		if row != nil {
			return errors.New("deleted service remains in readback")
		}
		return nil
	})
}
