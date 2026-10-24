package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// NATRule contains the supported, allowlisted part of a router NAT row.
type NATRule struct {
	Index             int64
	Name              string
	Protocol          string
	ExternalPortStart int64
	ExternalPortEnd   int64
	InternalClient    string
	InternalPortStart int64
	InternalPortEnd   int64
	Enabled           bool
}

func (c *Client) NATRules(ctx context.Context) ([]NATRule, error) {
	var rules []NATRule
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		rules, err = s.readNATRules(ctx)
		return err
	})
	return rules, err
}

func (c *Client) CreateNATRule(ctx context.Context, rule NATRule) (bool, error) {
	if err := validateNATRuleInput(rule); err != nil {
		return false, err
	}
	created := false
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readNATRules(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Name == rule.Name {
				return errors.New("a NAT rule with this name already exists; import it before managing it")
			}
			if row.Enabled && natRulesOverlap(row, rule) {
				return fmt.Errorf("NAT rule conflicts with existing enabled rule %q", row.Name)
			}
		}
		result, err := s.writeDAL(ctx, http.MethodPost, "nat", "", map[string]any{
			"Enable": true, "Description": rule.Name, "Protocol": routerNATProtocol(rule.Protocol),
			"ExternalPortStart": rule.ExternalPortStart, "ExternalPortEnd": rule.ExternalPortEnd,
			"InternalClient": rule.InternalClient, "InternalPortStart": rule.InternalPortStart,
			"InternalPortEnd": rule.InternalPortEnd,
		})
		if err != nil {
			var ambiguous *ambiguousWriteError
			if errors.As(err, &ambiguous) {
				created = true
			}
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the NAT rule create request")
		}
		created = true
		rows, err = s.readNATRules(ctx)
		if err != nil {
			return err
		}
		found, err := findNATRule(rows, rule.Name)
		if err != nil {
			return err
		}
		if found == nil || !sameNATConfiguration(*found, rule) || !found.Enabled {
			return errors.New("NAT rule create could not be confirmed by readback")
		}
		return nil
	})
	return created, err
}

func (c *Client) DeleteNATRule(ctx context.Context, name string) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readNATRules(ctx)
		if err != nil {
			return err
		}
		found, err := findNATRule(rows, name)
		if err != nil {
			return err
		}
		if found == nil {
			return nil
		}
		// Indexes can move after another rule is removed, so resolve identity again
		// immediately before issuing DELETE while this client's session is locked.
		rows, err = s.readNATRules(ctx)
		if err != nil {
			return err
		}
		found, err = findNATRule(rows, name)
		if err != nil {
			return err
		}
		if found == nil {
			return nil
		}
		if found.Index < 1 {
			return errors.New("router returned an invalid NAT rule index")
		}
		result, err := s.writeDAL(ctx, http.MethodDelete, "nat", fmt.Sprint(found.Index), map[string]any{})
		if err != nil {
			return err
		}
		if result["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the NAT rule delete request")
		}
		rows, err = s.readNATRules(ctx)
		if err != nil {
			return err
		}
		remaining, err := findNATRule(rows, name)
		if err != nil {
			return err
		}
		if remaining != nil {
			return errors.New("NAT rule delete could not be confirmed by readback")
		}
		return nil
	})
}

func (s *routerSession) readNATRules(ctx context.Context) ([]NATRule, error) {
	response, err := s.get(ctx, "/cgi-bin/DAL?oid=nat&sessionkey="+url.QueryEscape(s.sessionKey))
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, errors.New("router rejected the NAT rule read request")
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, errors.New("router NAT response did not contain a rule list")
	}
	rows := make([]NATRule, 0, len(objects))
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("router returned a malformed NAT rule")
		}
		rule, err := parseNATRule(row)
		if err != nil {
			return nil, err
		}
		rows = append(rows, rule)
	}
	return rows, nil
}

func parseNATRule(row map[string]any) (NATRule, error) {
	// Firmware can attach unrelated metadata to each row. Ignore it because the
	// router's supported create payload omits interface-specific settings.
	index, indexOK := natIndexValue(row["Index"])
	enabled, enabledOK := row["Enable"].(bool)
	name, nameOK := row["Description"].(string)
	protocol, protocolOK := normalizedNATProtocol(row["Protocol"])
	externalStart, externalStartOK := natPort(row["ExternalPortStart"])
	externalEnd, externalEndOK := natPort(row["ExternalPortEnd"])
	internalStart, internalStartOK := natPort(row["InternalPortStart"])
	internalEnd, internalEndOK := natPort(row["InternalPortEnd"])
	internalClient, clientOK := row["InternalClient"].(string)
	parsedClient := net.ParseIP(internalClient)
	if !indexOK || !enabledOK || !nameOK || strings.TrimSpace(name) == "" || !protocolOK || !externalStartOK || !externalEndOK || !internalStartOK || !internalEndOK || !clientOK || strings.Contains(internalClient, ":") || parsedClient == nil || parsedClient.To4() == nil || externalEnd < externalStart || internalEnd < internalStart || externalEnd-externalStart != internalEnd-internalStart {
		return NATRule{}, errors.New("router returned a malformed or unsupported NAT rule")
	}
	return NATRule{Index: index, Name: name, Protocol: protocol, ExternalPortStart: externalStart, ExternalPortEnd: externalEnd, InternalClient: internalClient, InternalPortStart: internalStart, InternalPortEnd: internalEnd, Enabled: enabled}, nil
}

func natIndexValue(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		// JSON float64 indexes must be whole numbers within its exact integer
		// range; converting fractional or oversized values can silently shift an index.
		if v < 1 || v > 9007199254740991 || math.Trunc(v) != v {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		parsed, err := v.Int64()
		return parsed, err == nil && parsed >= 1
	case int64:
		return v, v >= 1
	case int:
		return int64(v), v >= 1
	default:
		return 0, false
	}
}

func validateNATRuleInput(rule NATRule) error {
	if rule.Name == "" || strings.TrimSpace(rule.Name) != rule.Name {
		return errors.New("NAT rule name must be nonempty and have no surrounding whitespace")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "both" && rule.Protocol != "all" {
		return errors.New("NAT rule protocol must be tcp, udp, both, or all")
	}
	validPort := func(port int64) bool { return port >= 1 && port <= 65535 }
	if !validPort(rule.ExternalPortStart) || !validPort(rule.ExternalPortEnd) || !validPort(rule.InternalPortStart) || !validPort(rule.InternalPortEnd) {
		return errors.New("NAT rule ports must be between 1 and 65535")
	}
	if rule.ExternalPortEnd < rule.ExternalPortStart || rule.InternalPortEnd < rule.InternalPortStart {
		return errors.New("NAT rule range ends must be greater than or equal to their starts")
	}
	if rule.ExternalPortEnd-rule.ExternalPortStart != rule.InternalPortEnd-rule.InternalPortStart {
		return errors.New("external and internal NAT port ranges must have equal lengths")
	}
	parsed, err := netip.ParseAddr(rule.InternalClient)
	if err != nil || !parsed.Is4() {
		return errors.New("NAT rule internal_client must be an IPv4 address")
	}
	return nil
}

func natPort(value any) (int64, bool) {
	var port int64
	switch v := value.(type) {
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		port = int64(v)
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return 0, false
		}
		port = parsed
	case int64:
		port = v
	case int:
		port = int64(v)
	default:
		return 0, false
	}
	return port, port >= 1 && port <= 65535
}

func normalizedNATProtocol(value any) (string, bool) {
	protocol, ok := value.(string)
	if !ok {
		return "", false
	}
	switch protocol {
	case "TCP":
		return "tcp", true
	case "UDP":
		return "udp", true
	case "TCP+UDP":
		return "both", true
	case "ALL":
		return "all", true
	default:
		return "", false
	}
}

func routerNATProtocol(protocol string) string {
	switch protocol {
	case "tcp":
		return "TCP"
	case "udp":
		return "UDP"
	case "all":
		return "ALL"
	default:
		return "TCP+UDP"
	}
}

func natRulesOverlap(left, right NATRule) bool {
	if left.ExternalPortEnd < right.ExternalPortStart || right.ExternalPortEnd < left.ExternalPortStart {
		return false
	}
	return left.Protocol == "both" || right.Protocol == "both" || left.Protocol == "all" || right.Protocol == "all" || left.Protocol == right.Protocol
}

func sameNATConfiguration(left, right NATRule) bool {
	return left.Name == right.Name && left.Protocol == right.Protocol && left.ExternalPortStart == right.ExternalPortStart && left.ExternalPortEnd == right.ExternalPortEnd && left.InternalClient == right.InternalClient && left.InternalPortStart == right.InternalPortStart && left.InternalPortEnd == right.InternalPortEnd
}

func findNATRule(rows []NATRule, name string) (*NATRule, error) {
	var found *NATRule
	for i := range rows {
		if rows[i].Name == name {
			if found != nil {
				return nil, errors.New("router returned multiple NAT rules with this name")
			}
			found = &rows[i]
		}
	}
	return found, nil
}
