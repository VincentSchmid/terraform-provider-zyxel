package zyxel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const firewallACLOID = "firewall_acl"

var ErrACLRuleNotFound = errors.New("ACL rule not found")

type ACLRule struct {
	Name                 string
	Action               string
	Order                int64
	SourceCIDR           string
	DestinationCIDR      string
	DestinationPortStart int64
	DestinationPortEnd   int64
	SourcePortStart      *int64
	SourcePortEnd        *int64
	Enabled              bool
	RateLimit            *int64
	RateLimitUnit        string
	RouterIndex          int64
}

// ACLCreateOutcome describes a write even when CreateACLRule returns an error.
// Applied means the router accepted the write, not that readback matched.
// Ambiguous means acceptance is unknown. Either requires identity reconciliation
// before retrying; Rule contains the observed supported row when available.
type ACLCreateOutcome struct {
	Applied   bool
	Ambiguous bool
	Rule      *ACLRule
}

func (c *Client) ReadACLRule(ctx context.Context, name string) (ACLRule, error) {
	var result ACLRule
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		row, err := findACLRow(rows, name)
		if err != nil {
			return err
		}
		if row == nil {
			return ErrACLRuleNotFound
		}
		result, err = parseACLRule(*row)
		return err
	})
	return result, err
}

func (c *Client) CreateACLRule(ctx context.Context, rule ACLRule) (ACLCreateOutcome, error) {
	var outcome ACLCreateOutcome
	payload, err := rule.dalPayload()
	if err != nil {
		return outcome, err
	}
	err = c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		match, err := findACLRow(rows, rule.Name)
		if err != nil {
			return err
		}
		if match != nil {
			return errors.New("an ACL rule with this name already exists; import it before managing it")
		}
		for _, row := range rows {
			order, ok := aclInt64(row["Order"])
			if !ok || order < 1 {
				return errors.New("router returned an ACL rule with an invalid order; refusing to create an ambiguous rule")
			}
			if order == rule.Order {
				return fmt.Errorf("ACL order %d is already used by another router rule", rule.Order)
			}
		}

		response, err := s.writeDAL(ctx, http.MethodPost, firewallACLOID, "", payload)
		if err != nil {
			var ambiguous *AmbiguousWriteError
			var statusErr *responseStatusError
			outcome.Ambiguous = errors.As(err, &ambiguous) || (errors.As(err, &statusErr) && statusErr.status >= 500)
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the ACL rule create request")
		}
		outcome.Applied = true

		rows, err = s.readACLRows(ctx)
		if err != nil {
			return fmt.Errorf("ACL rule was created but readback failed: %w", err)
		}
		match, err = findACLRow(rows, rule.Name)
		if err != nil {
			return fmt.Errorf("ACL rule was created but readback was ambiguous: %w", err)
		}
		if match == nil {
			return errors.New("ACL rule was created but was not present in router readback")
		}
		observed, err := parseACLRule(*match)
		if err != nil {
			return fmt.Errorf("ACL rule was created but its readback is unsupported: %w", err)
		}
		outcome.Rule = &observed
		if differences := aclRuleDifferences(rule, observed); len(differences) > 0 {
			return fmt.Errorf("ACL rule was created but router readback differs in: %s", strings.Join(differences, ", "))
		}
		return nil
	})
	return outcome, err
}

func (c *Client) DeleteACLRule(ctx context.Context, name string) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		row, err := findACLRow(rows, name)
		if err != nil {
			return err
		}
		if row == nil {
			return nil
		}
		index, ok := aclInt64((*row)["Index"])
		if !ok || index < 1 {
			return errors.New("router returned an invalid ACL index for the named rule")
		}
		response, err := s.writeDAL(ctx, http.MethodDelete, firewallACLOID, strconv.FormatInt(index, 10), map[string]any{})
		if err != nil {
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return errors.New("router rejected the ACL rule delete request")
		}
		rows, err = s.readACLRows(ctx)
		if err != nil {
			return fmt.Errorf("ACL rule delete was accepted but readback failed: %w", err)
		}
		remaining, err := findACLRow(rows, name)
		if err != nil {
			return err
		}
		if remaining != nil {
			return errors.New("ACL rule delete was accepted but the named rule remains")
		}
		return nil
	})
}

func (s *routerSession) readACLRows(ctx context.Context) ([]map[string]any, error) {
	query := url.Values{"oid": {firewallACLOID}, "sessionkey": {s.sessionKey}}
	response, err := s.get(ctx, "/cgi-bin/DAL?"+query.Encode())
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, errors.New("router rejected the ACL table read request")
	}
	if value["Object"] == nil {
		return []map[string]any{}, nil
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, errors.New("router ACL response did not contain a rule list")
	}
	rows := make([]map[string]any, 0, len(objects))
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, errors.New("router returned a malformed ACL row")
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func findACLRow(rows []map[string]any, name string) (*map[string]any, error) {
	var found *map[string]any
	for i := range rows {
		rowName, ok := rows[i]["Name"].(string)
		if !ok {
			continue
		}
		if rowName == name {
			if found != nil {
				return nil, errors.New("router returned multiple ACL rules with this name")
			}
			found = &rows[i]
		}
	}
	return found, nil
}

func (r ACLRule) dalPayload() (map[string]any, error) {
	sourceIP, sourceMask, err := splitCanonicalIPv4CIDR(r.SourceCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid source_cidr: %w", err)
	}
	destinationIP, destinationMask, err := splitCanonicalIPv4CIDR(r.DestinationCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid destination_cidr: %w", err)
	}
	target := ""
	switch r.Action {
	case "accept":
		target = "Accept"
	case "drop":
		target = "Drop"
	default:
		return nil, errors.New("ACL action must be accept or drop")
	}
	if strings.TrimSpace(r.Name) == "" || r.Order < 1 {
		return nil, errors.New("ACL name must be non-empty and order must be positive")
	}
	if r.DestinationPortStart < 1 || r.DestinationPortStart > 65535 || r.DestinationPortEnd < r.DestinationPortStart || r.DestinationPortEnd > 65535 {
		return nil, errors.New("ACL destination port range is invalid")
	}
	sourceStart, sourceEnd := int64(-1), int64(-1)
	if (r.SourcePortStart == nil) != (r.SourcePortEnd == nil) {
		return nil, errors.New("ACL source port bounds must both be set or both be null")
	}
	if r.SourcePortStart != nil {
		sourceStart, sourceEnd = *r.SourcePortStart, *r.SourcePortEnd
		if sourceStart < 1 || sourceStart > 65535 || sourceEnd < sourceStart || sourceEnd > 65535 {
			return nil, errors.New("ACL source port range is invalid")
		}
	}
	rateLimitUnit := r.RateLimitUnit
	if rateLimitUnit == "" {
		rateLimitUnit = "minute"
	}
	if r.RateLimit != nil {
		if target != "Accept" {
			return nil, errors.New("ACL rate limiting requires the accept action")
		}
		if *r.RateLimit < 1 || *r.RateLimit > 512 {
			return nil, errors.New("ACL rate limit must be between 1 and 512 packets per unit")
		}
		if rateLimitUnit != "minute" && rateLimitUnit != "second" {
			return nil, errors.New("ACL rate limit unit must be minute or second")
		}
	}
	payload := map[string]any{
		"Enable": r.Enabled, "Name": r.Name, "Interface": "ALL", "Order": r.Order,
		"Target": target, "IPVersion": "IPv4", "SourceIP": sourceIP, "SourceMask": sourceMask,
		"MACAddress": "AnyMACAddress", "DestIP": destinationIP, "DestMask": destinationMask,
		"X_ZYXEL_ServiceIndex": 0, "Direction": "WAN_TO_LAN", "X_ZYXEL_ScheduleRule": "",
		"Protocol": "TCP", "SourcePort": sourceStart, "SourcePortRangeMax": sourceEnd,
		"DestPort": r.DestinationPortStart, "DestPortRangeMax": r.DestinationPortEnd,
		"IPv6header": "", "IPv6headertypes": "",
	}
	if r.RateLimit != nil {
		payload["LimitRate"] = *r.RateLimit
		payload["LimitRateUnit"] = rateLimitUnit
	}
	return payload, nil
}

func parseACLRule(row map[string]any) (ACLRule, error) {
	var rule ACLRule
	name, ok := aclString(row["Name"])
	if !ok || strings.TrimSpace(name) == "" {
		return rule, errors.New("ACL row has no valid name")
	}
	rule.Name = name
	rule.RouterIndex, ok = aclInt64(row["Index"])
	if !ok || rule.RouterIndex < 1 {
		return rule, errors.New("ACL row has an invalid index")
	}
	rule.Order, ok = aclInt64(row["Order"])
	if !ok || rule.Order < 1 {
		return rule, errors.New("ACL row has an invalid order")
	}
	target, ok := aclString(row["Target"])
	if !ok {
		return rule, errors.New("ACL row has no action")
	}
	switch strings.ToLower(target) {
	case "accept":
		rule.Action = "accept"
	case "drop":
		rule.Action = "drop"
	default:
		return rule, errors.New("ACL row uses an unsupported action")
	}
	rule.SourceCIDR, ok = aclCIDR(row["SourceIP"], row["SourceMask"], true)
	if !ok {
		return rule, errors.New("ACL row has an invalid source IPv4 CIDR")
	}
	rule.DestinationCIDR, ok = aclCIDR(row["DestIP"], row["DestMask"], false)
	if !ok {
		return rule, errors.New("ACL row has an invalid destination IPv4 CIDR")
	}
	rule.DestinationPortStart, ok = aclInt64(row["DestPort"])
	if !ok || rule.DestinationPortStart < 1 || rule.DestinationPortStart > 65535 {
		return rule, errors.New("ACL row has an invalid destination port")
	}
	rule.DestinationPortEnd, ok = aclInt64(row["DestPortRangeMax"])
	if !ok || rule.DestinationPortEnd < rule.DestinationPortStart || rule.DestinationPortEnd > 65535 {
		return rule, errors.New("ACL row has an invalid destination port range")
	}
	sourceStart, startOK := aclInt64(row["SourcePort"])
	sourceEnd, endOK := aclInt64(row["SourcePortRangeMax"])
	if !startOK || !endOK {
		return rule, errors.New("ACL row has invalid source port bounds")
	}
	if sourceStart == -1 && sourceEnd == -1 {
		rule.SourcePortStart, rule.SourcePortEnd = nil, nil
	} else {
		if sourceStart < 1 || sourceStart > 65535 || sourceEnd < sourceStart || sourceEnd > 65535 {
			return rule, errors.New("ACL row has an invalid source port range")
		}
		rule.SourcePortStart, rule.SourcePortEnd = &sourceStart, &sourceEnd
	}
	rule.Enabled, ok = aclBool(row["Enable"])
	if !ok {
		return rule, errors.New("ACL row has an invalid enabled flag")
	}
	rule.RateLimitUnit = "minute"
	if value, exists := row["LimitRate"]; exists && value != nil {
		if text, textOK := aclString(value); textOK && strings.TrimSpace(text) == "" {
			// The UI omits the field when rate limiting is disabled; some
			// firmware builds may store an empty string instead.
		} else {
			rateLimit, rateOK := aclInt64(value)
			if !rateOK || rateLimit < 0 || rateLimit > 512 {
				return rule, errors.New("ACL row has an invalid rate limit")
			}
			if rateLimit > 0 {
				rule.RateLimit = &rateLimit
			}
		}
	}
	if rule.RateLimit != nil {
		if rule.Action != "accept" {
			return rule, errors.New("ACL row uses an unsupported rate limit for its action")
		}
		if value, exists := row["LimitRateUnit"]; exists && value != nil {
			unit, unitOK := aclString(value)
			unit = strings.ToLower(strings.TrimSpace(unit))
			if !unitOK || (unit != "" && unit != "minute" && unit != "second") {
				return rule, errors.New("ACL row has an invalid rate limit unit")
			}
			if unit != "" {
				rule.RateLimitUnit = unit
			}
		}
	}
	if err := validateACLProfile(row); err != nil {
		return rule, err
	}
	return rule, nil
}

func validateACLProfile(row map[string]any) error {
	profileChecks := []struct {
		key, want string
	}{
		{"Protocol", "TCP"}, {"Direction", "WAN_TO_LAN"},
		{"MACAddress", "AnyMACAddress"},
		{"IPv6header", ""}, {"IPv6headertypes", ""},
	}
	for _, check := range profileChecks {
		got, ok := aclString(row[check.key])
		if !ok || got != check.want {
			return fmt.Errorf("ACL row uses unsupported %s profile value", check.key)
		}
	}
	// Firmware drops the submitted Interface value from stored rows, so an
	// absent or empty value means the same "ALL" the create payload sends.
	if iface, ok := aclString(row["Interface"]); ok && iface != "" && iface != "ALL" {
		return errors.New("ACL row uses unsupported Interface profile value")
	}
	// "No schedule" is submitted as an empty string and stored as 0.
	if schedule, ok := row["X_ZYXEL_ScheduleRule"]; ok {
		text, textOK := aclString(schedule)
		number, numberOK := aclInt64(schedule)
		if !(textOK && text == "") && !(numberOK && number == 0) {
			return errors.New("ACL row uses unsupported X_ZYXEL_ScheduleRule profile value")
		}
	}
	serviceIndex, ok := aclInt64(row["X_ZYXEL_ServiceIndex"])
	if !ok || serviceIndex != 0 {
		return errors.New("ACL row uses an unsupported service profile")
	}
	version, ok := aclIPVersion(row["IPVersion"])
	if !ok || version != 4 {
		return errors.New("ACL row uses an unsupported IP version")
	}
	return nil
}

func aclRuleDifferences(want, got ACLRule) []string {
	var differences []string
	if want.Name != got.Name {
		differences = append(differences, "name")
	}
	if want.Action != got.Action {
		differences = append(differences, "action")
	}
	if want.Order != got.Order {
		differences = append(differences, "order")
	}
	if want.SourceCIDR != got.SourceCIDR {
		differences = append(differences, "source_cidr")
	}
	if want.DestinationCIDR != got.DestinationCIDR {
		differences = append(differences, "destination_cidr")
	}
	if want.DestinationPortStart != got.DestinationPortStart {
		differences = append(differences, "destination_port_start")
	}
	if want.DestinationPortEnd != got.DestinationPortEnd {
		differences = append(differences, "destination_port_end")
	}
	if !sameInt64Pointer(want.SourcePortStart, got.SourcePortStart) {
		differences = append(differences, "source_port_start")
	}
	if !sameInt64Pointer(want.SourcePortEnd, got.SourcePortEnd) {
		differences = append(differences, "source_port_end")
	}
	if want.Enabled != got.Enabled {
		differences = append(differences, "enabled")
	}
	if !sameInt64Pointer(want.RateLimit, got.RateLimit) {
		differences = append(differences, "rate_limit")
	}
	wantUnit, gotUnit := want.RateLimitUnit, got.RateLimitUnit
	if wantUnit == "" {
		wantUnit = "minute"
	}
	if gotUnit == "" {
		gotUnit = "minute"
	}
	if wantUnit != gotUnit {
		differences = append(differences, "rate_limit_unit")
	}
	return differences
}

func sameInt64Pointer(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func splitCanonicalIPv4CIDR(value string) (string, string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return "", "", errors.New("must be an IPv4 CIDR")
	}
	if prefix != prefix.Masked() {
		return "", "", errors.New("must use the canonical network address for its prefix")
	}
	return prefix.Addr().String(), strconv.Itoa(prefix.Bits()), nil
}

func aclCIDR(ipValue, maskValue any, allowAny bool) (string, bool) {
	ip, ipOK := aclString(ipValue)
	mask, maskOK := aclStringOrInt(maskValue)
	if allowAny && (!ipOK || strings.TrimSpace(ip) == "" || ip == "*" || strings.EqualFold(ip, "any")) && (!maskOK || strings.TrimSpace(mask) == "" || strings.TrimSpace(mask) == "0") {
		return "0.0.0.0/0", true
	}
	if allowAny && ipOK && ip == "0.0.0.0" && (!maskOK || strings.TrimSpace(mask) == "" || strings.TrimSpace(mask) == "0") {
		return "0.0.0.0/0", true
	}
	if !ipOK || !maskOK {
		return "", false
	}
	ip = strings.TrimSpace(ip)
	mask = strings.TrimSpace(mask)
	if allowAny && (ip == "" || ip == "*" || strings.EqualFold(ip, "any")) && (mask == "" || mask == "0") {
		return "0.0.0.0/0", true
	}
	if allowAny && ip == "0.0.0.0" && (mask == "" || mask == "0") {
		return "0.0.0.0/0", true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return "", false
	}
	bits, err := strconv.Atoi(mask)
	if err != nil || bits < 0 || bits > 32 {
		return "", false
	}
	return netip.PrefixFrom(addr, bits).Masked().String(), true
}

func aclString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	default:
		return "", false
	}
}

func aclStringOrInt(value any) (string, bool) { return aclString(value) }

func aclInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		if v == float64(int64(v)) {
			return int64(v), true
		}
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		return parsed, err == nil
	case interface{ Int64() (int64, error) }:
		parsed, err := v.Int64()
		return parsed, err == nil
	}
	return 0, false
}

func aclBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true, true
		case "false", "0", "no":
			return false, true
		}
	case float64:
		if v == 1 {
			return true, true
		}
		if v == 0 {
			return false, true
		}
	case int:
		if v == 1 {
			return true, true
		}
		if v == 0 {
			return false, true
		}
	case int64:
		if v == 1 {
			return true, true
		}
		if v == 0 {
			return false, true
		}
	}
	return false, false
}

func aclIPVersion(value any) (int64, bool) {
	if text, ok := aclString(value); ok {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "ipv4", "4":
			return 4, true
		case "ipv6", "6":
			return 6, true
		}
	}
	return aclInt64(value)
}
