package zyxel

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
	"strconv"
	"strings"
)

const (
	firewallACLOID       = "firewall_acl"
	firewallProtocolOID  = "firewall_proto"
	aclIPVersionIPv4     = "ipv4"
	aclIPVersionIPv6     = "ipv6"
	aclDirectionWANToLAN = "wan_to_lan"
	ACLOrderStrict       = "strict"
	ACLOrderAppend       = "append"
)

var ErrACLRuleNotFound = errors.New("ACL rule not found")

// ACLWriteRejectedError reports the firmware's explicit ACL write rejection.
type ACLWriteRejectedError struct {
	Method, OID, Result string
}

func (e *ACLWriteRejectedError) Error() string {
	return fmt.Sprintf("router rejected ACL %s for %s: %s", e.Method, e.OID, e.Result)
}

func aclResultCode(response map[string]any) string {
	code, ok := response["result"].(string)
	if !ok || !strings.HasPrefix(code, "ZCFG_") || len(code) > 80 || strings.IndexFunc(code, func(r rune) bool {
		return r != '_' && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) >= 0 {
		return "unknown result"
	}
	return code
}

type ACLRule struct {
	Name   string
	Action string
	Order  int64
	// OrderMode selects creation semantics. Empty means strict. Append requires
	// Order == 0; the returned rule contains the observed position, not a mode.
	OrderMode       string
	Protocol        string
	IPVersion       string
	Direction       string
	SourceCIDR      string
	DestinationCIDR string
	// MACAddress is the canonical colon-separated MAC filter. Empty means any
	// source MAC address.
	MACAddress string
	// Service is the name of a custom protocol/service group from the router's
	// firewall_proto table. Empty means no custom service.
	Service string
	// ServiceID is the native firewall_proto Iid, resolved to a current display
	// index before writing. It is mutually exclusive with Service and inline filters.
	ServiceID string
	// SourcePorts and DestinationPorts accept *, a port, or start-end. Do not
	// combine them with the corresponding legacy numeric bounds.
	SourcePorts, DestinationPorts string
	// TCPFlag is the lowercase TCP flag name (syn, ack, urg, psh, rst, fin) the
	// rule matches. Empty means any flag. Only valid for tcp and tcp_udp.
	TCPFlag string
	// DestinationPortStart and DestinationPortEnd are nil for any destination
	// port. Ports only apply to the tcp, udp, and tcp_udp protocols.
	DestinationPortStart *int64
	DestinationPortEnd   *int64
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
	if err := rule.expandPorts(); err != nil {
		return outcome, err
	}
	// Validate the profile before opening a session so invalid direct Go input
	// never reaches the network. The service index is resolved inside the
	// session because it requires a router table read.
	if err := rule.validateForWrite(); err != nil {
		return outcome, err
	}
	err := c.withSession(ctx, func(s *routerSession) error {
		var err error
		outcome, err = s.createACLRule(ctx, rule, false)
		return err
	})
	return outcome, err
}

func (s *routerSession) createACLRule(ctx context.Context, rule ACLRule, policyStaging bool) (ACLCreateOutcome, error) {
	var outcome ACLCreateOutcome
	err := func() error {
		serviceIndex, err := s.resolveACLServiceIndex(ctx, rule.Service, rule.ServiceID)
		if err != nil {
			return err
		}
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
		appendOrder := rule.OrderMode == ACLOrderAppend
		var maximum int64
		for _, row := range rows {
			order, ok := aclInt64(row["Order"])
			if !ok || order < 1 {
				return errors.New("router returned an ACL rule with an invalid order; refusing to create an ambiguous rule")
			}
			if !appendOrder && order == rule.Order {
				return fmt.Errorf("ACL order %d is already used by another router rule", rule.Order)
			}
			if order > maximum {
				maximum = order
			}
		}
		if appendOrder {
			if !policyStaging {
				if err := validateACLAppend(rows, rule.Action); err != nil {
					return err
				}
			}
			if maximum == math.MaxInt64 {
				return errors.New("ACL order cannot be incremented safely")
			}
			rule.Order, rule.OrderMode = maximum+1, ACLOrderStrict
		}
		payload, err := rule.dalPayload(serviceIndex)
		if err != nil {
			return err
		}

		response, err := s.writeDAL(ctx, http.MethodPost, firewallACLOID, "", payload)
		if err != nil {
			var ambiguous *AmbiguousWriteError
			var statusErr *responseStatusError
			outcome.Ambiguous = errors.As(err, &ambiguous) || (errors.As(err, &statusErr) && statusErr.status >= 500)
			return err
		}
		if response["result"] != "ZCFG_SUCCESS" {
			return &ACLWriteRejectedError{Method: http.MethodPost, OID: firewallACLOID, Result: aclResultCode(response)}
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
		if appendOrder {
			// Firmware may compact the whole table. Verify relative placement,
			// not equality to the numeric position submitted before the write.
			if err := verifyACLAppendPosition(rows, observed); err != nil {
				return fmt.Errorf("ACL rule was created but append verification failed: %w", err)
			}
			if !policyStaging {
				if err := verifyACLAppend(rows, observed); err != nil {
					return fmt.Errorf("ACL rule was created but append verification failed: %w", err)
				}
			}
			rule.Order = observed.Order
		}
		if differences := aclRuleDifferences(rule, observed); len(differences) > 0 {
			return fmt.Errorf("ACL rule was created but router readback differs in: %s", strings.Join(differences, ", "))
		}
		return nil
	}()
	return outcome, err
}

// Without verified insertion/reordering, an accept behind a terminal rule may
// never take effect. Keep unrelated profiles opaque and fail conservatively.
func validateACLAppend(rows []map[string]any, action string) error {
	if action != "accept" {
		return nil
	}
	for _, row := range rows {
		if enabled, ok := aclBool(row["Enable"]); ok && !enabled {
			continue
		}
		target, ok := aclString(row["Target"])
		if !ok || !strings.EqualFold(target, "accept") {
			return errors.New("cannot append an accept after an existing drop/reject or unknown action; safe insertion/reordering is not supported; review the complete policy before any writes")
		}
	}
	return nil
}

func verifyACLAppend(rows []map[string]any, observed ACLRule) error {
	if err := verifyACLAppendPosition(rows, observed); err != nil {
		return err
	}
	var others []map[string]any
	for _, row := range rows {
		if row["Name"] != observed.Name {
			others = append(others, row)
		}
	}
	return validateACLAppend(others, observed.Action)
}

func verifyACLAppendPosition(rows []map[string]any, observed ACLRule) error {
	orders := make(map[int64]bool, len(rows))
	for _, row := range rows {
		order, ok := aclInt64(row["Order"])
		if !ok || order < 1 || orders[order] {
			return errors.New("router returned invalid or duplicate ACL orders")
		}
		orders[order] = true
		if row["Name"] == observed.Name {
			continue
		}
		if order >= observed.Order {
			return errors.New("created rule is not last in the ACL table")
		}
	}
	return nil
}

func (c *Client) DeleteACLRule(ctx context.Context, name string) error {
	return c.withSession(ctx, func(s *routerSession) error {
		return s.deleteACLRule(ctx, name)
	})
}

func (s *routerSession) deleteACLRule(ctx context.Context, name string) error {
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
		return &ACLWriteRejectedError{Method: http.MethodDelete, OID: firewallACLOID, Result: aclResultCode(response)}
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
}

func (s *routerSession) readACLRows(ctx context.Context) ([]map[string]any, error) {
	return s.readDALObjects(ctx, firewallACLOID)
}

func (s *routerSession) readDALObjects(ctx context.Context, oid string) ([]map[string]any, error) {
	query := url.Values{"oid": {oid}, "sessionkey": {s.sessionKey}}
	response, err := s.get(ctx, "/cgi-bin/DAL?"+query.Encode())
	if err != nil {
		return nil, err
	}
	value, err := s.decryptResponse(response)
	if err != nil {
		return nil, err
	}
	if value["result"] != "ZCFG_SUCCESS" {
		return nil, fmt.Errorf("router rejected the %s table read request", oid)
	}
	if value["Object"] == nil {
		return []map[string]any{}, nil
	}
	objects, ok := value["Object"].([]any)
	if !ok {
		return nil, fmt.Errorf("router %s response did not contain a row list", oid)
	}
	rows := make([]map[string]any, 0, len(objects))
	for _, object := range objects {
		row, ok := object.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("router returned a malformed %s row", oid)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// resolveACLServiceIndex maps a service name or native ID to the display index the ACL
// write endpoint expects. Firmware converts that index to the stored object
// index, so sending the stored index from a read would target the wrong row
// after a deletion shifted the table.
func (s *routerSession) resolveACLServiceIndex(ctx context.Context, service, id string) (int64, error) {
	if service == "" && id == "" {
		return 0, nil
	}
	rows, err := s.readDALObjects(ctx, firewallProtocolOID)
	if err != nil {
		return 0, fmt.Errorf("reading custom services: %w", err)
	}
	var index int64
	for _, row := range rows {
		name, ok := aclString(row["Name"])
		iid, _ := aclString(row["Iid"])
		if (id != "" && iid != id) || (id == "" && (!ok || name != service)) {
			continue
		}
		if index != 0 {
			return 0, fmt.Errorf("router returned multiple custom services named %q", service)
		}
		value, ok := aclInt64(row["Index"])
		if !ok || value < 1 {
			return 0, fmt.Errorf("router returned an invalid index for custom service %q", service)
		}
		index = value
	}
	if index == 0 {
		return 0, fmt.Errorf("custom service %q does not exist on the router", service)
	}
	return index, nil
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

func (r *ACLRule) expandPorts() error {
	for _, pair := range []struct {
		value      *string
		start, end **int64
	}{
		{&r.SourcePorts, &r.SourcePortStart, &r.SourcePortEnd},
		{&r.DestinationPorts, &r.DestinationPortStart, &r.DestinationPortEnd},
	} {
		if *pair.value == "" {
			continue
		}
		if *pair.start != nil || *pair.end != nil {
			return errors.New("compact ports conflict with numeric port bounds")
		}
		if !aclProtocolUsesPorts(r.Protocol) {
			return errors.New("compact ports require tcp, udp, or tcp_udp")
		}
		if r.ServiceID != "" {
			return errors.New("service_id conflicts with inline ports")
		}
		start, end, err := ParsePorts(*pair.value)
		if err != nil {
			return err
		}
		*pair.start, *pair.end, *pair.value = start, end, ""
	}
	return nil
}

func (r ACLRule) validateForWrite() error {
	if err := r.expandPorts(); err != nil {
		return err
	}
	if r.ServiceID != "" {
		id, err := strconv.ParseInt(r.ServiceID, 10, 64)
		if err != nil || id < 1 || strconv.FormatInt(id, 10) != r.ServiceID {
			return errors.New("service_id must be a positive native service ID")
		}
		if r.Service != "" || r.SourcePortStart != nil || r.DestinationPortStart != nil || r.SourcePorts != "" || r.DestinationPorts != "" || r.TCPFlag != "" {
			return errors.New("service_id conflicts with service and inline port/TCP flag filters")
		}
		if r.Protocol != "all" {
			return errors.New("service_id requires the neutral all protocol; the referenced service selects the protocol")
		}
	}
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("ACL name must be non-empty")
	}
	switch r.OrderMode {
	case "", ACLOrderStrict:
		if r.Order < 1 {
			return errors.New("strict ACL order must be positive")
		}
	case ACLOrderAppend:
		if r.Order != 0 {
			return errors.New("append ACL mode requires order to be omitted (zero)")
		}
	default:
		return errors.New("ACL order mode must be strict or append")
	}
	if _, err := r.routerTarget(); err != nil {
		return err
	}
	if _, err := routerACLProtocol(r.Protocol); err != nil {
		return err
	}
	if _, err := r.routerIPVersion(); err != nil {
		return err
	}
	if _, err := r.routerDirection(); err != nil {
		return err
	}
	if _, err := aclMACAddress(r.MACAddress); err != nil {
		return err
	}
	if strings.TrimSpace(r.Service) != r.Service {
		return errors.New("ACL service name must not have leading or trailing whitespace")
	}
	if _, err := routerACLTCPFlag(r.TCPFlag); err != nil {
		return err
	}
	if r.TCPFlag != "" && !aclProtocolUsesTCPFlags(r.Protocol) {
		return errors.New("ACL TCP flags are only supported by the tcp and tcp_udp protocols")
	}
	version := aclIPVersionNumber(r.IPVersion)
	if _, _, err := splitCanonicalCIDR(r.SourceCIDR, version); err != nil {
		return fmt.Errorf("invalid source_cidr: %w", err)
	}
	if _, _, err := splitCanonicalCIDR(r.DestinationCIDR, version); err != nil {
		return fmt.Errorf("invalid destination_cidr: %w", err)
	}
	if (r.DestinationPortStart == nil) != (r.DestinationPortEnd == nil) {
		return errors.New("ACL destination port bounds must both be set or both be null")
	}
	if r.DestinationPortStart != nil {
		if !aclProtocolUsesPorts(r.Protocol) {
			return errors.New("ACL protocol does not use destination ports")
		}
		start, end := *r.DestinationPortStart, *r.DestinationPortEnd
		if start < 1 || start > 65535 || end < start || end > 65535 {
			return errors.New("ACL destination port range is invalid")
		}
	}
	if (r.SourcePortStart == nil) != (r.SourcePortEnd == nil) {
		return errors.New("ACL source port bounds must both be set or both be null")
	}
	if r.SourcePortStart != nil {
		if !aclProtocolUsesPorts(r.Protocol) {
			return errors.New("ACL protocol does not use source ports")
		}
		start, end := *r.SourcePortStart, *r.SourcePortEnd
		if start < 1 || start > 65535 || end < start || end > 65535 {
			return errors.New("ACL source port range is invalid")
		}
	}
	if r.RateLimit != nil {
		if r.Action != "accept" {
			return errors.New("ACL rate limiting requires the accept action")
		}
		if *r.RateLimit < 1 || *r.RateLimit > 512 {
			return errors.New("ACL rate limit must be between 1 and 512 packets per unit")
		}
		unit := r.RateLimitUnit
		if unit == "" {
			unit = "minute"
		}
		if unit != "minute" && unit != "second" {
			return errors.New("ACL rate limit unit must be minute or second")
		}
	}
	return nil
}

// dalPayload builds the router write body. serviceIndex is the display index
// resolved from the firewall_proto table; it is zero when no service is used.
func (r ACLRule) dalPayload(serviceIndex int64) (map[string]any, error) {
	if err := r.expandPorts(); err != nil {
		return nil, err
	}
	if err := r.validateForWrite(); err != nil {
		return nil, err
	}
	if (r.Service == "" && r.ServiceID == "") != (serviceIndex == 0) {
		return nil, errors.New("ACL service name and resolved service index must agree")
	}
	version := aclIPVersionNumber(r.IPVersion)
	sourceIP, sourceMask, err := splitCanonicalCIDR(r.SourceCIDR, version)
	if err != nil {
		return nil, fmt.Errorf("invalid source_cidr: %w", err)
	}
	destinationIP, destinationMask, err := splitCanonicalCIDR(r.DestinationCIDR, version)
	if err != nil {
		return nil, fmt.Errorf("invalid destination_cidr: %w", err)
	}
	target, _ := r.routerTarget()
	protocol, _ := routerACLProtocol(r.Protocol)
	ipVersion, _ := r.routerIPVersion()
	direction, _ := r.routerDirection()
	macAddress, _ := aclMACAddress(r.MACAddress)
	tcpFlag, _ := routerACLTCPFlag(r.TCPFlag)

	destStart, destEnd := int64(-1), int64(-1)
	if r.DestinationPortStart != nil {
		destStart, destEnd = *r.DestinationPortStart, *r.DestinationPortEnd
	}
	sourceStart, sourceEnd := int64(-1), int64(-1)
	if r.SourcePortStart != nil {
		sourceStart, sourceEnd = *r.SourcePortStart, *r.SourcePortEnd
	}
	rateLimitUnit := r.RateLimitUnit
	if rateLimitUnit == "" {
		rateLimitUnit = "minute"
	}
	payload := map[string]any{
		"Enable": r.Enabled, "Name": r.Name, "Interface": "ALL", "Order": r.Order,
		"Target": target, "IPVersion": ipVersion, "SourceIP": sourceIP, "SourceMask": sourceMask,
		"MACAddress": macAddress, "DestIP": destinationIP, "DestMask": destinationMask,
		"X_ZYXEL_ServiceIndex": serviceIndex, "Direction": direction, "X_ZYXEL_ScheduleRule": "",
		"Protocol": protocol, "SourcePort": sourceStart, "SourcePortRangeMax": sourceEnd,
		"DestPort": destStart, "DestPortRangeMax": destEnd,
		"IPv6header": "", "IPv6headertypes": "",
	}
	if tcpFlag != "" {
		payload["TCPFlag"] = tcpFlag
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
	case "reject":
		rule.Action = "reject"
	default:
		return rule, errors.New("ACL row uses an unsupported action")
	}
	protocol, err := normalizedACLProtocol(row["Protocol"])
	if err != nil {
		return rule, err
	}
	rule.Protocol = protocol
	version, ok := aclIPVersion(row["IPVersion"])
	if !ok || (version != 4 && version != 6) {
		return rule, errors.New("ACL row uses an unsupported IP version")
	}
	rule.IPVersion = aclIPVersionName(version)
	direction, err := normalizedACLDirection(row["Direction"])
	if err != nil {
		return rule, err
	}
	rule.Direction = direction
	macAddress, err := normalizedACLMAC(row["MACAddress"])
	if err != nil {
		return rule, err
	}
	rule.MACAddress = macAddress
	rule.SourceCIDR, ok = aclCIDR(row["SourceIP"], row["SourceMask"], version)
	if !ok {
		return rule, fmt.Errorf("ACL row has an invalid source %s CIDR", rule.IPVersion)
	}
	rule.DestinationCIDR, ok = aclCIDR(row["DestIP"], row["DestMask"], version)
	if !ok {
		return rule, fmt.Errorf("ACL row has an invalid destination %s CIDR", rule.IPVersion)
	}
	rule.TCPFlag, err = normalizedACLTCPFlag(row)
	if err != nil {
		return rule, err
	}
	if rule.TCPFlag != "" && !aclProtocolUsesTCPFlags(rule.Protocol) {
		return rule, errors.New("ACL row uses TCP flags for a protocol that does not support them")
	}
	serviceIndex, ok := aclInt64(row["X_ZYXEL_ServiceIndex"])
	if !ok || serviceIndex < 0 {
		return rule, errors.New("ACL row has an invalid service index")
	}
	if serviceIndex != 0 {
		rule.ServiceID = strconv.FormatInt(serviceIndex, 10)
		service, ok := aclString(row["ServiceName"])
		if !ok || strings.TrimSpace(service) == "" {
			return rule, errors.New("ACL row references a custom service that is no longer available")
		}
		rule.Service = service
	}
	destStart, destEnd, err := aclPortRange(row, "DestPort", "DestPortRangeMax")
	if err != nil {
		return rule, fmt.Errorf("ACL row has an invalid destination port range: %w", err)
	}
	if destStart != nil {
		if !aclProtocolUsesPorts(rule.Protocol) {
			return rule, errors.New("ACL row uses destination ports for a protocol that does not support them")
		}
		rule.DestinationPortStart, rule.DestinationPortEnd = destStart, destEnd
	}
	sourceStart, sourceEnd, err := aclPortRange(row, "SourcePort", "SourcePortRangeMax")
	if err != nil {
		return rule, fmt.Errorf("ACL row has an invalid source port range: %w", err)
	}
	if sourceStart != nil {
		if !aclProtocolUsesPorts(rule.Protocol) {
			return rule, errors.New("ACL row uses source ports for a protocol that does not support them")
		}
		rule.SourcePortStart, rule.SourcePortEnd = sourceStart, sourceEnd
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
	// Firmware drops the submitted Interface value from stored rows, so an
	// absent or empty value means the same "ALL" the create payload sends.
	// Interface selection is not exposed by this resource.
	if iface, ok := aclString(row["Interface"]); ok && iface != "" && iface != "ALL" {
		return errors.New("ACL row uses unsupported Interface profile value")
	}
	for _, key := range []string{"IPv6header", "IPv6headertypes"} {
		if value, ok := aclString(row[key]); !ok || value != "" {
			return fmt.Errorf("ACL row uses unsupported %s profile value", key)
		}
	}
	// "No schedule" is submitted as an empty string and stored as 0. Schedule
	// rules are intentionally not exposed yet.
	if schedule, ok := row["X_ZYXEL_ScheduleRule"]; ok {
		text, textOK := aclString(schedule)
		number, numberOK := aclInt64(schedule)
		if !(textOK && text == "") && !(numberOK && number == 0) {
			return errors.New("ACL row uses unsupported X_ZYXEL_ScheduleRule profile value")
		}
	}
	return nil
}

func normalizedACLProtocol(value any) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", errors.New("ACL row has no protocol")
	}
	switch strings.ToUpper(strings.TrimSpace(text)) {
	case "ALL":
		return "all", nil
	case "TCP":
		return "tcp", nil
	case "UDP":
		return "udp", nil
	case "TCPUDP", "TCP/UDP":
		return "tcp_udp", nil
	case "ICMP":
		return "icmp", nil
	case "ICMPV6":
		return "icmpv6", nil
	default:
		return "", fmt.Errorf("ACL row uses unsupported Protocol value %q", text)
	}
}

func routerACLProtocol(protocol string) (string, error) {
	switch protocol {
	case "all":
		return "ALL", nil
	case "tcp":
		return "TCP", nil
	case "udp":
		return "UDP", nil
	case "tcp_udp":
		return "TCPUDP", nil
	case "icmp":
		return "ICMP", nil
	case "icmpv6":
		return "ICMPv6", nil
	default:
		return "", errors.New("ACL protocol must be all, tcp_udp, tcp, udp, icmp, or icmpv6")
	}
}

func aclProtocolUsesPorts(protocol string) bool {
	return protocol == "tcp" || protocol == "udp" || protocol == "tcp_udp"
}

func aclProtocolUsesTCPFlags(protocol string) bool {
	return protocol == "tcp" || protocol == "tcp_udp"
}

func (r ACLRule) routerTarget() (string, error) {
	switch r.Action {
	case "accept":
		return "Accept", nil
	case "drop":
		return "Drop", nil
	case "reject":
		return "Reject", nil
	default:
		return "", errors.New("ACL action must be accept, drop, or reject")
	}
}

func normalizedACLDirection(value any) (string, error) {
	text, ok := aclString(value)
	if !ok {
		return "", errors.New("ACL row has no direction")
	}
	switch strings.ToUpper(strings.TrimSpace(text)) {
	case "", "WAN_TO_LAN":
		return aclDirectionWANToLAN, nil
	case "LAN_TO_WAN":
		return "lan_to_wan", nil
	case "WAN_TO_ROUTER":
		return "wan_to_router", nil
	case "LAN_TO_ROUTER":
		return "lan_to_router", nil
	default:
		return "", fmt.Errorf("ACL row uses unsupported Direction value %q", text)
	}
}

func (r ACLRule) routerDirection() (string, error) {
	switch r.Direction {
	case "", aclDirectionWANToLAN:
		return "WAN_TO_LAN", nil
	case "lan_to_wan":
		return "LAN_TO_WAN", nil
	case "wan_to_router":
		return "WAN_TO_ROUTER", nil
	case "lan_to_router":
		return "LAN_TO_ROUTER", nil
	default:
		return "", errors.New("ACL direction must be wan_to_lan, lan_to_wan, wan_to_router, or lan_to_router")
	}
}

func aclIPVersionName(version int64) string {
	if version == 6 {
		return aclIPVersionIPv6
	}
	return aclIPVersionIPv4
}

func aclIPVersionNumber(name string) int64 {
	if name == aclIPVersionIPv6 {
		return 6
	}
	return 4
}

func (r ACLRule) routerIPVersion() (string, error) {
	switch r.IPVersion {
	case "", aclIPVersionIPv4:
		return "IPv4", nil
	case aclIPVersionIPv6:
		return "IPv6", nil
	default:
		return "", errors.New("ACL IP version must be ipv4 or ipv6")
	}
}

// aclMACAddress validates and canonicalizes a MAC address for the router. The
// empty string means any source MAC address.
func aclMACAddress(value string) (string, error) {
	if value == "" {
		return "AnyMACAddress", nil
	}
	hardware, err := net.ParseMAC(value)
	if err != nil || len(hardware) != 6 {
		return "", errors.New("ACL MAC address must be six colon-separated hexadecimal octets")
	}
	return strings.ToUpper(hardware.String()), nil
}

func normalizedACLMAC(value any) (string, error) {
	text, ok := aclString(value)
	if !ok {
		return "", errors.New("ACL row has an invalid MAC address")
	}
	text = strings.TrimSpace(text)
	if text == "" || text == "AnyMACAddress" || strings.EqualFold(text, "any") {
		return "", nil
	}
	hardware, err := net.ParseMAC(text)
	if err != nil || len(hardware) != 6 {
		return "", errors.New("ACL row has an invalid MAC address")
	}
	return strings.ToUpper(hardware.String()), nil
}

func routerACLTCPFlag(flag string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "":
		return "", nil
	case "syn":
		return "SYN", nil
	case "ack":
		return "ACK", nil
	case "urg":
		return "URG", nil
	case "psh":
		return "PSH", nil
	case "rst":
		return "RST", nil
	case "fin":
		return "FIN", nil
	default:
		return "", errors.New("ACL TCP flag must be empty, syn, ack, urg, psh, rst, or fin")
	}
}

func normalizedACLTCPFlag(row map[string]any) (string, error) {
	mask, maskOK := aclString(row["X_ZYXEL_TCPFlagMask"])
	comparison, comparisonOK := aclString(row["X_ZYXEL_TCPFlagComp"])
	if (!maskOK && !comparisonOK) || (strings.TrimSpace(mask) == "" && strings.TrimSpace(comparison) == "") {
		return "", nil
	}
	if !maskOK || !comparisonOK || strings.ToUpper(strings.TrimSpace(mask)) != strings.ToUpper(strings.TrimSpace(comparison)) {
		return "", errors.New("ACL row uses an unsupported TCP flag mask")
	}
	flag, err := routerACLTCPFlag(strings.ToLower(strings.TrimSpace(mask)))
	if err != nil || flag == "" {
		return "", errors.New("ACL row uses an unsupported TCP flag mask")
	}
	return strings.ToLower(flag), nil
}

func aclPortRange(row map[string]any, startKey, endKey string) (*int64, *int64, error) {
	startValue, startExists := row[startKey]
	endValue, endExists := row[endKey]
	if !startExists && !endExists {
		return nil, nil, nil
	}
	start, startOK := aclInt64(startValue)
	end, endOK := aclInt64(endValue)
	if !startOK || !endOK {
		return nil, nil, errors.New("bounds must be numeric")
	}
	if start == -1 && end == -1 {
		return nil, nil, nil
	}
	if start >= 1 && start <= 65535 && end == -1 {
		end = start
	}
	if start < 1 || start > 65535 || end < start || end > 65535 {
		return nil, nil, errors.New("bounds must be an ordered range from 1 through 65535, or -1/-1 for any")
	}
	return &start, &end, nil
}

func aclRuleDifferences(want, got ACLRule) []string {
	var differences []string
	if want.Name != got.Name {
		differences = append(differences, "name")
	}
	if want.Action != got.Action {
		differences = append(differences, "action")
	}
	if want.Protocol != got.Protocol {
		differences = append(differences, "protocol")
	}
	wantVersion, gotVersion := want.IPVersion, got.IPVersion
	if wantVersion == "" {
		wantVersion = aclIPVersionIPv4
	}
	if gotVersion == "" {
		gotVersion = aclIPVersionIPv4
	}
	if wantVersion != gotVersion {
		differences = append(differences, "ip_version")
	}
	wantDirection, gotDirection := want.Direction, got.Direction
	if wantDirection == "" {
		wantDirection = aclDirectionWANToLAN
	}
	if gotDirection == "" {
		gotDirection = aclDirectionWANToLAN
	}
	if wantDirection != gotDirection {
		differences = append(differences, "direction")
	}
	if want.MACAddress != got.MACAddress {
		differences = append(differences, "mac_address")
	}
	if want.ServiceID != "" && want.ServiceID != got.ServiceID {
		differences = append(differences, "service_id")
	}
	if want.ServiceID == "" && want.Service != got.Service {
		differences = append(differences, "service")
	}
	if want.TCPFlag != got.TCPFlag {
		differences = append(differences, "tcp_flag")
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
	if !sameInt64Pointer(want.DestinationPortStart, got.DestinationPortStart) {
		differences = append(differences, "destination_port_start")
	}
	if !sameInt64Pointer(want.DestinationPortEnd, got.DestinationPortEnd) {
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

func splitCanonicalCIDR(value string, version int64) (string, string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", "", errors.New("must be an IP CIDR")
	}
	if version == 6 {
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return "", "", errors.New("must be an IPv6 CIDR")
		}
	} else if !prefix.Addr().Is4() {
		return "", "", errors.New("must be an IPv4 CIDR")
	}
	if prefix != prefix.Masked() {
		return "", "", errors.New("must use the canonical network address for its prefix")
	}
	return prefix.Addr().String(), strconv.Itoa(prefix.Bits()), nil
}

func aclCIDR(ipValue, maskValue any, version int64) (string, bool) {
	ip, ipOK := aclString(ipValue)
	mask, maskOK := aclStringOrInt(maskValue)
	ip = strings.TrimSpace(ip)
	mask = strings.TrimSpace(mask)
	anyAddress := !ipOK || ip == "" || ip == "*" || strings.EqualFold(ip, "any")
	anyMask := !maskOK || mask == "" || mask == "0"
	if anyAddress && anyMask {
		if version == 6 {
			return "::/0", true
		}
		return "0.0.0.0/0", true
	}
	if !ipOK || !maskOK {
		return "", false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	bits, err := strconv.Atoi(mask)
	if err != nil || bits < 0 {
		return "", false
	}
	if version == 6 {
		if !addr.Is6() || addr.Is4In6() || bits > 128 {
			return "", false
		}
	} else if !addr.Is4() || bits > 32 {
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
