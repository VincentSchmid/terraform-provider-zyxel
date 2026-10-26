package zyxel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// ACLPolicy owns a contiguous tail of the ACL table. Rules are ordered accepts
// followed by one enabled, unrestricted-source drop covering the same filters.
// Names in Rules are logical names; the API creates generation-qualified names.
type ACLPolicy struct {
	Name  string
	Rules []ACLRule
}

// ACLPolicyState is the recoverable ownership ledger, not a prefix-adoption hint.
// Keep Names even on errors: a named write may have succeeded without readback.
type ACLPolicyState struct {
	Name       string
	Generation string
	Names      []string
	Rules      []ACLRule
}

type ACLPolicyOutcome struct {
	State   ACLPolicyState
	Changed bool
}

// Validate checks the deliberately restricted policy shape without networking.
func (p ACLPolicy) Validate() error {
	if strings.TrimSpace(p.Name) != p.Name || p.Name == "" || len(p.Name) > 48 {
		return errors.New("ACL policy name must be 1-48 bytes without surrounding whitespace")
	}
	if len(p.Rules) < 1 || len(p.Rules) > 999 {
		return errors.New("ACL policy requires 1-999 rules, ending in a catch-all drop")
	}
	seen := map[string]bool{}
	last := p.Rules[len(p.Rules)-1]
	for i, r := range p.Rules {
		if seen[r.Name] || strings.TrimSpace(r.Name) != r.Name || r.Name == "" {
			return errors.New("ACL policy logical rule names must be unique and non-empty without surrounding whitespace")
		}
		seen[r.Name] = true
		if r.Order != 0 || r.OrderMode != "" || !r.Enabled {
			return errors.New("ACL policy rules must be enabled and must omit order and order mode")
		}
		if i < len(p.Rules)-1 && r.Action != "accept" || i == len(p.Rules)-1 && r.Action != "drop" {
			return errors.New("ACL policy must contain only accepts followed by one final drop")
		}
		r.Order = 1
		if err := r.validateForWrite(); err != nil {
			return fmt.Errorf("ACL policy rule %d: %w", i+1, err)
		}
		if r.Service != "" || r.ServiceID != "" || r.MACAddress != "" || r.TCPFlag != "" || r.RateLimit != nil {
			return errors.New("ACL policy supports inline filters only, without services, MAC, TCP flag or rate-limit filters")
		}
		if !sameACLPolicyScope(r, last) {
			return errors.New("ACL policy rules must share protocol, address family, direction, destination CIDR and port filters")
		}
	}
	anySource := "0.0.0.0/0"
	if last.IPVersion == "ipv6" {
		anySource = "::/0"
	}
	if last.SourceCIDR != anySource {
		return errors.New("final ACL policy drop must match any source in its address family")
	}
	return nil
}

func sameACLPolicyScope(a, b ACLRule) bool {
	_ = a.expandPorts()
	_ = b.expandPorts()
	a.Name, b.Name = "scope", "scope"
	a.Action, b.Action = "drop", "drop"
	a.Order, b.Order = 1, 1
	a.SourceCIDR, b.SourceCIDR = "0.0.0.0/0", "0.0.0.0/0"
	a.RateLimit, b.RateLimit = nil, nil
	a.RateLimitUnit, b.RateLimitUnit = "minute", "minute"
	return len(aclRuleDifferences(a, b)) == 0
}

func aclPolicyPrefix(name string) string { return name + "-g" }

func aclPolicyRowName(name, generation string, i int) string {
	return fmt.Sprintf("%s%s-%03d", aclPolicyPrefix(name), generation, i+1)
}

func policyGeneration() (string, error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", errors.New("could not generate ACL policy generation")
	}
	return hex.EncodeToString(bytes[:]), nil
}

// ApplyACLPolicy stages a complete new tail behind the old drop, verifies it,
// then removes the old accepts and finally its drop. It never uses PUT/reorder.
// Updates cannot change the traffic scope. Partial failures require operator
// reconciliation; do not retry without inspecting the returned ownership ledger.
func (c *Client) ApplyACLPolicy(ctx context.Context, desired ACLPolicy, previous *ACLPolicyState) (ACLPolicyOutcome, error) {
	var out ACLPolicyOutcome
	if previous != nil {
		out.State = *previous
		out.State.Names = append([]string(nil), previous.Names...)
	}
	if err := desired.Validate(); err != nil {
		return out, err
	}
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		prefix, err := inspectACLPolicyTable(rows, desired.Name, previous)
		if err != nil {
			return err
		}
		if previous != nil {
			if !sameACLPolicyScope(desired.Rules[len(desired.Rules)-1], previous.Rules[len(previous.Rules)-1]) {
				return errors.New("ACL policy scope changes are unsupported; review a separate migration before writes")
			}
		}
		generation, err := policyGeneration()
		if err != nil {
			return err
		}
		staged := ACLPolicyState{Name: desired.Name, Generation: generation}
		if previous == nil {
			out.State = staged
		}
		for i, logical := range desired.Rules {
			rule := logical
			rule.Name = aclPolicyRowName(desired.Name, generation, i)
			rule.OrderMode = ACLOrderAppend
			if err := rule.expandPorts(); err != nil {
				return err
			}
			created, err := s.createACLRule(ctx, rule, true)
			if created.Applied || created.Ambiguous {
				out.Changed = true
				out.State.Names = append(out.State.Names, rule.Name)
			}
			if err != nil {
				return fmt.Errorf("ACL policy staging failed; retain state and reconcile before retrying: %w", err)
			}
			staged.Names = append(staged.Names, rule.Name)
			staged.Rules = append(staged.Rules, *created.Rule)
		}
		// Do not retire any old protection until the entire staged block,
		// including its final drop, has been read back and verified.
		if err := s.verifyStagedACLPolicy(ctx, prefix, previous, staged); err != nil {
			return err
		}
		if previous != nil {
			for _, name := range previous.Names {
				if err := s.verifyStagedACLPolicy(ctx, prefix, nil, staged); err != nil {
					return err
				}
				if err := s.deleteACLRule(ctx, name); err != nil {
					return fmt.Errorf("ACL policy retirement failed; retain both generations for recovery: %w", err)
				}
				out.Changed = true
			}
		}
		rows, err = s.readACLRows(ctx)
		if err != nil {
			return err
		}
		// Deletions can compact positions; compare every field except numeric
		// order and then record the final observations for the whole block.
		observed, err := observeACLPolicy(rows, staged)
		if err != nil {
			return err
		}
		if _, err := inspectACLPolicyTable(rows, desired.Name, &observed); err != nil {
			return err
		}
		out.State = observed
		return nil
	})
	return out, err
}

func (s *routerSession) verifyStagedACLPolicy(ctx context.Context, prefix []map[string]any, previous *ACLPolicyState, staged ACLPolicyState) error {
	rows, err := s.readACLRows(ctx)
	if err != nil {
		return err
	}
	if _, err := observeACLPolicy(rows, staged); err != nil {
		return err
	}
	ordered := append([]map[string]any(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		a, _ := aclInt64(ordered[i]["Order"])
		b, _ := aclInt64(ordered[j]["Order"])
		return a < b
	})
	seenOrders := map[int64]bool{}
	for i, row := range ordered {
		order, ok := aclInt64(row["Order"])
		if !ok || order < 1 || seenOrders[order] {
			return errors.New("invalid or duplicate ACL orders while staging")
		}
		seenOrders[order] = true
		if i >= len(ordered)-len(staged.Names) && row["Name"] != staged.Names[i-(len(ordered)-len(staged.Names))] {
			return errors.New("staged ACL policy is not the contiguous tail; refusing further writes")
		}
	}
	if previous != nil {
		if _, err := observeACLPolicy(rows, *previous); err != nil {
			return err
		}
	}
	currentPrefix := []map[string]any{}
	for _, row := range ordered {
		name, _ := row["Name"].(string)
		if !strings.HasPrefix(name, aclPolicyPrefix(staged.Name)) {
			currentPrefix = append(currentPrefix, aclPolicyComparableRow(row))
		}
	}
	if !reflect.DeepEqual(prefix, currentPrefix) {
		return errors.New("unrelated ACL prefix changed while staging policy; refusing further writes")
	}
	return nil
}

func aclPolicyComparableRow(row map[string]any) map[string]any {
	copy := make(map[string]any, len(row))
	for k, v := range row {
		if k != "Order" && k != "Index" {
			copy[k] = v
		}
	}
	return copy
}

// inspectACLPolicyTable rejects adoption, untracked generations, interleaving,
// terminal prefix rules and stale/incomplete ledgers before any mutation.
func inspectACLPolicyTable(rows []map[string]any, name string, previous *ACLPolicyState) ([]map[string]any, error) {
	if previous != nil {
		if previous.Name != name || len(previous.Names) == 0 || len(previous.Names) != len(previous.Rules) {
			return nil, errors.New("incomplete ACL policy ledger; operator recovery required")
		}
		policy := ACLPolicy{Name: name, Rules: append([]ACLRule(nil), previous.Rules...)}
		for i := range policy.Rules {
			policy.Rules[i].Order = 0
		}
		if err := policy.Validate(); err != nil {
			return nil, fmt.Errorf("invalid ACL policy ledger: %w", err)
		}
		if _, err := observeACLPolicy(rows, *previous); err != nil {
			return nil, err
		}
	}
	owned := map[string]bool{}
	if previous != nil {
		for _, n := range previous.Names {
			owned[n] = true
		}
	}
	sorted := append([]map[string]any(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		a, _ := aclInt64(sorted[i]["Order"])
		b, _ := aclInt64(sorted[j]["Order"])
		return a < b
	})
	prefix := []map[string]any{}
	seenOrder := map[int64]bool{}
	policyStarted := false
	for _, row := range sorted {
		order, ok := aclInt64(row["Order"])
		if !ok || order < 1 || seenOrder[order] {
			return nil, errors.New("ACL table has invalid or duplicate orders")
		}
		seenOrder[order] = true
		n, _ := row["Name"].(string)
		if strings.HasPrefix(n, aclPolicyPrefix(name)) && !owned[n] {
			return nil, errors.New("ACL policy namespace already exists outside its ownership ledger; explicit import/recovery required")
		}
		if owned[n] {
			policyStarted = true
			continue
		}
		if policyStarted {
			return nil, errors.New("ACL policy must own a contiguous tail; unrelated rules follow or interleave it")
		}
		prefix = append(prefix, aclPolicyComparableRow(row))
	}
	if err := validateACLAppend(prefix, "accept"); err != nil {
		return nil, err
	}
	return prefix, nil
}

func observeACLPolicy(rows []map[string]any, state ACLPolicyState) (ACLPolicyState, error) {
	observed := state
	observed.Rules = nil
	var lastOrder int64
	for i, name := range state.Names {
		if name != aclPolicyRowName(state.Name, state.Generation, i) || i >= len(state.Rules) {
			return state, errors.New("ACL policy has an incomplete ownership ledger; operator recovery required")
		}
		row, err := findACLRow(rows, name)
		if err != nil {
			return state, err
		}
		if row == nil {
			return state, errors.New("ACL policy row is missing; operator recovery required")
		}
		rule, err := parseACLRule(*row)
		if err != nil {
			return state, err
		}
		want := state.Rules[i]
		want.Order = rule.Order
		if diff := aclRuleDifferences(want, rule); len(diff) != 0 {
			return state, fmt.Errorf("ACL policy readback differs in: %s", strings.Join(diff, ", "))
		}
		if rule.Order <= lastOrder {
			return state, errors.New("ACL policy rules are not in the intended evaluation order")
		}
		lastOrder = rule.Order
		observed.Rules = append(observed.Rules, rule)
	}
	return observed, nil
}

func (c *Client) ReadACLPolicy(ctx context.Context, state ACLPolicyState) (ACLPolicyState, error) {
	var observed ACLPolicyState
	err := c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		if _, err := inspectACLPolicyTable(rows, state.Name, &state); err != nil {
			return err
		}
		observed, err = observeACLPolicy(rows, state)
		return err
	})
	return observed, err
}

// ImportACLPolicy explicitly adopts a single complete generation by exact
// policy name and generation token. It rejects mixed/partial generations.
func (c *Client) ImportACLPolicy(ctx context.Context, name, generation string) (ACLPolicyState, error) {
	state := ACLPolicyState{Name: name, Generation: generation}
	decoded, err := hex.DecodeString(generation)
	if err != nil || len(decoded) != 8 || hex.EncodeToString(decoded) != generation {
		return state, errors.New("ACL policy generation must be 16 lowercase hexadecimal characters")
	}
	err = c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		for i := 0; i < 999; i++ {
			n := aclPolicyRowName(name, generation, i)
			row, err := findACLRow(rows, n)
			if err != nil {
				return err
			}
			if row == nil {
				break
			}
			rule, err := parseACLRule(*row)
			if err != nil {
				return err
			}
			state.Names = append(state.Names, n)
			state.Rules = append(state.Rules, rule)
		}
		policy := ACLPolicy{Name: name, Rules: append([]ACLRule(nil), state.Rules...)}
		for i := range policy.Rules {
			policy.Rules[i].Order = 0
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		_, err = inspectACLPolicyTable(rows, name, &state)
		return err
	})
	return state, err
}

// DeleteACLPolicy deletes only exact tracked names, with all drops last. It can
// clean up a partial staging ledger, but never discovers/adopts untracked rows.
func (c *Client) DeleteACLPolicy(ctx context.Context, state ACLPolicyState) error {
	return c.withSession(ctx, func(s *routerSession) error {
		rows, err := s.readACLRows(ctx)
		if err != nil {
			return err
		}
		var accepts, drops []string
		seen := map[string]bool{}
		for _, name := range state.Names {
			if !strings.HasPrefix(name, aclPolicyPrefix(state.Name)) || seen[name] {
				return errors.New("invalid ACL policy ownership ledger")
			}
			seen[name] = true
			row, err := findACLRow(rows, name)
			if err != nil {
				return err
			}
			if row == nil {
				continue
			}
			rule, err := parseACLRule(*row)
			if err != nil {
				return err
			}
			if rule.Action == "accept" {
				accepts = append(accepts, name)
			} else {
				drops = append(drops, name)
			}
		}
		for _, name := range append(accepts, drops...) {
			if err := s.deleteACLRule(ctx, name); err != nil {
				return err
			}
		}
		return nil
	})
}
