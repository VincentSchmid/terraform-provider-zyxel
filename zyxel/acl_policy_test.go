package zyxel

import "testing"

func validTestPolicy() ACLPolicy {
	a, d := testACLRule("accept", "accept", 0), testACLRule("drop", "drop", 0)
	d.SourceCIDR = "0.0.0.0/0"
	return ACLPolicy{ManagementRules: []ACLRule{testACLRule("management", "accept", 0)}, Rules: []ACLRule{a, d}}
}

// servicePolicyRules mirrors the ACL rule parameters the provider adapter sends
// for rules that reference a custom service instead of inline filters.
func servicePolicyRules(serviceID string) []ACLRule {
	a, d := testACLRule("accept", "accept", 0), testACLRule("drop", "drop", 0)
	d.SourceCIDR = "0.0.0.0/0"
	rules := []ACLRule{a, d}
	for i := range rules {
		rules[i].Protocol, rules[i].ServiceID = "all", serviceID
		rules[i].DestinationPortStart, rules[i].DestinationPortEnd = nil, nil
	}
	return rules
}

func TestACLPolicyServiceRulesArePerRule(t *testing.T) {
	for name, p := range map[string]ACLPolicy{
		"same service":  {Rules: servicePolicyRules("101")},
		"resolved name": {Rules: servicePolicyRules("101")},
		"different services": {Rules: func() []ACLRule {
			rules := servicePolicyRules("101")
			rules[1].ServiceID = "102"
			return rules
		}()},
		"service only accept, inline drop": {Rules: func() []ACLRule {
			rules := servicePolicyRules("101")
			rules[1].Protocol, rules[1].ServiceID = "tcp", ""
			rules[1].DestinationPortStart, rules[1].DestinationPortEnd = int64Pointer(443), int64Pointer(443)
			return rules
		}()},
		"service name only": {Rules: func() []ACLRule {
			rules := servicePolicyRules("101")
			for i := range rules {
				rules[i].Service, rules[i].ServiceID = "https", ""
				rules[i].Protocol = "tcp"
				rules[i].DestinationPortStart, rules[i].DestinationPortEnd = int64Pointer(443), int64Pointer(443)
			}
			return rules
		}()},
	} {
		if name == "resolved name" {
			for i := range p.Rules {
				p.Rules[i].Service = "https"
			}
		}
		p.ManagementRules = validTestPolicy().ManagementRules
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: rejected supported policy: %v", name, err)
		}
	}
	for name, edit := range map[string]func(*ACLPolicy){
		"inline protocol with service_id": func(p *ACLPolicy) { p.Rules[0].Protocol = "tcp" },
		"inline ports with service_id": func(p *ACLPolicy) {
			p.Rules[0].DestinationPortStart, p.Rules[0].DestinationPortEnd = int64Pointer(443), int64Pointer(443)
		},
		"compact ports with service_id": func(p *ACLPolicy) { p.Rules[0].DestinationPorts = "443" },
		"tcp flag with service_id":      func(p *ACLPolicy) { p.Rules[0].TCPFlag = "syn" },
	} {
		p := ACLPolicy{Rules: servicePolicyRules("101")}
		edit(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("%s: accepted unsafe policy: %#v", name, p)
		}
	}
}

func TestACLPolicyValidation(t *testing.T) {
	if err := validTestPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*ACLPolicy){
		func(p *ACLPolicy) { p.Rules = nil },
		func(p *ACLPolicy) { p.Rules[1].Action = "accept" },
		func(p *ACLPolicy) { p.Rules = append(p.Rules, testACLRule("late", "accept", 0)) },
		func(p *ACLPolicy) { p.Rules[0].Order = 1 },
		func(p *ACLPolicy) { p.Rules[0].Enabled = false },
		func(p *ACLPolicy) { p.Rules[0].Name = p.Rules[1].Name },
		func(p *ACLPolicy) { p.Rules[0].Action = "redirect" },
		func(p *ACLPolicy) { p.Rules[1].RateLimit = int64Pointer(10) },
	} {
		p := validTestPolicy()
		edit(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted unsafe policy: %#v", p)
		}
	}
	// Heterogeneous scopes and multiple drops are supported.
	for _, p := range []ACLPolicy{
		{Rules: func() []ACLRule {
			accept := testACLRule("accept", "accept", 0)
			accept.DestinationPortStart, accept.DestinationPortEnd = int64Pointer(5006), int64Pointer(5006)
			first := testACLRule("drop-1", "drop", 0)
			first.DestinationPortStart, first.DestinationPortEnd = int64Pointer(443), int64Pointer(443)
			second := testACLRule("drop-2", "reject", 0)
			second.SourceCIDR = "0.0.0.0/0"
			return []ACLRule{accept, first, second}
		}()},
		{Rules: func() []ACLRule {
			first := testACLRule("drop-1", "drop", 0)
			second := testACLRule("drop-2", "drop", 0)
			return []ACLRule{first, second}
		}()},
	} {
		p.ManagementRules = validTestPolicy().ManagementRules
		if err := p.Validate(); err != nil {
			t.Fatalf("rejected supported policy: %v", err)
		}
	}
}
