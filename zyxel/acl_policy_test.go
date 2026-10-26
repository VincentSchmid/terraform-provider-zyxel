package zyxel

import "testing"

func validTestPolicy() ACLPolicy {
	a, d := testACLRule("accept", "accept", 0), testACLRule("drop", "drop", 0)
	d.SourceCIDR = "0.0.0.0/0"
	return ACLPolicy{Name: "policy", Rules: []ACLRule{a, d}}
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

func TestACLPolicyServiceValidation(t *testing.T) {
	valid := ACLPolicy{Name: "policy", Rules: servicePolicyRules("101")}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	// Readback carries the resolved service name next to the native ID.
	observed := ACLPolicy{Name: "policy", Rules: servicePolicyRules("101")}
	for i := range observed.Rules {
		observed.Rules[i].Service = "https"
	}
	if err := observed.Validate(); err != nil {
		t.Fatalf("resolved service name was rejected: %v", err)
	}
	for name, edit := range map[string]func(*ACLPolicy){
		"service name only": func(p *ACLPolicy) {
			for i := range p.Rules {
				p.Rules[i].Service, p.Rules[i].ServiceID = "https", ""
			}
		},
		"mixed service scope": func(p *ACLPolicy) { p.Rules[1].ServiceID = "" },
		"extra service":       func(p *ACLPolicy) { p.Rules[1].ServiceID = "102" },
		"inline protocol":     func(p *ACLPolicy) { p.Rules[0].Protocol = "tcp" },
		"inline ports": func(p *ACLPolicy) {
			p.Rules[0].DestinationPortStart, p.Rules[0].DestinationPortEnd = int64Pointer(443), int64Pointer(443)
		},
		"compact ports": func(p *ACLPolicy) { p.Rules[0].DestinationPorts = "443" },
	} {
		p := ACLPolicy{Name: "policy", Rules: servicePolicyRules("101")}
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
		func(p *ACLPolicy) { p.Name = "" },
		func(p *ACLPolicy) { p.Rules = nil },
		func(p *ACLPolicy) { p.Rules[1].Action = "accept" },
		func(p *ACLPolicy) { p.Rules[0].Action = "drop" },
		func(p *ACLPolicy) { p.Rules[1].SourceCIDR = "192.0.2.0/24" },
		func(p *ACLPolicy) { p.Rules[0].DestinationCIDR = "192.0.2.1/32" },
		func(p *ACLPolicy) { p.Rules[0].Order = 1 },
		func(p *ACLPolicy) { p.Rules[0].Enabled = false },
		func(p *ACLPolicy) { p.Rules[0].Service = "https" },
		func(p *ACLPolicy) { p.Rules[0].Name = p.Rules[1].Name },
	} {
		p := validTestPolicy()
		edit(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted unsafe policy: %#v", p)
		}
	}
}
