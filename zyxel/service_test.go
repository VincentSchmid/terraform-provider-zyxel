package zyxel

import (
	"context"
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	for _, value := range []string{"*", "1", "65535", "443", "443-445", "443-443"} {
		a, b, err := ParsePorts(value)
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		if value == "*" && (a != nil || b != nil) {
			t.Fatal("any must have nil bounds")
		}
		if a != nil && (*a < 1 || *b < *a) {
			t.Fatal("invalid bounds")
		}
	}
	for _, value := range []string{"0", "65536", "445-443", "443-", "-443", "1-2-3", " 443", "0443", "+443", "*,443", "443,445"} {
		if _, _, err := ParsePorts(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func serviceTestRow() map[string]any {
	return map[string]any{"Name": "https", "Description": "web", "Protocol": 6, "SourcePort": -1, "SourcePortEnd": -1, "DestPort": 443, "DestPortEnd": -1, "Index": 2, "Iid": 19}
}

func TestServicePayloadAndReadNormalization(t *testing.T) {
	row := serviceTestRow()
	s, err := parseService(row)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "19" || s.RouterIndex != 2 || s.SourcePorts != "*" || s.DestinationPorts != "443" {
		t.Fatalf("%#v", s)
	}
	payload, err := s.dalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if payload["Protocol"] != "TCP" || payload["DestPort"] != int64(443) || payload["DestPortEnd"] != int64(-1) {
		t.Fatalf("%#v", payload)
	}
	for _, protocol := range []string{"tcp", "udp", "icmp", "icmpv6", "other"} {
		n := int64(47)
		in := Service{Name: "test", Protocol: protocol}
		if protocol == "other" {
			in.ProtocolNumber = &n
		}
		if _, err := in.dalPayload(); err != nil {
			t.Errorf("%s: %v", protocol, err)
		}
	}
}

func TestServiceRejectsMalformedRows(t *testing.T) {
	for _, key := range []string{"Name", "Description", "Index", "Iid", "Protocol", "SourcePort", "DestPortEnd"} {
		row := serviceTestRow()
		delete(row, key)
		if _, err := parseService(row); err == nil {
			t.Errorf("accepted missing %s", key)
		}
	}
	rows := []map[string]any{serviceTestRow(), serviceTestRow()}
	if _, err := findServiceRow(rows, "https"); err == nil {
		t.Fatal("accepted duplicate names")
	}
}

func TestServiceInvalidInputDoesNotReachNetwork(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:1", Credentials{Username: "test", Password: "test"}, 0)
	n := int64(256)
	for _, s := range []Service{
		{Name: "", Protocol: "tcp"}, {Name: "test", Protocol: "bad"},
		{Name: "test", Protocol: "tcp", SourcePorts: "445-443"},
		{Name: "test", Protocol: "icmp", SourcePorts: "*"},
		{Name: "test", Protocol: "tcp", ICMPType: &n},
		{Name: "test", Protocol: "other"}, {Name: "test", Protocol: "other", ProtocolNumber: &n},
	} {
		outcome, err := client.CreateService(context.Background(), s)
		if err == nil || outcome.Applied || outcome.Ambiguous {
			t.Fatalf("%#v => %#v %v", s, outcome, err)
		}
		if _, err := s.dalPayload(); err == nil {
			t.Fatal("expected validation error")
		}
	}
}

func TestACLCompactPortsAndServiceID(t *testing.T) {
	r := testACLRule("compact", "accept", 10)
	r.DestinationPortStart, r.DestinationPortEnd = nil, nil
	r.SourcePorts, r.DestinationPorts = "*", "443-445"
	payload, err := r.dalPayload(0)
	if err != nil {
		t.Fatal(err)
	}
	if payload["DestPort"] != int64(443) || payload["DestPortRangeMax"] != int64(445) {
		t.Fatalf("%#v", payload)
	}
	r.DestinationPortStart = int64Pointer(443)
	if _, err := r.dalPayload(0); err == nil {
		t.Fatal("accepted both port representations")
	}
	r = testACLRule("service", "accept", 10)
	r.DestinationPortStart, r.DestinationPortEnd = nil, nil
	r.ServiceID = "19"
	r.Protocol = "all"
	payload, err = r.dalPayload(2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload["X_ZYXEL_ServiceIndex"], int64(2)) {
		t.Fatal("must write resolved display index")
	}
	r.Service = "named"
	if _, err := r.dalPayload(2); err == nil {
		t.Fatal("accepted both service selectors")
	}
}
