package zyxel_test

import (
	"context"
	"testing"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
)

func validGroup(name string) zyxel.InterfaceGroup {
	return zyxel.InterfaceGroup{Name: name, WANInterfaces: []string{"IP.Interface.2"}, LANInterfaces: []string{"Ethernet.Interface.2", "WiFi.SSID.3"}}
}

func TestInterfaceGroupLifecycleAndIndexShift(t *testing.T) {
	c, f := networkClient(t)
	ctx := context.Background()
	first := validGroup("first")
	first.WANInterfaces = []string{"IP.Interface.3"}
	first.LANInterfaces = []string{"Ethernet.Interface.1"}
	second := validGroup("second")
	for _, v := range []zyxel.InterfaceGroup{first, second} {
		if applied, err := c.CreateInterfaceGroup(ctx, v); err != nil || !applied {
			t.Fatal(applied, err)
		}
	}
	if f.LastWrite["lanIntf"] != "Bridging.Bridge.1.Port.3,Bridging.Bridge.1.Port.7" {
		t.Fatal("did not resolve bridge ports", f.LastWrite)
	}
	if applied, err := c.CreateInterfaceGroup(ctx, second); applied || err == nil {
		t.Fatal("adopted existing group")
	}
	conflict := validGroup("conflict")
	if applied, err := c.CreateInterfaceGroup(ctx, conflict); applied || err == nil {
		t.Fatal("stole interfaces")
	}
	if err := c.DeleteInterfaceGroup(ctx, "first"); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadInterfaceGroup(ctx, "second")
	if err != nil || got.Name != "second" || got.RouterIndex != 2 {
		t.Fatal(got, err)
	}
	if err := c.DeleteInterfaceGroup(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if f.LastWrite["Index"] != float64(2) {
		t.Fatal("used stale deletion index")
	}
	if err := c.DeleteInterfaceGroup(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ReadInterfaceGroup(ctx, "second"); got != nil || err != nil {
		t.Fatal(got, err)
	}
	if len(f.Groups) != 1 || f.Groups[0]["Group_Name"] != "Default" {
		t.Fatal("removed unrelated group")
	}
}

func TestInterfaceGroupValidationAndResolution(t *testing.T) {
	for _, name := range []string{"empty", "default", "duplicate-path", "bad-path", "unresolved-lan", "unresolved-wan"} {
		t.Run(name, func(t *testing.T) {
			c, f := networkClient(t)
			v := validGroup("test")
			switch name {
			case "empty":
				v.Name = ""
			case "default":
				v.Name = "Default"
			case "duplicate-path":
				v.LANInterfaces = append(v.LANInterfaces, v.LANInterfaces[0])
			case "bad-path":
				v.WANInterfaces = []string{"IP.Interface.01"}
			case "unresolved-lan":
				v.LANInterfaces = []string{"Ethernet.Interface.99"}
			case "unresolved-wan":
				v.WANInterfaces = []string{"IP.Interface.99"}
			}
			if applied, err := c.CreateInterfaceGroup(context.Background(), v); applied || err == nil {
				t.Fatal(applied, err)
			}
			if f.Writes != 0 {
				t.Fatal("mutated on invalid input")
			}
			if err := c.DeleteInterfaceGroup(context.Background(), "Default"); err == nil {
				t.Fatal("deleted Default")
			}
		})
	}
}

func TestInterfaceGroupDuplicateAndCriteriaSafety(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "criteria", true: "duplicate"}[duplicate], func(t *testing.T) {
			c, f := networkClient(t)
			ctx := context.Background()
			v := validGroup("test")
			if _, err := c.CreateInterfaceGroup(ctx, v); err != nil {
				t.Fatal(err)
			}
			f.Mu.Lock()
			if duplicate {
				f.Groups = append(f.Groups, f.Groups[1])
			} else {
				f.Groups[1]["Criteria"] = "MAC address: 02:00:00:00:00:01"
			}
			f.Mu.Unlock()
			if _, err := c.ReadInterfaceGroup(ctx, v.Name); err == nil {
				t.Fatal("read ambiguous/unsupported group")
			}
			if err := c.DeleteInterfaceGroup(ctx, v.Name); err == nil {
				t.Fatal("deleted ambiguous/unsupported group")
			}
			if f.Writes != 1 {
				t.Fatal("unsafe deletion")
			}
		})
	}
}

func TestInterfaceGroupUncertainCreation(t *testing.T) {
	for _, failure := range []string{"reject", "ignore", "readback", "after-commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f := networkClient(t)
			f.RejectWrite = failure == "reject"
			f.IgnoreWrite = failure == "ignore"
			f.FailReadback = failure == "readback"
			f.FailAfterWrite = failure == "after-commit"
			applied, err := c.CreateInterfaceGroup(context.Background(), validGroup("test"))
			if err == nil || applied != (failure != "reject") {
				t.Fatal(applied, err)
			}
			if f.Writes > 1 {
				t.Fatal("retried uncertain create")
			}
		})
	}
}

func TestInterfaceGroupMalformedMembershipBlocksCreation(t *testing.T) {
	c, f := networkClient(t)
	f.Mu.Lock()
	f.Groups = append(f.Groups, map[string]any{"Group_Name": "unmanaged", "wanIntf": 7, "lanIntf": "Ethernet.Interface.1", "Criteria": ""})
	f.Mu.Unlock()
	if applied, err := c.CreateInterfaceGroup(context.Background(), validGroup("test")); applied || err == nil {
		t.Fatal("could not check existing membership safely", applied, err)
	}
	if f.Writes != 0 {
		t.Fatal("wrote despite malformed membership")
	}
}
