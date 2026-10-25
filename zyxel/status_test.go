package zyxel

import "testing"

func TestStatusProjectionPreservesMissingAndEmptyFields(t *testing.T) {
	object := map[string]any{"DeviceInfo": map[string]any{"ModelName": "", "SoftwareVersion": 123}}
	model := statusString(object, "DeviceInfo", "ModelName")
	if model == nil || *model != "" {
		t.Fatal("an explicitly empty field must remain present")
	}
	if statusString(object, "DeviceInfo", "SoftwareVersion") != nil || statusString(object, "SystemInfo", "HostName") != nil {
		t.Fatal("missing or non-string fields must remain absent")
	}
}
