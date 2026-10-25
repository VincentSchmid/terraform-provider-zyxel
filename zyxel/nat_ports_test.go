package zyxel

import "testing"

func TestParseNATPorts(t *testing.T) {
	for _, tc := range []struct {
		value      string
		start, end int64
	}{{"5006", 5006, 5006}, {"5006-5007", 5006, 5007}, {"5006-5006", 5006, 5006}, {"1-65535", 1, 65535}} {
		t.Run(tc.value, func(t *testing.T) {
			start, end, err := ParseNATPorts(tc.value)
			if err != nil || start != tc.start || end != tc.end {
				t.Fatalf("ParseNATPorts(%q) = %d, %d, %v", tc.value, start, end, err)
			}
		})
	}
	for _, value := range []string{"", "*", "0", "65536", "2-1", "01", " 80", "80 ", "+80", "80-", "-80", "80,81", "1-2-3"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			if _, _, err := ParseNATPorts(value); err == nil {
				t.Fatalf("accepted invalid NAT ports %q", value)
			}
		})
	}
}
