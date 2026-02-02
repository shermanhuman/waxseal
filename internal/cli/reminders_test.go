package cli

import (
	"testing"
)

func TestParseIntList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"simple", "30,7,1", []int{30, 7, 1}},
		{"with brackets", "[30,7,1]", []int{30, 7, 1}},
		{"with spaces", "30, 7, 1", []int{30, 7, 1}},
		{"single", "30", []int{30}},
		{"empty", "", nil},
		{"invalid", "abc", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIntList(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseIntList(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseIntList(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFormatIntList(t *testing.T) {
	tests := []struct {
		name  string
		input []int
		want  string
	}{
		{"three", []int{30, 7, 1}, "30, 7, 1"},
		{"single", []int{30}, "30"},
		{"empty", []int{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIntList(tt.input)
			if got != tt.want {
				t.Errorf("formatIntList(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
