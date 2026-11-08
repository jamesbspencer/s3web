package config

import (
	"reflect"
	"testing"
)

func TestCleanExtensionSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "standard extensions with dots",
			input:    []string{".iso", ".img", ".tar.gz"},
			expected: []string{".iso", ".img", ".tar.gz"},
		},
		{
			name:     "extensions without leading dots",
			input:    []string{"iso", "img", "tar.gz"},
			expected: []string{".iso", ".img", ".tar.gz"},
		},
		{
			name:     "wildcard glob style inputs",
			input:    []string{"*.iso", "*.tar.gz", "*img"},
			expected: []string{".iso", ".tar.gz", ".img"},
		},
		{
			name:     "trailing dots and whitespace",
			input:    []string{"  .iso.  ", "  img  "},
			expected: []string{".iso", ".img"},
		},
		{
			name:     "duplicates and case normalization",
			input:    []string{".ISO", "iso", ".img", "IMG", ".iso"},
			expected: []string{".iso", ".img"},
		},
		{
			name:     "wildcard star returns empty slice",
			input:    []string{"*"},
			expected: []string{},
		},
		{
			name:     "wildcard all returns empty slice",
			input:    []string{"all"},
			expected: []string{},
		},
		{
			name:     "wildcard .* returns empty slice",
			input:    []string{".*"},
			expected: []string{},
		},
		{
			name:     "lone dots and empty elements ignored",
			input:    []string{".", "..", "   ", ""},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := CleanExtensionSlice(tc.input)
			if len(actual) == 0 && len(tc.expected) == 0 {
				return // both are empty
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Fatalf("CleanExtensionSlice(%v) = %v; want %v", tc.input, actual, tc.expected)
			}
		})
	}
}

func TestParseExtensionList(t *testing.T) {
	actual := ParseExtensionList(".iso, img, *.tar.gz, , .ISO")
	expected := []string{".iso", ".img", ".tar.gz"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("ParseExtensionList() = %v; want %v", actual, expected)
	}
}

