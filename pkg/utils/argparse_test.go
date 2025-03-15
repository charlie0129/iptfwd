package utils

import (
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			raw:  "-P PREROUTING",
			want: []string{"-P", "PREROUTING"},
		},
		{
			raw:  "  -P PREROUTING ",
			want: []string{"-P", "PREROUTING"},
		},
		{
			raw:  "  -P   PREROUTING  ",
			want: []string{"-P", "PREROUTING"},
		},
		{
			raw:  `  -P   "PREROUTING"  `,
			want: []string{"-P", "PREROUTING"},
		},
		{
			raw:  `  -P   " PREROU TI  NG "  `,
			want: []string{"-P", " PREROU TI  NG "},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseArgs(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}
