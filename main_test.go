package main

import (
	"testing"
	"time"
)

func TestParseUpdateInterval(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", in: "30", want: 30 * time.Second},
		{name: "one", in: "1", want: time.Second},
		{name: "zero", in: "0", wantErr: true},
		{name: "negative", in: "-5", wantErr: true},
		{name: "not a number", in: "soon", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "overflows duration", in: "9223372037", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUpdateInterval(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseUpdateInterval(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("parseUpdateInterval(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
