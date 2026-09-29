package dnssd

import (
	"strings"
	"testing"
)

func TestServiceTypeFromServiceName(t *testing.T) {
	cases := []struct {
		name     string
		wantType string
		wantOK   bool
	}{
		{"_http._tcp.example.com.", "_http._tcp", true},
		{"_WG._UDP.srp.dev.zenr.io.", "_wg._udp", true},
		{"_http._tcp.", "_http._tcp", true},
		{"_vpnserver._wg._udp.srp.dev.zenr.io.", "", false},
		{"_printer._sub._http._tcp.example.com.", "", false}, // a subtype name, not a base type
		{"_._tcp.example.com.", "", false},
		{"http._tcp.example.com.", "", false},
		{"_http._sctp.example.com.", "", false},
		{"_http.", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		gotType, gotOK := ServiceTypeFromServiceName(tc.name)
		if gotType != tc.wantType || gotOK != tc.wantOK {
			t.Errorf("ServiceTypeFromServiceName(%q) = (%q, %v), want (%q, %v)", tc.name, gotType, gotOK, tc.wantType, tc.wantOK)
		}
	}
}

func TestValidateServiceType(t *testing.T) {
	for _, ok := range []string{"_http._tcp", "_wg._udp", "_IPPS._TCP", "_matterc._udp", "_companion-link._tcp", "_123a._udp", "_abcdefghijklmno._tcp"} {
		if err := ValidateServiceType(ok); err != nil {
			t.Errorf("ValidateServiceType(%q) = %v, want nil", ok, err)
		}
	}

	cases := []struct {
		svcType string
		wantErr string
	}{
		{"_vpnserver._wg._udp", "exactly two labels"},
		{"_http", "exactly two labels"},
		{"_http._sctp", "_tcp or _udp"},
		{"http._tcp", "underscore"},
		{"_._tcp", "1-15 characters"},
		{"_abcdefghijklmnop._tcp", "1-15 characters"},
		{"_http_alt._tcp", "only letters, digits and hyphens"},
		{"_-http._tcp", "hyphen"},
		{"_http-._tcp", "hyphen"},
		{"_http--alt._tcp", "hyphen"},
		{"_1234._tcp", "at least one letter"},
	}
	for _, tc := range cases {
		err := ValidateServiceType(tc.svcType)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("ValidateServiceType(%q) = %v, want an error containing %q", tc.svcType, err, tc.wantErr)
		}
	}
}
