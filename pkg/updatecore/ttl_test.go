package updatecore

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func mustRR(t *testing.T, spec string) dns.RR {
	t.Helper()
	rr, err := dns.New(spec)
	if err != nil {
		t.Fatalf("dns.New(%q): %v", spec, err)
	}
	return rr
}

func TestCheckConsistentTTLs(t *testing.T) {
	cases := []struct {
		name    string
		records []dns.RR
		wantErr bool
	}{
		{
			name: "single RR is trivially consistent",
			records: []dns.RR{
				mustRR(t, `host.example. 3600 IN A 192.0.2.1`),
			},
		},
		{
			name: "same name+type+class, equal TTLs: consistent",
			records: []dns.RR{
				mustRR(t, `host.example. 3600 IN TXT "a"`),
				mustRR(t, `host.example. 3600 IN TXT "b"`),
			},
		},
		{
			name: "same name+type+class, differing TTLs: inconsistent",
			records: []dns.RR{
				mustRR(t, `host.example. 3600 IN TXT "a"`),
				mustRR(t, `host.example. 60 IN TXT "b"`),
			},
			wantErr: true,
		},
		{
			name: "same name+type, different class: never the same RRset",
			records: []dns.RR{
				mustRR(t, `host.example. 3600 IN TXT "a"`),
				mustRR(t, `host.example. 60 NONE TXT "b"`), // an RFC 2136 delete, unrelated TTL
			},
		},
		{
			name: "different owner names: independent RRsets, each internally consistent",
			records: []dns.RR{
				mustRR(t, `a.example. 100 IN A 192.0.2.1`),
				mustRR(t, `b.example. 200 IN A 192.0.2.2`),
			},
		},
		{
			name: "different types at the same name: independent RRsets",
			records: []dns.RR{
				mustRR(t, `host.example. 100 IN A 192.0.2.1`),
				mustRR(t, `host.example. 200 IN TXT "x"`),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckConsistentTTLs(tc.records)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}
