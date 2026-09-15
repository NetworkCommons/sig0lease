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

func TestNormalizeTTLs(t *testing.T) {
	t.Run("normalizes an inconsistent RRset to its minimum TTL", func(t *testing.T) {
		records := []dns.RR{
			mustRR(t, `host.example. 3600 IN TXT "a"`),
			mustRR(t, `host.example. 60 IN TXT "b"`),
			mustRR(t, `host.example. 1800 IN TXT "c"`),
		}
		changed := NormalizeTTLs(records)
		if changed != 1 {
			t.Fatalf("expected 1 RRset changed, got %d", changed)
		}
		for _, rr := range records {
			if got := rr.Header().TTL; got != 60 {
				t.Errorf("expected TTL normalized to 60, got %d for %s", got, rr.String())
			}
		}
	})

	t.Run("leaves an already-consistent RRset untouched", func(t *testing.T) {
		records := []dns.RR{
			mustRR(t, `host.example. 3600 IN A 192.0.2.1`),
			mustRR(t, `host.example. 3600 IN A 192.0.2.2`),
		}
		if changed := NormalizeTTLs(records); changed != 0 {
			t.Fatalf("expected 0 RRsets changed, got %d", changed)
		}
		for _, rr := range records {
			if got := rr.Header().TTL; got != 3600 {
				t.Errorf("expected TTL untouched at 3600, got %d", got)
			}
		}
	})

	t.Run("normalizes multiple independent RRsets independently", func(t *testing.T) {
		records := []dns.RR{
			mustRR(t, `a.example. 3600 IN TXT "a1"`),
			mustRR(t, `a.example. 60 IN TXT "a2"`),
			mustRR(t, `b.example. 100 IN A 192.0.2.1`),
			mustRR(t, `b.example. 50 IN A 192.0.2.2`),
		}
		if changed := NormalizeTTLs(records); changed != 2 {
			t.Fatalf("expected 2 RRsets changed, got %d", changed)
		}
		wantTTL := map[string]uint32{"a.example.": 60, "b.example.": 50}
		for _, rr := range records {
			want := wantTTL[rr.Header().Name]
			if got := rr.Header().TTL; got != want {
				t.Errorf("%s: expected TTL %d, got %d", rr.Header().Name, want, got)
			}
		}
	})

	t.Run("does not merge same name+type across different classes", func(t *testing.T) {
		records := []dns.RR{
			mustRR(t, `host.example. 3600 IN TXT "a"`),
			mustRR(t, `host.example. 60 NONE TXT "b"`), // delete instruction, unrelated RRset
		}
		if changed := NormalizeTTLs(records); changed != 0 {
			t.Fatalf("expected 0 RRsets changed (different classes are different RRsets), got %d", changed)
		}
		if records[0].Header().TTL != 3600 || records[1].Header().TTL != 60 {
			t.Fatalf("TTLs must be untouched: got %d, %d", records[0].Header().TTL, records[1].Header().TTL)
		}
	})
}
