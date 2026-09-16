package dnssd

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestEnumerationOwnerName(t *testing.T) {
	got := EnumerationOwnerName("test.dev.zenr.io.")
	want := "_services._dns-sd._udp.test.dev.zenr.io."
	if got != want {
		t.Fatalf("EnumerationOwnerName() = %q, want %q", got, want)
	}
}

func TestServiceTypeFromInstanceName(t *testing.T) {
	cases := []struct {
		name     string
		instance string
		wantType string
		wantOK   bool
		desc     string
	}{
		{
			name:     "simple instance",
			instance: "Widget._http._tcp.test.dev.zenr.io.",
			wantType: "_http._tcp",
			wantOK:   true,
			desc:     "instance occupies exactly one label per RFC 6763 S4.1",
		},
		{
			name:     "case-insensitive",
			instance: "Widget._HTTP._TCP.test.dev.zenr.io.",
			wantType: "_http._tcp",
			wantOK:   true,
			desc:     "type extraction canonicalizes case",
		},
		{
			name:     "deeper domain",
			instance: "Printer._ipp._tcp._sub.example.co.uk.",
			wantType: "_ipp._tcp",
			wantOK:   true,
			desc:     "the number of labels after type/proto doesn't change where type/proto are",
		},
		{
			name:     "too few labels",
			instance: "_http._tcp.",
			wantType: "",
			wantOK:   false,
			desc:     "no room for a separate instance label",
		},
		{
			name:     "empty",
			instance: "",
			wantType: "",
			wantOK:   false,
			desc:     "degenerate input",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotOK := ServiceTypeFromInstanceName(tc.instance)
			if gotOK != tc.wantOK || gotType != tc.wantType {
				t.Fatalf("%s: ServiceTypeFromInstanceName(%q) = (%q, %v), want (%q, %v)",
					tc.desc, tc.instance, gotType, gotOK, tc.wantType, tc.wantOK)
			}
		})
	}
}

func TestDiffEnumerationRecords_NoChangeIsNil(t *testing.T) {
	records := DiffEnumerationRecords("test.dev.zenr.io.", []string{"_http._tcp", "_ipp._tcp"}, []string{"_IPP._TCP", "_http._tcp"}, 3600)
	if records != nil {
		t.Fatalf("expected no records when previous and current describe the same set (modulo case), got: %+v", records)
	}
}

func TestDiffEnumerationRecords_EmptyPreviousOnlyAdds(t *testing.T) {
	// A fresh process (previous == nil, as on every process start) must never emit a
	// delete, no matter what current looks like.
	records := DiffEnumerationRecords("test.dev.zenr.io.", nil, []string{"_http._tcp"}, 3600)
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 add, got %d records: %+v", len(records), records)
	}
	ptr, ok := records[0].(*dns.PTR)
	if !ok || ptr.Hdr.Class != dns.ClassINET || ptr.Hdr.TTL != 3600 {
		t.Fatalf("expected an add (class IN, TTL 3600), got: %+v", records[0])
	}
	wantOwner := "_services._dns-sd._udp.test.dev.zenr.io."
	if ptr.Hdr.Name != wantOwner {
		t.Fatalf("PTR owner = %q, want %q", ptr.Hdr.Name, wantOwner)
	}
	if ptr.Ptr != "_http._tcp.test.dev.zenr.io." {
		t.Fatalf("PTR target = %q, want _http._tcp.test.dev.zenr.io.", ptr.Ptr)
	}
}

func TestDiffEnumerationRecords_RemovedTypeOnlyDeletesWhatWasPreviouslyKnown(t *testing.T) {
	// _ipp._tcp was never in previous, so even though it's also absent from current, it
	// must NOT generate a delete -- this process never confirmed it was there to begin
	// with, so it isn't this process's to remove (see the function's own doc comment on
	// why a full delete-all is unsafe here).
	records := DiffEnumerationRecords("test.dev.zenr.io.", []string{"_http._tcp"}, nil, 3600)
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 delete (only for the previously-known type), got %d records: %+v", len(records), records)
	}
	ptr, ok := records[0].(*dns.PTR)
	if !ok || ptr.Hdr.Class != dns.ClassNONE || ptr.Hdr.TTL != 0 {
		t.Fatalf("expected a single-RR delete (class NONE, TTL 0), got: %+v", records[0])
	}
	if ptr.Ptr != "_http._tcp.test.dev.zenr.io." {
		t.Fatalf("PTR target = %q, want _http._tcp.test.dev.zenr.io.", ptr.Ptr)
	}
}

func TestDomainEnumerationOwnerName(t *testing.T) {
	cases := []struct {
		prefix string
		want   string
	}{
		{BrowseDomainPrefix, "b._dns-sd._udp.test.dev.zenr.io."},
		{DefaultBrowseDomainPrefix, "db._dns-sd._udp.test.dev.zenr.io."},
		{LegacyBrowseDomainPrefix, "lb._dns-sd._udp.test.dev.zenr.io."},
		{RegistrationDomainPrefix, "r._dns-sd._udp.test.dev.zenr.io."},
		{DefaultRegistrationDomainPrefix, "dr._dns-sd._udp.test.dev.zenr.io."},
	}
	for _, tc := range cases {
		if got := DomainEnumerationOwnerName(tc.prefix, "test.dev.zenr.io."); got != tc.want {
			t.Fatalf("DomainEnumerationOwnerName(%q, ...) = %q, want %q", tc.prefix, got, tc.want)
		}
	}
}

func TestDiffSelfPointingDomainRecord_NoChangeIsNil(t *testing.T) {
	if got := DiffSelfPointingDomainRecord(BrowseDomainPrefix, "test.dev.zenr.io.", false, false, 3600); got != nil {
		t.Fatalf("false->false: expected nil, got %+v", got)
	}
	if got := DiffSelfPointingDomainRecord(BrowseDomainPrefix, "test.dev.zenr.io.", true, true, 3600); got != nil {
		t.Fatalf("true->true: expected nil, got %+v", got)
	}
}

func TestDiffSelfPointingDomainRecord_BecomingPresentAdds(t *testing.T) {
	records := DiffSelfPointingDomainRecord(RegistrationDomainPrefix, "test.dev.zenr.io.", false, true, 3600)
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 add, got %d records: %+v", len(records), records)
	}
	ptr, ok := records[0].(*dns.PTR)
	if !ok || ptr.Hdr.Class != dns.ClassINET || ptr.Hdr.TTL != 3600 {
		t.Fatalf("expected an add (class IN, TTL 3600), got: %+v", records[0])
	}
	wantOwner := "r._dns-sd._udp.test.dev.zenr.io."
	if ptr.Hdr.Name != wantOwner {
		t.Fatalf("PTR owner = %q, want %q", ptr.Hdr.Name, wantOwner)
	}
	if ptr.Ptr != "test.dev.zenr.io." {
		t.Fatalf("PTR target = %q, want the zone itself (self-pointing), got %q", ptr.Ptr, ptr.Ptr)
	}
}

func TestDiffSelfPointingDomainRecord_BecomingAbsentDeletes(t *testing.T) {
	records := DiffSelfPointingDomainRecord(DefaultRegistrationDomainPrefix, "test.dev.zenr.io.", true, false, 3600)
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 delete, got %d records: %+v", len(records), records)
	}
	ptr, ok := records[0].(*dns.PTR)
	if !ok || ptr.Hdr.Class != dns.ClassNONE || ptr.Hdr.TTL != 0 {
		t.Fatalf("expected a delete (class NONE, TTL 0), got: %+v", records[0])
	}
	if ptr.Ptr != "test.dev.zenr.io." {
		t.Fatalf("PTR target = %q, want the zone itself", ptr.Ptr)
	}
}

func TestDiffEnumerationRecords_MixedAddAndDelete(t *testing.T) {
	previous := []string{"_http._tcp", "_ipp._tcp"}
	current := []string{"_ipp._tcp", "_ftp._tcp"} // _http._tcp dropped, _ftp._tcp appeared
	records := DiffEnumerationRecords("test.dev.zenr.io.", previous, current, 3600)

	var adds, deletes []string
	for _, rr := range records {
		ptr := rr.(*dns.PTR)
		if ptr.Hdr.Class == dns.ClassNONE {
			deletes = append(deletes, ptr.Ptr)
		} else {
			adds = append(adds, ptr.Ptr)
		}
	}
	if len(adds) != 1 || adds[0] != "_ftp._tcp.test.dev.zenr.io." {
		t.Fatalf("expected one add for _ftp._tcp, got: %+v", adds)
	}
	if len(deletes) != 1 || deletes[0] != "_http._tcp.test.dev.zenr.io." {
		t.Fatalf("expected one delete for _http._tcp (present in previous, gone from current), got: %+v", deletes)
	}
	// _ipp._tcp is in both -- must appear in neither list.
	for _, target := range append(append([]string{}, adds...), deletes...) {
		if strings.HasPrefix(target, "_ipp._tcp") {
			t.Fatalf("_ipp._tcp is unchanged and must not appear in the diff, got it in: %+v", records)
		}
	}
}
