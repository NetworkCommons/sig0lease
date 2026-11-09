package handlers

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
)

func txtAt(name, text string) *dns.TXT {
	txt := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{text}
	return txt
}

// One request replaces a record: the new one added, the old one deleted (RFC 2136 S2.5.4), in
// the one UPDATE the handler forwards, deletes first. The store then holds the new record under
// the signer, and not the old one.
func TestHandle_ReplacesARecordInOneUpdate(t *testing.T) {
	signer := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	h, stub := lockTestHandler(t, signer)
	const owner = "_dnslink.test.dev.zenr.io."
	oldTXT, newTXT := txtAt(owner, "dnslink=/ipfs/old"), txtAt(owner, "dnslink=/ipfs/new")
	key := signer.PublicKey.Clone().(*dns.KEY)

	if res := h.Handle(context.Background(), stubResponseWriter{}, buildFCFSUpdate(t, signer, []*dns.KEY{key}, []dns.RR{oldTXT}, 120, 600)); rcodeOf(res) != dns.RcodeSuccess {
		t.Fatalf("registering the old record: %+v", res)
	}
	sentBefore := stub.sentCount()
	req := buildFCFSUpdate(t, signer, []*dns.KEY{key}, []dns.RR{newTXT, dnsmsg.AsDelete(oldTXT)}, 120, 600)
	if res := h.Handle(context.Background(), stubResponseWriter{}, req); rcodeOf(res) != dns.RcodeSuccess {
		t.Fatalf("replacing the record: %+v", res)
	}

	sent := stub.sentSnapshot()
	if len(sent) != sentBefore+1 {
		t.Fatalf("expected one UPDATE for the replacement, got %d", len(sent)-sentBefore)
	}
	ns := sent[len(sent)-1].Ns
	if len(ns) != 2 {
		t.Fatalf("expected the old record's delete and the new record's add, got %v", ns)
	}
	if del, ok := ns[0].(*dns.TXT); !ok || del.Hdr.Class != dns.ClassNONE || del.TXT.Txt[0] != "dnslink=/ipfs/old" {
		t.Fatalf("expected the old record's delete first, got %v", ns[0])
	}
	if add, ok := ns[1].(*dns.TXT); !ok || add.Hdr.Class != dns.ClassINET || add.TXT.Txt[0] != "dnslink=/ipfs/new" {
		t.Fatalf("expected the new record's add second, got %v", ns[1])
	}
	if h.leaseManager.LookupNonKEYRecord(oldTXT) != nil {
		t.Fatal("expected the old record gone from the store")
	}
	if rec := h.leaseManager.LookupNonKEYRecord(newTXT); rec == nil || rec.ParentKeyName != leasepkg.NodeKey(key) {
		t.Fatalf("expected the new record stored under the signer, got %+v", rec)
	}
}

// What an Update section must not be: each refused before anything is sent upstream.
func TestHandle_RefusesUpdateSectionsThatAreNotLeaseRequests(t *testing.T) {
	signer := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	key := signer.PublicKey.Clone().(*dns.KEY)
	txt := txtAt("test.dev.zenr.io.", "hello")
	deleteWithTTL := dnsmsg.AsDelete(txt)
	deleteWithTTL.Header().TTL = 60
	rrsetDelete := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassANY}}
	chaos := txtAt("test.dev.zenr.io.", "hello")
	chaos.Hdr.Class = dns.ClassCHAOS

	tests := []struct {
		name            string
		keys            []*dns.KEY
		records         []dns.RR
		lease, keyLease uint32
		rcode, infoCode uint16
		text            string
	}{
		{"records added on a LEASE of 0", []*dns.KEY{key}, []dns.RR{txt}, 0, 600,
			dns.RcodeFormatError, dns.ExtendedErrorOther, "LEASE=0 with records to add"},
		{"a KEY added on a KEY-LEASE of 0", []*dns.KEY{key}, nil, 120, 0,
			dns.RcodeFormatError, dns.ExtendedErrorOther, "KEY-LEASE=0 with a KEY RR to add"},
		{"a record both added and deleted", []*dns.KEY{key}, []dns.RR{txt, dnsmsg.AsDelete(txt)}, 120, 600,
			dns.RcodeFormatError, dns.ExtendedErrorOther, "both added and deleted"},
		{"the signer's KEY deleted with records added", nil, []dns.RR{dnsmsg.AsDelete(key), txt}, 120, 0,
			dns.RcodeFormatError, dns.ExtendedErrorOther, "deletes its signer's KEY"},
		{"a delete with a TTL", []*dns.KEY{key}, []dns.RR{deleteWithTTL}, 0, 600,
			dns.RcodeFormatError, dns.ExtendedErrorOther, "has TTL 60"},
		{"a record of class CH", []*dns.KEY{key}, []dns.RR{chaos}, 120, 600,
			dns.RcodeFormatError, dns.ExtendedErrorOther, "class CH"},
		{"an RRset delete (class ANY)", []*dns.KEY{key}, []dns.RR{rrsetDelete}, 0, 600,
			dns.RcodeRefused, dns.ExtendedErrorNotSupported, "deleting an RRset"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, stub := lockTestHandler(t, signer)
			res := h.Handle(context.Background(), stubResponseWriter{}, buildFCFSUpdate(t, signer, tt.keys, tt.records, tt.lease, tt.keyLease))
			wantErrorReply(t, res, tt.rcode, tt.infoCode, tt.text)
			if n := stub.sentCount(); n != 0 {
				t.Fatalf("expected nothing sent upstream, got %d UPDATEs", n)
			}
		})
	}
}

// A signer adding records without its KEY in the request follows the one rule for anything
// new: it must be lease-managed, or an online-only signer with allow_online_key_registration.
// The records then belong to it.
func TestHandle_RecordsAloneFollowTheRegistrationRule(t *testing.T) {
	signer := loadClientKey(t, "Ktest.dev.zenr.io.+015+05044")
	signerKeyOnline := func(ctx context.Context, zoneHint, name string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && dnsname.Normalize(name) == dnsname.Normalize(signer.PublicKey.Hdr.Name) {
			return []dns.RR{signer.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}
	txt := txtAt("test.dev.zenr.io.", "hello")

	t.Run("an online-only signer, by default", func(t *testing.T) {
		h, _ := newEDETestHandler(t, nil, signerKeyOnline)
		res := h.Handle(context.Background(), stubResponseWriter{}, buildFCFSUpdate(t, signer, nil, []dns.RR{txt}, 120, 0))
		wantErrorReply(t, res, dns.RcodeRefused, dns.ExtendedErrorProhibited, "signing key must be managed")
	})
	t.Run("an online-only signer, with allow_online_key_registration", func(t *testing.T) {
		h, _ := newEDETestHandler(t, map[string]any{"allow_online_key_registration": true}, signerKeyOnline)
		res := h.Handle(context.Background(), stubResponseWriter{}, buildFCFSUpdate(t, signer, nil, []dns.RR{txt}, 120, 0))
		if rcodeOf(res) != dns.RcodeSuccess {
			t.Fatalf("expected the records registered, got %+v", res)
		}
		if rec := h.leaseManager.LookupNonKEYRecord(txt); rec == nil || rec.ParentKeyName != leasepkg.NodeKey(signer.PublicKey) {
			t.Fatalf("expected the record stored under the signer, got %+v", rec)
		}
	})
}
