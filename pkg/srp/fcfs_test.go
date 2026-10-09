package srp

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"codeberg.org/miekg/dns"
)

// fakeStoreView is a minimal, in-test StoreView -- exactly the kind of thing the
// deliberately narrow StoreView interface exists to make easy.
type fakeStoreView map[string]*dns.KEY

func (f fakeStoreView) KeyAtName(name string) (*dns.KEY, bool) {
	k, ok := f[name]
	return k, ok
}

func fcfsTestKey(pub string) *dns.KEY {
	return keyRR("irrelevant-for-this-test.example.", 13, 0, pub)
}

func TestFCFS_StoreHit(t *testing.T) {
	updateKey := fcfsTestKey("AAAA")
	store := fakeStoreView{"myhost.example.": updateKey}

	t.Run("matching key: proceed", func(t *testing.T) {
		got, prereq, err := Evaluate(context.Background(), store, nil, "example.", "myhost.example.", fcfsTestKey("AAAA"), true)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if got != FCFSProceed {
			t.Fatalf("got %s, want proceed", got)
		}
		if prereq != nil {
			t.Fatalf("expected no prerequisite for a store-trusted refresh, got %v", prereq)
		}
	})

	t.Run("mismatched key: conflict", func(t *testing.T) {
		got, prereq, err := Evaluate(context.Background(), store, nil, "example.", "myhost.example.", fcfsTestKey("BBBB"), true)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if got != FCFSConflict {
			t.Fatalf("got %s, want conflict", got)
		}
		if prereq != nil {
			t.Fatalf("expected no prerequisite for a conflict, got %v", prereq)
		}
	})
}

func TestFCFS_LiveQueryTriState(t *testing.T) {
	updateKey := fcfsTestKey("AAAA")
	emptyStore := fakeStoreView{}

	cases := []struct {
		name                string
		state               AuthoritativeKeyState
		keys                []*dns.KEY
		refuseOnForeignData bool
		want                FCFSResult
		// wantPrereqType is the TYPE of the prerequisite a first-time claim gets, 0 for none:
		// ANY for "Name is not in use", KEY for "KEY RRset does not exist" -- whatever the
		// policy requires to still hold at write time, so a second concurrent claim racing
		// this same query is still caught by the authoritative server itself.
		wantPrereqType uint16
	}{
		{name: "NXDOMAIN, refuse=true: first come, name not in use", state: AuthNXDomain, refuseOnForeignData: true, want: FCFSProceed, wantPrereqType: dns.TypeANY},
		{name: "NXDOMAIN, refuse=false: first come, no KEY", state: AuthNXDomain, refuseOnForeignData: false, want: FCFSProceed, wantPrereqType: dns.TypeKEY},
		{name: "NOERROR no KEY, refuse=true: foreign data", state: AuthNoKey, refuseOnForeignData: true, want: FCFSForeignData},
		{name: "NOERROR no KEY, refuse=false: proceed (clobber), no KEY", state: AuthNoKey, refuseOnForeignData: false, want: FCFSProceed, wantPrereqType: dns.TypeKEY},
		{name: "NOERROR KEY matches: proceed", state: AuthKeyPresent, keys: []*dns.KEY{fcfsTestKey("AAAA")}, want: FCFSProceed},
		{name: "NOERROR KEY differs: conflict", state: AuthKeyPresent, keys: []*dns.KEY{fcfsTestKey("BBBB")}, want: FCFSConflict},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := func(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error) {
				return tc.state, tc.keys, nil
			}
			got, prereq, err := Evaluate(context.Background(), emptyStore, query, "example.", "myhost.example.", updateKey, tc.refuseOnForeignData)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if gotPrereq, wantPrereq := prereq != nil, tc.wantPrereqType != 0; gotPrereq != wantPrereq {
				t.Fatalf("prereq != nil = %v, want %v (prereq=%v)", gotPrereq, wantPrereq, prereq)
			}
			if tc.wantPrereqType != 0 {
				hdr := prereq.Header()
				if hdr.Name != "myhost.example." || hdr.Class != dns.ClassNONE || dns.RRToType(prereq) != tc.wantPrereqType {
					t.Fatalf("unexpected prerequisite shape: %+v", prereq)
				}
			}
		})
	}
}

func TestFCFS_NoStoreEntryAndNoQuery_Errors(t *testing.T) {
	_, _, err := Evaluate(context.Background(), fakeStoreView{}, nil, "example.", "myhost.example.", fcfsTestKey("AAAA"), true)
	if err == nil {
		t.Fatal("expected an error when there's no store entry and no query function")
	}
}

func TestFCFS_QueryErrorPropagates(t *testing.T) {
	wantErr := errors.New("network exploded")
	query := func(ctx context.Context, zoneHint, name string) (AuthoritativeKeyState, []*dns.KEY, error) {
		return 0, nil, wantErr
	}
	_, _, err := Evaluate(context.Background(), fakeStoreView{}, query, "example.", "myhost.example.", fcfsTestKey("AAAA"), true)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected the query error to propagate, got: %v", err)
	}
}

func TestFCFS_NamesAndKeyFor(t *testing.T) {
	const zone = "example.com."
	const host = "myhost.example.com."
	const inst1 = "printer._ipps._tcp.example.com."
	const inst2 = "scanner._ipps._tcp.example.com."

	hostKey := keyRR(host, 13, 0, "hostkey")
	inst1OwnKey := keyRR(inst1, 13, 0, "hostkey") // explicit but identical, as S3.2.5.1 requires
	rrs := []dns.RR{
		deleteAll(host), mustRR(t, host+" 3600 IN A 192.0.2.1"), hostKey,
		deleteAll(inst1), mustRR(t, inst1+" 3600 IN SRV 0 0 631 "+host), mustRR(t, inst1+` 3600 IN TXT "a"`), inst1OwnKey,
		deleteAll(inst2), mustRR(t, inst2+" 3600 IN SRV 0 0 631 "+host), mustRR(t, inst2+` 3600 IN TXT "b"`),
		mustRR(t, "_ipps._tcp.example.com. 3600 IN PTR "+inst1),
		mustRR(t, "_ipps._tcp.example.com. 3600 IN PTR "+inst2),
	}
	cu, err := Classify(newUpdate(zone, rrs...))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	names := Names(cu)
	if len(names) != 3 {
		t.Fatalf("expected exactly 3 names (host + 2 instances, no SRV/TXT/PTR owner names), got: %v", names)
	}
	wantSet := map[string]bool{host: true, inst1: true, inst2: true}
	for _, n := range names {
		if !wantSet[n] {
			t.Fatalf("unexpected name in Names(): %s", n)
		}
	}

	if got := KeyFor(cu, host); got != cu.Host.Key {
		t.Fatalf("KeyFor(host) = %v, want the Host Description's own key", got)
	}
	if got := KeyFor(cu, inst1); got != inst1OwnKey && !keysIdentical(got, inst1OwnKey) {
		t.Fatalf("KeyFor(inst1) should be inst1's own explicit key")
	}
	// inst2 has no explicit KEY -- inherits the host's key material (S3.2.5.1), but at
	// its OWN owner name, not the host's literal KEY RR object. Returning cu.Host.Key
	// verbatim here was a real bug (caught by a live end-to-end test):
	// pkg/lease.NodeKey is name-scoped, so a caller deriving a lease-store node identity
	// from an inherited key with the host's name would silently collide the instance's
	// node with the host's own.
	if got := KeyFor(cu, inst2); !keysIdentical(got, cu.Host.Key) {
		t.Fatalf("KeyFor(inst2) should inherit the host's key material (S3.2.5.1), got a different key")
	}
	if got := KeyFor(cu, inst2); got.Hdr.Name != inst2 {
		t.Fatalf("KeyFor(inst2).Hdr.Name = %q, want the instance's own name %q -- an inherited key must not carry the host's owner name (this is exactly the bug: pkg/lease.NodeKey is name-scoped, so this field alone determines which lease-store node a caller ends up touching)", got.Hdr.Name, inst2)
	}
	if got := KeyFor(cu, host); got.Hdr.Name != host {
		t.Fatalf("KeyFor(host).Hdr.Name = %q, want %q", got.Hdr.Name, host)
	}
}

// TestFCFS_KeyForPreservesInstanceNameCase pins the case of an inherited KEY's owner
// name: Classify lower-cases ServiceInstance.Name for comparisons, but the handler forwards
// KeyFor's result upstream as the instance's published KEY, so it must carry the name as
// the requester spelled it (RFC 1035 S2.3.3: compare case-insensitively, preserve case).
// Before the fix a "DemoScene" instance got its KEY published at "demoscene".
func TestFCFS_KeyForPreservesInstanceNameCase(t *testing.T) {
	const zone = "example.com."
	const host = "MyHost.example.com."
	const inst = "DemoScene._http._tcp.example.com."

	rrs := []dns.RR{
		deleteAll(host), mustRR(t, host+" 3600 IN A 192.0.2.1"), keyRR(host, 13, 0, "hostkey"),
		deleteAll(inst), mustRR(t, inst+" 3600 IN SRV 0 0 668 "+host), mustRR(t, inst+` 3600 IN TXT "path=/daemon"`),
		mustRR(t, "_http._tcp.example.com. 3600 IN PTR "+inst),
	}
	cu, err := Classify(newUpdate(zone, rrs...))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	if got := KeyFor(cu, cu.Instances[0].Name).Hdr.Name; got != inst {
		t.Fatalf("KeyFor(instance).Hdr.Name = %q, want the requester's spelling %q", got, inst)
	}
	if got := KeyFor(cu, cu.Host.Name).Hdr.Name; got != host {
		t.Fatalf("KeyFor(host).Hdr.Name = %q, want the requester's spelling %q", got, host)
	}
}

func TestFCFS_KeyForPanicsOnUnknownName(t *testing.T) {
	const zone = "example.com."
	const host = "myhost.example.com."
	rrs := []dns.RR{deleteAll(host), mustRR(t, host+" 3600 IN A 192.0.2.1"), keyRR(host, 13, 0, "hostkey")}
	cu, err := Classify(newUpdate(zone, rrs...))
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected KeyFor to panic on a name outside the update")
		}
	}()
	KeyFor(cu, "nobody.example.com.")
}

// Both prerequisites must reach the wire with RDLENGTH 0 (RFC 2136 S3.2.2: anything else is
// a FORMERR): NAME, then TYPE, CLASS=NONE(254), TTL=0, RDLENGTH=0.
func TestFCFS_PrerequisitesWireEncodeWithEmptyRDATA(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prereq dns.RR
		typ    uint16
	}{
		{"name not in use", nameNotInUsePrerequisite("printer.example."), dns.TypeANY},
		{"KEY RRset does not exist", keyRRsetDoesNotExistPrerequisite("printer.example."), dns.TypeKEY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.Opcode = dns.OpcodeUpdate
			m.Question = []dns.RR{&dns.SOA{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}
			m.Answer = []dns.RR{tc.prereq}
			if err := m.Pack(); err != nil {
				t.Fatalf("pack: %v", err)
			}
			want := []byte{byte(tc.typ >> 8), byte(tc.typ), 0x00, 0xfe, 0, 0, 0, 0, 0x00, 0x00}
			if got := m.Data[len(m.Data)-len(want):]; !bytes.Equal(got, want) {
				t.Fatalf("prerequisite ends % x on the wire, want % x", got, want)
			}
		})
	}
}
