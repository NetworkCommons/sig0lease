package srp

import (
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
		wantPrereq          bool
	}{
		// NXDOMAIN is the "never-before-seen name" case a live query alone can't
		// atomically protect: it gets a "Name is not in use" prerequisite attached to
		// the caller's later upstream forward, so a second concurrent registration
		// racing this same query is still caught -- by the authoritative server itself,
		// atomically -- even though both requests observed NXDOMAIN here.
		{name: "NXDOMAIN: first come", state: AuthNXDomain, want: FCFSProceed, wantPrereq: true},
		{name: "NOERROR no KEY, refuse=true: foreign data", state: AuthNoKey, refuseOnForeignData: true, want: FCFSForeignData},
		{name: "NOERROR no KEY, refuse=false: proceed (clobber)", state: AuthNoKey, refuseOnForeignData: false, want: FCFSProceed},
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
			if gotPrereq := prereq != nil; gotPrereq != tc.wantPrereq {
				t.Fatalf("prereq != nil = %v, want %v (prereq=%v)", gotPrereq, tc.wantPrereq, prereq)
			}
			if tc.wantPrereq {
				hdr := prereq.Header()
				if hdr.Name != "myhost.example." || hdr.Class != dns.ClassNONE || dns.RRToType(prereq) != dns.TypeANY {
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
