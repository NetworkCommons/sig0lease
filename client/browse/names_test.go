package browse

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
)

// chain is a zone signed with NSEC, dev.example. below example., in canonical order: its own
// KEY; the registrar's discovery record; a name held by a KEY, with a record below it; a held
// name whose TXT record goes before it is asked for; a record written by hand; an SRP domain
// with a host in it; and a CNAME, whose NSEC record leads out of the zone.
var chain = []string{
	"dev.example. NSEC _dnssd-srp._tcp.dev.example. KEY RRSIG NSEC",
	"_dnssd-srp._tcp.dev.example. NSEC demo.dev.example. SRV RRSIG NSEC",
	"_dnssd-srp._tcp.dev.example. SRV 0 0 853 registrar.example.",
	"demo.dev.example. NSEC hello.demo.dev.example. A TXT KEY RRSIG NSEC",
	"demo.dev.example. A 192.0.2.7",
	`demo.dev.example. TXT "published"`,
	`demo.dev.example. TXT "by the agent"`,
	"hello.demo.dev.example. NSEC held.dev.example. TXT RRSIG NSEC",
	`hello.demo.dev.example. TXT "added" "caf\195\169"`,
	"held.dev.example. NSEC note.dev.example. TXT KEY RRSIG NSEC",
	"note.dev.example. NSEC a.srp.dev.example. TXT RRSIG NSEC",
	`note.dev.example. TXT "by hand"`,
	"a.srp.dev.example. NSEC host.srp.dev.example. PTR RRSIG NSEC",
	"a.srp.dev.example. PTR host.srp.dev.example.",
	"host.srp.dev.example. NSEC zz.dev.example. A KEY RRSIG NSEC",
	"host.srp.dev.example. A 192.0.2.9",
	"zz.dev.example. NSEC www.example. CNAME RRSIG NSEC",
	"zz.dev.example. CNAME elsewhere.example.",
	"www.example. NSEC example. A RRSIG NSEC",
	"www.example. A 192.0.2.80",
}

func TestNames(t *testing.T) {
	z := newZone(t, chain...)
	got, err := Names(context.Background(), z.query, "dev.example", "srp.dev.example.")
	if err != nil {
		t.Fatal(err)
	}
	want := []Name{
		{Name: "_dnssd-srp._tcp.dev.example.", Records: []Record{{Type: "SRV", Data: []string{"0 0 853 registrar.example."}}}},
		{Name: "demo.dev.example.", Key: true, Records: []Record{
			{Type: "A", Data: []string{"192.0.2.7"}},
			{Type: "TXT", Data: []string{"by the agent"}},
			{Type: "TXT", Data: []string{"published"}},
			{Owner: "hello", Type: "TXT", Data: []string{"added", "café"}},
		}},
		{Name: "held.dev.example.", Key: true, Records: []Record{}},
		{Name: "note.dev.example.", Records: []Record{{Type: "TXT", Data: []string{"by hand"}}}},
		{Name: "zz.dev.example.", Records: []Record{{Type: "CNAME", Data: []string{"elsewhere.example."}}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Names:\n got %+v\nwant %+v", got, want)
	}
	// The walk asks every name in the zone for its NSEC record, the skipped ones too, and stops
	// at the first name out of it; it asks no name skipped for its records, and none for KEY,
	// RRSIG or NSEC records but the walk's.
	for _, q := range z.asked {
		name, qtype, _ := strings.Cut(q, " ")
		switch {
		case strings.HasSuffix(name, "example.") && !strings.HasSuffix(name, ".dev.example.") && name != "dev.example.":
			t.Errorf("asked %s, out of the zone", q)
		case strings.HasSuffix(name, ".srp.dev.example.") && qtype != "NSEC":
			t.Errorf("asked %s, in the domain skipped", q)
		case qtype == "KEY" || qtype == "RRSIG":
			t.Errorf("asked %s", q)
		}
	}
	if !slices.Contains(z.asked, "host.srp.dev.example. NSEC") {
		t.Errorf("did not walk through the domain skipped: asked %q", z.asked)
	}

	// Nothing skipped, the SRP host is a name a KEY holds.
	got, err = Names(context.Background(), newZone(t, chain...).query, "dev.example.", "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(got, func(n Name) bool {
		return n.Name == "host.srp.dev.example." && n.Key && reflect.DeepEqual(n.Records, []Record{{Type: "A", Data: []string{"192.0.2.9"}}})
	}) {
		t.Fatalf("Names, skipping none: %+v, want host.srp.dev.example. among them", got)
	}
}

func TestNames_Empty(t *testing.T) {
	got, err := Names(context.Background(), newZone(t, "dev.example. NSEC www.example. KEY RRSIG NSEC").query, "dev.example.", "")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("Names of a zone with no name below it: %#v, %v; want empty, not nil", got, err)
	}
}

// TestNames_NoNSEC: a zone without an NSEC record at its name cannot be walked.
func TestNames_NoNSEC(t *testing.T) {
	_, err := Names(context.Background(), newZone(t, `dev.example. TXT "x"`).query, "dev.example.", "")
	if err == nil || !strings.Contains(err.Error(), "dev.example. has no NSEC record") {
		t.Fatalf("Names of an unsigned zone: %v, want an error saying it has no NSEC record", err)
	}
}

// TestNames_Gone: a name gone between the NSEC record naming it and its own question is
// stepped over, as the name before it names what follows now; one still named, or gone with
// the name before it, is an error.
func TestNames_Gone(t *testing.T) {
	z := newZone(t,
		"dev.example. NSEC a.dev.example. KEY RRSIG NSEC",
		"a.dev.example. NSEC c.dev.example. KEY RRSIG NSEC",
		"c.dev.example. NSEC www.example. KEY RRSIG NSEC",
	)
	// b.dev.example. went once a. was read: a.'s NSEC record named it, and names c. since.
	before := newZone(t, "a.dev.example. NSEC b.dev.example. KEY RRSIG NSEC")
	asked := 0
	q := func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
		if name == "a.dev.example." && qtype == dns.TypeNSEC {
			if asked++; asked == 1 {
				return before.query(ctx, name, qtype)
			}
		}
		return z.query(ctx, name, qtype)
	}
	got, err := Names(context.Background(), q, "dev.example.", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []Name{{Name: "a.dev.example.", Key: true, Records: []Record{}}, {Name: "c.dev.example.", Key: true, Records: []Record{}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Names: %+v, want %+v", got, want)
	}

	still := newZone(t,
		"dev.example. NSEC a.dev.example. KEY RRSIG NSEC",
		"a.dev.example. NSEC b.dev.example. KEY RRSIG NSEC",
	)
	if _, err := Names(context.Background(), still.query, "dev.example.", ""); err == nil || !strings.Contains(err.Error(), "names b.dev.example., which has none") {
		t.Fatalf("Names, with a name's NSEC record naming one that has none: %v, want an error saying so", err)
	}

	asked = 0
	both := func(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
		if name == "a.dev.example." && qtype == dns.TypeNSEC {
			if asked++; asked > 1 {
				return nil, nil // a. went too
			}
			return before.query(ctx, name, qtype)
		}
		return z.query(ctx, name, qtype)
	}
	if _, err := Names(context.Background(), both, "dev.example.", ""); err == nil || !strings.Contains(err.Error(), "went from dev.example. while read") {
		t.Fatalf("Names, with a name gone and the one before it: %v, want an error saying so", err)
	}
}

// TestNames_Loop: a chain that comes back to a name it went through is an error, not a walk
// that never ends.
func TestNames_Loop(t *testing.T) {
	z := newZone(t,
		"dev.example. NSEC a.dev.example. KEY RRSIG NSEC",
		"a.dev.example. NSEC b.dev.example. KEY RRSIG NSEC",
		"b.dev.example. NSEC a.dev.example. KEY RRSIG NSEC",
	)
	if _, err := Names(context.Background(), z.query, "dev.example.", ""); err == nil || !strings.Contains(err.Error(), "comes back from b.dev.example. to a.dev.example.") {
		t.Fatalf("Names of a chain with a loop: %v, want an error saying so", err)
	}
}

// TestNames_FailedQuestion: any question that fails fails the whole, in the walk and after it.
func TestNames_FailedQuestion(t *testing.T) {
	for _, q := range []string{
		"dev.example. NSEC",
		"held.dev.example. NSEC",
		"hello.demo.dev.example. TXT",
	} {
		z := newZone(t, chain...)
		z.fail = q
		if got, err := Names(context.Background(), z.query, "dev.example.", "srp.dev.example."); err == nil {
			t.Errorf("%s failing: Names = %+v, want an error", q, got)
		}
	}
}
