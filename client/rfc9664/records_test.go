package rfc9664

import (
	"net/netip"
	"slices"
	"testing"
)

// ParseRecords reads records relative to the name, and reports each spec it cannot take by its
// index, keeping the others.
func TestParseRecords(t *testing.T) {
	specs := []string{
		`_dnslink TXT "dnslink=/ipfs/bafy"`, // 0: relative
		"@ TXT hello",                       // 1: the name itself
		"www CNAME site.example.",           // 2
		"www.site.example. A 192.0.2.1",     // 3: fully qualified
		"@ A 192.0.2.1",                     // 4: an address of the name
		"x KEY 256 3 13 AAAA",               // 5: a KEY (CheckRecords)
		"@ TXT hello",                       // 6: twice
		"@",                                 // 7: no type
	}
	var bad []int
	got := ParseRecords("site.example.", specs, func(i int, err error) { bad = append(bad, i) })
	var described []string
	for _, rr := range got {
		described = append(described, Describe(rr))
	}
	want := []string{`_dnslink.site.example. TXT "dnslink=/ipfs/bafy"`, `site.example. TXT "hello"`, "www.site.example. CNAME site.example."}
	if !slices.Equal(described, want) {
		t.Errorf("records = %q, want %q", described, want)
	}
	if !slices.Equal(bad, []int{3, 4, 5, 6, 7}) {
		t.Errorf("refused specs %v, want 3 to 7", bad)
	}
}

// WithAddresses puts an A or AAAA record at the name for each address, before the records.
func TestWithAddresses(t *testing.T) {
	got := WithAddresses("site.example.", []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, records(t, wwwA))
	var described []string
	for _, rr := range got {
		described = append(described, Describe(rr))
	}
	want := []string{"site.example. A 192.0.2.1", "site.example. AAAA 2001:db8::1", "www.site.example. A 192.0.2.1"}
	if !slices.Equal(described, want) {
		t.Errorf("WithAddresses = %q, want %q", described, want)
	}
}
