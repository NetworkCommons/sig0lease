package dnsmsg

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestAsDelete_RewritesClassAndTTL(t *testing.T) {
	add, err := dns.New("myhost.dev.zenr.io. 3600 IN A 192.0.2.1")
	if err != nil {
		t.Fatalf("dns.New: %v", err)
	}
	del := AsDelete(add)
	hdr := del.Header()
	if hdr.Class != dns.ClassNONE || hdr.TTL != 0 {
		t.Fatalf("expected class NONE ttl 0, got class=%v ttl=%d", hdr.Class, hdr.TTL)
	}
	// RDATA (and NAME/TYPE) unchanged -- same identity, just a different instruction.
	if del.String() == add.String() {
		t.Fatal("expected the presentation form to differ (class/ttl), but it didn't change at all")
	}
	if origHdr := add.Header(); origHdr.Class != dns.ClassINET {
		t.Fatal("AsDelete must not mutate its input")
	}
}
