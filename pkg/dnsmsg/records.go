package dnsmsg

import (
	"fmt"

	"codeberg.org/miekg/dns"
)

// RecordStrings returns records in presentation format, one string each, as ParseRecords
// reads them back: how a requester keeps the records it registered.
func RecordStrings(records []dns.RR) []string {
	var out []string
	for _, rr := range records {
		out = append(out, rr.String())
	}
	return out
}

// ParseRecords reads records kept in presentation format, one string each (RecordStrings).
func ParseRecords(saved []string) ([]dns.RR, error) {
	var out []dns.RR
	for _, r := range saved {
		rr, err := dns.New(r)
		if err != nil {
			return nil, fmt.Errorf("record %q: %w", r, err)
		}
		out = append(out, rr)
	}
	return out, nil
}
