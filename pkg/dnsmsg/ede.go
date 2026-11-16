package dnsmsg

import (
	"fmt"

	"codeberg.org/miekg/dns"
)

// AddEDE adds an Extended DNS Error (RFC 8914) with infoCode and text to resp, the reply to
// req, if req carried an OPT RR: RFC 8914 S2 allows the option only in a reply to a request
// that did. The option goes in resp.Pseudo, from which the dns library builds resp's one OPT
// RR.
//
// text is EXTRA-TEXT, for people to read, not for parsing (RFC 8914 S2). Every reply the
// proxy builds gets its EDE here; the server removes the text of an error reply's EDEs unless
// server.diagnostics is on (StripEDEText).
func AddEDE(resp, req *dns.Msg, infoCode uint16, text string) {
	if !hasOPT(req) {
		return
	}
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{InfoCode: infoCode, ExtraText: text})
}

// hasOPT reports whether m carries an OPT RR, in any of the shapes lease.FindOption reads: the
// dns library moves the OPT RR of a message it unpacks into the header, with UDPSize at least
// 512, and its options into Pseudo; a message built in process may instead hold only the
// options in Pseudo, or an OPT RR in Extra. Pseudo also holds a SIG(0) or TSIG, which are not
// options.
func hasOPT(m *dns.Msg) bool {
	if m.UDPSize > 0 {
		return true
	}
	for _, rr := range m.Pseudo {
		if _, ok := rr.(dns.EDNS0); ok {
			return true
		}
	}
	for _, rr := range m.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			return true
		}
	}
	return false
}

// EDEs returns the Extended DNS Errors in m, in order.
func EDEs(m *dns.Msg) []*dns.EDE {
	var edes []*dns.EDE
	for _, rr := range m.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			edes = append(edes, ede)
		}
	}
	return edes
}

// StripEDEText empties the EXTRA-TEXT of every Extended DNS Error in m and keeps its
// INFO-CODE.
func StripEDEText(m *dns.Msg) {
	for _, ede := range EDEs(m) {
		ede.ExtraText = ""
	}
}

// FormatEDE renders e for people: its INFO-CODE, the code's name in the IANA "Extended DNS
// Error Codes" registry, and its EXTRA-TEXT, if any.
func FormatEDE(e *dns.EDE) string {
	name, ok := dns.ExtendedErrorToString[e.InfoCode]
	if !ok {
		name = "Unassigned"
	}
	if e.ExtraText == "" {
		return fmt.Sprintf("%d (%s)", e.InfoCode, name)
	}
	return fmt.Sprintf("%d (%s): %s", e.InfoCode, name, e.ExtraText)
}
