package dnsmsg

import (
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
)

// EscapeTXT turns raw, one TXT string's octets, into the form a TXT record's strings take in
// codeberg.org/miekg/dns: presentation text, where a backslash starts an escape, which the
// library decodes when it packs the record. It is the form the library unpacks a TXT string
// into -- a quote or a backslash escaped with a backslash, an octet outside printable ASCII as
// \DDD -- so a record made with it is the same record as one read from the wire, and compares
// equal to it (pkg/lease.RecordKey).
func EscapeTXT(raw string) string {
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		switch b := raw[i]; {
		case b == '"' || b == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(b)
		case b < ' ' || b > '~':
			fmt.Fprintf(&sb, `\%03d`, b)
		default:
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// UnescapeTXT returns the octets of s, a TXT string in the library's form (EscapeTXT), as the
// library packs them: \DDD is the octet DDD, a backslash before any other character that
// character, and a backslash ending s nothing.
func UnescapeTXT(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			sb.WriteByte(s[i])
			continue
		}
		i++
		switch {
		case i == len(s):
		case i+3 <= len(s) && isDigit(s[i]) && isDigit(s[i+1]) && isDigit(s[i+2]):
			sb.WriteByte((s[i]-'0')*100 + (s[i+1]-'0')*10 + (s[i+2] - '0'))
			i += 2
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// TXTStrings returns the strings of txt, each as its octets (UnescapeTXT); none, not nil, when
// it has none.
func TXTStrings(txt *dns.TXT) []string {
	out := []string{}
	for _, s := range txt.Txt {
		out = append(out, UnescapeTXT(s))
	}
	return out
}

func isDigit(b byte) bool { return '0' <= b && b <= '9' }
