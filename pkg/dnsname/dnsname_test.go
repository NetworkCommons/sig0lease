package dnsname

import "testing"

func TestFold(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"DemoScene._http._tcp.dev.zenr.io.", "demoscene._http._tcp.dev.zenr.io."},
		{"already.lower.", "already.lower."},
		{"", ""},
		// Non-ASCII letters are distinct octets in the DNS, never folded.
		{"CAFÉ.example.", "cafÉ.example."},
		{"Kitchen.example.", "Kitchen.example."}, // KELVIN SIGN, which strings.ToLower maps to ASCII 'k'
		{"İstanbul.example.", "İstanbul.example."},
		// Bytes that aren't valid UTF-8 pass through untouched (strings.ToLower would turn
		// each into a 3-byte U+FFFD).
		{"A\xffB.example.", "a\xffb.example."},
	}
	for _, c := range cases {
		got := Fold(c.in)
		if got != c.want {
			t.Errorf("Fold(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(got) != len(c.in) {
			t.Errorf("Fold(%q) changed the length from %d to %d", c.in, len(c.in), len(got))
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Demo.Example.", "demo.example"},
		{"demo.example", "demo.example"},
		{" demo.example. ", "demo.example"},
		{"CAFÉ.example.", "cafÉ.example"},
		{".", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEqualFold(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"DemoScene.example.", "demoscene.example.", true},
		{"DEMOSCENE.EXAMPLE.", "demoscene.example.", true},
		{"demoscene.example.", "demoscene.example", false},
		{"CAFÉ.example.", "café.example.", false},
		{"Kitchen.example.", "kitchen.example.", false},
		{"a\xffb.example.", "a\xfeb.example.", false},
		{"a\xffb.example.", "A\xffB.example.", true},
	}
	for _, c := range cases {
		if got := EqualFold(c.a, c.b); got != c.want {
			t.Errorf("EqualFold(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := EqualFold(c.a, c.b); got != (Fold(c.a) == Fold(c.b)) {
			t.Errorf("EqualFold(%q, %q) disagrees with comparing Fold results", c.a, c.b)
		}
	}
}
