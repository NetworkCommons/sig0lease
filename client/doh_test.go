package client

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

// TestQueryDoH_QueryGETUpdatePOST: over "doh", a query goes as a GET, its message in the dns
// parameter, with no body and no Content-Type, which a browser sends to another origin without
// a CORS preflight; an UPDATE goes as a POST with the DNS message Content-Type. Both keep the
// message's ID.
func TestQueryDoH_QueryGETUpdatePOST(t *testing.T) {
	var method, contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, contentType = r.Method, r.Header.Get("Content-Type")
		if r.URL.Path != dnshttp.Path || r.Header.Get("Accept") != dnshttp.MimeType {
			t.Errorf("%s %s with Accept %q, want %s with Accept %s", r.Method, r.URL.Path, r.Header.Get("Accept"), dnshttp.Path, dnshttp.MimeType)
		}
		var wire []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if b, _ := io.ReadAll(r.Body); len(b) != 0 {
				t.Errorf("GET has a body of %d octets", len(b))
			}
		case http.MethodPost:
			wire, err = io.ReadAll(r.Body)
		}
		if err != nil {
			t.Fatalf("%s: %v", r.Method, err)
		}
		m := &dns.Msg{Data: wire}
		if err := m.Unpack(); err != nil {
			t.Fatalf("%s: unpack: %v", r.Method, err)
		}
		m.Response = true
		if err := m.Pack(); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", dnshttp.MimeType)
		w.Write(m.Data)
	}))
	defer srv.Close()

	update := dns.NewMsg("example.", dns.TypeSOA)
	update.Opcode = dns.OpcodeUpdate
	for _, tc := range []struct {
		msg               *dns.Msg
		method, mediaType string
	}{
		{dns.NewMsg("demo.example.", dns.TypeA), http.MethodGet, ""},
		{update, http.MethodPost, dnshttp.MimeType},
	} {
		tc.msg.ID = 4242
		resp, err := New(srv.URL, "doh", 2*time.Second).Query(tc.msg)
		if err != nil {
			t.Fatalf("opcode %d: %v", tc.msg.Opcode, err)
		}
		if method != tc.method || contentType != tc.mediaType || resp.ID != 4242 {
			t.Errorf("opcode %d: sent as %s with Content-Type %q, answered with ID %d; want %s with %q, ID 4242",
				tc.msg.Opcode, method, contentType, resp.ID, tc.method, tc.mediaType)
		}
	}
}
