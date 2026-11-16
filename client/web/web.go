// Package web is what the demo's browser page does (docs/demo.md, D6), apart from showing it:
// it browses a DNS-SD domain and lists the names in a zone (client/browse), and lets the
// visitor claim a name in the zone with a short message, a TXT record at the name that
// client/rfc9664's Name keeps registered while the page is open. Everything goes to the proxy
// over DNS-over-HTTPS, the one DNS transport a browser has; the proxy answers queries for its zones from their authoritative server, so the
// page sees a change as soon as the server has it. A question about any other name, which a
// proxy that forwards none refuses, goes to the Fallback resolver. The name's key, what the
// name holds and the claim are kept in the browser's storage, so that a visitor who comes back
// within the name's KEY-LEASE gets the name back. cmd/sig0lease-web makes a Page the page's
// JavaScript API.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/browse"
	"github.com/NetworkCommons/sig0lease/client/rfc9664"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/dnsname"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// Storage keeps strings by key: the browser's localStorage, or what stands in for it.
type Storage interface {
	Get(key string) (value string, ok bool)
	Set(key, value string) error
	Remove(key string)
}

// Config configures New.
type Config struct {
	DoH     string  // the proxy's DNS-over-HTTPS server, "http://host:port"
	Zone    string  // the zone names are claimed in, and Names lists: the proxy's RFC 9664 handler's
	Domain  string  // the DNS-SD domain Browse reads, which Names leaves out
	Storage Storage // required
	// Fallback is the DNS-over-HTTPS server asked the questions DoH refuses as names it does
	// not serve (browse.Fallback), as a URL with no path, which a page may ask from any
	// origin: a public resolver, such as https://dns.google. Default: none, and those
	// questions fail.
	Fallback string
	// Logf receives the claimed name's log lines. Default: none.
	Logf    func(format string, args ...any)
	Timeout time.Duration    // per exchange; default 10s
	Send    client.Transport // default client.LiveTransport(Timeout)
}

// The leases asked for a claimed name: its message stays up to 10 minutes after the page
// closes, and the name stays the visitor's key's for 30, the live zone's longest KEY-LEASE
// (config.yaml).
const (
	lease    = 600
	keyLease = 1800
)

// Where the browser's storage keeps the claim, and each name's key and records.
const (
	claimKey      = "sig0lease/claim"
	keyPrefix     = "sig0lease/key/"
	recordsPrefix = "sig0lease/records/"
)

// Page is the page's requester: what it shows, and the name it claims.
type Page struct {
	cfg   Config
	query browse.Query
	mu    sync.Mutex    // held by Claim and Release
	name  *rfc9664.Name // the name kept registered; nil: none
	label string        // name's label
}

// Claim is what the visitor claimed: a name, by its label, and the message there.
type Claim struct {
	Label   string `json:"label"`
	Message string `json:"message"`
}

// New validates cfg and applies its defaults.
func New(cfg Config) (*Page, error) {
	if err := client.NetworkDoH.CheckServer(cfg.DoH); err != nil {
		return nil, fmt.Errorf("web: DoH: %w", err)
	}
	if cfg.Fallback != "" {
		if err := client.NetworkDoH.CheckServer(cfg.Fallback); err != nil {
			return nil, fmt.Errorf("web: Fallback: %w", err)
		}
	}
	if cfg.Zone == "" || cfg.Domain == "" {
		return nil, errors.New("web: Zone and Domain are required")
	}
	if cfg.Storage == nil {
		return nil, errors.New("web: Storage is required")
	}
	cfg.Zone, cfg.Domain = dnsutil.Fqdn(cfg.Zone), dnsutil.Fqdn(cfg.Domain)
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Send == nil {
		cfg.Send = client.LiveTransport(cfg.Timeout)
	}
	query := browse.Querier(cfg.Send, cfg.DoH, client.NetworkDoH)
	if cfg.Fallback != "" {
		query = browse.Fallback(query, browse.Querier(cfg.Send, cfg.Fallback, client.NetworkDoH))
	}
	return &Page{cfg: cfg, query: query}, nil
}

// Browse reads the domain (browse.Browse).
func (p *Page) Browse(ctx context.Context) (*browse.Domain, error) {
	return browse.Browse(ctx, p.query, p.cfg.Domain)
}

// Names lists the names in the zone, outside the domain (browse.Names): the zone must be
// signed with NSEC.
func (p *Page) Names(ctx context.Context) ([]browse.Name, error) {
	return browse.Names(ctx, p.query, p.cfg.Zone, p.cfg.Domain)
}

// Message returns the strings of the TXT records at label's name, as their octets: none when
// it has none.
func (p *Page) Message(ctx context.Context, label string) ([]string, error) {
	name, err := p.nameOf(label)
	if err != nil {
		return nil, err
	}
	rrs, err := p.query(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	msg := []string{}
	for _, rr := range rrs {
		msg = append(msg, dnsmsg.TXTStrings(rr.(*dns.TXT))...)
	}
	return msg, nil
}

// Claimed returns the claim the browser keeps, which the page resumes when it opens.
func (p *Page) Claimed() (c Claim, ok bool, err error) {
	s, ok := p.cfg.Storage.Get(claimKey)
	if !ok {
		return Claim{}, false, nil
	}
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return Claim{}, false, fmt.Errorf("the claim kept in this browser: %w", err)
	}
	return c, true, nil
}

// Claim claims label's name with message: the name, held by a key kept in the browser (made
// the first time), gets a TXT record of message, kept registered until Release. A claim of
// another name first frees the one claimed before. The name is registered in the background:
// the log lines say how it went, and Message what the zone has.
func (p *Page) Claim(label, message string) error {
	label = strings.ToLower(label)
	name, err := p.nameOf(label)
	if err != nil {
		return err
	}
	if len(message) > 255 {
		return fmt.Errorf("the message is %d bytes; a TXT record's string holds at most 255", len(message))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.name != nil && p.label != label {
		p.stop()
	}
	if p.name == nil {
		cfg, err := p.nameConfig(label)
		if err != nil {
			return err
		}
		if p.name, err = rfc9664.StartName(cfg); err != nil {
			return err
		}
		p.label = label
	}
	b, err := json.Marshal(Claim{Label: label, Message: message})
	if err != nil {
		return err
	}
	if err := p.cfg.Storage.Set(claimKey, string(b)); err != nil {
		return fmt.Errorf("keeping the claim in this browser: %w", err)
	}
	txt := &dns.TXT{Hdr: dns.Header{Name: name, Class: dns.ClassINET}}
	txt.TXT.Txt = []string{dnsmsg.EscapeTXT(message)}
	p.name.Set([]dns.RR{txt})
	return nil
}

// Release frees the name claimed, deleting its message and its key's hold on it, and forgets
// the claim. A claim the page has not resumed is freed too (rfc9664.Release).
func (p *Page) Release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok, err := p.Claimed()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("no name is claimed")
	}
	if p.name != nil {
		p.stop()
	} else {
		cfg, err := p.nameConfig(c.Label)
		if err != nil {
			return err
		}
		if err := rfc9664.Release(cfg); err != nil {
			return err
		}
	}
	p.cfg.Storage.Remove(claimKey)
	return nil
}

// stop stops keeping the name claimed, which deregisters it and frees it.
func (p *Page) stop() {
	p.name.Stop()
	p.name.Wait()
	p.name, p.label = nil, ""
}

// nameOf returns label's name in the zone: label must be a host name label, as the name is
// typed and linked.
func (p *Page) nameOf(label string) (string, error) {
	if !dnsname.IsHostLabel(label) {
		return "", fmt.Errorf("%q: a name is letters, digits and hyphens, not starting or ending with a hyphen, at most 63", label)
	}
	return label + "." + p.cfg.Zone, nil
}

// nameConfig configures the Name of label's name, with the name's key from the browser's
// storage, made and kept there the first time.
func (p *Page) nameConfig(label string) (rfc9664.NameConfig, error) {
	name, err := p.nameOf(label)
	if err != nil {
		return rfc9664.NameConfig{}, err
	}
	key, err := p.key(name)
	if err != nil {
		return rfc9664.NameConfig{}, err
	}
	store := nameStore{p.cfg.Storage}
	if _, _, err := store.load(name); err != nil {
		return rfc9664.NameConfig{}, err
	}
	return rfc9664.NameConfig{
		Client: rfc9664.Config{
			Name: name, Key: key,
			RequestedLease: lease, RequestedKeyLease: keyLease,
			Server: p.cfg.DoH, Network: client.NetworkDoH, Timeout: p.cfg.Timeout, Send: p.cfg.Send,
		},
		Store: store,
		KeeperConfig: client.KeeperConfig{
			Logf:    p.cfg.Logf,
			OnFatal: func(err error) { p.cfg.Logf("%s: %v", name, err) },
		},
	}, nil
}

// savedKey is a key as the browser's storage keeps it: its KEY record and its private key,
// in the files' formats (keyrec.LoadedKey.KeyText).
type savedKey struct {
	Public  string `json:"public"`
	Private string `json:"private"`
}

// key returns name's key from the browser's storage, made and kept there if it has none.
func (p *Page) key(name string) (*keyrec.LoadedKey, error) {
	if s, ok := p.cfg.Storage.Get(keyPrefix + name); ok {
		var k savedKey
		if err := json.Unmarshal([]byte(s), &k); err != nil {
			return nil, fmt.Errorf("the key for %s kept in this browser: %w", name, err)
		}
		key, err := keyrec.ParseKey(name, k.Public, k.Private)
		if err != nil {
			return nil, fmt.Errorf("the key for %s kept in this browser: %w", name, err)
		}
		return key, nil
	}
	key, err := keyrec.GenerateKey(name, dns.ECDSAP256SHA256, 0, 256)
	if err != nil {
		return nil, err
	}
	var k savedKey
	k.Public, k.Private = key.KeyText()
	b, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	if err := p.cfg.Storage.Set(keyPrefix+name, string(b)); err != nil {
		return nil, fmt.Errorf("keeping the key for %s in this browser: %w", name, err)
	}
	return key, nil
}

// nameStore is the rfc9664.NameStore of the browser's storage.
type nameStore struct{ s Storage }

type savedName struct {
	Held    bool     `json:"held"`
	Records []string `json:"records"` // dnsmsg.RecordStrings
}

// load returns what the storage keeps for name: nothing (false, nil) when it keeps nothing.
func (st nameStore) load(name string) (held bool, records []dns.RR, err error) {
	s, ok := st.s.Get(recordsPrefix + name)
	if !ok {
		return false, nil, nil
	}
	var n savedName
	if err := json.Unmarshal([]byte(s), &n); err != nil {
		return false, nil, fmt.Errorf("the records of %s kept in this browser: %w", name, err)
	}
	records, err = dnsmsg.ParseRecords(n.Records)
	if err != nil {
		return false, nil, fmt.Errorf("the records of %s kept in this browser: %w", name, err)
	}
	return n.Held, records, nil
}

func (st nameStore) Load(name string) []dns.RR {
	_, records, err := st.load(name)
	if err != nil {
		// nameConfig loaded them before the Name started, and Save writes only what the
		// library prints.
		panic(fmt.Sprintf("web: %v", err))
	}
	return records
}

func (st nameStore) Save(name string, held bool, records []dns.RR) error {
	b, err := json.Marshal(savedName{Held: held, Records: dnsmsg.RecordStrings(records)})
	if err != nil {
		return err
	}
	return st.s.Set(recordsPrefix+name, string(b))
}
