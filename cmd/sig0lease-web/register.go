//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"syscall/js"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/srp"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
)

// registerTimeout is how long register waits for the registrar's answer.
const registerTimeout = 20 * time.Second

// RegisterRequest is register's argument: one SRP host, with its addresses and instances,
// registered at the SRP registrar doh (a DoH URL, RFC 9665 names no DoH discovery) for Lease
// seconds, its KEY for KeyLease. Key, if set, is the host's key as Key returns it; else a
// fresh key signs.
type RegisterRequest struct {
	DoH       string             `json:"doh"`
	Domain    string             `json:"domain"`
	Host      string             `json:"host"`
	Addresses []string           `json:"addresses"`
	Instances []RegisterInstance `json:"instances"`
	Lease     uint32             `json:"lease"`
	KeyLease  uint32             `json:"keyLease"`
	Key       *Key               `json:"key"`
}

// RegisterInstance is one service instance of a RegisterRequest: Service is the service type
// ("_fedi._tcp"), Subtypes bare labels, TXT the strings as they are (not escaped).
type RegisterInstance struct {
	Label    string   `json:"label"`
	Service  string   `json:"service"`
	Subtypes []string `json:"subtypes"`
	Port     uint16   `json:"port"`
	TXT      []string `json:"txt"`
}

// Key is a SIG(0) key as text (keyrec.LoadedKey.KeyText), for the page to keep and hand back.
type Key struct {
	Public  string `json:"public"`
	Private string `json:"private"`
}

// RegisterResult is register's result: Registered, or Conflict when another key holds a name
// of the request (YXDOMAIN, RFC 9665 S3.3.3), which register does not rename around; Key is
// the key that signed.
type RegisterResult struct {
	Registered bool `json:"registered"`
	Conflict   bool `json:"conflict"`
	Key        Key  `json:"key"`
}

// registerFunc is sig0lease.register: it registers the RegisterRequest args[0] once, without
// a Page, and without refreshing it: it lasts as long as its lease.
func registerFunc(_ js.Value, args []js.Value) any {
	return promise(func() (any, error) {
		if len(args) != 1 || args[0].Type() != js.TypeObject {
			return nil, errors.New("register takes one object: {doh, domain, host, addresses, instances, lease, keyLease, key}")
		}
		var req RegisterRequest
		text := js.Global().Get("JSON").Call("stringify", args[0]).String()
		if err := json.Unmarshal([]byte(text), &req); err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
		defer cancel()
		return register(ctx, req)
	})
}

// newKeyFunc is sig0lease.newKey: a fresh P-256 SIG(0) key for the name args[0], as Key, so
// that a page keeps a key before it registers with it, and a retried registration, whose
// answer was lost, signs with the same key.
func newKeyFunc(_ js.Value, args []js.Value) any {
	return promise(func() (any, error) {
		name := arg(args, 0)
		if name == "" {
			return nil, errors.New("newKey takes the key's name")
		}
		key, err := keyrec.GenerateKey(dnsutil.Fqdn(name), dns.ECDSAP256SHA256, 0, 256)
		if err != nil {
			return nil, fmt.Errorf("newKey: %w", err)
		}
		var k Key
		k.Public, k.Private = key.KeyText()
		return k, nil
	})
}

// register registers req once at its DoH registrar.
func register(ctx context.Context, req RegisterRequest) (*RegisterResult, error) {
	if err := client.NetworkDoH.CheckServer(req.DoH); err != nil {
		return nil, fmt.Errorf("register: DoH: %w", err)
	}
	var addrs []netip.Addr
	for _, s := range req.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("register: address %q: %w", s, err)
		}
		addrs = append(addrs, a)
	}
	addrs = srp.PublishableAddresses(addrs)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("register: %s has no publishable address", req.Host)
	}

	owner := dnsutil.Fqdn(req.Host + "." + req.Domain)
	var key *keyrec.LoadedKey
	var err error
	if req.Key != nil {
		key, err = keyrec.ParseKey(owner, req.Key.Public, req.Key.Private)
	} else {
		key, err = keyrec.GenerateKey(owner, dns.ECDSAP256SHA256, 0, 256)
	}
	if err != nil {
		return nil, fmt.Errorf("register: key for %s: %w", owner, err)
	}

	instances := make([]srp.InstanceConfig, len(req.Instances))
	for i, in := range req.Instances {
		txt := make([]string, len(in.TXT))
		for j, s := range in.TXT {
			txt[j] = dnsmsg.EscapeTXT(s)
		}
		instances[i] = srp.InstanceConfig{
			Label:       in.Label,
			ServiceType: in.Service,
			Subtypes:    in.Subtypes,
			Port:        in.Port,
			TXT:         txt,
		}
	}
	c, err := srp.NewClient(srp.Config{
		Domain:            req.Domain,
		HostLabel:         req.Host,
		Addresses:         addrs,
		Instances:         instances,
		Key:               key,
		RequestedLease:    req.Lease,
		RequestedKeyLease: req.KeyLease,
		RegistrarAddr:     req.DoH,
		Network:           client.NetworkDoH,
		Send:              send,
	})
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	resp, outcome, err := c.Register(ctx)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	res := &RegisterResult{
		Registered: outcome == client.OutcomeSuccess,
		Conflict:   outcome == client.OutcomeConflict,
	}
	res.Key.Public, res.Key.Private = key.KeyText()
	if !res.Registered && !res.Conflict {
		return nil, fmt.Errorf("register: %s: %s", owner, client.DescribeAnswer(resp, outcome))
	}
	return res, nil
}
