//go:build js && wasm

// Command sig0lease-web is the program of the demo's browser page (docs/demo.md, D6): a
// client/web Page, as the global object sig0lease, whose functions all return a Promise:
//
//	sig0lease.start({doh, updateDomain, srpDomain, log})
//	                                           starts the Page (web.Config): the proxy's DoH
//	                                           server, where names are claimed (the RFC 9664
//	                                           handler's subtree), the DNS-SD domain browsed
//	                                           (the SRP handler's), and a function that takes
//	                                           each log line
//	sig0lease.browse()                          the SRP domain: {domain, types, instances}
//	sig0lease.names()                           the names in updateDomain, outside srpDomain:
//	                                           [{name, key, records: [{owner, type, data}]}]
//	sig0lease.message(label)                    the strings of the TXT records at the name
//	sig0lease.claimed()                         the claim the browser keeps, {label, message},
//	                                           or null
//	sig0lease.claim(label, message)             claims the name with the message
//	sig0lease.release()                         frees the name claimed
//	sig0lease.lookup(doh, name, type)           asks the DoH server doh (a proxy, which answers
//	                                           its zones from their authoritative server, and
//	                                           never from a cache) one question, without start:
//	                                           {authoritative, records: [{name, type, ttl,
//	                                           data}]}; a name the proxy does not serve goes
//	                                           to fallback, and authoritative is false
//	sig0lease.register({doh, domain, host, addresses, instances, lease, keyLease, key})
//	                                           registers an SRP host once at the SRP
//	                                           registrar doh, without start or refresh
//	                                           (RegisterRequest): {registered, conflict, key}
//	sig0lease.newKey(name)                      a fresh key for register: {public, private}
//
// The browser's localStorage keeps the name's key and the claim. A question the proxy refuses
// as a name it does not serve goes to fallback, Google's public resolver, which any page may
// ask. make web builds it, with the page and Go's loader beside it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/NetworkCommons/sig0lease/client"
	"github.com/NetworkCommons/sig0lease/client/browse"
	"github.com/NetworkCommons/sig0lease/client/web"
	"github.com/NetworkCommons/sig0lease/pkg/dnsmsg"
)

// page is the Page start made; nil before.
var page *web.Page

func main() {
	js.Global().Set("sig0lease", js.ValueOf(map[string]any{
		"start": js.FuncOf(func(_ js.Value, args []js.Value) any {
			return promise(func() (any, error) { return nil, start(args) })
		}),
		"browse": call(func(p *web.Page, _ []js.Value) (any, error) {
			return p.Browse(context.Background())
		}),
		"names": call(func(p *web.Page, _ []js.Value) (any, error) {
			return p.Names(context.Background())
		}),
		"message": call(func(p *web.Page, args []js.Value) (any, error) {
			return p.Message(context.Background(), arg(args, 0))
		}),
		"claimed": call(func(p *web.Page, _ []js.Value) (any, error) {
			c, ok, err := p.Claimed()
			if err != nil || !ok {
				return nil, err
			}
			return c, nil
		}),
		"claim": call(func(p *web.Page, args []js.Value) (any, error) {
			return nil, p.Claim(arg(args, 0), arg(args, 1))
		}),
		"release": call(func(p *web.Page, _ []js.Value) (any, error) {
			return nil, p.Release()
		}),
		"register": js.FuncOf(registerFunc),
		"newKey":   js.FuncOf(newKeyFunc),
		"lookup": js.FuncOf(func(_ js.Value, args []js.Value) any {
			return promise(func() (any, error) {
				return lookup(context.Background(), arg(args, 0), arg(args, 1), arg(args, 2))
			})
		}),
	}))
	select {} // the page calls in until it closes
}

// fallback is the page's web.Config.Fallback: Google's public DNS-over-HTTPS resolver, which
// allows any origin, for a GET (client.Client's queryDoH sends queries so).
const fallback = "https://dns.google"

// lookupTimeout is how long lookup waits for one answer.
const lookupTimeout = 10 * time.Second

// send is lookup's transport; queriers are its Query per DoH server.
var (
	send     = client.LiveTransport(lookupTimeout)
	queriers sync.Map // DoH server -> browse.Query
)

// Answer is lookup's result: the records, and whether the proxy, which asks the zone's
// authoritative server, answered, rather than fallback, a resolver that may answer from its
// cache.
type Answer struct {
	Authoritative bool     `json:"authoritative"`
	Records       []Record `json:"records"`
}

// Record is one record of an Answer. Data is, by type: PTR, CNAME, NS its target; SRV an
// SRVData; TXT its strings, as their octets; any other its data in presentation format.
type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data any    `json:"data"`
}

// SRVData is the data of an SRV Record.
type SRVData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// lookup asks doh for the records of type qtype at name (browse.Answers, so it follows CNAMEs),
// and asks fallback instead when doh refuses the name as one it does not serve.
func lookup(ctx context.Context, doh, name, qtype string) (*Answer, error) {
	if err := client.NetworkDoH.CheckServer(doh); err != nil {
		return nil, fmt.Errorf("lookup: DoH: %w", err)
	}
	if name == "" {
		return nil, errors.New("lookup: no name")
	}
	t, err := dnsutil.StringToType(strings.ToUpper(qtype))
	if err != nil {
		return nil, fmt.Errorf("lookup: type %q: %w", qtype, err)
	}
	name = dnsutil.Fqdn(name)
	q, _ := queriers.LoadOrStore(doh, browse.Querier(send, doh, client.NetworkDoH))
	ans := &Answer{Authoritative: true}
	rrs, err := q.(browse.Query)(ctx, name, t)
	if notServed(err) {
		ans.Authoritative = false
		rrs, err = browse.Querier(send, fallback, client.NetworkDoH)(ctx, name, t)
	}
	if err != nil {
		return nil, err
	}
	ans.Records = make([]Record, 0, len(rrs))
	for _, rr := range rrs {
		ans.Records = append(ans.Records, Record{
			Name: rr.Header().Name,
			Type: dnsutil.TypeToString(dns.RRToType(rr)),
			TTL:  rr.Header().TTL,
			Data: recordData(rr),
		})
	}
	return ans, nil
}

// recordData returns rr's data as a Record holds it.
func recordData(rr dns.RR) any {
	switch rr := rr.(type) {
	case *dns.PTR:
		return rr.Ptr
	case *dns.CNAME:
		return rr.Target
	case *dns.NS:
		return rr.Ns
	case *dns.SRV:
		return SRVData{Priority: rr.Priority, Weight: rr.Weight, Port: rr.Port, Target: rr.Target}
	case *dns.TXT:
		return dnsmsg.TXTStrings(rr)
	}
	return rr.Data().String()
}

// notServed reports whether err is the answer of a proxy that refuses the name as not one it
// serves: REFUSED, with Extended DNS Error 20, Not Authoritative (browse.Fallback).
func notServed(err error) bool {
	var re *browse.RcodeError
	if !errors.As(err, &re) || re.Rcode != dns.RcodeRefused {
		return false
	}
	for _, ede := range re.EDEs {
		if ede.InfoCode == dns.ExtendedErrorNotAuthoritative {
			return true
		}
	}
	return false
}

// start makes the Page from the configuration object args[0].
func start(args []js.Value) (err error) {
	if page != nil {
		return errors.New("sig0lease is started already")
	}
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return errors.New("start takes one object: {doh, updateDomain, srpDomain, log}")
	}
	o := args[0]
	log := o.Get("log")
	if log.Type() != js.TypeFunction {
		return errors.New("start: log must be a function")
	}
	storage, err := localStorage()
	if err != nil {
		return err
	}
	page, err = web.New(web.Config{
		DoH:          field(o, "doh"),
		UpdateDomain: field(o, "updateDomain"),
		SRPDomain:    field(o, "srpDomain"),
		Storage:      storage,
		Fallback:     fallback,
		Logf:         func(format string, a ...any) { log.Invoke(fmt.Sprintf(format, a...)) },
	})
	return err
}

// call makes the JavaScript function that runs f with the Page start made.
func call(f func(*web.Page, []js.Value) (any, error)) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		return promise(func() (any, error) {
			if page == nil {
				return nil, errors.New("call sig0lease.start first")
			}
			return f(page, args)
		})
	})
}

// promise returns a Promise of f's result, as JSON.parse reads it from f's value in JSON, and
// runs f in a goroutine of its own: a call from JavaScript has to return at once, as nothing
// else runs until it does, the answers to the requests f sends through fetch included.
func promise(f func() (any, error)) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			v, err := f()
			if err == nil {
				var b []byte
				if b, err = json.Marshal(v); err == nil {
					resolve.Invoke(js.Global().Get("JSON").Call("parse", string(b)))
					return
				}
			}
			reject.Invoke(js.Global().Get("Error").New(err.Error()))
		}()
		return nil
	})
	defer executor.Release() // the Promise calls it before New returns
	return js.Global().Get("Promise").New(executor)
}

// arg returns args[i] as a string: "" when it is missing or not a string, which the Page
// refuses as a label.
func arg(args []js.Value, i int) string {
	if i >= len(args) || args[i].Type() != js.TypeString {
		return ""
	}
	return args[i].String()
}

// field returns o's property name as a string: "" when it is missing or not a string, which
// web.New refuses.
func field(o js.Value, name string) string {
	if v := o.Get(name); v.Type() == js.TypeString {
		return v.String()
	}
	return ""
}

// storage is the browser's localStorage as a web.Storage.
type storage struct{ v js.Value }

// localStorage returns the browser's localStorage, which a browser may refuse the page, as
// when it blocks storage for the site.
func localStorage() (s storage, err error) {
	defer catch(&err)
	v := js.Global().Get("localStorage")
	if v.Type() != js.TypeObject {
		return storage{}, errors.New("this browser gives the page no localStorage, where the name's key is kept")
	}
	return storage{v}, nil
}

func (s storage) Get(key string) (string, bool) {
	v := s.v.Call("getItem", key)
	if v.IsNull() {
		return "", false
	}
	return v.String(), true
}

// Set stores value, or fails as setItem does when the storage is full.
func (s storage) Set(key, value string) (err error) {
	defer catch(&err)
	s.v.Call("setItem", key, value)
	return nil
}

func (s storage) Remove(key string) { s.v.Call("removeItem", key) }

// catch turns the panic a JavaScript exception raises in the function deferring it into that
// function's error.
func catch(err *error) {
	if r := recover(); r != nil {
		jsErr, ok := r.(js.Error)
		if !ok {
			panic(r)
		}
		*err = jsErr
	}
}
