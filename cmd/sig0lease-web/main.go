//go:build js && wasm

// Command sig0lease-web is the program of the demo's browser page (docs/demo.md, E3): a
// client/web Page, as the global object sig0lease, whose functions all return a Promise:
//
//	sig0lease.start({doh, zone, domain, log})  starts the Page (web.Config): the proxy's DoH
//	                                           server, the zone names are claimed in, the
//	                                           DNS-SD domain browsed, and a function that takes
//	                                           each log line
//	sig0lease.browse()                          the domain: {domain, types, instances}
//	sig0lease.message(label)                    the strings of the TXT records at the name
//	sig0lease.claimed()                         the claim the browser keeps, {label, message},
//	                                           or null
//	sig0lease.claim(label, message)             claims the name with the message
//	sig0lease.release()                         frees the name claimed
//
// The browser's localStorage keeps the name's key and the claim. make web builds it, with the
// page and Go's loader beside it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"

	"github.com/NetworkCommons/sig0lease/client/web"
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
	}))
	select {} // the page calls in until it closes
}

// start makes the Page from the configuration object args[0].
func start(args []js.Value) (err error) {
	if page != nil {
		return errors.New("sig0lease is started already")
	}
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return errors.New("start takes one object: {doh, zone, domain, log}")
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
		DoH:     field(o, "doh"),
		Zone:    field(o, "zone"),
		Domain:  field(o, "domain"),
		Storage: storage,
		Logf:    func(format string, a ...any) { log.Invoke(fmt.Sprintf(format, a...)) },
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
