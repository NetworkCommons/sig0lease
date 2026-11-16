package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// probe checks that the service answers at one of addrs, port port: it tries them all at once,
// each for at most timeout, and passes as soon as one answers.
func probe(ctx context.Context, p Probe, addrs []netip.Addr, port uint16, timeout time.Duration) error {
	if len(addrs) == 0 {
		return errors.New("the host has no address to probe")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make([]error, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Go(func() {
			if errs[i] = probeAt(ctx, p, netip.AddrPortFrom(a, port).String(), timeout); errs[i] == nil {
				cancel() // the others need not finish
			}
		})
	}
	wg.Wait()
	msgs := make([]string, len(errs))
	for i, err := range errs {
		if err == nil {
			return nil
		}
		msgs[i] = err.Error()
	}
	return errors.New(strings.Join(msgs, "; "))
}

func probeAt(ctx context.Context, p Probe, target string, timeout time.Duration) error {
	switch p.Kind {
	case ProbeTCP:
		return probeTCP(ctx, target, timeout)
	case ProbeHTTP:
		return probeHTTP(ctx, target, p.Path, timeout)
	default:
		panic(fmt.Sprintf("agent: probe of kind %d", p.Kind))
	}
}

func probeTCP(ctx context.Context, target string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// probeHTTP passes when a GET of path answers 2xx or 3xx; a redirect is not followed.
func probeHTTP(ctx context.Context, target, path string, timeout time.Duration) error {
	c := &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{DisableKeepAlives: true, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := "http://" + target + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return nil
}
