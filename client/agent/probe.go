package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// probe checks that the service answers at one of addrs, port port: it passes at the first
// address that does, each tried for at most timeout.
func probe(ctx context.Context, p Probe, addrs []netip.Addr, port uint16, timeout time.Duration) error {
	if len(addrs) == 0 {
		return errors.New("the host has no address to probe")
	}
	var errs []string
	for _, a := range addrs {
		target := netip.AddrPortFrom(a, port).String()
		var err error
		switch p.Kind {
		case ProbeTCP:
			err = probeTCP(ctx, target, timeout)
		case ProbeHTTP:
			err = probeHTTP(ctx, target, p.Path, timeout)
		default:
			panic(fmt.Sprintf("agent: probe of kind %d", p.Kind))
		}
		if err == nil {
			return nil
		}
		errs = append(errs, err.Error())
	}
	return errors.New(strings.Join(errs, "; "))
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
