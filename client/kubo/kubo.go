// Package kubo asks a kubo node -- the IPFS daemon, which IPFS Desktop runs -- through its RPC
// API (docs.ipfs.tech/reference/kubo/rpc/): its peer ID and addresses, the CID of a path in its
// files (MFS, IPFS Desktop's Files), and its pins.
package kubo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// DefaultAPI is where kubo's RPC API listens unless configured otherwise (Addresses.API).
const DefaultAPI = "http://127.0.0.1:5001"

// CheckAPI reports whether api is an RPC API's address: "http://host:port", with no path.
func CheckAPI(api string) error {
	u, err := url.Parse(api)
	if err != nil {
		return err
	}
	if u.Scheme != "http" || u.Host == "" || u.Port() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return fmt.Errorf("%q: want http://host:port, such as %s", api, DefaultAPI)
	}
	return nil
}

// Client is a kubo node's RPC API.
type Client struct {
	api     string
	timeout time.Duration
	http    *http.Client
}

// New returns the Client of the RPC API at api (CheckAPI). Every request but Pin's lasts at
// most timeout.
func New(api string, timeout time.Duration) *Client {
	u, _ := url.Parse(api)
	u.Path = ""
	return &Client{api: u.String(), timeout: timeout, http: &http.Client{Transport: &http.Transport{Proxy: nil}}}
}

// ID returns the node's peer ID and the addresses it can be reached at, each a multiaddr ending
// in /p2p/<ID>.
func (c *Client) ID(ctx context.Context) (id string, addrs []string, err error) {
	var out struct {
		ID        string
		Addresses []string
	}
	if err := c.call(ctx, c.timeout, "id", nil, &out); err != nil {
		return "", nil, err
	}
	return out.ID, out.Addresses, nil
}

// MFSCID returns the CID of path in the node's files (MFS).
func (c *Client) MFSCID(ctx context.Context, path string) (string, error) {
	var out struct{ Hash string }
	if err := c.call(ctx, c.timeout, "files/stat", url.Values{"arg": {path}, "hash": {"true"}}, &out); err != nil {
		return "", err
	}
	if out.Hash == "" {
		return "", fmt.Errorf("kubo files/stat %s: no hash in the answer", path)
	}
	return out.Hash, nil
}

// Pin pins cid and everything it links to under name, fetching from other nodes what the node
// does not hold, which lasts until the node holds it all or ctx ends. It returns the CID as
// the node writes it.
func (c *Client) Pin(ctx context.Context, cid, name string) (string, error) {
	var out struct{ Pins []string }
	if err := c.call(ctx, 0, "pin/add", url.Values{"arg": {"/ipfs/" + cid}, "name": {name}}, &out); err != nil {
		return "", err
	}
	if len(out.Pins) != 1 {
		return "", fmt.Errorf("kubo pin/add %s: pinned %v", cid, out.Pins)
	}
	return out.Pins[0], nil
}

// PinsNamed returns the CIDs pinned with everything they link to under name, sorted.
func (c *Client) PinsNamed(ctx context.Context, name string) ([]string, error) {
	var out struct {
		Keys map[string]struct{ Name string }
	}
	if err := c.call(ctx, c.timeout, "pin/ls", url.Values{"type": {"recursive"}, "names": {"true"}}, &out); err != nil {
		return nil, err
	}
	var cids []string
	for cid, p := range out.Keys {
		if p.Name == name {
			cids = append(cids, cid)
		}
	}
	slices.Sort(cids)
	return cids, nil
}

// Unpin removes cid's pin. What it pinned stays in the node until kubo's garbage collector
// frees it.
func (c *Client) Unpin(ctx context.Context, cid string) error {
	return c.call(ctx, c.timeout, "pin/rm", url.Values{"arg": {"/ipfs/" + cid}}, nil)
}

// call sends the RPC command cmd with args, for at most timeout unless 0, and decodes its
// answer into out unless nil. kubo answers an error with a status other than 200 and a JSON
// object whose Message says what failed.
func (c *Client) call(ctx context.Context, timeout time.Duration, cmd string, args url.Values, out any) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.api+"/api/v0/"+cmd+"?"+args.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kubo %s: %w", cmd, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Message string }
		if json.NewDecoder(resp.Body).Decode(&e) != nil || e.Message == "" {
			return fmt.Errorf("kubo %s: %s", cmd, resp.Status)
		}
		return fmt.Errorf("kubo %s: %s", cmd, e.Message)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("kubo %s: reading the answer: %w", cmd, err)
	}
	return nil
}
