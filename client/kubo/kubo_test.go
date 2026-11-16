package kubo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCheckAPI(t *testing.T) {
	for _, api := range []string{"http://127.0.0.1:5001", "http://[::1]:5001/", "http://node.local:5001"} {
		if err := CheckAPI(api); err != nil {
			t.Errorf("CheckAPI(%q) = %v", api, err)
		}
	}
	for _, api := range []string{"", "127.0.0.1:5001", "https://127.0.0.1:5001", "http://127.0.0.1", "http://127.0.0.1:5001/api/v0", "http://127.0.0.1:5001?x=1", "http://u:p@127.0.0.1:5001"} {
		if err := CheckAPI(api); err == nil {
			t.Errorf("CheckAPI(%q): no error", api)
		}
	}
}

// node answers each RPC command from answers, by path, after checking that it is a POST; a
// command it has no answer for fails as kubo does, with a 500 and a Message.
func node(t *testing.T, answers map[string]string, asked *[]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("%s %s, want POST", r.Method, r.URL)
		}
		*asked = append(*asked, r.URL.Path+"?"+r.URL.RawQuery)
		answer, ok := answers[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"Message":"file does not exist","Code":0,"Type":"error"}`))
			return
		}
		w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/", time.Second)
}

func TestClient(t *testing.T) {
	var asked []string
	c := node(t, map[string]string{
		"/api/v0/id":         `{"ID":"12D3Koo","Addresses":["/ip4/127.0.0.1/tcp/4001/p2p/12D3Koo"],"AgentVersion":"kubo/0.43.1"}`,
		"/api/v0/files/stat": `{"Hash":"QmFolder","Size":0,"CumulativeSize":4,"Blocks":0,"Type":"directory"}`,
		"/api/v0/pin/add":    `{"Pins":["QmFolder"]}`,
		"/api/v0/pin/ls":     `{"Keys":{"QmB":{"Type":"recursive","Name":"site"},"QmA":{"Type":"recursive","Name":"site"},"QmC":{"Type":"recursive","Name":"site 2"},"QmD":{"Type":"recursive","Name":""}}}`,
		"/api/v0/pin/rm":     `{"Pins":["QmA"]}`,
	}, &asked)
	ctx := context.Background()

	if id, addrs, err := c.ID(ctx); err != nil || id != "12D3Koo" || !slices.Equal(addrs, []string{"/ip4/127.0.0.1/tcp/4001/p2p/12D3Koo"}) {
		t.Errorf("ID = %q, %q, %v", id, addrs, err)
	}
	if cid, err := c.MFSCID(ctx, "/my folder"); err != nil || cid != "QmFolder" {
		t.Errorf("MFSCID = %q, %v", cid, err)
	}
	if got, err := c.Pin(ctx, "QmFolder", "site"); err != nil || got != "QmFolder" {
		t.Errorf("Pin = %q, %v", got, err)
	}
	if cids, err := c.PinsNamed(ctx, "site"); err != nil || !slices.Equal(cids, []string{"QmA", "QmB"}) {
		t.Errorf("PinsNamed = %q, %v; want the pins named exactly site", cids, err)
	}
	if err := c.Unpin(ctx, "QmA"); err != nil {
		t.Errorf("Unpin = %v", err)
	}
	want := []string{
		"/api/v0/id?",
		"/api/v0/files/stat?arg=%2Fmy+folder&hash=true",
		"/api/v0/pin/add?arg=%2Fipfs%2FQmFolder&name=site",
		"/api/v0/pin/ls?names=true&type=recursive",
		"/api/v0/pin/rm?arg=%2Fipfs%2FQmA",
	}
	if !slices.Equal(asked, want) {
		t.Errorf("asked\n  %s\nwant\n  %s", strings.Join(asked, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestClient_Errors(t *testing.T) {
	var asked []string
	c := node(t, nil, &asked)
	if _, err := c.MFSCID(context.Background(), "/community"); err == nil || err.Error() != "kubo files/stat: file does not exist" {
		t.Errorf("MFSCID of a missing path = %v, want kubo's message", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if _, _, err := New(srv.URL, time.Second).ID(context.Background()); err == nil || err.Error() != "kubo id: 403 Forbidden" {
		t.Errorf("ID answered 403 without a body = %v, want the status", err)
	}
	srv.Close()
	if _, _, err := New(srv.URL, time.Second).ID(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "kubo id: ") {
		t.Errorf("ID of a node not running = %v", err)
	}
}

// Pin waits for the node however long it takes, until its context ends; the other requests
// last at most the client's timeout.
func TestClient_Timeouts(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.Write([]byte(`{"Pins":["QmX"]}`))
	}))
	defer srv.Close()
	defer close(release)
	c := New(srv.URL, 50*time.Millisecond)
	if _, _, err := c.ID(context.Background()); err == nil {
		t.Fatal("ID of a node that does not answer: no error")
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.Pin(context.Background(), "QmX", "n")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("Pin returned within the timeout: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("Pin = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, err := c.Pin(ctx, "QmX", "n")
		done <- err
	}()
	cancel()
	if err := <-done; err == nil {
		t.Fatal("Pin with its context cancelled: no error")
	}
}
