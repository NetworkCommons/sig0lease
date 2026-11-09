package mdnsresponder

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeDaemon accepts one connection on a Unix socket, checks the request the way
// uds_daemon.c's read_msg reads it, answers with status and then the replies.
type fakeDaemon struct {
	path string
	ln   net.Listener
	got  chan request
}

type request struct {
	op   uint32
	data []byte
}

func newFakeDaemon(t *testing.T, status int32, replies [][]byte, keepOpen bool) *fakeDaemon {
	t.Helper()
	// Not under t.TempDir(): on macOS that path is long enough to push a socket path past
	// sun_path's 104 bytes, and bind then fails with EINVAL.
	dir, err := os.MkdirTemp("/tmp", "mdnsd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "mdnsd")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDaemon{path: path, ln: ln, got: make(chan request, 1)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var hdr [headerLen]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		data := make([]byte, binary.BigEndian.Uint32(hdr[4:]))
		if _, err := io.ReadFull(c, data); err != nil {
			return
		}
		if binary.BigEndian.Uint32(hdr[0:]) != ipcVersion || binary.BigEndian.Uint32(hdr[8:]) != 0 {
			return // wrong version, or ipc_flags asking for something we do not do
		}
		d.got <- request{op: binary.BigEndian.Uint32(hdr[12:]), data: data}
		c.Write(binary.BigEndian.AppendUint32(nil, uint32(status)))
		for _, r := range replies {
			c.Write(r)
		}
		if keepOpen {
			io.Copy(io.Discard, c) // until the client closes
		}
	}()
	return d
}

// replyMsg builds one reply: header, flags, interface, error, then body.
func replyMsg(op, flags, ifIndex uint32, errCode int32, body []byte) []byte {
	data := binary.BigEndian.AppendUint32(nil, flags)
	data = binary.BigEndian.AppendUint32(data, ifIndex)
	data = binary.BigEndian.AppendUint32(data, uint32(errCode))
	data = append(data, body...)
	hdr := make([]byte, headerLen)
	binary.BigEndian.PutUint32(hdr[0:], ipcVersion)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(data)))
	binary.BigEndian.PutUint32(hdr[12:], op)
	return append(hdr, data...)
}

func strs(ss ...string) []byte {
	var b []byte
	for _, s := range ss {
		b = putString(b, s)
	}
	return b
}

func TestBrowse_SendsRequestAndReportsAddAndRemove(t *testing.T) {
	d := newFakeDaemon(t, 0, [][]byte{
		replyMsg(opBrowseReply, flagAdd, 2, 0, strs("Living Room", "_http._tcp.", "local.")),
		replyMsg(opBrowseReply, 0, 2, 0, strs("Living Room", "_http._tcp.", "local.")),
	}, true)
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan BrowseEvent)
	done := make(chan error, 1)
	go func() { done <- Browse(ctx, d.path, "_http._tcp", "local.", events) }()

	req := <-d.got
	want := append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 0), strs("_http._tcp", "local.")...)
	if req.op != opBrowse || !slices.Equal(req.data, want) {
		t.Fatalf("request = op %d %q, want op %d %q", req.op, req.data, opBrowse, want)
	}
	add, rmv := <-events, <-events
	if !add.Add || add.Name != "Living Room" || add.Type != "_http._tcp." || add.Domain != "local." || add.InterfaceIndex != 2 {
		t.Errorf("first event = %+v", add)
	}
	if rmv.Add || rmv.Name != "Living Room" {
		t.Errorf("second event = %+v, want the removal", rmv)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Browse after cancel = %v, want context.Canceled", err)
	}
}

func TestBrowse_RequestStatusIsReturned(t *testing.T) {
	d := newFakeDaemon(t, int32(ErrPolicyDenied), nil, false)
	err := Browse(context.Background(), d.path, "_http._tcp", "local.", make(chan BrowseEvent))
	var e Error
	if !errors.As(err, &e) || e != ErrPolicyDenied {
		t.Fatalf("Browse = %v, want ErrPolicyDenied", err)
	}
}

func TestBrowse_ReplyErrorEndsIt(t *testing.T) {
	d := newFakeDaemon(t, 0, [][]byte{
		replyMsg(opBrowseReply, 0, 0, int32(ErrPolicyDenied), strs("", "", "")),
	}, true)
	err := Browse(context.Background(), d.path, "_http._tcp", "local.", make(chan BrowseEvent))
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("Browse = %v, want ErrPolicyDenied", err)
	}
}

func TestBrowse_UnexpectedReplyOpIsAnError(t *testing.T) {
	d := newFakeDaemon(t, 0, [][]byte{
		replyMsg(opResolveReply, flagAdd, 0, 0, strs("x", "_http._tcp.", "local.")),
	}, true)
	if err := Browse(context.Background(), d.path, "_http._tcp", "local.", make(chan BrowseEvent)); err == nil {
		t.Fatal("Browse accepted a resolve reply")
	}
}

func TestResolve_ParsesTargetPortAndTXT(t *testing.T) {
	body := strs(`Living\032Room._http._tcp.local.`, "box.local.")
	body = binary.BigEndian.AppendUint16(body, 8080)
	txt := []byte("\x07path=/x\x00\x03a=b")
	body = binary.BigEndian.AppendUint16(body, uint16(len(txt)))
	body = append(body, txt...)
	d := newFakeDaemon(t, 0, [][]byte{replyMsg(opResolveReply, 0, 3, 0, body)}, true)

	res, err := Resolve(context.Background(), d.path, 3, "Living Room", "_http._tcp.", "local.")
	if err != nil {
		t.Fatal(err)
	}
	req := <-d.got
	want := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 3)
	want = append(want, strs("Living Room", "_http._tcp.", "local.")...)
	if req.op != opResolve || !slices.Equal(req.data, want) {
		t.Fatalf("request = op %d %q, want op %d %q", req.op, req.data, opResolve, want)
	}
	if res.Target != "box.local." || res.Port != 8080 || res.FullName != `Living\032Room._http._tcp.local.` {
		t.Errorf("result = %+v", res)
	}
	wantTXT := [][]byte{[]byte("path=/x"), {}, []byte("a=b")}
	if !slices.EqualFunc(res.TXT, wantTXT, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Errorf("TXT = %q, want %q", res.TXT, wantTXT)
	}
}

func TestResolve_TXTRunningPastItsEndIsAnError(t *testing.T) {
	body := strs("x._http._tcp.local.", "box.local.")
	body = binary.BigEndian.AppendUint16(body, 80)
	body = binary.BigEndian.AppendUint16(body, 3)
	body = append(body, "\x05ab"...)
	d := newFakeDaemon(t, 0, [][]byte{replyMsg(opResolveReply, 0, 3, 0, body)}, true)
	if _, err := Resolve(context.Background(), d.path, 3, "x", "_http._tcp.", "local."); err == nil {
		t.Fatal("Resolve accepted a TXT string longer than the record")
	}
}

func addrReply(rrtype uint16, rdata []byte) []byte {
	body := strs("box.local.")
	body = binary.BigEndian.AppendUint16(body, rrtype)
	body = binary.BigEndian.AppendUint16(body, 1) // class IN
	body = binary.BigEndian.AppendUint16(body, uint16(len(rdata)))
	body = append(body, rdata...)
	body = binary.BigEndian.AppendUint32(body, 120)
	return replyMsg(opAddrInfoReply, flagAdd, 2, 0, body)
}

func TestAddresses_CollectsAAndAAAAUntilQuiet(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.5")
	v6 := netip.MustParseAddr("2001:db8::5")
	d := newFakeDaemon(t, 0, [][]byte{
		addrReply(typeA, v4.AsSlice()),
		addrReply(typeAAAA, v6.AsSlice()),
		addrReply(typeA, v4.AsSlice()), // a second interface reports it again
	}, true)

	got, err := Addresses(context.Background(), d.path, 0, "box.local.", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	req := <-d.got
	want := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0), 0)
	want = binary.BigEndian.AppendUint32(want, protocolIPv4|protocolIPv6)
	want = append(want, strs("box.local.")...)
	if req.op != opAddrInfo || !slices.Equal(req.data, want) {
		t.Fatalf("request = op %d %q, want op %d %q", req.op, req.data, opAddrInfo, want)
	}
	if !slices.Equal(got, []netip.Addr{v4, v6}) {
		t.Errorf("Addresses = %v, want [%v %v]", got, v4, v6)
	}
}

func TestAddresses_NoAddressIsAnError(t *testing.T) {
	d := newFakeDaemon(t, 0, nil, true)
	if _, err := Addresses(context.Background(), d.path, 0, "box.local.", 50*time.Millisecond); err == nil {
		t.Fatal("Addresses returned no error without any address")
	}
}

func TestAddresses_WrongLengthRdataIsAnError(t *testing.T) {
	d := newFakeDaemon(t, 0, [][]byte{addrReply(typeA, []byte{1, 2, 3})}, true)
	if _, err := Addresses(context.Background(), d.path, 0, "box.local.", 50*time.Millisecond); err == nil {
		t.Fatal("Addresses accepted a 3-byte A record")
	}
}

func TestConnectFailureNamesTheSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	_, err := Resolve(context.Background(), path, 0, "x", "_http._tcp.", "local.")
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("Resolve = %v, want an error naming %s", err, path)
	}
}
