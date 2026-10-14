// Package mdnsresponder talks to a running mDNSResponder daemon over its own client socket:
// the Unix-domain socket every DNS-SD application reaches through dns_sd.h
// (mDNSShared/dnssd_clientstub.c on the client side, mDNSShared/uds_daemon.c in the daemon).
// It implements the three read-only operations a bridge needs -- browse, resolve and address
// lookup -- in pure Go, so one binary talks to the system daemon on macOS and to mDNSPosix's
// mdnsd on Linux without cgo.
//
// Each operation gets its own connection, as DNSServiceBrowse and friends do without
// kDNSServiceFlagsShareConnection. The daemon then returns the request's status as four
// bytes on that same socket (no separate error socket is passed), followed by the replies;
// closing the connection cancels the operation.
package mdnsresponder

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"time"
)

// DefaultSocketPath is where the daemon listens on this OS: /var/run/mDNSResponder on macOS
// (dnssd_ipc.h's MDNS_UDS_SERVERPATH default), /var/run/mdnsd elsewhere (the path
// mDNSPosix/Makefile compiles into mdnsd).
func DefaultSocketPath() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/mDNSResponder"
	}
	return "/var/run/mdnsd"
}

// Request and reply operation codes (dnssd_ipc.h request_op_t, reply_op_t).
const (
	opBrowse   = 6
	opResolve  = 7
	opAddrInfo = 15

	opBrowseReply   = 66
	opResolveReply  = 67
	opAddrInfoReply = 72
)

const (
	ipcVersion = 1  // dnssd_ipc.h VERSION
	headerLen  = 28 // sizeof(ipc_msg_hdr)
	// maxReplyLen bounds a reply's datalen; the daemon itself refuses requests above 70000
	// bytes (uds_daemon.c read_msg), and no reply carries more than one record's rdata.
	maxReplyLen = 70000

	flagAdd = 0x2 // kDNSServiceFlagsAdd

	protocolIPv4 = 0x1 // kDNSServiceProtocol_IPv4
	protocolIPv6 = 0x2 // kDNSServiceProtocol_IPv6

	typeA    = 1
	typeAAAA = 28
)

// Error is a DNSServiceErrorType the daemon returned, as a request status or in a reply.
type Error int32

const (
	ErrNoSuchRecord Error = -65554 // kDNSServiceErr_NoSuchRecord
	ErrNoAuth       Error = -65555 // kDNSServiceErr_NoAuth
	ErrPolicyDenied Error = -65570 // kDNSServiceErr_PolicyDenied
)

func (e Error) Error() string {
	switch e {
	case ErrPolicyDenied:
		// What macOS returns when the process (or the terminal it runs in) has no Local
		// Network permission.
		return fmt.Sprintf("mDNSResponder error %d (PolicyDenied: on macOS, allow local network access for this terminal in System Settings > Privacy & Security > Local Network)", int32(e))
	case ErrNoAuth:
		return fmt.Sprintf("mDNSResponder error %d (NoAuth)", int32(e))
	case ErrNoSuchRecord:
		return fmt.Sprintf("mDNSResponder error %d (NoSuchRecord)", int32(e))
	}
	return fmt.Sprintf("mDNSResponder error %d", int32(e))
}

// BrowseEvent is one browse reply: an instance appeared (Add) or went away on one
// interface. The same instance is reported once per interface it is seen on.
type BrowseEvent struct {
	Add            bool
	InterfaceIndex uint32
	Name           string // instance name as UTF-8 text, unescaped, e.g. "Living Room"
	Type           string // e.g. "_http._tcp."
	Domain         string // e.g. "local."
}

// ResolveResult is a resolved service instance.
type ResolveResult struct {
	FullName string // escaped, e.g. `Living\032Room._http._tcp.local.`
	Target   string // host name, e.g. "printer.local."
	Port     uint16
	// TXT holds the instance's TXT strings as raw bytes, in order (RFC 6763 S6).
	TXT [][]byte
}

// conn is one request's connection to the daemon.
type conn struct {
	c net.Conn
}

// open connects to the daemon at socketPath, sends one request and reads its status.
func open(ctx context.Context, socketPath string, op uint32, data []byte) (*conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("mdnsresponder: connect to %s: %w", socketPath, err)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	hdr := make([]byte, headerLen, headerLen+len(data))
	binary.BigEndian.PutUint32(hdr[0:], ipcVersion)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(data)))
	// hdr[8:12] ipc_flags, hdr[16:24] client_context and hdr[24:28] reg_index stay zero.
	binary.BigEndian.PutUint32(hdr[12:], op)
	if _, err := c.Write(append(hdr, data...)); err != nil {
		c.Close()
		return nil, ctxErr(ctx, fmt.Errorf("mdnsresponder: send request: %w", err))
	}
	var status [4]byte
	if _, err := io.ReadFull(c, status[:]); err != nil {
		c.Close()
		return nil, ctxErr(ctx, fmt.Errorf("mdnsresponder: read request status: %w", err))
	}
	if code := Error(int32(binary.BigEndian.Uint32(status[:]))); code != 0 {
		c.Close()
		return nil, code
	}
	return &conn{c: c}, nil
}

// reply is one reply's common fields (the CallbackHeader the client stub reads first) and
// the rest of its data.
type reply struct {
	flags          uint32
	interfaceIndex uint32
	err            Error
	rest           []byte
}

// next reads one reply, which must be of type wantOp.
func (cn *conn) next(wantOp uint32) (reply, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(cn.c, hdr[:]); err != nil {
		return reply{}, fmt.Errorf("mdnsresponder: read reply header: %w", err)
	}
	if v := binary.BigEndian.Uint32(hdr[0:]); v != ipcVersion {
		return reply{}, fmt.Errorf("mdnsresponder: reply has IPC version %d, want %d", v, ipcVersion)
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	if n > maxReplyLen {
		return reply{}, fmt.Errorf("mdnsresponder: reply datalen %d exceeds %d", n, maxReplyLen)
	}
	if op := binary.BigEndian.Uint32(hdr[12:]); op != wantOp {
		return reply{}, fmt.Errorf("mdnsresponder: got reply op %d, want %d", op, wantOp)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(cn.c, data); err != nil {
		return reply{}, fmt.Errorf("mdnsresponder: read reply data: %w", err)
	}
	if len(data) < 12 {
		return reply{}, fmt.Errorf("mdnsresponder: reply data is %d bytes, want at least 12", len(data))
	}
	return reply{
		flags:          binary.BigEndian.Uint32(data[0:]),
		interfaceIndex: binary.BigEndian.Uint32(data[4:]),
		err:            Error(int32(binary.BigEndian.Uint32(data[8:]))),
		rest:           data[12:],
	}, nil
}

func (cn *conn) close() { cn.c.Close() }

// Browse browses for instances of serviceType ("_http._tcp") in domain ("local.") on every
// interface and sends each reply to events until ctx ends, when it returns ctx's error. A
// failed reply, including a policy denial, ends it with that error.
func Browse(ctx context.Context, socketPath, serviceType, domain string, events chan<- BrowseEvent) error {
	var data []byte
	data = putUint32(data, 0) // flags
	data = putUint32(data, 0) // kDNSServiceInterfaceIndexAny
	data = putString(data, serviceType)
	data = putString(data, domain)
	cn, err := open(ctx, socketPath, opBrowse, data)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, cn.close)
	defer stop()
	defer cn.close()

	for {
		r, err := cn.next(opBrowseReply)
		if err != nil {
			return ctxErr(ctx, fmt.Errorf("browse %s in %s: %w", serviceType, domain, err))
		}
		if r.err != 0 {
			return fmt.Errorf("mdnsresponder: browse %s in %s: %w", serviceType, domain, r.err)
		}
		rest := r.rest
		var ev BrowseEvent
		var ok1, ok2, ok3 bool
		ev.Name, rest, ok1 = getString(rest)
		ev.Type, rest, ok2 = getString(rest)
		ev.Domain, _, ok3 = getString(rest)
		if !ok1 || !ok2 || !ok3 {
			return fmt.Errorf("mdnsresponder: browse %s in %s: malformed reply", serviceType, domain)
		}
		ev.Add = r.flags&flagAdd != 0
		ev.InterfaceIndex = r.interfaceIndex
		select {
		case events <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Resolve resolves the instance a browse reply named (its Name, Type and Domain, unchanged)
// on interfaceIndex, and returns the first answer.
func Resolve(ctx context.Context, socketPath string, interfaceIndex uint32, name, serviceType, domain string) (ResolveResult, error) {
	var data []byte
	data = putUint32(data, 0) // flags
	data = putUint32(data, interfaceIndex)
	data = putString(data, name)
	data = putString(data, serviceType)
	data = putString(data, domain)
	cn, err := open(ctx, socketPath, opResolve, data)
	if err != nil {
		return ResolveResult{}, err
	}
	stop := context.AfterFunc(ctx, cn.close)
	defer stop()
	defer cn.close()

	r, err := cn.next(opResolveReply)
	if err != nil {
		return ResolveResult{}, ctxErr(ctx, fmt.Errorf("resolve %q: %w", name, err))
	}
	if r.err != 0 {
		return ResolveResult{}, fmt.Errorf("mdnsresponder: resolve %q: %w", name, r.err)
	}
	return parseResolveReply(r.rest)
}

func parseResolveReply(b []byte) (ResolveResult, error) {
	var res ResolveResult
	var ok bool
	if res.FullName, b, ok = getString(b); !ok {
		return res, errors.New("mdnsresponder: resolve reply: malformed full name")
	}
	if res.Target, b, ok = getString(b); !ok {
		return res, errors.New("mdnsresponder: resolve reply: malformed target")
	}
	if len(b) < 4 {
		return res, errors.New("mdnsresponder: resolve reply: truncated port or TXT length")
	}
	res.Port = binary.BigEndian.Uint16(b[0:])
	txtLen := int(binary.BigEndian.Uint16(b[2:]))
	b = b[4:]
	if len(b) < txtLen {
		return res, errors.New("mdnsresponder: resolve reply: truncated TXT record")
	}
	txt, err := splitTXT(b[:txtLen])
	if err != nil {
		return res, err
	}
	res.TXT = txt
	return res, nil
}

// splitTXT splits TXT rdata into its length-prefixed strings.
func splitTXT(rdata []byte) ([][]byte, error) {
	var out [][]byte
	for len(rdata) > 0 {
		n := int(rdata[0])
		if 1+n > len(rdata) {
			return nil, errors.New("mdnsresponder: TXT record: string runs past its end")
		}
		out = append(out, bytes.Clone(rdata[1:1+n]))
		rdata = rdata[1+n:]
	}
	return out, nil
}

// Addresses returns host's IPv4 and IPv6 addresses on interfaceIndex (0 for any), as the
// daemon reports them through DNSServiceGetAddrInfo. The daemon sends each address as its
// own reply and nothing marks the last, so Addresses collects replies until none has
// arrived for settle, or until ctx ends. It fails if no address arrived.
func Addresses(ctx context.Context, socketPath string, interfaceIndex uint32, host string, settle time.Duration) ([]netip.Addr, error) {
	var data []byte
	data = putUint32(data, 0) // flags
	data = putUint32(data, interfaceIndex)
	data = putUint32(data, protocolIPv4|protocolIPv6)
	data = putString(data, host)
	cn, err := open(ctx, socketPath, opAddrInfo, data)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, cn.close)
	defer stop()
	defer cn.close()

	var addrs []netip.Addr
	seen := map[netip.Addr]bool{}
	for {
		deadline := time.Now().Add(settle)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := cn.c.SetReadDeadline(deadline); err != nil {
			return nil, ctxErr(ctx, fmt.Errorf("mdnsresponder: addresses of %s: %w", host, err))
		}
		r, err := cn.next(opAddrInfoReply)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			return nil, ctxErr(ctx, fmt.Errorf("addresses of %s: %w", host, err))
		}
		if r.err != 0 {
			return nil, fmt.Errorf("mdnsresponder: addresses of %s: %w", host, r.err)
		}
		if r.flags&flagAdd == 0 {
			continue
		}
		addr, err := parseAddrInfoReply(r.rest)
		if err != nil {
			return nil, err
		}
		if addr.IsValid() && !seen[addr] {
			seen[addr] = true
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("mdnsresponder: no address for %s within %s", host, settle)
	}
	return addrs, nil
}

// parseAddrInfoReply returns the address in one getaddrinfo reply, or the zero Addr for a
// record that is neither A nor AAAA (the client stub drops those too).
func parseAddrInfoReply(b []byte) (netip.Addr, error) {
	_, b, ok := getString(b) // hostname
	if !ok || len(b) < 6 {
		return netip.Addr{}, errors.New("mdnsresponder: getaddrinfo reply: malformed")
	}
	rrtype := binary.BigEndian.Uint16(b[0:])
	rdlen := int(binary.BigEndian.Uint16(b[4:]))
	b = b[6:]
	if len(b) < rdlen {
		return netip.Addr{}, errors.New("mdnsresponder: getaddrinfo reply: truncated rdata")
	}
	switch {
	case rrtype == typeA && rdlen == 4:
		return netip.AddrFrom4([4]byte(b[:4])), nil
	case rrtype == typeAAAA && rdlen == 16:
		return netip.AddrFrom16([16]byte(b[:16])), nil
	case rrtype == typeA || rrtype == typeAAAA:
		return netip.Addr{}, fmt.Errorf("mdnsresponder: getaddrinfo reply: type %d with %d-byte rdata", rrtype, rdlen)
	}
	return netip.Addr{}, nil
}

func putUint32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

func putString(b []byte, s string) []byte { return append(append(b, s...), 0) }

// getString reads one NUL-terminated string.
func getString(b []byte) (s string, rest []byte, ok bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

// ctxErr returns ctx's error when ctx ended, since closing the connection on cancellation is
// what made the I/O fail; err otherwise.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
