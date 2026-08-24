package handlers

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/NetworkCommons/sig0lease/pkg/keyrec"
	leasepkg "github.com/NetworkCommons/sig0lease/pkg/lease"
	"github.com/NetworkCommons/sig0lease/pkg/sig0"
)

type stubUpstreamCoordinator struct {
	resp *dns.Msg
	err  error
}

func (s *stubUpstreamCoordinator) SendUpdate(ctx context.Context, upstreamZone string, updateMsg *dns.Msg) (*dns.Msg, error) {
	return s.resp, s.err
}

type stubResponseWriter struct{}

func (stubResponseWriter) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (stubResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (stubResponseWriter) Conn() net.Conn            { return nil }
func (stubResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (stubResponseWriter) Close() error              { return nil }
func (stubResponseWriter) Session() *dns.Session     { return nil }
func (stubResponseWriter) Hijack()                   {}

func buildSignedLeaseRegistrationForHandleTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string, leaseDuration uint32, keyLeaseDuration uint32) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	keyRR := signerKey.PublicKey.Clone().(*dns.KEY)
	keyRR.Hdr.Name = signerKey.PublicKey.Hdr.Name
	msg.Ns = append(msg.Ns, keyRR)

	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(leaseDuration, keyLeaseDuration)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func buildSignedUpdateForTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func buildSignedUpdateWithSignerKeyInUpdateForTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	keyRR := signerKey.PublicKey.Clone().(*dns.KEY)
	keyRR.Hdr.Name = signerKey.PublicKey.Hdr.Name
	msg.Ns = append(msg.Ns, keyRR)

	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func buildSignedUpdateWithSignerKeyInAdditionalForTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	keyRR := signerKey.PublicKey.Clone().(*dns.KEY)
	msg.Extra = append(msg.Extra, keyRR)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string, leaseDuration uint32, includeSignerKeyInUpdate bool) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	if includeSignerKeyInUpdate {
		keyRR := signerKey.PublicKey.Clone().(*dns.KEY)
		keyRR.Hdr.Name = signerKey.PublicKey.Hdr.Name
		msg.Ns = append(msg.Ns, keyRR)
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: leaseOwner, Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"payload"}
	msg.Ns = append(msg.Ns, txt)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(leaseDuration, 0)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

func TestExtractAndValidateSig0_UsesAuthoritativeSignerKey(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType != dns.TypeKEY {
			return nil, nil
		}
		return []dns.RR{loaded.PublicKey}, nil
	}

	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	sig, resolved, source, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", nil, nil)
	if err != nil {
		t.Fatalf("expected validation success: %v", err)
	}
	if sig == nil || resolved == nil {
		t.Fatalf("expected non-nil signature and key")
	}
	if resolved.KeyTag() != loaded.PublicKey.KeyTag() {
		t.Fatalf("expected resolved key tag %d, got %d", loaded.PublicKey.KeyTag(), resolved.KeyTag())
	}
	if source != signerKeySourceAuthoritative {
		t.Fatalf("expected signer source authoritative, got %v", source)
	}
}

func TestExtractAndValidateSig0_RejectsSignerOutsideLeaseHierarchy(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	outsideSigner := loaded.PublicKey.Clone().(*dns.KEY)
	outsideSigner.Hdr.Name = "outside.example.org."
	outsideLoaded := &keyrec.LoadedKey{
		Name:       loaded.Name,
		PublicKey:  outsideSigner,
		PrivateKey: loaded.PrivateKey,
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType != dns.TypeKEY {
			return nil, nil
		}
		return []dns.RR{outsideSigner}, nil
	}

	signed := buildSignedUpdateForTest(t, outsideLoaded, "test.dev.zenr.io.")
	_, _, _, err = h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", nil, nil)
	if err == nil {
		t.Fatalf("expected hierarchy validation failure")
	}
}

func TestExtractAndValidateSig0_DNSFailureFallsBackToLeaseStore(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	if err := h.leaseManager.Register(context.Background(), loaded.PublicKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease key: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		return nil, fmt.Errorf("authoritative DNS unavailable")
	}

	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	_, resolved, source, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", nil, nil)
	if err != nil {
		t.Fatalf("expected lease-store fallback success when authoritative lookup fails: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved key from lease store")
	}
	if source != signerKeySourceLeaseStore {
		t.Fatalf("expected signer source lease-store, got %v", source)
	}
}

func TestExtractAndValidateSig0_DNSNoKeyFallsBackToLeaseStore(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	if err := h.leaseManager.Register(context.Background(), loaded.PublicKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register lease key: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		return []dns.RR{}, nil
	}

	signed := buildSignedUpdateForTest(t, loaded, "test.dev.zenr.io.")
	_, resolved, source, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", nil, nil)
	if err != nil {
		t.Fatalf("expected lease-store fallback success when authoritative DNS has no signer key: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved key from lease store")
	}
	if source != signerKeySourceLeaseStore {
		t.Fatalf("expected signer source lease-store, got %v", source)
	}
}

func TestExtractAndValidateSig0_RequestKeyWorksWhenDnsAndLeaseStoreDontHaveSigner(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		// DNS is reachable, but has no signer KEY.
		return []dns.RR{}, nil
	}

	// No key is registered in lease-store; signer key is only in UPDATE section.
	signed := buildSignedUpdateWithSignerKeyInUpdateForTest(t, loaded, "test.dev.zenr.io.")
	requestKey := loaded.PublicKey.Clone().(*dns.KEY)

	_, resolved, source, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", nil, []*dns.KEY{requestKey})
	if err != nil {
		t.Fatalf("expected validation success using request KEY only: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved signer key")
	}
	if source != signerKeySourceRequest {
		t.Fatalf("expected signer source request, got %v", source)
	}
}

func TestExtractAndValidateSig0_AdditionalSigningKeyWorksWithoutAuthoritativeMatch(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := newTestHandler()
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		// DNS is reachable, but has no signer KEY.
		return []dns.RR{}, nil
	}

	signed := buildSignedUpdateWithSignerKeyInAdditionalForTest(t, loaded, "test.dev.zenr.io.")
	requestKey := loaded.PublicKey.Clone().(*dns.KEY)

	_, resolved, source, err := h.extractAndValidateSig0(context.Background(), signed, "test.dev.zenr.io.", []*dns.KEY{requestKey}, nil)
	if err != nil {
		t.Fatalf("expected validation success using Additional-section signing KEY: %v", err)
	}
	if resolved == nil {
		t.Fatalf("expected resolved signer key")
	}
	if source != signerKeySourceRequest {
		t.Fatalf("expected signer source request, got %v", source)
	}
}

func TestHandle_DoesNotPersistLeaseWhenUpstreamRejectsUpdate(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY {
			return []dns.RR{}, nil
		}
		return []dns.RR{}, nil
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{
		resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeYXRrset}},
	}

	leaseOwner := "test.dev.zenr.io."
	req := buildSignedLeaseRegistrationForHandleTest(t, loaded, leaseOwner, 120, 120)
	if got := h.leaseManager.FindByName(leaseOwner); len(got) != 0 {
		t.Fatalf("expected empty lease store before request, got %+v", got)
	}

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil {
		t.Fatalf("expected handler result")
	}
	if res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when upstream rejects update, got rcode=%d", res.Message.Rcode)
	}
	if got := h.leaseManager.FindByName(leaseOwner); len(got) != 0 {
		t.Fatalf("expected lease store unchanged when upstream update fails, got %+v", got)
	}
}

func TestHandle_ReRegistersManagedKeyWhenAuthoritativeFQDNIsMissing(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		return []dns.RR{}, nil
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}

	keyRR := loaded.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), keyRR, 10, 10, "dev.zenr.io."); err != nil {
		t.Fatalf("register existing key lease: %v", err)
	}

	leaseOwner := "test.dev.zenr.io."
	req := buildSignedLeaseRegistrationForHandleTest(t, loaded, leaseOwner, 120, 120)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got rcode=%d", res.Message.Rcode)
	}

	got := h.leaseManager.LookupByKEY(keyRR)
	if got == nil {
		t.Fatalf("expected key lease to remain managed")
	}
	if got.LeaseDuration >= 120 {
		t.Fatalf("expected key lease to be re-registered with remaining lease time, got %d", got.LeaseDuration)
	}
}

// TestHandle_RefreshPreservesOriginalRegisteredAt exercises the "normal
// refresh" branch of Case A (key still present at its authoritative FQDN)
// end to end through Handle(), confirming the RenewLease wiring: a refresh
// must extend the lease timers without resetting RegisteredAt, unlike the
// old design where every refresh silently re-created the node with
// RegisteredAt = now.
func TestHandle_RefreshPreservesOriginalRegisteredAt(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY {
			return []dns.RR{loaded.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}

	keyRR := loaded.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), keyRR, 60, 60, "dev.zenr.io."); err != nil {
		t.Fatalf("register key: %v", err)
	}
	original := h.leaseManager.LookupByKEY(keyRR)
	if original == nil {
		t.Fatalf("expected key to be registered")
	}
	registeredAt := original.RegisteredAt

	time.Sleep(5 * time.Millisecond)

	req := buildSignedLeaseRegistrationForHandleTest(t, loaded, "test.dev.zenr.io.", 120, 120)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful refresh, got rcode=%d", res.Message.Rcode)
	}

	after := h.leaseManager.LookupByKEY(keyRR)
	if after == nil {
		t.Fatalf("expected key to remain registered after refresh")
	}
	if !after.RegisteredAt.Equal(registeredAt) {
		t.Fatalf("expected RegisteredAt to survive a Handle()-driven refresh unchanged, got %v want %v", after.RegisteredAt, registeredAt)
	}
	if after.LeaseDuration != 120 {
		t.Fatalf("expected renewed key-lease duration to be applied, got %d", after.LeaseDuration)
	}
}

func TestHandle_NonKeyOnlyLeaseWithoutUpdateKeyRR_RegistersNonKeyRRs(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}

	signerKey := loaded.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), signerKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register signer key in lease store: %v", err)
	}

	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && canonicalName(fqdn) == canonicalName(signerKey.Hdr.Name) {
			return []dns.RR{loaded.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}

	owner := "host.test.dev.zenr.io."
	req := buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, loaded, owner, 120, false)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful non-KEY-only update without KEY RR, got rcode=%d", res.Message.Rcode)
	}

	if !h.hasActiveNonKeyRecord(leasepkg.NodeKey(signerKey), req.Ns[0]) {
		t.Fatalf("expected non-KEY RR to be registered under signer ownership")
	}
}

func TestHandle_NonKeyOnlyLeaseRejectsUpdateKeyRR(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	loaded, err := keyrec.LoadKeyFromFile(keystoreDir, "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}

	signerKey := loaded.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), signerKey, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register signer key in lease store: %v", err)
	}

	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && canonicalName(fqdn) == canonicalName(signerKey.Hdr.Name) {
			return []dns.RR{loaded.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}

	owner := "host.test.dev.zenr.io."
	req := buildSignedNonKeyOnlyLeaseUpdateForHandleTest(t, loaded, owner, 120, true)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for non-KEY-only update containing KEY RR, got rcode=%d", res.Message.Rcode)
	}
}

func TestValidateSignerHierarchyForUpdateRecords_AllowsSignerSelfKeyAndChildren(t *testing.T) {
	h := newTestHandler()
	signer := "dev.zenr.io."

	keys := []*dns.KEY{
		testKeyRR("dev.zenr.io.", "AAAASIGNER="),
		testKeyRR("child.dev.zenr.io.", "AAAACHILD="),
	}
	txt := &dns.TXT{Hdr: dns.Header{Name: "svc.child.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"ok"}

	if err := h.validateSignerHierarchyForUpdateRecords(signer, keys, []dns.RR{txt}); err != nil {
		t.Fatalf("expected hierarchy validation success, got error: %v", err)
	}
}

func TestValidateSignerHierarchyForUpdateRecords_AcceptNonKeyAtSignerName(t *testing.T) {
	h := newTestHandler()
	signer := "dev.zenr.io."
	txt := &dns.TXT{Hdr: dns.Header{Name: "dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"not-allowed"}

	err := h.validateSignerHierarchyForUpdateRecords(signer, nil, []dns.RR{txt})
	if err != nil {
		t.Fatalf("expected hierarchy validation for non-KEY at same level as signer owner")
	}
}

func TestValidateSignerHierarchyForUpdateRecords_RejectsKeyOutsideSignerSubtree(t *testing.T) {
	h := newTestHandler()
	signer := "dev.zenr.io."

	err := h.validateSignerHierarchyForUpdateRecords(signer, []*dns.KEY{testKeyRR("outside.example.org.", "AAAAOUTSIDE=")}, nil)
	if err == nil {
		t.Fatalf("expected hierarchy validation failure for KEY outside signer subtree")
	}
}

func TestGroupOtherRecordsByTargetKey_DefaultAssignsAllToSigner(t *testing.T) {
	signer := testKeyRR("dev.zenr.io.", "AAAASIGNER=")
	signerID := keyIDFromKEY(signer)
	keys := []*dns.KEY{
		testKeyRR("a.dev.zenr.io.", "AAAAA="),
		testKeyRR("b.dev.zenr.io.", "AAAAB="),
	}

	txtA := &dns.TXT{Hdr: dns.Header{Name: "x.a.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txtA.TXT.Txt = []string{"a"}
	txtB := &dns.TXT{Hdr: dns.Header{Name: "x.b.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txtB.TXT.Txt = []string{"b"}

	grouped, err := groupOtherRecordsByTargetKey(signerID, keys, []dns.RR{txtA, txtB}, false)
	if err != nil {
		t.Fatalf("expected grouping success, got error: %v", err)
	}
	if len(grouped[signerID]) != 2 {
		t.Fatalf("expected both RRs assigned to signer, got %d", len(grouped[signerID]))
	}
}

func TestGroupOtherRecordsByTargetKey_HierarchyAssignsToMostSpecificOwner(t *testing.T) {
	signer := testKeyRR("dev.zenr.io.", "AAAASIGNER=")
	signerID := keyIDFromKEY(signer)
	keys := []*dns.KEY{
		testKeyRR("a.dev.zenr.io.", "AAAAA="),
		testKeyRR("b.dev.zenr.io.", "AAAAB="),
	}

	txtA := &dns.TXT{Hdr: dns.Header{Name: "x.a.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txtA.TXT.Txt = []string{"a"}
	txtB := &dns.TXT{Hdr: dns.Header{Name: "x.b.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txtB.TXT.Txt = []string{"b"}

	grouped, err := groupOtherRecordsByTargetKey(signerID, keys, []dns.RR{txtA, txtB}, true)
	if err != nil {
		t.Fatalf("expected grouping success, got error: %v", err)
	}
	if len(grouped[keyIDFromKEY(keys[0])]) != 1 {
		t.Fatalf("expected one RR mapped to a.dev.zenr.io")
	}
	if len(grouped[keyIDFromKEY(keys[1])]) != 1 {
		t.Fatalf("expected one RR mapped to b.dev.zenr.io")
	}
}

func TestGroupOtherRecordsByTargetKey_HierarchyRejectsUnmappedOwner(t *testing.T) {
	signer := testKeyRR("dev.zenr.io.", "AAAASIGNER=")
	signerID := keyIDFromKEY(signer)
	keys := []*dns.KEY{
		testKeyRR("a.dev.zenr.io.", "AAAAA="),
		testKeyRR("b.dev.zenr.io.", "AAAAB="),
	}

	txt := &dns.TXT{Hdr: dns.Header{Name: "x.c.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	txt.TXT.Txt = []string{"c"}

	_, err := groupOtherRecordsByTargetKey(signerID, keys, []dns.RR{txt}, true)
	if err == nil {
		t.Fatalf("expected grouping failure for unmapped owner in hierarchy mode")
	}
}

// buildSignedCaseCDeleteForHandleTest builds a Case C delete request
// (LEASE=0, KEY-LEASE=0) naming a single KEY RR, signed by signerKey.
func buildSignedCaseCDeleteForHandleTest(t *testing.T, signerKey *keyrec.LoadedKey, keyRRToDelete *dns.KEY) *dns.Msg {
	t.Helper()

	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate
	msg.Ns = append(msg.Ns, keyRRToDelete)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(0, 0)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, signerKey.PublicKey, signerKey.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}
	return signed
}

// setupCaseCDeleteHandler registers a parent key (test.dev.zenr.io.) and a
// child key it registered (client.test.dev.zenr.io., ParentKeyName pointing
// at the parent), and returns a handler plus the parent, child, and an
// "unrelated" key (dev.zenr.io.) that is hierarchically above the child by
// DNS name but is not the child's immediate parent -- used to prove that
// hierarchy alone is no longer sufficient to authorize a Case C KEY delete.
func setupCaseCDeleteHandler(t *testing.T) (h *UpdateHandler, parent, child, unrelated *keyrec.LoadedKey) {
	t.Helper()

	serverKeystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}

	parent, err = keyrec.LoadKeyFromFile("../keystore/client", "Ktest.dev.zenr.io.+015+05044")
	if err != nil {
		t.Fatalf("load parent key: %v", err)
	}
	child, err = keyrec.LoadKeyFromFile("../keystore/client", "Kclient.test.dev.zenr.io.+015+00457")
	if err != nil {
		t.Fatalf("load child key: %v", err)
	}
	unrelated, err = keyrec.LoadKeyFromFile("../keystore/server", "Kdev.zenr.io.+015+35317")
	if err != nil {
		t.Fatalf("load unrelated ancestor key: %v", err)
	}

	h = NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  serverKeystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	// Stage-3 (authoritative) SIG(0) resolution for the unrelated key, which
	// is never lease-managed and never present in the request itself.
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && canonicalName(fqdn) == canonicalName(unrelated.PublicKey.Hdr.Name) {
			return []dns.RR{unrelated.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}

	parentRR := parent.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), parentRR, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register parent key: %v", err)
	}
	treeStore, ok := h.leaseManager.(leasepkg.HierarchicalLeaseStore)
	if !ok {
		t.Fatalf("expected lease manager to support hierarchical registration")
	}
	childRR := child.PublicKey.Clone().(*dns.KEY)
	if err := treeStore.RegisterWithParent(context.Background(), leasepkg.NodeKey(parentRR), childRR, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register child key under parent: %v", err)
	}

	return h, parent, child, unrelated
}

func TestHandle_CaseCDelete_ImmediateParentCanDeleteChildKey(t *testing.T) {
	h, parent, child, _ := setupCaseCDeleteHandler(t)

	childRR := child.PublicKey.Clone().(*dns.KEY)
	req := buildSignedCaseCDeleteForHandleTest(t, parent, childRR)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got rcode=%d", res.Message.Rcode)
	}
	if got := h.leaseManager.LookupByKEY(childRR); got != nil {
		t.Fatalf("expected child key to be deleted by its immediate parent")
	}
}

func TestHandle_CaseCDelete_UnrelatedHierarchicalAncestorCannotDeleteChildKey(t *testing.T) {
	h, _, child, unrelated := setupCaseCDeleteHandler(t)

	childRR := child.PublicKey.Clone().(*dns.KEY)
	req := buildSignedCaseCDeleteForHandleTest(t, unrelated, childRR)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected soft no-op success (delete refused, request still succeeds), got rcode=%d", res.Message.Rcode)
	}
	if got := h.leaseManager.LookupByKEY(childRR); got == nil {
		t.Fatalf("expected child key to remain after delete attempt by a non-parent hierarchical ancestor")
	}

	wantNote := fmt.Sprintf("KEY %s not found for delete", childRR.Hdr.Name)
	foundNote := false
	for _, rr := range res.Message.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, line := range txt.TXT.Txt {
				if line == wantNote {
					foundNote = true
				}
			}
		}
	}
	if !foundNote {
		t.Fatalf("expected note %q when a non-parent ancestor attempts delete, got answers=%+v", wantNote, res.Message.Answer)
	}
}

func TestHandle_CaseCDelete_SelfRegisteredKeyCanDeleteItself(t *testing.T) {
	h, parent, _, _ := setupCaseCDeleteHandler(t)

	parentRR := parent.PublicKey.Clone().(*dns.KEY)
	req := buildSignedCaseCDeleteForHandleTest(t, parent, parentRR)

	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got rcode=%d", res.Message.Rcode)
	}
	if got := h.leaseManager.LookupByKEY(parentRR); got != nil {
		t.Fatalf("expected self-registered root key to be able to delete itself")
	}
}

// Regression coverage for an ownership-hijack gap: "refreshing" an
// already-registered KEY RR only ever checked that the resubmitted RDATA
// matched what was on record (validateRefreshOwnership, now
// authorizeKeyRefresh) -- it never checked that the SIG(0) signer performing
// the refresh was actually the record's owner. Since a KEY RR's RDATA is
// public DNS data, any signer that separately cleared
// signerAuthorizedForNewRegistration could resubmit a byte-for-byte copy of
// someone else's already-registered KEY RR and silently become its
// registered parent (ParentKeyName), because registerKeyLease/
// RegisterWithParent recompute and overwrite the parent on every call with
// no check against the node's existing owner.
//
// CLIENT_KEY_NAME (Ktest.dev.zenr.io.+015+05044) and WRONG_CLIENT_KEY_NAME
// (Ktest.dev.zenr.io.+015+42176) are two independently generated keys that
// both happen to be owned by the name test.dev.zenr.io. (only
// algorithm/keytag/pubkey differ) -- mirroring the case these tests
// reproduce.

func TestHandle_CaseARefresh_ForeignSignerWithOwnRegistrationCannotHijackExistingKey(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	client, err := keyrec.LoadKeyFromFile("../keystore/client", "Ktest.dev.zenr.io.+015+05044")
	if err != nil {
		t.Fatalf("load client key: %v", err)
	}
	wrong, err := keyrec.LoadKeyFromFile("../keystore/client", "Ktest.dev.zenr.io.+015+42176")
	if err != nil {
		t.Fatalf("load wrong-client key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && canonicalName(fqdn) == canonicalName(client.PublicKey.Hdr.Name) {
			return []dns.RR{client.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}

	// Client legitimately registered its KEY plus a companion TXT as its own
	// self-registered (root) node.
	clientKeyRR := client.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), clientKeyRR, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register client key: %v", err)
	}
	clientTXT := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	clientTXT.TXT.Txt = []string{"client-payload"}
	h.setNonKeyLease(leasepkg.NodeKey(clientKeyRR), []dns.RR{clientTXT}, 120, "dev.zenr.io.")
	h.scheduleLeaseExpiry(leasepkg.NodeKey(clientKeyRR))
	defer h.clearLeaseTimer(leasepkg.NodeKey(clientKeyRR))

	// Attack: WRONG_CLIENT_KEY_NAME registers itself for the first time
	// (legitimately satisfying signerAuthorizedForNewRegistration via
	// signerInUpdate) while also resubmitting a byte-for-byte copy of the
	// client's already-registered KEY RR in the same Update section, all
	// signed only by its own new key. No special config is required.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	wrongKeyRR := wrong.PublicKey.Clone().(*dns.KEY)
	copiedClientKeyRR := client.PublicKey.Clone().(*dns.KEY)
	msg.Ns = append(msg.Ns, wrongKeyRR, copiedClientKeyRR)

	attackTXT := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	attackTXT.TXT.Txt = []string{"attacker-payload"}
	msg.Ns = append(msg.Ns, attackTXT)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(120, 120)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, wrong.PublicKey, wrong.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	res := h.Handle(context.Background(), stubResponseWriter{}, signed)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected refused when a foreign signer tries to refresh another key's registration, got rcode=%d", res.Message.Rcode)
	}

	got := h.leaseManager.LookupByKEY(clientKeyRR)
	if got == nil {
		t.Fatalf("expected client key lease to remain")
	}
	if got.ParentKeyName != "" {
		t.Fatalf("expected client key to remain a self-registered root node, got hijacked parent %q", got.ParentKeyName)
	}
	if h.leaseManager.LookupByKEY(wrongKeyRR) != nil {
		t.Fatalf("expected the whole request to fail closed: attacker's own new key must not be registered either")
	}
}

func TestHandle_CaseARefresh_OnlineAuthorizedSignerCannotHijackExistingKey(t *testing.T) {
	keystoreDir, err := createTestKeystore(t)
	if err != nil {
		t.Fatalf("setup test keystore: %v", err)
	}
	client, err := keyrec.LoadKeyFromFile("../keystore/client", "Ktest.dev.zenr.io.+015+05044")
	if err != nil {
		t.Fatalf("load client key: %v", err)
	}
	wrong, err := keyrec.LoadKeyFromFile("../keystore/client", "Ktest.dev.zenr.io.+015+42176")
	if err != nil {
		t.Fatalf("load wrong-client key: %v", err)
	}

	h := NewUpdateHandler()
	h.SetLogger(newTestHandler().logger)
	if err := h.Setup(map[string]any{
		"upstream_zone": "dev.zenr.io.",
		"keystore_dir":  keystoreDir,
	}); err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	// This is the hypothetical the case explicitly raised: even if
	// WRONG_CLIENT_KEY_NAME resolves as an authorized online signer, it must
	// not be able to hijack RRs another key already registered.
	h.AllowOnlineKeyRegistration = true
	h.upstreamCoordinator = &stubUpstreamCoordinator{resp: &dns.Msg{MsgHeader: dns.MsgHeader{Rcode: dns.RcodeSuccess}}}
	// Both keys are independently published under the same owner name, so
	// WRONG_CLIENT_KEY_NAME resolves as a valid SIG(0) signer purely via
	// authoritative DNS: it is never lease-managed and never present
	// anywhere in the request itself (signerSource=Authoritative).
	h.authoritativeLookup = func(ctx context.Context, zoneHint, fqdn string, rrType uint16) ([]dns.RR, error) {
		if rrType == dns.TypeKEY && canonicalName(fqdn) == canonicalName(client.PublicKey.Hdr.Name) {
			return []dns.RR{client.PublicKey, wrong.PublicKey}, nil
		}
		return []dns.RR{}, nil
	}

	clientKeyRR := client.PublicKey.Clone().(*dns.KEY)
	if err := h.leaseManager.Register(context.Background(), clientKeyRR, 120, 120, "dev.zenr.io."); err != nil {
		t.Fatalf("register client key: %v", err)
	}
	clientTXT := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	clientTXT.TXT.Txt = []string{"client-payload"}
	h.setNonKeyLease(leasepkg.NodeKey(clientKeyRR), []dns.RR{clientTXT}, 120, "dev.zenr.io.")
	h.scheduleLeaseExpiry(leasepkg.NodeKey(clientKeyRR))
	defer h.clearLeaseTimer(leasepkg.NodeKey(clientKeyRR))

	// Attack: "refresh" the client's already-registered KEY+TXT data, but
	// sign the transaction with WRONG_CLIENT_KEY_NAME instead.
	msg := dns.NewMsg("test.dev.zenr.io.", dns.TypeSOA)
	if msg == nil {
		t.Fatalf("expected message")
	}
	msg.Opcode = dns.OpcodeUpdate

	copiedClientKeyRR := client.PublicKey.Clone().(*dns.KEY)
	msg.Ns = append(msg.Ns, copiedClientKeyRR)

	attackTXT := &dns.TXT{Hdr: dns.Header{Name: "test.dev.zenr.io.", Class: dns.ClassINET, TTL: 60}}
	attackTXT.TXT.Txt = []string{"client-payload"}
	msg.Ns = append(msg.Ns, attackTXT)

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	leaseOpt := leasepkg.Encode8Byte(120, 120)
	if err := leaseOpt.Encode(opt); err != nil {
		t.Fatalf("encode lease option: %v", err)
	}
	msg.Extra = append(msg.Extra, opt)

	signed, err := sig0.SignMessage(msg, wrong.PublicKey, wrong.PrivateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	res := h.Handle(context.Background(), stubResponseWriter{}, signed)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected refused when an online-authorized foreign signer tries to refresh another key's registration, got rcode=%d", res.Message.Rcode)
	}

	got := h.leaseManager.LookupByKEY(clientKeyRR)
	if got == nil {
		t.Fatalf("expected client key lease to remain")
	}
	if got.ParentKeyName != "" {
		t.Fatalf("expected client key to remain a self-registered root node, got hijacked parent %q", got.ParentKeyName)
	}

	wrongSignerNodeKey := leasepkg.NodeKeyFromSIG(wrong.PublicKey.Hdr.Name, wrong.PublicKey.Algorithm, wrong.PublicKey.KeyTag())
	if set := h.getNonKeyLease(wrongSignerNodeKey); set != nil && len(set.Records) > 0 {
		t.Fatalf("expected no phantom data to be registered under the rejected foreign signer, got %+v", set.Records)
	}
}
