package handlers

import (
	"context"
	"fmt"
	"net"
	"testing"

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

func buildSignedDataOnlyLeaseUpdateForHandleTest(t *testing.T, signerKey *keyrec.LoadedKey, leaseOwner string, leaseDuration uint32, includeSignerKeyInUpdate bool) *dns.Msg {
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

func TestHandle_DataOnlyLeaseWithoutUpdateKeyRR_RegistersNonKeyRRs(t *testing.T) {
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
	req := buildSignedDataOnlyLeaseUpdateForHandleTest(t, loaded, owner, 120, false)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful data-only update without KEY RR, got rcode=%d", res.Message.Rcode)
	}

	if !h.hasActiveDataRecord(leasepkg.NodeKey(signerKey), req.Ns[0]) {
		t.Fatalf("expected non-KEY RR to be registered under signer ownership")
	}
}

func TestHandle_DataOnlyLeaseRejectsUpdateKeyRR(t *testing.T) {
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
	req := buildSignedDataOnlyLeaseUpdateForHandleTest(t, loaded, owner, 120, true)
	res := h.Handle(context.Background(), stubResponseWriter{}, req)
	if res == nil || res.Message == nil {
		t.Fatalf("expected response message")
	}
	if res.Message.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for data-only update containing KEY RR, got rcode=%d", res.Message.Rcode)
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
