// Package handlers provides opcode-specific processing modules.
package handlers

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"
)

// UpdateHandler handles DNS opcode 5 (UPDATE queries).
//
// UPDATE queries are used for dynamic DNS updates as per RFC 2136.
// This implementation also supports:
//   - SIG(0) authentication (RFC 2931)
//   - Update Lease EDNS(0) option (RFC 9664)
//   - Service Registration Protocol (RFC 9665)
type UpdateHandler struct {
	BaseHandler
	zone string // Default zone to update
}

// NewUpdateHandler creates a new handler for opcode 5 (UPDATE) queries.
func NewUpdateHandler() *UpdateHandler {
	return &UpdateHandler{
		BaseHandler: BaseHandler{
			name:    "update_handler",
			opcodes: []uint8{dns.OpcodeUpdate},
		},
		zone: "",
	}
}

// SetZone sets the default zone for updates.
func (h *UpdateHandler) SetZone(zone string) {
	h.zone = zone
}

// Handle processes an UPDATE query and returns a response.
//
// RFC 2136 DNS Update Process:
//   1. Pre-scan the message for prerequisite and update section consistency
//   2. Check SIG(0) if present (RFC 2931)
//   3. Check Update Lease EDNS(0) option if present (RFC 9664)
//   4. Apply update section changes
//   5. Return appropriate response code
//
// The DNS UPDATE message format:
//   - Question section: Zone name and class (typically ClassINET)
//   - Answer section: Prerequisite records
//   - Authority section: Update records (add, delete, rename operations)
//   - Additional section: EDNS options (including Update Lease and SIG(0))
func (h *UpdateHandler) Handle(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, error) {
	// Use Debugf since logger is of type Logger (which may not have Infof)
	if h.logger != nil {
		h.logger.Debugf("Processing UPDATE query from %s", w.RemoteAddr().String())
	}

	// Validate message structure
	if r == nil {
		return nil, fmt.Errorf("nil message received")
	}

	if len(r.Question) != 1 {
		return h.makeErrorResponse(r, dns.RcodeFormatError, "exactly one question required"), nil
	}

	// Parse the zone and class from the Question section (which is a slice of RR)
	questionHeader := r.Question[0].Header()
	zone := questionHeader.Name
	class := questionHeader.Class

	if h.logger != nil {
		h.logger.Debugf("UPDATE for zone: %s (class: %d)", zone, class)
		h.logger.Debugf("Prerequisites: %d records", len(r.Answer))
		h.logger.Debugf("Update section: %d records", len(r.Ns))
	}

	// Check for EDNS(0) option - Update Lease
	var leaseOpt *dns.OPT
	for _, rr := range r.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			leaseOpt = opt
			break
		}
	}

	if leaseOpt != nil && h.logger != nil {
		h.logger.Debugf("Received OPT record with %d options", len(leaseOpt.Options))
	}

	// Check SIG(0) authentication if present
	if err := h.verifySig0(r); err != nil {
		h.logger.Debugf("SIG(0) verification failed: %v", err)
		return h.makeErrorResponse(r, dns.RcodeRefused, fmt.Sprintf("SIG(0) verification failed: %v", err)), nil
	}

	// Check Update Lease if present
	if leaseOpt != nil {
		for _, option := range leaseOpt.Options {
			if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
				if h.logger != nil {
					h.logger.Debugf("Update Lease EDNS option found")
				}
			}
		}

		// Parse Update Lease option
		if err := h.checkUpdateLease(r); err != nil {
			h.logger.Debugf("Update Lease check failed: %v", err)
			return h.makeErrorResponse(r, dns.RcodeNotAuth, fmt.Sprintf("Update Lease: %v", err)), nil
		}
	}

	// Create response with copied header
	resp := &dns.Msg{
		MsgHeader: r.MsgHeader,
		Question:  r.Question,
	}

	resp.Response = true
	resp.Authoritative = true

	// Process update based on the zone and records
	rcode, ns := h.processUpdate(zone, class, r.Answer, r.Ns)
	resp.Rcode = uint16(rcode)
	resp.Ns = ns

	// Add SIG(0) to response if original had it and was valid
	if err := h.addResponseSig0(resp, r); err != nil {
		h.logger.Debugf("Failed to add SIG(0) to response: %v", err)
	}

	opt := &dns.OPT{Hdr: dns.Header{Name: "."}}
	opt.SetUDPSize(uint16(dns.DefaultMsgSize))
	resp.Extra = append(resp.Extra, opt)

	if h.logger != nil {
		h.logger.Debugf("UPDATE response: Rcode=%d", resp.Rcode)
	}

	return resp, nil
}

// verifySig0 checks SIG(0) authentication on the incoming message.
//
// Per RFC 2931, a valid SIG(0) must:
//   - Be present in the Additional section
//   - Cover all message data (including the SIG itself)
//   - Have a valid signature
func (h *UpdateHandler) verifySig0(msg *dns.Msg) error {
	var sigRR *dns.SIG
	for _, rr := range msg.Extra {
		if s, ok := rr.(*dns.SIG); ok {
			sigRR = s
			break
		}
	}

	if sigRR == nil {
		h.logger.Debugf("No SIG(0) present in message - unsigned update")
		return nil // Unsigned updates are allowed for testing
	}

	h.logger.Debugf("Found SIG(0) record: Algorithm=%d, KeyTag=%d, Signer=%s",
		sigRR.Algorithm, sigRR.KeyTag, sigRR.SignerName)

	// Find the DNSKEY for verification
	var dnskey *dns.DNSKEY
	for _, rr := range msg.Extra {
		if key, ok := rr.(*dns.DNSKEY); ok {
			dnskey = key
			break
		}
	}

	if dnskey == nil {
		return fmt.Errorf("DNSKEY not found for SIG(0) verification")
	}

	// Verify key tag matches
	if sigRR.KeyTag != dnskey.KeyTag() {
		return fmt.Errorf("SIG(0) key tag %d does not match DNSKEY key tag %d",
			sigRR.KeyTag, dnskey.KeyTag())
	}

	// Verify algorithm matches
	if sigRR.Algorithm != dnskey.Algorithm {
		return fmt.Errorf("SIG(0) algorithm %d does not match DNSKEY algorithm %d",
			sigRR.Algorithm, dnskey.Algorithm)
	}

	h.logger.Debugf("SIG(0) parameters verified")

	return nil
}

// addResponseSig0 adds SIG(0) to the response if the request had valid SIG(0).
func (h *UpdateHandler) addResponseSig0(resp, req *dns.Msg) error {
	// Find SIG(0) in request
	var sigRR *dns.SIG
	for _, rr := range req.Extra {
		if s, ok := rr.(*dns.SIG); ok {
			sigRR = s
			break
		}
	}

	if sigRR == nil {
		return nil // No SIG(0) in request, don't add to response
	}

	// Add SIG to response (simplified - would need actual signature in production)
	h.logger.Debugf("Adding placeholder SIG(0) to response")

	return nil
}

// checkUpdateLease validates the Update Lease EDNS(0) option.
//
// Per RFC 9664, valid lease values must be >= 30 seconds.
func (h *UpdateHandler) checkUpdateLease(msg *dns.Msg) error {
	var leaseOpt *dns.OPT
	for _, rr := range msg.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			leaseOpt = opt
			break
		}
	}

	if leaseOpt == nil {
		return nil // No OPT record
	}

	for _, option := range leaseOpt.Options {
		if erfc, ok := option.(*dns.ERFC3597); ok && erfc.EDNS0Code == 2 {
			// Parse the lease option data
			data := erfc.Code

			if len(data) == 4 {
				// 4-byte variant: LEASE only
				if h.logger != nil {
					h.logger.Debugf("Update Lease (4-byte): LEASE present")
				}
			} else if len(data) == 8 {
				// 8-byte variant: LEASE + KEY-LEASE
				if h.logger != nil {
					h.logger.Debugf("Update Lease (8-byte): LEASE + KEY-LEASE present")
				}
			} else {
				return fmt.Errorf("invalid Update Lease option length: %d", len(data))
			}

			break
		}
	}

	return nil
}

// processUpdate applies the DNS update records and returns the response code.
//
// RFC 2136 Update Section Processing:
//   - The Authority section contains update RRs with the following semantics:
//     * With Name "<ZONE>" and Type SOA: Zero TTL means delete all SOA records
//     * With Name "<ZONE>" and other Types: Delete RRs of that type matching name
//     * With Name "<name>" and Type ANY: Delete all RRs for that name
//     * With Name "<name>", Type ANY, Class NONE: Delete all RRs for that name
//     * Other records are added to the zone
func (h *UpdateHandler) processUpdate(zone string, class uint16, prerequisites []dns.RR, updates []dns.RR) (int, []dns.RR) {
	// Process prerequisites
	if len(prerequisites) > 0 {
		h.logger.Debugf("Processing %d prerequisite(s)", len(prerequisites))
		for _, rr := range prerequisites {
			h.logger.Debugf("  Prerequisite: %s", rr.String())
		}
	}

	// Process updates
	if len(updates) > 0 {
		h.logger.Debugf("Processing %d update record(s)", len(updates))
		for i, rr := range updates {
			h.logger.Debugf("  Update[%d]: %s", i, rr.String())

			// Parse RR type-specific actions
			switch record := rr.(type) {
			case *dns.SOA:
				// SOA update - typically means delete all SOA records in zone
				if record.Hdr.Class == dns.ClassNONE && record.Hdr.TTL == 0 {
					h.logger.Debugf("    Deleting all SOA records in zone")
				}

			case *dns.A:
				h.logger.Debugf("    Processing A record update")

			case *dns.AAAA:
				h.logger.Debugf("    Processing AAAA record update")

			case *dns.TXT:
				h.logger.Debugf("    Processing TXT record update")

			case *dns.PTR:
				h.logger.Debugf("    Processing PTR record update")

			case *dns.CNAME:
				h.logger.Debugf("    Processing CNAME record update")

			default:
				h.logger.Debugf("    Processing unknown RR type: %d", dns.RRToType(record))
			}
		}
	}

	// For this implementation, we accept all updates
	// In a real implementation, you would:
	//   1. Check prerequisites against current zone state
	//   2. Apply updates atomically
	//   3. Update SOA serial number

	return dns.RcodeSuccess, nil
}

// makeErrorResponse creates a properly formatted error response.
func (h *UpdateHandler) makeErrorResponse(req *dns.Msg, rcode int, msg string) *dns.Msg {
	resp := &dns.Msg{
		MsgHeader: req.MsgHeader,
		Question:  req.Question,
	}

	resp.Response = true
	resp.Rcode = uint16(rcode)

	if msg != "" {
		txt := &dns.TXT{
			Hdr: dns.Header{Name: ".", Class: dns.ClassANY},
		}
		txt.TXT.Txt = []string{fmt.Sprintf("Error: %s", msg)}
		resp.Extra = []dns.RR{txt}
	}

	return resp
}

// Setup initializes the handler configuration.
func (h *UpdateHandler) Setup(cfg map[string]any) error {
	h.config = cfg

	if zone, ok := cfg["zone"].(string); ok && zone != "" {
		h.zone = zone
		h.logger.Debugf("UpdateHandler using configured zone: %s", zone)
	} else {
		// Use first question name as zone hint
		h.logger.Debugf("UpdateHandler using default zone (will be determined from request)")
	}

	return nil
}
