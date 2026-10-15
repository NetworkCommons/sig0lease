package handlers

// Setup initializes the SRP handler configuration: the options both UPDATE handlers read
// (upstream_zone, keystore_dir, upstream, bootstrap_resolvers, lease_policy, record_ttl_sec,
// lease_manager or storage; see leaseHandler.setup), and these of its own:
//   - "allow_udp": permit UDP for this zone (TCP is required by default,
//     for non-CNN zones this proxy targets). [OPTIONAL, defaults to false]
//   - "rewrite_default_service_arpa": accept requests whose Zone Section is literally
//     "default.service.arpa." (real SRP clients hardcode this name -- they have no way to
//     discover any other zone) *in addition to* upstream_zone, rewriting every name in
//     the update to upstream_zone before FCFS/forwarding so the rest of the pipeline (and
//     the authoritative server) never sees default.service.arpa. at all. The response still
//     echoes back default.service.arpa., matching what the client itself sent. [OPTIONAL,
//     defaults to false]
//   - "refuse_on_foreign_data": RFC 9665 S3.3.3's NOERROR-no-KEY case -- true refuses the
//     update (REFUSED) when a name exists at the authoritative server with data but no
//     KEY; false lets the delete-all-then-add clobber it. [OPTIONAL, defaults to true]
//   - "advertise_registration_domain": also publish the RFC 6763 S11 "r"/"dr" registration-
//     domain records (self-pointing at upstream_zone), independent of whether any service
//     type is currently live -- unlike the always-on "b"/"db"/"lb" browsing-domain records,
//     which only appear once at least one service type is live. Advertising this zone as an
//     open target for direct RFC 2136 Dynamic Update registration (not just SRP) is a
//     deployment policy choice -- SIG(0)/FCFS still gate who can actually write, but this
//     controls whether domain-enumeration tools are told to try. [OPTIONAL, defaults to false]
func (h *SRPHandler) Setup(cfg map[string]any) error {
	var err error
	if h.allowUDP, err = boolOption(cfg, "allow_udp", false); err != nil {
		return err
	}
	if h.rewriteDefaultServiceARPA, err = boolOption(cfg, "rewrite_default_service_arpa", false); err != nil {
		return err
	}
	// Default true (fail closed against foreign/orphaned data) unless explicitly
	// disabled -- see pkg/srp.Evaluate's doc comment for what this actually gates.
	if h.refuseOnForeignData, err = boolOption(cfg, "refuse_on_foreign_data", true); err != nil {
		return err
	}
	if h.advertiseRegistrationDomain, err = boolOption(cfg, "advertise_registration_domain", false); err != nil {
		return err
	}
	return h.setup(cfg)
}
