## Behavior Specifications

1. Signature verification
   1. UPDATE requests must carry a valid SIG(0).
   2. An UPDATE request contains RRs to be updated. The name of those records determines the FQDN. The signer key must be at or above this FQDN. In the following we say that a key is "at-FQDN" when it is registered at or above that FQDN.
   3. The key can be present in the request as KEY RR, either in the Update section, or in the Additional section.
   4. If the key is not present in the request, lease-store key material is used as fallback.
   5. If lease-store does not contain the key, verification uses authoritative DNS as the last source for signer key resolution.
   6. If authoritative DNS is reachable but returns no matching signer KEY, the request fails.
      6.a. If the authoritative DNS cannot be reached for signer-key lookup, the request fails. This is because we are modifying records for a DNS that does not respond.
   7. According to RFC 2136, the Update Section contains RRs to be added to or deleted from the zone. Thus if a KEY RR is not been registered or refreshed, it should not be in the Authority/Update section of a signed lease-update request.
   8. Multiple KEY RRs can be present in a request in the Update section.
2. When a signed registration comes in, the proxy first needs to verify the signature. This can be done either because the signing RR KEY is in the message (either in the Update or Additional section), or because the KEY is online (its name is already present at the FQDN or above of the records contained in the lease update request), or because the KEY is in the LeaseStore. Any of this can be used to verify the signature.
3. You can sign a lease-update request with a key, but the request is to register or refresh a different RR KEY (which is not a signing KEY in this context). In this case only the latter is in the Update section.
4. If verification is passed, it means that we could find the signing key. We found it either:
   1. In-LeaseStore AND at-FQDN -> this is a key we are managing
   2. In-LeaseStore AND NOT at-FQDN -> we assume the key has been removed externally from our proxy, so we need to register it with the remaining lease time from the lease-store. This implies that we need to add this KEY RR to the RRs to be registered.
   3. NOT In-LeaseStore AND at-FQDN -> the key is already registered, but we assume this has happened outside the lease mechanism (permanent update) and not under our control
   4. NOT In-LeaseStore AND NOT at-FQDN -> the key must be in the request (either Update or Additional section), otherwise we would never get here since we would not have had any KEY to verify the signature.
5. From now on we look at the Update section and the RR records it contains. If the Update section contains a KEY RR, this does not need to be the key that signed the request. Looking at the request lease-times:
   1. KEY-LEASE != 0, LEASE != 0: This is a registration or a refresh of KEY and non-KEY RRs.
      1. The KEY RR and non-KEY RRs (at least one) must be present in the request, otherwise this is an error
      2. If the KEY RR is already present in the LeaseStore, this is a refresh of the KEY, otherwise a registration
      3. For any of the non-KEY RRs that is present in the LeaseStore, this is a refresh
      4. If a non-KEY RRs is not present in the LeaseStore, it needs to be recorded together with the key that registers it, because we need to remove it when that key expires. In this case, the key that registers it is the key that signed the request.
      5. This key must either be in the LeaseStore, or if not in the LeaseStore it must be in the Update section. It cannot be only in the Additional section, because the user intention must be to register a key, and not just use it to sign a request, so it must be part of the Update section.
      6. There might be more than one KEY RRs in the Update section, so it is important to determine which KEY RR is the signing key.
   2. KEY-LEASE == 0, LEASE != 0: this is a registration/refresh of non-KEY RRs
      1. non-KEY RRs (at least one) must be present in the request, otherwise this is an error
      2. For any of the non-KEY RRs that are not present in the LeaseStore, this is a registration, otherwise a refresh
      3. Signing KEY must already exist in the LeaseStore, and must not be present in the Update section (given KEY-LEASE == 0, this is not a registration of the key, the key must already be registered). If it is not already at the FQDN at the authoritative DNS, it needs to be registered again (see 4.2).
   3. KEY-LEASE == 0, LEASE == 0:
      1. If KEY RR present -> delete KEY
      2. If non-KEY RRs present -> delete non-KEY RRs
      3. Both present -> delete both
      4. Neither present -> error
      5. Authorization for delete is ownership, not just at-FQDN: a KEY or non-KEY RR may only be deleted by its immediate parent (the KEY that registered it), or, for a KEY RR, by itself if it has no parent (self-registered/root). A signer that is at-FQDN but not the immediate parent cannot delete the record directly, even though it could sign the request; the record is treated the same as if it did not exist, and no error results.
   4. KEY-LEASE != 0, LEASE == 0:
      1. KEY RR must be present -> register or refresh KEY
      2. If non-KEY RRs present -> delete non-KEY RRs
6. If the proxy attemps to register a record that already exists at the DNS server, the request must fail also in the parts that would be successful if performed alone, because the consistency of the LeaseStore cannot be guaranteed, especially in case of already existing KEY RR.
   1. This implies that the proxy needs to verify whether in case of a registration, an identical record is already at the FQDN.
7. For all attempts of deleting records, if the record does not exist in the lease-store, we assume the record is either outside our control, or it has been removed after expiry. The request does not fail but the user needs to be informed about this. If the record exists in the lease-store but not at the DNS, do not fail the request but signal the situation. Missing local records do not force whole-request failure.

## Storage Model

1. KEY lease storage
- KEY lease state is tracked per canonical key name in the lease manager.
- Given keys can be registered by other keys, a key can be linked to the key that registered it.

2. Non-KEY lease storage
- Non-KEY records are tracked individually and are linked to their key owner.
- This link is used to clear each records registered with a particular key when this key expires.
- Record identity is as defined in comparison rules in RFC 2136 Section 1.1.
- It is not possible for 2 different keys to register identical RRs.
- Records that differ in any field are treated as distinct records.

When a key expires, it can trigger a chain deletion, for example in the case key A registered key B that registered records C,D,E and key A expires. A,B,C,D and E are all deleted.
