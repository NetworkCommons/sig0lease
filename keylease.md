


1. A KEY RR does not need to always be present in the Authority/Update section (according to RFC 2136) of a signed lease-update request, but it is either present or absent, so the option of having a Header only KEY RR must be removed from client and proxy.
2. When a signed registration comes in, the proxy first needs to verify the signature. This can be done either because the signing RR KEY is in the message, or because the KEY is online (already registered), or because the KEY is in the lease store. Any of this can be used to verify the signature.
3. You can sign a lease-update request with a key, but the request is to register a different RR KEY (this is not a signing KEY in this context)
3. If verification is passed, it means that we could find the signing key. We have these cases:
    1. KEY-LEASE != 0, LEASE != 0: This is a registration or a refresh of KEY and non-KEY RRs.
        1. If the signing KEY is not in the request, this KEY can be in the lease store and/or in at the FQDN:
            1. In-LeaseStore AND at-FQDN -> refresh of the KEY RR if it is the signing KEY, otherwise registration
            2. In-LeaseStore AND NOT at-FQDN -> registration of the KEY RR
            3. NOT In-LeaseStore AND at-FQDN -> key is already registered, but we assume this has happened outside the lease mechanism (permanent update) and we fail
            4. NOT In-LeaseStore AND NOT at-FQDN -> this is an error, but we would never get here since we would not have had any KEY to verify the signature.
        2. If the KEY is in the request, the KEY can also be in the lease store and/or in at the FQDN:
            1. In-LeaseStore AND at-FQDN -> refresh of the key
            2. In-LeaseStore AND NOT at-FQDN -> registration of the key
            3. NOT In-LeaseStore AND at-FQDN -> key is already registered, but we assume this has happened outside the lease mechanism (permanent update) and we fail
            4. NOT In-LeaseStore AND NOT at-FQDN -> registration
        3. Given LEASE != 0, if there are no non-KEY RRs -> Error

  4. KEY-LEASE == 0, LEASE != 0, other RRs present → register/refresh data lease only
  5. Case 2 — KEY-LEASE == 0, LEASE == 0, other RRs present → delete KEY and other RRsCase 3 — KEY-LEASE == 0, LEASE != 0, no other RRs → error
Case 4 — KEY-LEASE == 0, LEASE == 0, no other RRs → delete key
Other cases:

Case 5 — KEY-LEASE != 0, LEASE == 0, other RRs present → refresh/register KEY, delete other RRs
