/// Central DNS object
///
/// Read-only adaptation of `dns-sd-inspector/dns.js` for the dashboard:
/// the key management and update functions were removed, and `query()`
/// can report failures so that a transient network error does not wipe
/// the dashboard.
class Dns {
  /// construct the DNS object with the domain to query
  constructor(domain_name, on_initialized) {
    // FIXME: there is an error to investigate within the dohjs library when
    // resolving queries via 'https://doh.zembla.io/dns-query'.
    // In the meantime, we resolve everything via 'https://1.1.1.1/dns-query'
    this.doh_url_dohjs = 'https://1.1.1.1/dns-query';
    // domain name
    this.domain = domain_name;
    this.doh_method = 'POST';
    this.zone = null;

    // set initialization flags
    this.dnssec_enabled = false;
    this.initialized = false;

    // create the resolver
    this.resolver = new doh.DohResolver(this.doh_url_dohjs);

    // initialize longer tasks
    this.init(on_initialized);
  }

  /// start asynchronous, longer running tasks at initialization
  async init(callback) {
    try {
      // get zone
      this.zone = await this.get_zone(this.domain);
      // check if RRSIG record is available
      this.dnssec_enabled = await this.check_rrsig(this.domain);
    } catch (error) {
      console.log('Dns initialization of ' + this.domain + ' incomplete');
      console.error(error);
    }

    // set initialized flag
    this.initialized = true;
    if (typeof callback === 'function') {
      callback(this);
    }
  }

  /// read the record types from dns of a domain
  /// and returns an array of answers of the requested type.
  ///
  /// If `strict` is false (default) this function never errors and returns
  /// an empty array on failure. If `strict` is true, failures are thrown.
  async query(query_domain, record_type, strict) {
    const query = doh.makeQuery(query_domain, record_type);
    // we always want to query with DNSSEC enabled
    query.additionals = [{
      type: 'OPT',
      name: '.',
      udpPayloadSize: 4096,
      flags: doh.dnsPacket.DNSSEC_OK,
      options: []
    }];

    try {
      const query_result =
          await doh.sendDohMsg(query, this.doh_url_dohjs, this.doh_method);

      let results = [];
      for (const answer of query_result.answers) {
        if (answer.type == record_type) {
          results.push(answer);
        }
      }
      return results;
    } catch (error) {
      if (strict) {
        throw error;
      }
      console.error(error);
      return [];
    }
  }

  /// read the query response & look for SOA record from:
  ///   1. answers section, which means zone cut is at query_domain, or
  ///   2. authorities section, which means zone cut is above query domain
  async get_zone(query_domain) {
    const query_result = await this.resolver.query(query_domain, 'SOA');

    for (const ans of query_result.answers) {
      if (ans.type == 'SOA') {
        return ans.name;
      }
    }
    for (const auth of query_result.authorities) {
      if (auth.type == 'SOA') {
        return auth.name;
      }
    }
    throw new Error('no Zone found for ' + query_domain);
  }

  /// check if an RRSIG record is present for a specific domain
  async check_rrsig(query_domain) {
    try {
      const query_result = await this.resolver.query(query_domain, 'RRSIG');
      return query_result.answers.length > 0;
    } catch (error) {
      console.error('check_rrsig query failed for ' + query_domain);
      return false;
    }
  }
}


/// Return Service from a domain
function get_service(domain) {
  const domain_array = domain.split('.');
  return {
    service: domain_array[0], protocol: domain_array[1]
  }
}
