/// Central DNS object
///
/// Every question goes through the sig0lease WASM (`sig0lease.lookup`) to
/// the DNS-over-HTTPS endpoint of a sig0lease proxy. For the zones it serves,
/// the proxy asks the zone's authoritative server and answers with
/// `Cache-Control: no-store`, so the dashboard sees a change as soon as the
/// server has it, not when a resolver's cache expires. A name the proxy does
/// not serve (e.g. an instance in another zone) is answered by a public
/// resolver instead; such answers are counted in `cached_answers`.
class Dns {
  /// construct the DNS object for `domain_name`, asking the DoH server `doh`
  /// (a URL without path, e.g. `https://registrar.example`)
  constructor(domain_name, doh, on_initialized) {
    this.domain = domain_name;
    this.doh = doh;

    // set initialization flags
    this.dnssec_enabled = false;
    this.initialized = false;
    // answers of the last refresh that did not come from the proxy
    this.cached_answers = 0;

    this.init(on_initialized);
  }

  /// start asynchronous, longer running tasks at initialization
  async init(callback) {
    // check if the domain, or its DNS-SD service list (the domain itself is
    // often an empty non-terminal without records), is signed
    this.dnssec_enabled = await this.check_rrsig(this.domain) ||
        await this.check_rrsig('_services._dns-sd._udp.' + this.domain);

    // set initialized flag
    this.initialized = true;
    if (typeof callback === 'function') {
      callback(this);
    }
  }

  /// query `record_type` records of `query_domain` and return an array of
  /// answers `{name, type, ttl, data}`. `data` is a string for PTR, an
  /// object `{priority, weight, port, target}` for SRV and an array of
  /// strings for TXT.
  ///
  /// If `strict` is false (default) this function never errors and returns
  /// an empty array on failure. If `strict` is true, failures are thrown.
  async query(query_domain, record_type, strict) {
    try {
      const answer =
          await sig0lease.lookup(this.doh, query_domain, record_type);
      if (!answer.authoritative) {
        this.cached_answers++;
      }
      return answer.records;
    } catch (error) {
      if (strict) {
        throw error;
      }
      console.error(error);
      return [];
    }
  }

  /// check if an RRSIG record is present for a specific domain
  async check_rrsig(query_domain) {
    try {
      const records = await this.query(query_domain, 'RRSIG', true);
      return records.length > 0;
    } catch (error) {
      console.error('check_rrsig query failed for ' + query_domain, error);
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
