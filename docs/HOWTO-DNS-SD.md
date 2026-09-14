# DNS-SD introduction of browsing domains, service type listing & service resolution

# to walk all service instances of all service types for a domain
avahi-browse -batd zembla.zenr.io


# to query for a list of current dnssd service types for a domain
# example domain: zembla.zenr.io
dig PTR _services._dns-sd._udp.zembla.zenr.io


# to query a list of service instances for a service type for a domain
# example domain: zembla.zenr.io
# example service type: _http._tcp

dig PTR _http._tcp.zembla.zenr.io


# to query service instance details for a service type for a domain (note any != all and full RRtype list to query can depend on service type)
# (note presentation differences of '\032' in RR labels versus presentation in dig utility of '\ ')
# RR of below is represented as sig0namectl\032Homepage._http._udp.zembla.zenr.io
# example domain: zembla.zenr.io
# example service type: _http._tcp
# example service instance: sig0namectl\ Homepage

dig sig0namectl\ Homepage._http._tcp.zembla.zenr.io. any

