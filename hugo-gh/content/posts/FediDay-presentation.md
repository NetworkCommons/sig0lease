+++
title = 'FediDay Berlin 2026: sig0lease presentation'
layout = 'posts'
date = 2026-09-15T11:12:15+02:00
draft = false
#featured_image = '/images/mycosystem-quarter.jpg'
featured_image = ""
toc = true
+++


Adam & Mathias present progress so far for the sig0lease project at Berlin FediDay 2026.


On Sunday September 13th, Adam Burns and Mathias Jud held a workshop at the 2026 edition of [Berlin FediDay](https://berlinfedi.day/en) entitled *[The fediverse at the edge (of time): sig0lease and devuan-pi-gadgeteer](https://ctalx.c-base.org/fediday-2026/talk/FPEMAR/)*.

The presentation explained how sig0lease allows time-based leasing and updating of hostnames in the Internet's Domain Name System (DNS) together with publication of service descriptions and service discovery information for services offered by each host joining the local network.

![targets](/images/PXL_20260913_122145604.MP.jpg)
 

Adam summarized the current status of the sig0lease project:

We have successfully:
- completed an initial version of a DNS proxy server and client capable of handling registration, refreshing and deletion of DNS Leases (as described in [RFC 9664](https://datatracker.ietf.org/doc/rfc9664/)).

- begun work on a client capable of handling SRP (the Service Registration Protocol) that handles registration and refreshing of host, service and service discovery DNS lease updates that is capable of registering names of hosts, details of services offered by the host together with the service discovery DNS records to publish the services, easing the searching and connection to services offered within a network domain.

Together they represent an initial collection of tools that offer standards-based DNS publishing tools that allow users to publish and regularly update accurate, timely information on currently available services within a local community network infrastructure, automatically removing information of services that do not regularly refresh or update their details, ensuring a seamless user experience for searching and resolving these local network services.
