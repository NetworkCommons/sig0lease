# SWS JG2 : A sig0namectl dynamic DNS Service Discovery module (sig0lease)
## Project description and utilization plan
### Short project description
sig0lease creates a comprehensive library-module for applications to incorporate automated
publishing of human-readable service and resource details in secure DNS infrastructure with
sufficient technical parameters to allow resolution and connection to services and resources without
further user intervention.

During the sig0namectl project (see https//sig0namectl.networkcommons.org), it was identified that
there is no easy-to-use method for developers and providers to easily incorporate DNS Service
Discovery (DNS-SD) into their applications, especially to enable users to update dynamic services
and resources that move or disappear over time. sig0lease solves this issue by ensuring the
necessary information is accurate and available over the entire application deployment lifecycle.

### What problem/social challenge do you want to address with the project? What is your motivation?
Up until now, the primary mechanism used to publish, find and connect to available digital
resources has been through the use of central web search engine services offered by third-party
organisations. Publishing and discovering resources is mediated by search engine that not only
profits from financial payment for priority ranking in search results but also profits through the
gaining and on-selling of valuable data assets from those doing the searching.

DNS Service Discovery is a mechanism by which secure autonomous service publication can be
achieved without such intermediaries. The sig0namectl project developed the world’s first read-only
DNS-SD web browser application. The sig0lease module brings to the project a capability that
enables easy-to-use collaborative live updates for secure DNS Service Discovery.

### How will the project solve this problem? How do you intend to implement the project technically? What similar approaches already exist, and what will make your project different or better?
The project builds on recently published IETF standards that define secure DNS-SD updates
through a new standard, the “Service Registration Protocol” (defined in RFC9664 & RFC9665).
This is achieved by building on the existing sig0namectl Golang module, which makes use the
standard Golang DNS module, one of the most feature-complete and modular DNS application
libraries available.

Specifically: developing Golang library modules that support:
- a SRP proxy server which parses lease DNS-SD lease requests from SRP clients and, if
found to be valid, forwards signed DNS updates to authoritative DNSSEC-enabled DNS servers.
- a SRP client which requests and renews SRP leases from a SRP server.

This module addition to sig0namectl offers ease of use, integrity and accuracy to dynamic
collaborative updates of DNS-SD data structures to secure DNS domains.

Projects with similar approaches include:
- Avahi Project (https://avahi.org/) offers no DNS updates & is local network focused, only DNS querying has been developed for Internet wide-area DNS scope.
- The mDNSResponder project (https://github.com/apple-oss-distributions/mDNSResponder) incorporates the new SRP protocol, but only supports singular non-scalable TSIG authentication to authoritative DNS servers.
- OpenThread project (https://github.com/openthread/openthread/) implements a SRP DNS proxy server but is designed to work for IoT devices over the Thread networking protocol.

sig0lease builds an innovative cross-platform SRP solution targeted for Internet-based applications aimed for human use, not just IoT devices.

### Existing libraries that can be reused
https://codeberg.org/miekg/dns is a well-respected library that should be used as a basis for development, possibly contributing back functionality to the repository.

### Briefly describe the risks involved in implementing your project and explain what measures you have planned to mitigate these risks or what alternative solutions you have in mind.
Risk: The two IETF RFCs that define the SRP protocol could be unclear, incomplete or
contradictory for this project’s intended implementation and use case with the standard.

Mitigations: A developer in the project has subscribed to IETF DNS and DNS-SD mailing lists for 2
decades, and has reached out to the authors of these standards for previous clarifications. The
mailing lists and IETF datatracker and git resources are other resources to assist in resolution. An
implementation work-around that does not conform exactly to the standard may be a mitigation in
such cases, a work around that should be documented until resolved.

Risk: The third-party upstream development dependencies of DNS-related Golang modules used in
the project could contain bugs or missing specific features exposed during the development implementation.

Mitigations: A developer in the project has been subscribed to the Golang DNS module github
mailing list for many years and has raised bug reports to the maintainers against the module before.
It is actively maintained with prompt responses given to issues and questions. Developing against a
different version may be another approach, or finding a suitable other workaround.

Risk: Developer health or availability during crucial times may cause milestones to be missed or in
extreme cases may put the completion of the project at risk.

Mitigation: There is a reasonable level of redundancy in shared specific knowledge-domain depth
and breadth amongst the project members.

### Who is the target group and how will they benefit from the project? How will your project reach them?
Identified target groups include:
- Maintainers of community networks around the world including regional Freifunk community network groups in Germany, allowing accurate and updated services and resources to be hosted, published and searchable inside their own local networks. Freifunk and Freifunk Berlin have already implemented sig0namectl within their networks.
- Developers of peer to peer services where nodes are changing their Internet access details unpredictably and frequently over time.
- Developers and operators of digital services and resources whose Internet hosting infrastructure frequently change over time. The ability to maintain up to date access details for services whose access details frequently change over time offers an anti-censorship measure in countries and regions of repressive censorship regimes.

Throughout the project, communication and feedback with target groups and partners will continue over email lists, chat groups, on-line conferencing events as well as live in-person events.

Many organisations are willing to host future sig0lease presentations after past invitations for presentations on sig0namectl, including:
- SplinterCon Berlin 2024
- IETF 123 2025 organised by Internet Engineering Task Force
- Battlemesh v16 2025
- web3privacy “Cypherpunk Retreat 2025”

### Create work packages with start and end dates and the planned working hours, and outline the most important milestones and the corresponding deadlines for the six-month funding period. Break down the planned working hours by team member if you are applying for funding as a team.
Project Open Source Licence: Affero General Public License version 3 (AGPLv3)
Project Open Source Repository: GitHub (under https://github.com/NetworkCommons)

Work Package 1: SRP Server Development
Start Date: 01.06.2026
End Date: 15.08.2026
Planned Person Hours: 800 (Adam 300, Mathias 250, Stefano 250)
Summary Description: This work package delivers an initial prototype SRP server that provides
core functions to secure updates to DNS entries based on the SRP protocol and lease mechanism for
DNS-SD resource record structures within an DNSSEC-enabled authoritative DNS resolver. As a
complement to unit testing for source code, a system layer test harness is developed to test SRP
server development against the documented standards. This test harness will act as an initial
functional guideline for development of a modular SRP client in Work Package 2.
Tasks include:
- Developing SRP wire protocol listener daemon module (Adam 60, Mathias 70, Stefano 30)
- Developing DNSSEC DNS-SD authoritative server update module (Adam 60, Mathias 30, Stefano 70)
- Developing SRP server lease lifetime management module (Adam 60, Mathias 100, Stefano 100)
- Developing SRP server configuration module (Adam 120, Mathias 50, Stefano 50)
Milestone 1: (Due 01.08.2026) Functional SRP Server that is capable of validating SRP client
leases requests, manage lease lifecycles, and forward secure DNS update requests to
authoritative DNSSEC enabled DNS servers.

Work Package 2: SRP Client Development
Start Date: 01.08.2026
End Date: 15.09.2026
Planned Person Hours: 400 (Adam 150, Mathias 125, Stefano 125)
Summary Description: Based on the test harness code developed to systemically test the Work
Package 1 deliverable SRP server code, SRP client code development is to be developed as a
modular self-standing SRP client executable along with not only unit tests but also a systemic test
harness of client functionality against the SRP server and DNSSEC test harness infrastructure. A
modular DNS-SD service type plug-in API is to be developed to allow for flexible development of
innovative specific service types along with their respective handler functions. This initial API
forms the basis for development in Work Package 3.
Tasks include:
- Developing SRP wire protocol lease request and renewal module (Mathias 25, Stefano 25).
- Developing SRP client lease maintenance daemon module (Adam 50, Mathias 50, Stefano 50).
- Developing initial DNS-SD service type API along with service type handler specifications. (Adam 100, Mathias 50, Stefano 50)
Milestone 2: (Due 31.08.2026) Functional SRP Client Implementation able to request SRP leases and send lease renewals at required intervals from a SRP server.

Work Package 3: Customization, Integration and Testing
Start Date: 05.09.2026
End Date: 30.11.2026
Planned Person Hours: 700 (Adam 300, Mathias 200, Stefano 200)
Summary Description: Based on the work carried out in Work Package 1 and Work Package 2,
particularly the initial DNS-SD server type API and service type handler specifications, allow for
the development of a generic service type module. Based on the generic module, at least four DNS-
SD service type modules are to be developed for distinct DNS-SD service types. The completion of
the service type modules will allow the development and deployment of a full end-to-end testing
and validation system for the modular SRP client interaction with the SRP server and on-bound
DNSSEC enabled DNS authoritative resolvers.
Tasks include:
- Developing generic SRP server DNS-SD service type template module specifying the required DNS Resource Records for each specific service type the SRP server accepts from a SRP client. (Adam 60, Mathias 20, Stefano 60)
- Development of at least four initial DNS-SD service type modules based off the template module. (Adam 180, Mathias 120, Stefano 120)
- Transpiling SRP client module into WebAssembly to enable future SRP client based Javascript web browser based applications to be developed (Adam 30, Mathias 40).
- Developing a final end-to-end system test harness, with SRP server, SRP client and implemented service type handler functions and perform end-to-end tests to validate entire system deployment life cycle of each service type (Adam 30, Mathias 20, Stefano 20).
Milestone 3: (Due 15.11.2026) DNS-SD Service Type Customization Feature Complete
