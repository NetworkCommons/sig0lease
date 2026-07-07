# Key management

The keystore must contain two directories:
- client
- server

Inside the `server` directory you need to put a key that is registered at a FQDN in the DNS server you want to update

Inside the `client` directory you need to put a key that the client uses to sign its requests and that gets inserted in a key record at a particular FQDN under the FQDN defined above.

You can generate the keys with dnssec-keygen, for example:

`dnssec-keygen -a ED25519 exampleKey.myDNSserver.com`

See also [sig0namectl](https://github.com/NetworkCommons/sig0namectl/blob/master/docs/sig0namectl%20Key%20Management.md) on how to register keys.
