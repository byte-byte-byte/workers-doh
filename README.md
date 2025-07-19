# workers-doh
A lightweight DNS over HTTPS (DoH) server built on Cloudflare Workers.

## features
Support for GET dns-query?nameSupport, GET/POST dns-query?dns, GET resolve?name
Support for responding to application/dns-json and application/dns-message.
Transmit the edns_client_subnet parameter to the upstream DNS server.
The edns_client_subnet parameter obscures the client IP address, thereby protecting privacy.
Support for A, AAAA, NC, CNAME, MX, TXT, SOA, RRSIG, and SRV type responses from upstream DNS servers.

