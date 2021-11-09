# ezk-sip-core

[![crates.io][crates-badge]][crates-url]
[![documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/kbalt/ezk/blob/main/LICENSE

[crates-badge]: https://img.shields.io/crates/v/ezk-sip-core.svg
[crates-url]: https://crates.io/crates/ezk-sip-core

[docs-badge]: https://img.shields.io/docsrs/ezk-sip-core/latest
[docs-url]: https://docs.rs/ezk-sip-core/latest

SIP core library providing abstractions for transports and SIP transactions.

It is the centerpiece of any stateful SIP applications as it provides the `Endpoint`
which holds all low level information about the SIP Stack (transport/transaction state).

While not complete, transport and transaction management are implemented after the following RFCs:

- [RFC3261](https://www.rfc-editor.org/rfc/rfc3261.html) - SIP: Session Initiation Protocol
- [RFC6026](https://www.rfc-editor.org/rfc/rfc6026.html) - Correct Transaction Handling for 2xx Responses to SIP INVITE Requests
