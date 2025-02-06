# ezk-sip-auth

[![crates.io][crates-badge]][crates-url]
[![documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/kbalt/ezk/blob/main/LICENSE

[crates-badge]: https://img.shields.io/crates/v/ezk-sip-auth.svg
[crates-url]: https://crates.io/crates/ezk-sip-auth

[docs-badge]: https://img.shields.io/docsrs/ezk-sip-auth/latest
[docs-url]: https://docs.rs/ezk-sip-auth/latest

Built on top of [`ezk-sip-types`](https://crates.io/crates/ezk-sip-types) it provides an client digest authentication based on the following RFCs:

- [RFC3261](https://www.rfc-editor.org/rfc/rfc3261.html) - SIP: Session Initiation Protocol
- [RFC7616](https://www.rfc-editor.org/rfc/rfc7616.html) - HTTP Digest Access Authentication
- [RFC8769](https://www.rfc-editor.org/rfc/rfc8760.html) - The SIP Digest Access Authentication Scheme
