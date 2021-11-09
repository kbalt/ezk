# ezk-sip-ua

[![crates.io][crates-badge]][crates-url]
[![documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/kbalt/ezk/blob/main/LICENSE

[crates-badge]: https://img.shields.io/crates/v/ezk-sip-ua.svg
[crates-url]: https://crates.io/crates/ezk-sip-ua

[docs-badge]: https://img.shields.io/docsrs/ezk-sip-ua/latest
[docs-url]: https://docs.rs/ezk-sip-ua/latest

Incomplete low level SIP user agent utilities.

- Create/remove bindings via `REGISTER`
- Does not yet support outgoing `INVITE`s
- Create dialog from incoming `INVITE` & manage dialog
- Supports `100rel` and `timer` extension

Following RFCs were used:

- [RFC3261](https://www.rfc-editor.org/rfc/rfc3261.html) - SIP: Session Initiation Protocol
- [RFC3262](https://www.rfc-editor.org/rfc/rfc3262.html) - Reliability of Provisional Responses in SIP
- [RFC4028](https://www.rfc-editor.org/rfc/rfc4028.html) - Session Timers in SIP
