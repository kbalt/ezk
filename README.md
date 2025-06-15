# EZK - Collection of SIP related crates (and more)

List of notable crates are:

- [ezk-rtc](./media/rtc/) - SDP based media session
- [ezk-sip-core](./sip/sip-core/) - SIP concepts like transports & transactions
- [ezk-sip-ua](./sip/sip-core/) - SIP User Agent abstractions for registrations & calls using `ezk-rtc`

## Examples

Explore the [examples](./examples/) which showcase some basic SIP scenarios.

These cannot be run without a few changes, as SIP calls usually require an endpoint to communicate with.

# Building

`ezk-rtc` currently uses bindings to `openssl` and `libsrtp` which must be installed on your system.
Alternatively you can use the feature flags `vendor-openssl` and `vendor-srtp`.

> Note: `vendor-srtp` does not currently work on Windows
