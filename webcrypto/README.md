# `@absolutejs/e2ee-webcrypto`

Experimental RFC 9180 HPKE envelope provider for `@absolutejs/e2ee`, using the
WebCrypto-backed primitives in [`hpke`](https://github.com/panva/hpke).

> This `0.x` package has not been independently audited by AbsoluteJS. It provides
> isolated single-recipient envelopes, not MLS or a secure messaging protocol.

The initial suite is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM for
broad WebCrypto runtime support. The suite and wire version are explicit and
authenticated context is supplied as both HPKE `info` and AEAD additional data.

See [SECURITY.md](./SECURITY.md) for limitations.

## License

Apache-2.0
