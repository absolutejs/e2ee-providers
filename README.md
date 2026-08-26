# AbsoluteJS E2EE providers

Interchangeable implementations for [`@absolutejs/e2ee`](https://github.com/absolutejs/e2ee),
organized like `voice-adapters`. The repository root is private; every provider is
an independently versioned public package named `@absolutejs/e2ee-<provider>`.

Provider roles are explicit. Messaging engines, envelope implementations, key
custodians, recovery authorities, and transports do not claim equivalent security
merely because they share one selection API.

## Providers

| Package                                     | Role                                                            | Status       |
| ------------------------------------------- | --------------------------------------------------------------- | ------------ |
| [`@absolutejs/e2ee-mls`](./mls)             | RFC 9420 messaging using the pure TypeScript `ts-mls` engine    | Experimental |
| [`@absolutejs/e2ee-webcrypto`](./webcrypto) | RFC 9180 single-recipient envelopes using WebCrypto-backed HPKE | Experimental |

Every provider publishes a machine-readable capability and assurance manifest and
runs the shared `@absolutejs/e2ee/conformance` checks.

Provider releases also export an exact-version certification report. Reports keep
shared conformance, adversarial lifecycle coverage, official vectors, and true
cross-implementation interoperability as separate claims. See
[`CERTIFICATION.md`](./CERTIFICATION.md) for the threat model and audit boundary.
Interoperability receipts are sanitized summaries; raw Working Group transcripts
are not retained because they contain ephemeral private key material.

## Development

```bash
bun install
bun run check:package
```

## Security

All providers are `0.x`. Read each package's security limitations before using it.
An `experimental` manifest is not a production recommendation.

## License

Apache-2.0
