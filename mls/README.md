# `@absolutejs/e2ee-mls`

Experimental RFC 9420 messaging provider for `@absolutejs/e2ee`, backed by the
pure TypeScript `ts-mls@2.0.0-rc.16` engine.

This package exercises the complete AbsoluteJS messaging boundary with real MLS
messages: per-device credentials, KeyPackages, Welcome messages, encrypted
application data, membership commits, self-updates, and sealed group state. It
uses the mandatory-to-implement
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ciphersuite.

> This provider is not production-approved. `ts-mls` has not received a formal
> security audit, and this adapter has not received an independent review. Read
> [SECURITY.md](./SECURITY.md).

## Explicit application services

The provider requires an `AuthenticationService`; it does not accept anonymous
or self-asserted device credentials. The service issues credentials bound to the
generated MLS signature public key and validates that same binding when a remote
KeyPackage or membership change is processed.

KeyPackage directory, delivery, durable state, and recovery services remain the
application's responsibility through the contracts in `@absolutejs/e2ee`.
Strict E2EE clients must keep sealed state on participant-controlled devices.
`stateProtection` is required and must encrypt and authenticate exported MLS
state using a device-controlled key. A managed recovery authority may wrap that
already-sealed result separately.

Remote add, remove, and other sensitive membership proposals fail closed unless
`authorizeMembershipChange` explicitly approves them. Applications should bind
that callback to conversation roles and the current verified device roster.

## Usage

```ts
import { createMlsMessagingProvider } from "@absolutejs/e2ee-mls";

const provider = await createMlsMessagingProvider({
  authenticationService,
  stateProtection,
});
const alice = await provider.createDeviceCredential({
  deviceId: "alice-phone",
  identityId: "alice",
});
const conversation = await provider.createConversation({
  conversationId: crypto.randomUUID(),
  creatorCredential: alice,
  securityMode: "strict-e2ee",
});
```

Create every additional device's KeyPackage, call `addMembers()`, deliver its
returned Welcome exactly once, and deliver the returned handshake to existing
members. Authenticated message context must use the local device ID as
`senderId` and the session's current epoch.

Changing between `strict-e2ee` and `managed-recovery` requires a new
conversation. Never relabel or wrap an existing strict conversation in place.

## License

Apache-2.0
The `./certification` export binds this exact release to its shared conformance,
adversarial lifecycle suite, a pinned MLS Working Group KeyPackage vector, and
adapter-bound interoperability with OpenMLS 0.9.0. It does not claim an
independent security audit.
`mlsBrowserProviderCertification` is a separate Chromium report produced by
`bun run certify:browser`; browser evidence is never inferred from the build
target.

The repository contains a sanitized
[upstream migration receipt](./evidence/upstream-ts-mls-2.0.0-rc.16-openmls-0.9.0-welcome-join.json)
showing this exact engine release and OpenMLS 0.9.0 passing the official
role-permuting `welcome_join` matrix for ciphersuite 1. A separate
[adapter-bound receipt](./evidence/absolutejs-e2ee-mls-0.4.0-openmls-0.9.0-application.json)
shows this package creating the group, admitting OpenMLS's KeyPackage, delivering
the Welcome, and authenticating application data in both directions. Receipts
contain result metadata only; raw transcripts and test key material are not
persisted.

Every session exposes the security mode authenticated by MLS group state. Joining
a Welcome requires the caller's expected mode and rejects a mismatch before the
single-use KeyPackage is consumed.
