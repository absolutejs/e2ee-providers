# Changelog

## 0.4.0

- Expose the security mode authenticated by MLS group state on every session.
- Reject a Welcome before consuming its KeyPackage when its authenticated mode
  differs from the caller's required mode.

## 0.3.0

- Add adapter-bound interoperability evidence against OpenMLS 0.9.0 using the
  pinned MLS Working Group gRPC contract.
- Certify external KeyPackage admission, Welcome processing, and authenticated
  application messages in both directions without retaining secret transcripts.

## 0.2.1

- Declare compatibility with the `@absolutejs/e2ee` 0.6 independent-audit
  evidence contract and recertify the exact provider release.

## 0.2.0

- Harden the official MLS interoperability runner with exact implementation
  identities, self-reported-name checks, pinned compatible protobuf generators,
  explicit ciphersuite selection, and sanitized durable receipts.
- Port the adapter and its encrypted state format to `ts-mls@2.0.0-rc.16`, the
  first upstream release line with an official interoperability server.
- Preserve a passing upstream `ts-mls@2.0.0-rc.16`/OpenMLS 0.9.0 migration
  receipt without extending the current adapter's certification claims.

## 0.1.1

- Add a separately scoped Chromium certification report backed by an executable
  browser group-message and authenticated-context test.
- Keep cross-implementation certification withheld until the stable engine can
  run the MLS Working Group harness against another implementation.

## 0.1.0

- Publish exact-release certification evidence with a pinned MLS Working Group
  message vector and adversarial lifecycle scenarios.
- Keep known-answer-vector coverage distinct from independent implementation
  interoperability.

## 0.0.1

- Add experimental RFC 9420 messaging with device-bound credentials.
- Add KeyPackage, Welcome, membership, self-update, and application-message
  lifecycle support.
- Add sealed conversation state and explicit strict/managed mode carriage.
- Add conformance, tampering, replay, removal, and restoration tests.
