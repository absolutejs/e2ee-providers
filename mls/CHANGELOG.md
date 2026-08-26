# Changelog

## Unreleased

- Harden the official MLS interoperability runner with exact implementation
  identities, self-reported-name checks, pinned compatible protobuf generators,
  explicit ciphersuite selection, and sanitized durable receipts.
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
