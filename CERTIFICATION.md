# Provider certification and threat model

AbsoluteJS treats a provider manifest as a capability declaration and a
certification report as evidence about one exact package release. Neither is an
independent security audit.

## Trust boundaries

- The provider owns cryptographic state transitions and protocol serialization.
- The application owns identity presentation, authorization, user-visible device
  membership, and security-mode selection.
- An MLS Authentication Service owns the binding between application identities
  and MLS signature keys.
- An MLS Delivery Service may delay, drop, replay, reorder, or correlate traffic,
  but must not gain group secrets merely by operating delivery.
- State protection owns encryption and rollback resistance for serialized local
  group state. The MLS provider does not silently create a recovery authority.
- PaaS owns durable execution, exact package admission, scheduler freshness, and
  the sealed drill evidence chain when it offers the managed service.

## Adversaries in scope

- A hostile network or Delivery Service modifying, replaying, reordering, or
  withholding messages.
- A malicious caller relabeling authenticated context or security mode.
- Reuse of Welcome or KeyPackage material.
- Stale, malformed, or tampered local state.
- A package substitution or certification report copied from another version.
- A provider claiming vector or cross-implementation coverage it did not produce.

Endpoint compromise, a malicious Authentication Service issuing a valid ghost
credential, traffic analysis, denial of service, and loss of every device and
export remain application/deployment risks. They are not erased by MLS.

## Evidence levels

1. `provider-conformance` validates the shared AbsoluteJS provider contract.
2. `adversarial-lifecycle` exercises wrapper and application security boundaries.
3. `known-answer-vectors` binds tests to an immutable upstream vector corpus.
4. `cross-implementation` requires at least two distinct implementation names in
   a report and must come from a harness where each implementation participates in
   the same group state and application-message flows.
5. `audited` remains a separate manifest assurance level and requires published
   independent audit material.

The MLS provider currently reaches levels 1–3 for Bun and levels 1–2 in
Chromium. The WebCrypto provider reaches levels 1–2 in both Bun and Chromium.
Browser reports are separate from Bun reports so a consumer cannot mistake a
bundle target for evidence from an executed browser. Run `bun run
certify:browser` to regenerate the executable browser evidence.

The MLS provider deliberately does not claim level 4 or an independent audit.
The current `ts-mls@2.0.0-rc.16` engine server passed the pinned runner's
`welcome_join` suite-1 matrix against OpenMLS 0.9.0 on 2026-08-26. That result is
preserved as an [upstream engine receipt](./mls/evidence/upstream-ts-mls-2.0.0-rc.16-openmls-0.9.0-welcome-join.json),
not as cross-implementation evidence for the AbsoluteJS adapter: the upstream
engine server, rather than this adapter, participated in the run. A future
provider release may claim level 4 only after its exact adapter release passes
an adapter-bound gate. The
pinned vector is from the Working Group's implementation coordination
repository. RFC 9750 explains why compatible MLS cryptography alone does not
establish compatible Authentication Services, Delivery Services, identities,
or application framing.

Once two distinct implementation servers are running, use the pinned official
runner rather than an AbsoluteJS-specific message exchange:

```sh
bun run certify:interop -- \
  --client localhost:50051 \
  --implementation OpenMLS@VERSION#40_HEX_REVISION \
  --client localhost:50053 \
  --implementation ts-mls@VERSION#40_HEX_REVISION \
  --config welcome_join \
  --suite 1 \
  --output receipt.json
```

The command checks out the exact Working Group revision, builds its runner with
pinned compatible protobuf generators, runs the role-permuting gRPC test, and
emits a JSON receipt with implementation revisions, configuration and output
digests, scenarios, assignments, and the runner image digest. It rejects the
same endpoint or implementation name twice and checks declared names against
the servers' gRPC `Name` responses. Raw transcripts are neither printed nor
persisted because they contain test private keys. Source revisions remain
operator declarations and must be independently reproduced during audit. A
passing receipt is necessary for a `cross-implementation` claim, but does not by
itself prove application, Authentication Service, or Delivery Service
interoperability.

## Audit preparation

An independent review should cover the provider wrapper, its exact engine and
transitive cryptographic dependencies, credential validation, membership-policy
hooks, state protection supplied by the host, key erasure limits in JavaScript,
mode transitions, manifest claims, and the PaaS drill/admission integration.

Every finding should name a machine-readable control, affected package version,
test or drill, owner, remediation revision, and expiration/retest date. A package
bump invalidates the old report even when the source change appears unrelated.

## Primary specifications

- RFC 9420: <https://www.rfc-editor.org/rfc/rfc9420>
- RFC 9750: <https://www.rfc-editor.org/rfc/rfc9750>
- MLS Working Group vectors and harness:
  <https://github.com/mlswg/mls-implementations>
