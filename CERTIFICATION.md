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

The MLS provider currently reaches levels 1–3 for Bun. It deliberately does not
claim level 4 or an independent audit. The pinned vector is from the MLS Working
Group's implementation coordination repository. RFC 9750 explains why compatible
MLS cryptography alone does not establish compatible Authentication Services,
Delivery Services, identities, or application framing.

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
