import {
  defineE2EECertificationReport,
  type E2EECertificationClaim,
} from "@absolutejs/e2ee/certification";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { mlsProviderManifest } from "./provider-manifest";

export const MLS_WORKING_GROUP_VECTOR_REVISION =
  "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a";
export const MLS_MESSAGE_VECTOR_SHA256 =
  "b194abe1561995223482dbad51c180146920dc2f637e74d01e07a388308791fb";
export const MLS_CERTIFICATION_SCENARIOS = Object.freeze([
  "manifest-conformance",
  "official-message-wire-vector",
  "authenticated-context-substitution",
  "welcome-keypackage-single-use",
  "encrypted-state-tamper",
  "security-mode-binding",
  "membership-removal",
] as const);

const claims: readonly E2EECertificationClaim[] = Object.freeze([
  "adversarial-lifecycle",
  "known-answer-vectors",
  "provider-conformance",
  "runtime-bun",
]);
const evidenceStatement = JSON.stringify({
  claims,
  engine: "ts-mls@1.6.2",
  provider: `${mlsProviderManifest.packageName}@${mlsProviderManifest.version}`,
  scenarios: MLS_CERTIFICATION_SCENARIOS,
  vectorRevision: MLS_WORKING_GROUP_VECTOR_REVISION,
  vectorSha256: MLS_MESSAGE_VECTOR_SHA256,
});

const browserClaims: readonly E2EECertificationClaim[] = Object.freeze([
  "adversarial-lifecycle",
  "provider-conformance",
  "runtime-browser",
]);
export const MLS_BROWSER_CERTIFICATION_SCENARIOS = Object.freeze([
  "browser-encrypted-group-round-trip",
  "browser-authenticated-context-substitution",
] as const);
const browserEvidenceStatement = JSON.stringify({
  claims: browserClaims,
  engine: "ts-mls@1.6.2",
  provider: `${mlsProviderManifest.packageName}@${mlsProviderManifest.version}`,
  scenarios: MLS_BROWSER_CERTIFICATION_SCENARIOS,
  runtime: "chromium",
});

export const mlsProviderCertification = defineE2EECertificationReport({
  claims,
  completedAt: "2026-08-26T18:45:00.000Z",
  contract: 1,
  evidenceDigestSha256: bytesToHex(
    sha256(new TextEncoder().encode(evidenceStatement)),
  ),
  implementations: [{ name: "ts-mls", version: "1.6.2" }],
  provider: {
    id: mlsProviderManifest.id,
    packageName: mlsProviderManifest.packageName,
    version: mlsProviderManifest.version,
  },
  runtime: "bun",
  scenarios: MLS_CERTIFICATION_SCENARIOS,
  suite: "absolutejs-e2ee-certification/1",
  vectors: [
    {
      digestSha256: MLS_MESSAGE_VECTOR_SHA256,
      sourceUrl: `https://raw.githubusercontent.com/mlswg/mls-implementations/${MLS_WORKING_GROUP_VECTOR_REVISION}/test-vectors/messages.json`,
    },
  ],
});

export const mlsBrowserProviderCertification = defineE2EECertificationReport({
  claims: browserClaims,
  completedAt: "2026-08-26T19:05:00.000Z",
  contract: 1,
  evidenceDigestSha256: bytesToHex(
    sha256(new TextEncoder().encode(browserEvidenceStatement)),
  ),
  implementations: [{ name: "ts-mls", version: "1.6.2" }],
  provider: {
    id: mlsProviderManifest.id,
    packageName: mlsProviderManifest.packageName,
    version: mlsProviderManifest.version,
  },
  runtime: "browser",
  scenarios: MLS_BROWSER_CERTIFICATION_SCENARIOS,
  suite: "absolutejs-e2ee-certification/1",
  vectors: [],
});
