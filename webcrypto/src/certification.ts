import { defineE2EECertificationReport } from "@absolutejs/e2ee/certification";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { webcryptoProviderManifest } from "./provider-manifest";

const bunClaims = Object.freeze([
  "adversarial-lifecycle",
  "provider-conformance",
  "runtime-bun",
] as const);
const bunScenarios = Object.freeze([
  "manifest-conformance",
  "purpose-bound-round-trip",
  "context-substitution",
  "ciphertext-tamper",
  "malformed-envelope",
  "expired-context",
  "plaintext-limit",
  "non-exportable-private-key",
] as const);
const bunEvidenceStatement = JSON.stringify({
  claims: bunClaims,
  engine: "hpke@1.1.4",
  provider: `${webcryptoProviderManifest.packageName}@${webcryptoProviderManifest.version}`,
  runtime: "bun",
  scenarios: bunScenarios,
});

export const webcryptoProviderCertification = defineE2EECertificationReport({
  claims: bunClaims,
  completedAt: "2026-08-26T21:52:00.000Z",
  contract: 1,
  evidenceDigestSha256: bytesToHex(
    sha256(new TextEncoder().encode(bunEvidenceStatement)),
  ),
  implementations: [{ name: "hpke", version: "1.1.4" }],
  provider: {
    id: webcryptoProviderManifest.id,
    packageName: webcryptoProviderManifest.packageName,
    version: webcryptoProviderManifest.version,
  },
  runtime: "bun",
  scenarios: bunScenarios,
  suite: "absolutejs-e2ee-certification/1",
  vectors: [],
});

export const WEBCRYPTO_BROWSER_CERTIFICATION_SCENARIOS = Object.freeze([
  "browser-purpose-bound-round-trip",
  "browser-context-substitution",
  "browser-ciphertext-tamper",
  "browser-non-exportable-private-key",
] as const);
const browserClaims = Object.freeze([
  "adversarial-lifecycle",
  "provider-conformance",
  "runtime-browser",
] as const);
const browserEvidenceStatement = JSON.stringify({
  claims: browserClaims,
  engine: "hpke@1.1.4",
  provider: `${webcryptoProviderManifest.packageName}@${webcryptoProviderManifest.version}`,
  runtime: "chromium",
  scenarios: WEBCRYPTO_BROWSER_CERTIFICATION_SCENARIOS,
});

export const webcryptoBrowserProviderCertification =
  defineE2EECertificationReport({
    claims: browserClaims,
    completedAt: "2026-08-26T21:52:00.000Z",
    contract: 1,
    evidenceDigestSha256: bytesToHex(
      sha256(new TextEncoder().encode(browserEvidenceStatement)),
    ),
    implementations: [{ name: "hpke", version: "1.1.4" }],
    provider: {
      id: webcryptoProviderManifest.id,
      packageName: webcryptoProviderManifest.packageName,
      version: webcryptoProviderManifest.version,
    },
    runtime: "browser",
    scenarios: WEBCRYPTO_BROWSER_CERTIFICATION_SCENARIOS,
    suite: "absolutejs-e2ee-certification/1",
    vectors: [],
  });
