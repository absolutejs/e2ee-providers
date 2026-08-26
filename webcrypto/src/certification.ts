import { defineE2EECertificationReport } from "@absolutejs/e2ee/certification";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { webcryptoProviderManifest } from "./provider-manifest";

export const webcryptoProviderCertification = defineE2EECertificationReport({
  claims: ["adversarial-lifecycle", "provider-conformance", "runtime-bun"],
  completedAt: "2026-08-26T18:45:00.000Z",
  contract: 1,
  evidenceDigestSha256:
    "940a33388ce04d35dfdc65db639ced786b477457fbb2cc693e41d29f279317b5",
  implementations: [{ name: "hpke", version: "1.1.4" }],
  provider: {
    id: webcryptoProviderManifest.id,
    packageName: webcryptoProviderManifest.packageName,
    version: webcryptoProviderManifest.version,
  },
  runtime: "bun",
  scenarios: [
    "manifest-conformance",
    "purpose-bound-round-trip",
    "context-substitution",
    "ciphertext-tamper",
    "malformed-envelope",
    "expired-context",
    "plaintext-limit",
    "non-exportable-private-key",
  ],
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
    completedAt: "2026-08-26T19:05:00.000Z",
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
