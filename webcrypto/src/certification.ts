import { defineE2EECertificationReport } from "@absolutejs/e2ee/certification";
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
