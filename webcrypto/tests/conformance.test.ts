import { expect, test } from "bun:test";
import { checkE2EEProviderConformance } from "@absolutejs/e2ee/conformance";
import { checkE2EECertification } from "@absolutejs/e2ee/certification";
import {
  createWebCryptoEnvelopeProvider,
  webcryptoBrowserProviderCertification,
  webcryptoProviderCertification,
  webcryptoProviderManifest,
} from "../src";

test("passes shared E2EE provider conformance", async () => {
  const result = await checkE2EEProviderConformance({
    createProvider: () =>
      createWebCryptoEnvelopeProvider({
        resolveRecipientPrivateKey: async () => undefined,
      }),
    validRequirement: {
      minimumAssurance: "experimental",
      operatorCanDecrypt: false,
      protocols: ["RFC9180-BASE-P256-SHA256-AES128GCM"],
      roles: ["envelope"],
      runtime: "browser",
      securityMode: "strict-e2ee",
    },
  });

  expect(result).toEqual({
    issues: [],
    manifest: webcryptoProviderManifest,
    passed: true,
  });
  expect(
    checkE2EECertification(webcryptoProviderCertification, {
      manifest: webcryptoProviderManifest,
      maximumAgeMs: 31_536_000_000,
      requiredClaims: ["provider-conformance", "adversarial-lifecycle"],
      runtime: "bun",
    }).passed,
  ).toBe(true);
  expect(
    checkE2EECertification(webcryptoBrowserProviderCertification, {
      manifest: webcryptoProviderManifest,
      maximumAgeMs: 31_536_000_000,
      requiredClaims: ["provider-conformance", "adversarial-lifecycle"],
      runtime: "browser",
    }).passed,
  ).toBe(true);
});
