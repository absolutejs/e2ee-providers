import { expect, test } from "bun:test";
import { checkE2EEProviderConformance } from "@absolutejs/e2ee/conformance";
import {
  createWebCryptoEnvelopeProvider,
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
});
