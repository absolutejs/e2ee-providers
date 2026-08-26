import { checkMessagingProviderConformance } from "@absolutejs/e2ee/conformance";
import type { AuthenticationService } from "@absolutejs/e2ee";
import { expect, test } from "bun:test";
import { createMlsMessagingProvider } from "../src";

test("satisfies the shared MLS provider manifest conformance", async () => {
  const authenticationService: AuthenticationService = {
    issueDeviceCredential: async ({ deviceId, identityId }) => ({
      bytes: new Uint8Array([1]),
      deviceId,
      identityId,
      issuedAt: 1,
    }),
    sameIdentity: async (left, right) => left.identityId === right.identityId,
    validateDeviceCredential: async ({ credential }) => ({
      identityId: credential.identityId,
      status: "valid",
    }),
  };
  const result = await checkMessagingProviderConformance({
    createProvider: () =>
      createMlsMessagingProvider({
        authenticationService,
        now: () => 1,
        stateProtection: {
          open: async () => {
            throw new Error("not exercised by manifest conformance");
          },
          seal: async () => {
            throw new Error("not exercised by manifest conformance");
          },
        },
      }),
  });

  expect(result).toMatchObject({ issues: [], passed: true });
});
