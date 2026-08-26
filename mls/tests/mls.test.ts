import type { AuthenticationService, DeviceCredential } from "@absolutejs/e2ee";
import { describe, expect, test } from "bun:test";
import { createMlsMessagingProvider, type MlsStateProtection } from "../src";

const NOW = Date.now();

const hex = (bytes: Uint8Array) =>
  [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");

const authenticationFixture = () => {
  let credentialSequence = 0;
  const bindings = new Map<string, string>();
  const service: AuthenticationService = {
    issueDeviceCredential: async ({ deviceId, identityId, publicKey }) => {
      const bytes = new TextEncoder().encode(
        `credential-${credentialSequence}`,
      );
      credentialSequence += 1;
      bindings.set(hex(bytes), hex(publicKey));
      return {
        bytes,
        deviceId,
        expiresAt: NOW + 60_000,
        identityId,
        issuedAt: NOW,
      };
    },
    sameIdentity: async (left, right) => left.identityId === right.identityId,
    validateDeviceCredential: async ({ credential, publicKey }) => ({
      identityId: credential.identityId,
      status:
        bindings.get(hex(credential.bytes)) === hex(publicKey)
          ? "valid"
          : "invalid",
    }),
  };
  return service;
};

const stateProtectionFixture = async (): Promise<MlsStateProtection> => {
  const key = await crypto.subtle.generateKey(
    { length: 256, name: "AES-GCM" },
    false,
    ["decrypt", "encrypt"],
  );
  return {
    open: async ({ sealedState }) => {
      if (sealedState.length < 13) throw new Error("Invalid sealed state.");
      return new Uint8Array(
        await crypto.subtle.decrypt(
          { iv: sealedState.slice(0, 12), name: "AES-GCM" },
          key,
          sealedState.slice(12),
        ),
      );
    },
    seal: async ({ state }) => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
          { iv, name: "AES-GCM" },
          key,
          Uint8Array.from(state),
        ),
      );
      const sealed = new Uint8Array(iv.length + ciphertext.length);
      sealed.set(iv);
      sealed.set(ciphertext, iv.length);
      return sealed;
    },
  };
};

const setup = async (
  mode: "managed-recovery" | "strict-e2ee" = "strict-e2ee",
  authorizeMembershipChange = true,
) => {
  const authenticationService = authenticationFixture();
  const stateProtection = await stateProtectionFixture();
  let sequence = 0;
  const options = {
    authenticationService,
    ...(authorizeMembershipChange
      ? { authorizeMembershipChange: () => true }
      : {}),
    now: () => NOW,
    randomId: () => `id-${sequence++}`,
    stateProtection,
  };
  const aliceProvider = await createMlsMessagingProvider(options);
  const bobProvider = await createMlsMessagingProvider(options);
  const alice = await aliceProvider.createDeviceCredential({
    deviceId: "alice-phone",
    identityId: "alice",
  });
  const bob = await bobProvider.createDeviceCredential({
    deviceId: "bob-laptop",
    identityId: "bob",
  });
  const bobKeyPackage = await bobProvider.createKeyPackage({
    credential: bob,
    expiresAt: NOW + 30_000,
  });
  const aliceSession = await aliceProvider.createConversation({
    conversationId: "conversation-1",
    creatorCredential: alice,
    securityMode: mode,
  });
  const membership = await aliceSession.addMembers([bobKeyPackage]);
  const welcome = membership.welcomes[0];
  if (welcome === undefined) throw new Error("Expected Bob's Welcome.");
  const bobSession = await bobProvider.joinConversation({
    credential: bob,
    expectedSecurityMode: mode,
    welcome: welcome.bytes,
  });

  return {
    alice,
    aliceProvider,
    aliceSession,
    authenticationService,
    bob,
    bobKeyPackage,
    bobProvider,
    bobSession,
    membership,
    stateProtection,
  };
};

describe("MLS messaging provider", () => {
  test("adds a device and exchanges sender-bound encrypted messages", async () => {
    const surface = await setup();

    expect(surface.membership.epoch).toBe(1);
    expect(surface.membership.handshake).toHaveLength(1);
    expect(surface.membership.welcomes).toHaveLength(1);
    expect(
      (await surface.aliceSession.members()).map(
        (member) => member.credential.deviceId,
      ),
    ).toEqual(["alice-phone", "bob-laptop"]);

    const protectedMessage = await surface.aliceSession.protect(
      new TextEncoder().encode("hello bob"),
      {
        conversationId: "conversation-1",
        purpose: "chat.message",
        securityEpoch: 1,
        senderId: "alice-phone",
      },
    );
    const processed = await surface.bobSession.process(protectedMessage);

    expect(processed?.kind).toBe("application");
    expect(
      processed?.kind === "application"
        ? new TextDecoder().decode(processed.message.plaintext)
        : undefined,
    ).toBe("hello bob");
    expect(
      processed?.kind === "application"
        ? processed.message.authenticatedContext.senderId
        : undefined,
    ).toBe("alice-phone");
  });

  test("rejects wrapper-context substitution without consuming the message", async () => {
    const surface = await setup();
    const message = await surface.aliceSession.protect(
      new TextEncoder().encode("bound message"),
      {
        conversationId: "conversation-1",
        purpose: "chat.message",
        securityEpoch: 1,
        senderId: "alice-phone",
      },
    );

    await expect(
      surface.bobSession.process({
        ...message,
        authenticatedContext: {
          ...message.authenticatedContext,
          senderId: "mallory-device",
        },
      }),
    ).rejects.toThrow("does not match MLS AAD");
    expect((await surface.bobSession.process(message))?.kind).toBe(
      "application",
    );
  });

  test("consumes Welcome KeyPackages exactly once", async () => {
    const surface = await setup();
    const welcome = surface.membership.welcomes[0];
    if (welcome === undefined) throw new Error("Expected Bob's Welcome.");

    await expect(
      surface.bobProvider.joinConversation({
        credential: surface.bob,
        expectedSecurityMode: "strict-e2ee",
        welcome: welcome.bytes,
      }),
    ).rejects.toThrow("available KeyPackage");
  });

  test("rejects mode substitution without consuming the Welcome KeyPackage", async () => {
    const surface = await setup("managed-recovery");
    const charlieProvider = await createMlsMessagingProvider({
      authenticationService: surface.authenticationService,
      stateProtection: surface.stateProtection,
    });
    const charlie = await charlieProvider.createDeviceCredential({
      deviceId: "charlie-tablet",
      identityId: "charlie",
    });
    const keyPackage = await charlieProvider.createKeyPackage({
      credential: charlie,
      expiresAt: NOW + 30_000,
    });
    const membership = await surface.aliceSession.addMembers([keyPackage]);
    const welcome = membership.welcomes[0];
    if (welcome === undefined) throw new Error("Expected Charlie's Welcome.");

    await expect(
      charlieProvider.joinConversation({
        credential: charlie,
        expectedSecurityMode: "strict-e2ee",
        welcome: welcome.bytes,
      }),
    ).rejects.toThrow("does not match expected mode");
    const joined = await charlieProvider.joinConversation({
      credential: charlie,
      expectedSecurityMode: "managed-recovery",
      welcome: welcome.bytes,
    });
    expect(joined.securityMode).toBe("managed-recovery");
    await joined.close();
  });

  test("seals and restores evolving conversation state", async () => {
    const surface = await setup("managed-recovery");
    const sealed = await surface.aliceProvider.sealConversationState(
      surface.aliceSession,
    );
    await surface.aliceSession.close();
    const restoredProvider = await createMlsMessagingProvider({
      authenticationService: authenticationFixture(),
      now: () => NOW,
      stateProtection: surface.stateProtection,
    });
    const restored = await restoredProvider.restoreConversation({
      sealedState: sealed,
    });
    const message = await restored.protect(
      new TextEncoder().encode("restored"),
      {
        conversationId: "conversation-1",
        purpose: "chat.message",
        securityEpoch: 1,
        senderId: "alice-phone",
      },
    );

    expect((await surface.bobSession.process(message))?.kind).toBe(
      "application",
    );
  });

  test("removes devices through an authenticated epoch commit", async () => {
    const surface = await setup();
    const removal = await surface.aliceSession.removeMembers(["bob-laptop"]);
    expect(removal.epoch).toBe(2);
    expect(
      (await surface.aliceSession.members()).map(
        (member) => member.credential.deviceId,
      ),
    ).toEqual(["alice-phone"]);
    expect(
      (await surface.bobSession.process(removal.handshake[0]!))?.kind,
    ).toBe("membership-change");
    await expect(
      surface.bobSession.protect(new Uint8Array([1]), {
        conversationId: "conversation-1",
        purpose: "chat.message",
        securityEpoch: 2,
        senderId: "bob-laptop",
      }),
    ).rejects.toThrow();
  });

  test("fails closed when remote membership policy is absent", async () => {
    const surface = await setup("strict-e2ee", false);
    const removal = await surface.aliceSession.removeMembers(["bob-laptop"]);

    await expect(
      surface.bobSession.process(removal.handshake[0]!),
    ).rejects.toThrow("not authorized");
    expect(surface.bobSession.epoch).toBe(1);
  });

  test("binds the security mode into MLS group state", async () => {
    const surface = await setup("managed-recovery");
    const sealed = await surface.aliceProvider.sealConversationState(
      surface.aliceSession,
    );
    const plaintext = await surface.stateProtection.open({
      sealedState: sealed,
    });
    const changed = new TextEncoder().encode(
      new TextDecoder()
        .decode(plaintext)
        .replace('"mode":"managed-recovery"', '"mode":"strict-e2ee"'),
    );
    const relabeled = await surface.stateProtection.seal({ state: changed });

    await expect(
      surface.aliceProvider.restoreConversation({ sealedState: relabeled }),
    ).rejects.toThrow("does not match the MLS group");
  });

  test("rejects tampered encrypted conversation state", async () => {
    const surface = await setup();
    const sealed = await surface.aliceProvider.sealConversationState(
      surface.aliceSession,
    );
    sealed[sealed.length - 1] = (sealed[sealed.length - 1] ?? 0) ^ 1;

    await expect(
      surface.aliceProvider.restoreConversation({ sealedState: sealed }),
    ).rejects.toThrow();
  });
});
