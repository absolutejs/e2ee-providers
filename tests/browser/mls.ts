import type { AuthenticationService } from "@absolutejs/e2ee";
import {
  createMlsMessagingProvider,
  type MlsStateProtection,
} from "../../mls/src";

type BrowserCertificationResult = {
  readonly error?: string;
  readonly ok: boolean;
};

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");

const run = async (): Promise<BrowserCertificationResult> => {
  try {
    const now = Date.now();
    let credentialSequence = 0;
    const bindings = new Map<string, string>();
    const authenticationService: AuthenticationService = {
      issueDeviceCredential: async ({ deviceId, identityId, publicKey }) => {
        const bytes = new TextEncoder().encode(
          `browser-credential-${credentialSequence++}`,
        );
        bindings.set(hex(bytes), hex(publicKey));
        return {
          bytes,
          deviceId,
          expiresAt: now + 60_000,
          identityId,
          issuedAt: now,
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
    const stateKey = await crypto.subtle.generateKey(
      { length: 256, name: "AES-GCM" },
      false,
      ["decrypt", "encrypt"],
    );
    const stateProtection: MlsStateProtection = {
      open: async ({ sealedState }) =>
        new Uint8Array(
          await crypto.subtle.decrypt(
            { iv: sealedState.slice(0, 12), name: "AES-GCM" },
            stateKey,
            sealedState.slice(12),
          ),
        ),
      seal: async ({ state }) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt({ iv, name: "AES-GCM" }, stateKey, state),
        );
        const sealed = new Uint8Array(iv.length + ciphertext.length);
        sealed.set(iv);
        sealed.set(ciphertext, iv.length);
        return sealed;
      },
    };
    const options = {
      authenticationService,
      authorizeMembershipChange: () => true,
      now: () => now,
      stateProtection,
    };
    const aliceProvider = await createMlsMessagingProvider(options);
    const bobProvider = await createMlsMessagingProvider(options);
    const alice = await aliceProvider.createDeviceCredential({
      deviceId: "alice-browser",
      identityId: "alice",
    });
    const bob = await bobProvider.createDeviceCredential({
      deviceId: "bob-browser",
      identityId: "bob",
    });
    const bobKeyPackage = await bobProvider.createKeyPackage({
      credential: bob,
      expiresAt: now + 30_000,
    });
    const aliceSession = await aliceProvider.createConversation({
      conversationId: "browser-conversation",
      creatorCredential: alice,
      securityMode: "strict-e2ee",
    });
    const membership = await aliceSession.addMembers([bobKeyPackage]);
    const welcome = membership.welcomes[0];
    if (welcome === undefined) throw new Error("Browser MLS Welcome missing.");
    const bobSession = await bobProvider.joinConversation({
      credential: bob,
      expectedSecurityMode: "strict-e2ee",
      welcome: welcome.bytes,
    });
    const message = await aliceSession.protect(
      new TextEncoder().encode("browser MLS"),
      {
        conversationId: "browser-conversation",
        purpose: "chat.message",
        securityEpoch: 1,
        senderId: "alice-browser",
      },
    );
    await bobSession
      .process({
        ...message,
        authenticatedContext: {
          ...message.authenticatedContext,
          senderId: "mallory-browser",
        },
      })
      .then(
        () => {
          throw new Error("Browser MLS accepted substituted context.");
        },
        () => undefined,
      );
    const opened = await bobSession.process(message);
    if (
      opened?.kind !== "application" ||
      new TextDecoder().decode(opened.message.plaintext) !== "browser MLS"
    ) {
      throw new Error("Browser MLS plaintext did not round-trip.");
    }
    return { ok: true };
  } catch (error) {
    return {
      error: error instanceof Error ? error.stack : String(error),
      ok: false,
    };
  }
};

Object.assign(globalThis, { __absoluteCertification: run() });
