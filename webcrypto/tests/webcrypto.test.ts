import { describe, expect, test } from "bun:test";
import {
  createWebCryptoEnvelopeProvider,
  generateWebCryptoRecipientKeyPair,
  type WebCryptoRecipientKeyMaterial,
} from "../src";
import type { AuthenticatedContext } from "@absolutejs/e2ee";

const context = (): AuthenticatedContext => ({
  conversationId: "conversation-1",
  expiresAt: Date.now() + 60_000,
  purpose: "verification.submit",
  securityEpoch: 1,
  senderId: "user-1",
});

const fixture = async () => {
  const pair = await generateWebCryptoRecipientKeyPair();
  const keys = new Map<string, WebCryptoRecipientKeyMaterial>([
    ["recipient-1", pair.keyMaterial],
  ]);
  const provider = createWebCryptoEnvelopeProvider({
    resolveRecipientPrivateKey: async (handle) => keys.get(handle),
  });
  return { pair, provider };
};

describe("WebCrypto HPKE envelope provider", () => {
  test("seals and opens a purpose-bound envelope", async () => {
    const { pair, provider } = await fixture();
    const authenticatedContext = context();
    const plaintext = new TextEncoder().encode("482193");

    const envelope = await provider.seal({
      authenticatedContext,
      plaintext,
      recipientPublicKey: pair.publicKey,
    });
    const opened = await provider.open({
      envelope,
      expectedContext: authenticatedContext,
      recipientKeyHandle: "recipient-1",
    });

    expect(new TextDecoder().decode(opened)).toBe("482193");
    expect(new TextDecoder().decode(envelope.slice(0, 8))).toBe("ABSHPKE1");
  });

  test("rejects context substitution", async () => {
    const { pair, provider } = await fixture();
    const authenticatedContext = context();
    const envelope = await provider.seal({
      authenticatedContext,
      plaintext: new TextEncoder().encode("482193"),
      recipientPublicKey: pair.publicKey,
    });

    await expect(
      provider.open({
        envelope,
        expectedContext: {
          ...authenticatedContext,
          purpose: "account.recovery",
        },
        recipientKeyHandle: "recipient-1",
      }),
    ).rejects.toThrow();
  });

  test("rejects tampering and malformed envelopes", async () => {
    const { pair, provider } = await fixture();
    const authenticatedContext = context();
    const envelope = await provider.seal({
      authenticatedContext,
      plaintext: new TextEncoder().encode("protected"),
      recipientPublicKey: pair.publicKey,
    });
    const tampered = envelope.slice();
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;

    await expect(
      provider.open({
        envelope: tampered,
        expectedContext: authenticatedContext,
        recipientKeyHandle: "recipient-1",
      }),
    ).rejects.toThrow();
    await expect(
      provider.open({
        envelope: new Uint8Array([1, 2, 3]),
        expectedContext: authenticatedContext,
        recipientKeyHandle: "recipient-1",
      }),
    ).rejects.toThrow("Invalid HPKE envelope");
  });

  test("rejects expired contexts before key resolution", async () => {
    let resolutions = 0;
    const provider = createWebCryptoEnvelopeProvider({
      resolveRecipientPrivateKey: async () => {
        resolutions += 1;
        return undefined;
      },
    });

    await expect(
      provider.open({
        envelope: new Uint8Array(64),
        expectedContext: { ...context(), expiresAt: Date.now() - 1 },
        recipientKeyHandle: "recipient-1",
      }),
    ).rejects.toThrow("expired");
    expect(resolutions).toBe(0);
  });

  test("enforces plaintext limits before sealing", async () => {
    const pair = await generateWebCryptoRecipientKeyPair();
    const provider = createWebCryptoEnvelopeProvider({
      maxPlaintextBytes: 3,
      resolveRecipientPrivateKey: async () => pair.keyMaterial,
    });

    await expect(
      provider.seal({
        authenticatedContext: context(),
        plaintext: new Uint8Array(4),
        recipientPublicKey: pair.publicKey,
      }),
    ).rejects.toThrow("exceeds maxPlaintextBytes");
  });

  test("generates non-exportable private keys by default", async () => {
    const pair = await generateWebCryptoRecipientKeyPair();
    expect(pair.keyMaterial.privateKey.extractable).toBe(false);
    expect(pair.keyMaterial.privateKey.type).toBe("private");
  });
});
