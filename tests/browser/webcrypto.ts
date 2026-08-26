import {
  createWebCryptoEnvelopeProvider,
  generateWebCryptoRecipientKeyPair,
} from "../../webcrypto/src";

type BrowserCertificationResult = {
  readonly error?: string;
  readonly ok: boolean;
};

const run = async (): Promise<BrowserCertificationResult> => {
  try {
    const pair = await generateWebCryptoRecipientKeyPair();
    const provider = createWebCryptoEnvelopeProvider({
      resolveRecipientPrivateKey: async () => pair.keyMaterial,
    });
    const authenticatedContext = {
      conversationId: "browser-conversation",
      expiresAt: Date.now() + 60_000,
      purpose: "verification.submit",
      securityEpoch: 1,
      senderId: "browser-sender",
    };
    const envelope = await provider.seal({
      authenticatedContext,
      plaintext: new TextEncoder().encode("482193"),
      recipientPublicKey: pair.publicKey,
    });
    const plaintext = await provider.open({
      envelope,
      expectedContext: authenticatedContext,
      recipientKeyHandle: "browser-recipient",
    });
    if (new TextDecoder().decode(plaintext) !== "482193") {
      throw new Error("Browser HPKE plaintext did not round-trip.");
    }
    if (pair.keyMaterial.privateKey.extractable) {
      throw new Error("Browser private key was unexpectedly exportable.");
    }
    await provider
      .open({
        envelope,
        expectedContext: {
          ...authenticatedContext,
          purpose: "account.recovery",
        },
        recipientKeyHandle: "browser-recipient",
      })
      .then(
        () => {
          throw new Error("Browser accepted substituted context.");
        },
        () => undefined,
      );
    const tampered = envelope.slice();
    tampered[tampered.length - 1] = (tampered.at(-1) ?? 0) ^ 1;
    await provider
      .open({
        envelope: tampered,
        expectedContext: authenticatedContext,
        recipientKeyHandle: "browser-recipient",
      })
      .then(
        () => {
          throw new Error("Browser accepted tampered ciphertext.");
        },
        () => undefined,
      );
    return { ok: true };
  } catch (error) {
    return {
      error: error instanceof Error ? error.stack : String(error),
      ok: false,
    };
  }
};

Object.assign(globalThis, { __absoluteCertification: run() });
