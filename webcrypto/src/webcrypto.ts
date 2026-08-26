import {
  validateAuthenticatedContext,
  type AuthenticatedContext,
  type EnvelopeProvider,
  type E2EEProviderManifest,
} from "@absolutejs/e2ee";
import {
  AEAD_AES_128_GCM,
  CipherSuite,
  KDF_HKDF_SHA256,
  KEM_DHKEM_P256_HKDF_SHA256,
  type CryptoKey,
} from "hpke";
import { webcryptoProviderManifest } from "./provider-manifest";

const MAGIC = new TextEncoder().encode("ABSHPKE1");
const DOMAIN = new TextEncoder().encode(
  "@absolutejs/e2ee-webcrypto:envelope:v1",
);
const HEADER_LENGTH = MAGIC.length + 2;
const MINIMUM_CIPHERTEXT_LENGTH = 16;
const DEFAULT_MAX_PLAINTEXT_BYTES = 1024 * 1024;

const suite = new CipherSuite(
  KEM_DHKEM_P256_HKDF_SHA256,
  KDF_HKDF_SHA256,
  AEAD_AES_128_GCM,
);

export type WebCryptoRecipientKeyMaterial = {
  readonly privateKey: Readonly<CryptoKey>;
  readonly publicKey: Readonly<CryptoKey>;
};

export type WebCryptoRecipientKeyPair = {
  readonly keyMaterial: WebCryptoRecipientKeyMaterial;
  readonly publicKey: Uint8Array;
};

export type WebCryptoEnvelopeProviderOptions = {
  readonly allowExtractablePrivateKeys?: boolean;
  readonly maxPlaintextBytes?: number;
  readonly resolveRecipientPrivateKey: (
    keyHandle: string,
  ) => Promise<WebCryptoRecipientKeyMaterial | undefined>;
};

const concatenate = (...parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const encodeContext = (context: AuthenticatedContext): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify([
      context.conversationId,
      context.expiresAt ?? null,
      context.purpose,
      context.securityEpoch,
      context.senderId,
    ]),
  );

const contextParameters = (
  context: AuthenticatedContext,
): { readonly aad: Uint8Array; readonly info: Uint8Array } => {
  const aad = encodeContext(context);
  return { aad, info: concatenate(DOMAIN, new Uint8Array([0]), aad) };
};

const encodeEnvelope = (
  encapsulatedSecret: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array => {
  if (encapsulatedSecret.length > 0xffff) {
    throw new Error("HPKE encapsulated secret exceeds the envelope limit.");
  }
  const header = new Uint8Array(HEADER_LENGTH);
  header.set(MAGIC, 0);
  new DataView(header.buffer).setUint16(
    MAGIC.length,
    encapsulatedSecret.length,
  );
  return concatenate(header, encapsulatedSecret, ciphertext);
};

const decodeEnvelope = (
  envelope: Uint8Array,
): {
  readonly ciphertext: Uint8Array;
  readonly encapsulatedSecret: Uint8Array;
} => {
  if (envelope.length < HEADER_LENGTH + MINIMUM_CIPHERTEXT_LENGTH) {
    throw new Error("Invalid HPKE envelope.");
  }
  for (let index = 0; index < MAGIC.length; index += 1) {
    if (envelope[index] !== MAGIC[index]) {
      throw new Error("Invalid HPKE envelope.");
    }
  }

  const encapsulatedLength = new DataView(
    envelope.buffer,
    envelope.byteOffset,
    HEADER_LENGTH,
  ).getUint16(MAGIC.length);
  const ciphertextOffset = HEADER_LENGTH + encapsulatedLength;
  if (
    encapsulatedLength === 0 ||
    envelope.length < ciphertextOffset + MINIMUM_CIPHERTEXT_LENGTH
  ) {
    throw new Error("Invalid HPKE envelope.");
  }

  return {
    ciphertext: envelope.slice(ciphertextOffset),
    encapsulatedSecret: envelope.slice(HEADER_LENGTH, ciphertextOffset),
  };
};

const providerManifestFor = (
  allowExtractablePrivateKeys: boolean,
): E2EEProviderManifest =>
  allowExtractablePrivateKeys
    ? Object.freeze({
        ...webcryptoProviderManifest,
        security: Object.freeze({
          ...webcryptoProviderManifest.security,
          privateKeyProtection: "exportable" as const,
        }),
      })
    : webcryptoProviderManifest;

export const generateWebCryptoRecipientKeyPair = async (
  extractable = false,
): Promise<WebCryptoRecipientKeyPair> => {
  const keyPair = await suite.GenerateKeyPair(extractable);
  return Object.freeze({
    keyMaterial: Object.freeze({
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    }),
    publicKey: await suite.SerializePublicKey(keyPair.publicKey),
  });
};

export const createWebCryptoEnvelopeProvider = (
  options: WebCryptoEnvelopeProviderOptions,
): EnvelopeProvider => {
  const allowExtractablePrivateKeys =
    options.allowExtractablePrivateKeys ?? false;
  const maxPlaintextBytes =
    options.maxPlaintextBytes ?? DEFAULT_MAX_PLAINTEXT_BYTES;

  if (!Number.isSafeInteger(maxPlaintextBytes) || maxPlaintextBytes < 1) {
    throw new Error("maxPlaintextBytes must be a positive safe integer.");
  }

  return Object.freeze({
    manifest: providerManifestFor(allowExtractablePrivateKeys),
    open: async ({ envelope, expectedContext, recipientKeyHandle }) => {
      validateAuthenticatedContext(expectedContext);
      const keyMaterial =
        await options.resolveRecipientPrivateKey(recipientKeyHandle);
      if (keyMaterial === undefined) {
        throw new Error("Recipient key is unavailable.");
      }
      if (
        keyMaterial.privateKey.type !== "private" ||
        keyMaterial.publicKey.type !== "public"
      ) {
        throw new Error(
          "Recipient key handle did not resolve to a private key.",
        );
      }
      if (keyMaterial.privateKey.extractable && !allowExtractablePrivateKeys) {
        throw new Error("Extractable recipient private keys are disabled.");
      }

      const { ciphertext, encapsulatedSecret } = decodeEnvelope(envelope);
      const context = contextParameters(expectedContext);
      const plaintext = await suite.Open(
        keyMaterial,
        encapsulatedSecret,
        ciphertext,
        context,
      );
      if (plaintext.length > maxPlaintextBytes) {
        throw new Error("Decrypted plaintext exceeds maxPlaintextBytes.");
      }
      return plaintext;
    },
    seal: async ({ authenticatedContext, plaintext, recipientPublicKey }) => {
      validateAuthenticatedContext(authenticatedContext);
      if (plaintext.length > maxPlaintextBytes) {
        throw new Error("Plaintext exceeds maxPlaintextBytes.");
      }
      const publicKey = await suite.DeserializePublicKey(recipientPublicKey);
      const sealed = await suite.Seal(
        publicKey,
        plaintext,
        contextParameters(authenticatedContext),
      );
      return encodeEnvelope(sealed.encapsulatedSecret, sealed.ciphertext);
    },
  });
};
