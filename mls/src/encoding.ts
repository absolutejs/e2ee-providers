import type {
  AuthenticatedContext,
  DeviceCredential,
  LocalDeviceCredential,
  SecurityMode,
} from "@absolutejs/e2ee";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const encodeText = (value: string): Uint8Array => encoder.encode(value);
export const decodeText = (value: Uint8Array): string => decoder.decode(value);

export const encodeGroupId = (
  conversationId: string,
  mode: SecurityMode,
): Uint8Array =>
  encodeText(JSON.stringify({ conversationId, format: 1, mode }));

export const decodeGroupId = (
  bytes: Uint8Array,
): { conversationId: string; mode: SecurityMode } => {
  const value = parseRecord(bytes);
  if (
    value.format !== 1 ||
    typeof value.conversationId !== "string" ||
    (value.mode !== "strict-e2ee" && value.mode !== "managed-recovery")
  ) {
    throw new Error("Invalid MLS group identifier.");
  }
  return { conversationId: value.conversationId, mode: value.mode };
};

const toHex = (bytes: Uint8Array): string =>
  [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");

const fromHex = (value: string): Uint8Array => {
  if (!/^(?:[0-9a-f]{2})*$/u.test(value)) throw new Error("Invalid hex data.");
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
};

const parseRecord = (bytes: Uint8Array): Record<string, unknown> => {
  const value = JSON.parse(decodeText(bytes)) as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Invalid encoded record.");
  }
  return value as Record<string, unknown>;
};

export const encodeCredential = (credential: DeviceCredential): Uint8Array =>
  encodeText(
    JSON.stringify({
      bytes: toHex(credential.bytes),
      deviceId: credential.deviceId,
      expiresAt: credential.expiresAt ?? null,
      format: 1,
      identityId: credential.identityId,
      issuedAt: credential.issuedAt,
    }),
  );

export const decodeCredential = (bytes: Uint8Array): DeviceCredential => {
  const value = parseRecord(bytes);
  if (
    value.format !== 1 ||
    typeof value.bytes !== "string" ||
    typeof value.deviceId !== "string" ||
    (value.expiresAt !== null && typeof value.expiresAt !== "number") ||
    typeof value.identityId !== "string" ||
    typeof value.issuedAt !== "number"
  ) {
    throw new Error("Invalid device credential encoding.");
  }
  return {
    bytes: fromHex(value.bytes),
    deviceId: value.deviceId,
    ...(value.expiresAt === null ? {} : { expiresAt: value.expiresAt }),
    identityId: value.identityId,
    issuedAt: value.issuedAt,
  };
};

export const encodeContext = (context: AuthenticatedContext): Uint8Array =>
  encodeText(
    JSON.stringify({
      conversationId: context.conversationId,
      expiresAt: context.expiresAt ?? null,
      format: 1,
      purpose: context.purpose,
      securityEpoch: context.securityEpoch,
      senderId: context.senderId,
    }),
  );

export const decodeContext = (bytes: Uint8Array): AuthenticatedContext => {
  const value = parseRecord(bytes);
  if (
    value.format !== 1 ||
    typeof value.conversationId !== "string" ||
    (value.expiresAt !== null && typeof value.expiresAt !== "number") ||
    typeof value.purpose !== "string" ||
    typeof value.securityEpoch !== "number" ||
    typeof value.senderId !== "string"
  ) {
    throw new Error("Invalid authenticated context encoding.");
  }
  return {
    conversationId: value.conversationId,
    ...(value.expiresAt === null ? {} : { expiresAt: value.expiresAt }),
    purpose: value.purpose,
    securityEpoch: value.securityEpoch,
    senderId: value.senderId,
  };
};

export const sameContext = (
  left: AuthenticatedContext,
  right: AuthenticatedContext,
): boolean =>
  left.conversationId === right.conversationId &&
  left.expiresAt === right.expiresAt &&
  left.purpose === right.purpose &&
  left.securityEpoch === right.securityEpoch &&
  left.senderId === right.senderId;

export const encodeWelcome = (input: {
  keyPackageId: string;
  ratchetTree: Uint8Array;
  welcome: Uint8Array;
}): Uint8Array =>
  encodeText(
    JSON.stringify({
      format: 1,
      keyPackageId: input.keyPackageId,
      ratchetTree: toHex(input.ratchetTree),
      welcome: toHex(input.welcome),
    }),
  );

export const decodeWelcome = (
  bytes: Uint8Array,
): {
  keyPackageId: string;
  ratchetTree: Uint8Array;
  welcome: Uint8Array;
} => {
  const value = parseRecord(bytes);
  if (
    value.format !== 1 ||
    typeof value.keyPackageId !== "string" ||
    typeof value.ratchetTree !== "string" ||
    typeof value.welcome !== "string"
  ) {
    throw new Error("Invalid MLS Welcome envelope.");
  }
  return {
    keyPackageId: value.keyPackageId,
    ratchetTree: fromHex(value.ratchetTree),
    welcome: fromHex(value.welcome),
  };
};

export const encodeState = (input: {
  credential: LocalDeviceCredential;
  mode: SecurityMode;
  state: Uint8Array;
}): Uint8Array =>
  encodeText(
    JSON.stringify({
      credential: {
        bytes: toHex(input.credential.bytes),
        deviceId: input.credential.deviceId,
        expiresAt: input.credential.expiresAt ?? null,
        identityId: input.credential.identityId,
        issuedAt: input.credential.issuedAt,
        keyHandle: input.credential.keyHandle,
      },
      format: 1,
      mode: input.mode,
      state: toHex(input.state),
    }),
  );

export const decodeState = (
  bytes: Uint8Array,
): {
  credential: LocalDeviceCredential;
  mode: SecurityMode;
  state: Uint8Array;
} => {
  const value = parseRecord(bytes);
  const credential = value.credential;
  if (
    value.format !== 1 ||
    (value.mode !== "strict-e2ee" && value.mode !== "managed-recovery") ||
    typeof value.state !== "string" ||
    typeof credential !== "object" ||
    credential === null ||
    Array.isArray(credential)
  ) {
    throw new Error("Invalid MLS state envelope.");
  }
  const item = credential as Record<string, unknown>;
  if (
    typeof item.bytes !== "string" ||
    typeof item.deviceId !== "string" ||
    (item.expiresAt !== null && typeof item.expiresAt !== "number") ||
    typeof item.identityId !== "string" ||
    typeof item.issuedAt !== "number" ||
    typeof item.keyHandle !== "string"
  ) {
    throw new Error("Invalid MLS state credential.");
  }
  return {
    credential: {
      bytes: fromHex(item.bytes),
      deviceId: item.deviceId,
      ...(item.expiresAt === null ? {} : { expiresAt: item.expiresAt }),
      identityId: item.identityId,
      issuedAt: item.issuedAt,
      keyHandle: item.keyHandle,
    },
    mode: value.mode,
    state: fromHex(value.state),
  };
};
