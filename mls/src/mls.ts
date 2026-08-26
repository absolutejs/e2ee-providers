import {
  validateAuthenticatedContext,
  validateDeviceCredential,
  validateKeyPackage,
  type AuthenticatedContext,
  type AuthenticationService,
  type ConversationMember,
  type DecryptedMessage,
  type DeviceCredential,
  type E2EEKeyPackage,
  type LocalDeviceCredential,
  type MembershipChange,
  type MessagingProcessResult,
  type MessagingProvider,
  type MessagingSession,
  type ProtectedMessage,
  type SecurityMode,
} from "@absolutejs/e2ee";
import {
  clientStateDecoder,
  clientStateEncoder,
  contentTypes,
  createApplicationMessage,
  createCommit,
  createGroup,
  defaultCredentialTypes,
  defaultCapabilities,
  defaultProposalTypes,
  encode,
  generateKeyPackageWithKey,
  getCiphersuiteImpl,
  joinGroup,
  mlsMessageDecoder,
  mlsMessageEncoder,
  nodeTypes,
  processMessage,
  protocolVersions,
  wireformats,
  zeroOutUint8Array,
  type ClientState,
  type CiphersuiteImpl,
  type Credential,
  type KeyPackage,
  type MlsContext,
  type PrivateKeyPackage,
  type Proposal,
  type RatchetTree,
} from "ts-mls";
import {
  decodeContext,
  decodeCredential,
  decodeGroupId,
  decodeState,
  decodeWelcome,
  encodeContext,
  encodeCredential,
  encodeGroupId,
  encodeState,
  encodeWelcome,
  sameContext,
} from "./encoding";
import { mlsProviderManifest } from "./provider-manifest";

const CIPHERSUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" as const;
const DEFAULT_KEY_PACKAGE_TTL_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_MAX_PLAINTEXT_BYTES = 1024 * 1024;
const PROTOCOL = "MLS-1.0";
const SESSION = Symbol("absolutejs.e2ee.mls.session");

type SignatureKeyPair = {
  readonly publicKey: Uint8Array;
  readonly signKey: Uint8Array;
};

type KeyPackageMaterial = {
  readonly privatePackage: PrivateKeyPackage;
  readonly publicPackage: KeyPackage;
};

type InternalSession = {
  closed: boolean;
  readonly credential: LocalDeviceCredential;
  readonly mode: SecurityMode;
  state: ClientState;
};

type MlsSession = MessagingSession & {
  readonly [SESSION]: InternalSession;
};

export type MlsMessagingProviderOptions = {
  readonly authenticationService: AuthenticationService;
  readonly authorizeMembershipChange?: (
    input: MlsMembershipAuthorization,
  ) => boolean;
  readonly maxPlaintextBytes?: number;
  readonly now?: () => number;
  readonly randomId?: () => string;
  readonly stateProtection: MlsStateProtection;
};

export type MlsMembershipAuthorization = {
  readonly conversationId: string;
  readonly proposalTypes: readonly (number | string)[];
  readonly sender: DeviceCredential;
};

export type MlsStateProtection = {
  open(input: { readonly sealedState: Uint8Array }): Promise<Uint8Array>;
  seal(input: { readonly state: Uint8Array }): Promise<Uint8Array>;
};

const decodeExact = <Value>(
  decode: (bytes: Uint8Array, offset: number) => [Value, number] | undefined,
  bytes: Uint8Array,
  name: string,
): Value => {
  const result = decode(bytes, 0);
  if (result === undefined || result[1] !== bytes.length) {
    throw new Error(`Invalid ${name} encoding.`);
  }
  return result[0];
};

const cloneCredential = (credential: DeviceCredential): DeviceCredential =>
  Object.freeze({
    ...credential,
    bytes: credential.bytes.slice(),
  });

const credentialsEqual = (
  left: DeviceCredential,
  right: DeviceCredential,
): boolean =>
  left.deviceId === right.deviceId &&
  left.expiresAt === right.expiresAt &&
  left.identityId === right.identityId &&
  left.issuedAt === right.issuedAt &&
  left.bytes.length === right.bytes.length &&
  left.bytes.every((value, index) => value === right.bytes[index]);

const credentialFromMls = (credential: Credential): DeviceCredential => {
  if (
    credential.credentialType !== defaultCredentialTypes.basic ||
    !("identity" in credential)
  ) {
    throw new Error("Only MLS BasicCredential is supported.");
  }
  return decodeCredential(credential.identity);
};

const credentialAt = (
  tree: RatchetTree,
  leafIndex: number,
): DeviceCredential => {
  const node = tree[leafIndex * 2];
  if (node?.nodeType !== nodeTypes.leaf) {
    throw new Error("MLS sender credential is unavailable.");
  }
  return credentialFromMls(node.leaf.credential);
};

const membersOf = (tree: RatchetTree): readonly ConversationMember[] =>
  Object.freeze(
    tree.flatMap((node, nodeIndex) =>
      node?.nodeType === nodeTypes.leaf
        ? [
            Object.freeze({
              credential: cloneCredential(
                credentialFromMls(node.leaf.credential),
              ),
              index: nodeIndex / 2,
            }),
          ]
        : [],
    ),
  );

const zeroConsumed = (values: readonly Uint8Array[]): void => {
  for (const value of values) zeroOutUint8Array(value);
};

const zeroGraph = (value: unknown, seen = new Set<object>()): void => {
  if (value instanceof Uint8Array) {
    value.fill(0);
    return;
  }
  if (typeof value !== "object" || value === null || seen.has(value)) return;
  seen.add(value);
  if (value instanceof Map) {
    for (const [key, item] of value) {
      zeroGraph(key, seen);
      zeroGraph(item, seen);
    }
    return;
  }
  for (const item of Object.values(value)) zeroGraph(item, seen);
};

const contextFor = (
  session: InternalSession,
  purpose: string,
): AuthenticatedContext => ({
  conversationId: decodeGroupId(session.state.groupContext.groupId)
    .conversationId,
  purpose,
  securityEpoch: Number(session.state.groupContext.epoch),
  senderId: session.credential.deviceId,
});

const protectedHandshake = (
  bytes: Uint8Array,
  context: AuthenticatedContext,
): ProtectedMessage => ({
  authenticatedContext: context,
  bytes,
  protocol: PROTOCOL,
});

const requireSession = (session: MessagingSession): InternalSession => {
  if (!(SESSION in session))
    throw new Error("Session belongs to another provider.");
  const internal = (session as MlsSession)[SESSION];
  if (internal.closed) throw new Error("MLS session is closed.");
  return internal;
};

export const createMlsMessagingProvider = async (
  options: MlsMessagingProviderOptions,
): Promise<MessagingProvider> => {
  const now = options.now ?? Date.now;
  const randomId = options.randomId ?? (() => crypto.randomUUID());
  const maxPlaintextBytes =
    options.maxPlaintextBytes ?? DEFAULT_MAX_PLAINTEXT_BYTES;
  if (!Number.isSafeInteger(maxPlaintextBytes) || maxPlaintextBytes < 1) {
    throw new Error("maxPlaintextBytes must be a positive safe integer.");
  }

  const ciphersuite: CiphersuiteImpl = await getCiphersuiteImpl(CIPHERSUITE);
  const signingKeys = new Map<string, SignatureKeyPair>();
  const keyPackages = new Map<string, KeyPackageMaterial>();
  const mlsContext: MlsContext = {
    authService: {
      validateCredential: async (
        credential: Credential,
        publicKey: Uint8Array,
      ) => {
        try {
          const decoded = credentialFromMls(credential);
          validateDeviceCredential(decoded, now());
          const result =
            await options.authenticationService.validateDeviceCredential({
              credential: decoded,
              publicKey,
            });
          return (
            result.status === "valid" &&
            result.identityId === decoded.identityId
          );
        } catch {
          return false;
        }
      },
      validateSuccessorCredential: async (oldCredential, newCredential) => {
        try {
          const oldDevice = credentialFromMls(oldCredential);
          const newDevice = credentialFromMls(newCredential);
          validateDeviceCredential(oldDevice, now());
          validateDeviceCredential(newDevice, now());
          return credentialsEqual(oldDevice, newDevice);
        } catch {
          return false;
        }
      },
    },
    cipherSuite: ciphersuite,
  };

  const createMaterial = async (
    credential: LocalDeviceCredential,
    expiresAt: number,
  ): Promise<KeyPackageMaterial> => {
    validateDeviceCredential(credential, now());
    const keys = signingKeys.get(credential.keyHandle);
    if (keys === undefined)
      throw new Error("Device signing key is unavailable.");
    const generated = await generateKeyPackageWithKey({
      capabilities: defaultCapabilities(),
      cipherSuite: ciphersuite,
      credential: {
        credentialType: defaultCredentialTypes.basic,
        identity: encodeCredential(credential),
      },
      lifetime: {
        notAfter: BigInt(Math.floor(expiresAt / 1_000)),
        notBefore: BigInt(Math.floor(now() / 1_000)),
      },
      signatureKeyPair: keys,
    });
    return {
      privatePackage: generated.privatePackage,
      publicPackage: generated.publicPackage,
    };
  };

  const createSession = (internal: InternalSession): MlsSession => {
    const additionsFor = (packages: readonly E2EEKeyPackage[]): Proposal[] => {
      if (packages.length === 0) throw new Error("No members were supplied.");
      const proposals: Proposal[] = [];
      const deviceIds = new Set<string>();
      for (const keyPackage of packages) {
        validateKeyPackage(keyPackage, now());
        if (keyPackage.protocol !== PROTOCOL) {
          throw new Error("Unsupported key package protocol.");
        }
        if (deviceIds.has(keyPackage.credential.deviceId))
          throw new Error("Duplicate member addition.");
        deviceIds.add(keyPackage.credential.deviceId);
        const decoded = decodeExact(
          mlsMessageDecoder,
          keyPackage.bytes,
          "MLS KeyPackage",
        );
        if (decoded.wireformat !== wireformats.mls_key_package) {
          throw new Error("Expected an MLS KeyPackage.");
        }
        const embedded = credentialFromMls(
          decoded.keyPackage.leafNode.credential,
        );
        if (!credentialsEqual(embedded, keyPackage.credential)) {
          throw new Error("Key package credential metadata does not match.");
        }
        proposals.push({
          add: { keyPackage: decoded.keyPackage },
          proposalType: defaultProposalTypes.add,
        });
      }
      return proposals;
    };

    const removalsFor = (deviceIds: readonly string[]): Proposal[] => {
      if (deviceIds.length === 0) throw new Error("No members were supplied.");
      const members = membersOf(internal.state.ratchetTree);
      const unique = new Set(deviceIds);
      if (unique.size !== deviceIds.length) {
        throw new Error("Duplicate member removal.");
      }
      return deviceIds.map((deviceId): Proposal => {
        const member = members.find(
          ({ credential }) => credential.deviceId === deviceId,
        );
        if (member === undefined) throw new Error("Member was not found.");
        return {
          proposalType: defaultProposalTypes.remove,
          remove: { removed: member.index },
        };
      });
    };

    const commit = async (
      proposals: readonly Proposal[],
      purpose: string,
      welcomeTargets: readonly E2EEKeyPackage[] = [],
    ): Promise<MembershipChange> => {
      if (internal.closed) throw new Error("MLS session is closed.");
      const authenticatedContext = contextFor(internal, purpose);
      const result = await createCommit({
        authenticatedData: encodeContext(authenticatedContext),
        context: mlsContext,
        extraProposals: [...proposals],
        ratchetTreeExtension: true,
        state: internal.state,
      });
      internal.state = result.newState;
      zeroConsumed(result.consumed);
      const encodedCommit = encode(mlsMessageEncoder, result.commit);
      const welcome = result.welcome;
      const welcomes =
        welcome === undefined
          ? []
          : welcomeTargets.map((target) => ({
              bytes: encodeWelcome({
                keyPackageId: target.id,
                ratchetTree: new Uint8Array(),
                welcome: encode(mlsMessageEncoder, welcome),
              }),
              deviceId: target.credential.deviceId,
            }));
      return Object.freeze({
        epoch: Number(internal.state.groupContext.epoch),
        handshake: Object.freeze([
          protectedHandshake(encodedCommit, authenticatedContext),
        ]),
        welcomes: Object.freeze(welcomes),
      });
    };

    const session: MlsSession = Object.freeze({
      [SESSION]: internal,
      addMembers: async (packages) => {
        return commit(additionsFor(packages), "membership.add", packages);
      },
      close: async () => {
        if (internal.closed) return;
        internal.closed = true;
        zeroGraph(internal.state);
      },
      get conversationId() {
        return decodeGroupId(internal.state.groupContext.groupId)
          .conversationId;
      },
      get epoch() {
        return Number(internal.state.groupContext.epoch);
      },
      get securityMode() {
        return decodeGroupId(internal.state.groupContext.groupId).mode;
      },
      members: async () => membersOf(internal.state.ratchetTree),
      process: async (message) => {
        if (internal.closed) throw new Error("MLS session is closed.");
        if (message.protocol !== PROTOCOL) {
          throw new Error("Unsupported protected-message protocol.");
        }
        const decoded = decodeExact(
          mlsMessageDecoder,
          message.bytes,
          "MLS message",
        );
        if (
          decoded.wireformat !== wireformats.mls_private_message &&
          decoded.wireformat !== wireformats.mls_public_message
        ) {
          throw new Error("Expected an MLS protected message.");
        }
        const wireContext = decodeContext(
          decoded.wireformat === wireformats.mls_private_message
            ? decoded.privateMessage.authenticatedData
            : decoded.publicMessage.content.authenticatedData,
        );
        validateAuthenticatedContext(wireContext, now());
        if (!sameContext(wireContext, message.authenticatedContext)) {
          throw new Error("Authenticated context does not match MLS AAD.");
        }
        if (wireContext.conversationId !== session.conversationId) {
          throw new Error("Authenticated context has the wrong conversation.");
        }
        const messageEpoch =
          decoded.wireformat === wireformats.mls_private_message
            ? decoded.privateMessage.epoch
            : decoded.publicMessage.content.epoch;
        if (wireContext.securityEpoch !== Number(messageEpoch)) {
          throw new Error("Authenticated context has the wrong MLS epoch.");
        }

        if (
          decoded.wireformat === wireformats.mls_private_message &&
          decoded.privateMessage.contentType === contentTypes.application
        ) {
          if (
            decoded.privateMessage.epoch !== internal.state.groupContext.epoch
          ) {
            throw new Error("Application message epoch is not current.");
          }
          const result = await processMessage({
            context: mlsContext,
            message: decoded,
            state: internal.state,
          });
          if (result.kind !== "applicationMessage") {
            zeroConsumed(result.consumed);
            throw new Error("Expected an MLS member application message.");
          }
          const sender = credentialAt(
            internal.state.ratchetTree,
            result.senderLeafIndex,
          );
          if (wireContext.senderId !== sender.deviceId) {
            zeroConsumed(result.consumed);
            throw new Error(
              "Authenticated sender does not match MLS membership.",
            );
          }
          internal.state = result.newState;
          zeroConsumed(result.consumed);
          const decrypted: DecryptedMessage = Object.freeze({
            authenticatedContext: wireContext,
            plaintext: result.message,
            senderCredential: sender.bytes,
          });
          return Object.freeze({
            kind: "application",
            message: decrypted,
          });
        }

        let membershipRejected = false;
        let senderLeafIndex: number | undefined;
        const result = await processMessage({
          callback: (incoming) => {
            senderLeafIndex =
              incoming.kind === "commit"
                ? incoming.senderLeafIndex
                : incoming.proposal.senderLeafIndex;
            const proposalTypes =
              incoming.kind === "commit"
                ? incoming.proposals.map(
                    ({ proposal }) => proposal.proposalType,
                  )
                : [incoming.proposal.proposal.proposalType];
            const sensitive = proposalTypes.filter(
              (type) => type !== defaultProposalTypes.update,
            );
            if (sensitive.length === 0) return "accept";
            if (senderLeafIndex === undefined) return "reject";
            const sender = credentialAt(
              internal.state.ratchetTree,
              senderLeafIndex,
            );
            const allowed = options.authorizeMembershipChange?.({
              conversationId: session.conversationId,
              proposalTypes: Object.freeze(sensitive),
              sender,
            });
            membershipRejected = allowed !== true;
            return membershipRejected ? "reject" : "accept";
          },
          context: mlsContext,
          message: decoded,
          state: internal.state,
        });
        if (membershipRejected) {
          zeroConsumed(result.consumed);
          throw new Error("MLS membership change was not authorized.");
        }
        if (senderLeafIndex === undefined) {
          zeroConsumed(result.consumed);
          throw new Error("External MLS state changes are disabled.");
        }
        const sender = credentialAt(
          internal.state.ratchetTree,
          senderLeafIndex,
        );
        if (wireContext.senderId !== sender.deviceId) {
          zeroConsumed(result.consumed);
          throw new Error(
            "Authenticated sender does not match MLS membership.",
          );
        }
        if (result.kind !== "newState") {
          zeroConsumed(result.consumed);
          throw new Error("Expected an MLS state change.");
        }
        internal.state = result.newState;
        zeroConsumed(result.consumed);
        const processed: MessagingProcessResult = Object.freeze({
          epoch: Number(internal.state.groupContext.epoch),
          kind:
            decoded.wireformat === wireformats.mls_public_message ||
            decoded.privateMessage.contentType === contentTypes.commit
              ? "membership-change"
              : "state-change",
        });
        return processed;
      },
      protect: async (plaintext, authenticatedContext) => {
        if (internal.closed) throw new Error("MLS session is closed.");
        if (plaintext.length > maxPlaintextBytes) {
          throw new Error("Plaintext exceeds maxPlaintextBytes.");
        }
        validateAuthenticatedContext(authenticatedContext, now());
        if (
          authenticatedContext.conversationId !== session.conversationId ||
          authenticatedContext.securityEpoch !== session.epoch ||
          authenticatedContext.senderId !== internal.credential.deviceId
        ) {
          throw new Error(
            "Authenticated context is not bound to this session.",
          );
        }
        const result = await createApplicationMessage({
          authenticatedData: encodeContext(authenticatedContext),
          context: mlsContext,
          message: plaintext,
          state: internal.state,
        });
        internal.state = result.newState;
        zeroConsumed(result.consumed);
        return Object.freeze({
          authenticatedContext,
          bytes: encode(mlsMessageEncoder, result.message),
          protocol: PROTOCOL,
        });
      },
      removeMembers: async (deviceIds) => {
        return commit(removalsFor(deviceIds), "membership.remove");
      },
      replaceMembers: async ({ add, removeDeviceIds }) => {
        const added = new Set(add.map(({ credential }) => credential.deviceId));
        if (added.size !== add.length)
          throw new Error("Duplicate member addition.");
        const current = membersOf(internal.state.ratchetTree);
        for (const deviceId of added)
          if (
            current.some(
              ({ credential }) => credential.deviceId === deviceId,
            ) &&
            !removeDeviceIds.includes(deviceId)
          )
            throw new Error("Replacement device is already a member.");
        return commit(
          [...additionsFor(add), ...removalsFor(removeDeviceIds)],
          "membership.replace",
          add,
        );
      },
      selfUpdate: () => commit([], "membership.self-update"),
    });
    return session;
  };

  const provider: MessagingProvider = Object.freeze({
    createConversation: async ({
      conversationId,
      creatorCredential,
      securityMode,
    }) => {
      if (conversationId.trim().length === 0) {
        throw new Error("conversationId must not be empty.");
      }
      const material = await createMaterial(
        creatorCredential,
        now() + DEFAULT_KEY_PACKAGE_TTL_MS,
      );
      const state = await createGroup({
        context: mlsContext,
        extensions: [],
        groupId: encodeGroupId(conversationId, securityMode),
        keyPackage: material.publicPackage,
        privateKeyPackage: material.privatePackage,
      });
      return createSession({
        closed: false,
        credential: creatorCredential,
        mode: securityMode,
        state,
      });
    },
    createDeviceCredential: async ({ deviceId, identityId }) => {
      if (deviceId.trim().length === 0 || identityId.trim().length === 0) {
        throw new Error("Device and identity IDs must not be empty.");
      }
      const keys = await ciphersuite.signature.keygen();
      const issued = await options.authenticationService.issueDeviceCredential({
        deviceId,
        identityId,
        publicKey: keys.publicKey,
      });
      validateDeviceCredential(issued, now());
      if (issued.deviceId !== deviceId || issued.identityId !== identityId) {
        zeroOutUint8Array(keys.signKey);
        throw new Error(
          "Authentication Service changed the requested identity.",
        );
      }
      const keyHandle = randomId();
      signingKeys.set(keyHandle, keys);
      return Object.freeze({
        ...cloneCredential(issued),
        keyHandle,
      });
    },
    createKeyPackage: async ({ credential, expiresAt }) => {
      const material = await createMaterial(credential, expiresAt);
      const id = randomId();
      keyPackages.set(id, material);
      return Object.freeze({
        bytes: encode(mlsMessageEncoder, {
          keyPackage: material.publicPackage,
          version: protocolVersions.mls10,
          wireformat: wireformats.mls_key_package,
        }),
        credential: cloneCredential(credential),
        expiresAt,
        id,
        protocol: PROTOCOL,
      });
    },
    joinConversation: async ({ credential, expectedSecurityMode, welcome }) => {
      const decodedEnvelope = decodeWelcome(welcome);
      const material = keyPackages.get(decodedEnvelope.keyPackageId);
      if (material === undefined) {
        throw new Error("Welcome does not reference an available KeyPackage.");
      }
      const embedded = credentialFromMls(
        material.publicPackage.leafNode.credential,
      );
      if (!credentialsEqual(embedded, credential)) {
        throw new Error("Welcome KeyPackage belongs to another device.");
      }
      const decodedWelcome = decodeExact(
        mlsMessageDecoder,
        decodedEnvelope.welcome,
        "MLS Welcome",
      );
      if (decodedWelcome.wireformat !== wireformats.mls_welcome) {
        throw new Error("Expected an MLS Welcome.");
      }
      const state = await joinGroup({
        context: mlsContext,
        keyPackage: material.publicPackage,
        privateKeys: material.privatePackage,
        welcome: decodedWelcome.welcome,
      });
      const boundGroup = decodeGroupId(state.groupContext.groupId);
      if (boundGroup.mode !== expectedSecurityMode) {
        zeroGraph(state);
        throw new Error(
          `Welcome security mode ${boundGroup.mode} does not match expected mode ${expectedSecurityMode}.`,
        );
      }
      keyPackages.delete(decodedEnvelope.keyPackageId);
      return createSession({
        closed: false,
        credential,
        mode: boundGroup.mode,
        state,
      });
    },
    manifest: mlsProviderManifest,
    restoreConversation: async ({ sealedState }) => {
      const envelope = decodeState(
        await options.stateProtection.open({ sealedState }),
      );
      const state = decodeExact(
        clientStateDecoder,
        envelope.state,
        "MLS group state",
      );
      const boundGroup = decodeGroupId(state.groupContext.groupId);
      if (boundGroup.mode !== envelope.mode) {
        throw new Error(
          "Persisted security mode does not match the MLS group.",
        );
      }
      return createSession({
        closed: false,
        credential: envelope.credential,
        mode: envelope.mode,
        state,
      });
    },
    sealConversationState: async (session) => {
      const internal = requireSession(session);
      return options.stateProtection.seal({
        state: encodeState({
          credential: internal.credential,
          mode: internal.mode,
          state: encode(clientStateEncoder, internal.state),
        }),
      });
    },
  });

  return provider;
};
