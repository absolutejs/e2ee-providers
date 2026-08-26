import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  AuthenticatedContext,
  AuthenticationService,
  DeviceCredential,
} from "@absolutejs/e2ee";
import {
  createMlsMessagingProvider,
  mlsProviderManifest,
} from "../mls/src/index";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { format as formatText } from "prettier";
import {
  mlsMessageDecoder,
  wireformats,
  type MlsKeyPackage,
} from "../mls/node_modules/ts-mls";
import {
  decodeWelcome,
  encodeContext,
  encodeCredential,
} from "../mls/src/encoding";
import { parseImplementationIdentity } from "./certify-mls-interop";

const HARNESS_REVISION = "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a";
const HARNESS_REPOSITORY = "https://github.com/mlswg/mls-implementations.git";
const MLS_CIPHERSUITE = 1;
const usage =
  "Usage: bun run certify:adapter-interop -- --client localhost:PORT --implementation NAME@VERSION#REVISION --output FILE";

type Arguments = {
  readonly client: string;
  readonly implementation: ReturnType<typeof parseImplementationIdentity>;
  readonly output: string;
};

type UnaryMethod = (
  request: Readonly<Record<string, unknown>>,
  callback: (
    error: grpc.ServiceError | null,
    response: Readonly<Record<string, unknown>>,
  ) => void,
) => grpc.ClientUnaryCall;

type InteropClient = grpc.Client & {
  readonly createKeyPackage: UnaryMethod;
  readonly free: UnaryMethod;
  readonly joinGroup: UnaryMethod;
  readonly name: UnaryMethod;
  readonly protect: UnaryMethod;
  readonly supportedCiphersuites: UnaryMethod;
  readonly unprotect: UnaryMethod;
};

const isLoopbackEndpoint = (value: string): boolean => {
  const match = /^(?:localhost|127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$/.exec(
    value,
  );
  return match !== null && Number(match[1]) <= 65_535;
};

export const parseArguments = (values: readonly string[]): Arguments => {
  let client: string | undefined;
  let implementation: Arguments["implementation"] | undefined;
  let output: string | undefined;
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (value === undefined) throw new Error(usage);
    if (flag === "--client") client = value;
    else if (flag === "--implementation")
      implementation = parseImplementationIdentity(value);
    else if (flag === "--output") output = value;
    else throw new Error(usage);
  }
  if (
    client === undefined ||
    !isLoopbackEndpoint(client) ||
    implementation === undefined ||
    output === undefined ||
    output.length === 0
  )
    throw new Error(usage);
  return Object.freeze({ client, implementation, output });
};

const run = async (command: readonly string[], cwd: string): Promise<void> => {
  const child = Bun.spawn([...command], {
    cwd,
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stderr, stdout] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
    new Response(child.stdout).text(),
  ]);
  if (stdout.length > 0) process.stdout.write(stdout);
  if (stderr.length > 0) process.stderr.write(stderr);
  if (exitCode !== 0)
    throw new Error(`${command[0]} exited with status ${exitCode}.`);
};

const call = <Response>(
  method: UnaryMethod,
  request: Readonly<Record<string, unknown>>,
): Promise<Response> =>
  new Promise((resolve, reject) => {
    method(request, (error, response) => {
      if (error === null) resolve(response as Response);
      else reject(error);
    });
  });

const requireBytes = (value: unknown, field: string): Uint8Array => {
  if (!(value instanceof Uint8Array))
    throw new Error(`OpenMLS response ${field} is not bytes.`);
  return Uint8Array.from(value);
};

const requireInteger = (value: unknown, field: string): number => {
  if (!Number.isSafeInteger(value) || Number(value) < 0)
    throw new Error(`OpenMLS response ${field} is not an integer.`);
  return Number(value);
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

const encodeExternalCredential = (credential: DeviceCredential): Uint8Array =>
  encodeCredential(credential);

export const main = async (): Promise<void> => {
  const input = parseArguments(Bun.argv.slice(2));
  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), "absolutejs-mls-adapter-interop-"),
  );
  const checkout = join(temporaryDirectory, "mls-implementations");
  let client: InteropClient | undefined;
  let remoteStateId: number | undefined;

  try {
    await run(["git", "init", checkout], temporaryDirectory);
    await run(
      ["git", "-C", checkout, "remote", "add", "origin", HARNESS_REPOSITORY],
      temporaryDirectory,
    );
    await run(
      [
        "git",
        "-C",
        checkout,
        "fetch",
        "--depth",
        "1",
        "origin",
        HARNESS_REVISION,
      ],
      temporaryDirectory,
    );
    await run(
      ["git", "-C", checkout, "checkout", "--detach", "FETCH_HEAD"],
      temporaryDirectory,
    );
    const packageDefinition = protoLoader.loadSync(
      join(checkout, "interop", "proto", "mls_client.proto"),
      {
        defaults: true,
        enums: Number,
        keepCase: false,
        longs: Number,
        oneofs: true,
      },
    );
    const descriptor = grpc.loadPackageDefinition(
      packageDefinition,
    ) as unknown as {
      readonly mls_client: {
        readonly MLSClient: new (
          address: string,
          credentials: grpc.ChannelCredentials,
        ) => InteropClient;
      };
    };
    client = new descriptor.mls_client.MLSClient(
      input.client,
      grpc.credentials.createInsecure(),
    );
    const nameResponse = await call<{ readonly name: string }>(
      client.name.bind(client),
      {},
    );
    if (nameResponse.name !== input.implementation.name)
      throw new Error(
        `Server name ${nameResponse.name} does not match ${input.implementation.name}.`,
      );
    const suites = await call<{ readonly ciphersuites: readonly number[] }>(
      client.supportedCiphersuites.bind(client),
      {},
    );
    if (!suites.ciphersuites.includes(MLS_CIPHERSUITE))
      throw new Error("OpenMLS does not support the required ciphersuite.");

    const issuedAt = Date.now();
    const expiresAt = issuedAt + 3_600_000;
    const bob: DeviceCredential = Object.freeze({
      bytes: new TextEncoder().encode("absolutejs-openmls-interop-credential"),
      deviceId: "openmls-device",
      expiresAt,
      identityId: "openmls-user",
      issuedAt,
    });
    const bobIdentity = encodeExternalCredential(bob);
    const keyPackageResponse = await call<{
      readonly keyPackage: Uint8Array;
      readonly transactionId: number;
    }>(client.createKeyPackage.bind(client), {
      cipherSuite: MLS_CIPHERSUITE,
      identity: bobIdentity,
    });
    const keyPackageBytes = requireBytes(
      keyPackageResponse.keyPackage,
      "keyPackage",
    );
    const transactionId = requireInteger(
      keyPackageResponse.transactionId,
      "transactionId",
    );
    const decodedKeyPackage = mlsMessageDecoder(keyPackageBytes, 0);
    if (
      decodedKeyPackage === undefined ||
      decodedKeyPackage[1] !== keyPackageBytes.length ||
      decodedKeyPackage[0].wireformat !== wireformats.mls_key_package
    )
      throw new Error("OpenMLS returned an invalid KeyPackage message.");
    const publicKey = (decodedKeyPackage[0] as MlsKeyPackage).keyPackage
      .leafNode.signaturePublicKey;
    const trustedKeys = new Map<string, Uint8Array>([
      [bob.deviceId, publicKey.slice()],
    ]);
    const authenticationService: AuthenticationService = {
      issueDeviceCredential: async ({ deviceId, identityId, publicKey }) => {
        trustedKeys.set(deviceId, publicKey.slice());
        return Object.freeze({
          bytes: new TextEncoder().encode(`absolutejs:${deviceId}`),
          deviceId,
          expiresAt,
          identityId,
          issuedAt,
        });
      },
      sameIdentity: async (left, right) => left.identityId === right.identityId,
      validateDeviceCredential: async ({ credential, publicKey }) => ({
        identityId: credential.identityId,
        status:
          credential.expiresAt !== undefined &&
          credential.expiresAt >= Date.now() &&
          bytesEqual(
            trustedKeys.get(credential.deviceId) ?? new Uint8Array(),
            publicKey,
          )
            ? "valid"
            : "invalid",
      }),
    };
    const provider = await createMlsMessagingProvider({
      authenticationService,
      stateProtection: {
        open: async ({ sealedState }) => sealedState.slice(),
        seal: async ({ state }) => state.slice(),
      },
    });
    const alice = await provider.createDeviceCredential({
      deviceId: "absolutejs-device",
      identityId: "absolutejs-user",
    });
    const conversationId = `adapter-interop-${crypto.randomUUID()}`;
    const aliceSession = await provider.createConversation({
      conversationId,
      creatorCredential: alice,
      securityMode: "strict-e2ee",
    });
    try {
      const membership = await aliceSession.addMembers([
        {
          bytes: keyPackageBytes,
          credential: bob,
          expiresAt,
          id: `openmls-${transactionId}`,
          protocol: "MLS-1.0",
        },
      ]);
      const welcome = membership.welcomes[0];
      if (welcome === undefined)
        throw new Error("Adapter did not emit a Welcome.");
      const welcomeEnvelope = decodeWelcome(welcome.bytes);
      const joinResponse = await call<{ readonly stateId: number }>(
        client.joinGroup.bind(client),
        {
          encryptHandshake: true,
          identity: bobIdentity,
          ratchetTree: welcomeEnvelope.ratchetTree,
          transactionId,
          welcome: welcomeEnvelope.welcome,
        },
      );
      remoteStateId = requireInteger(joinResponse.stateId, "stateId");

      const absoluteToOpenMlsContext: AuthenticatedContext = {
        conversationId,
        purpose: "interop.absolute-to-openmls",
        securityEpoch: aliceSession.epoch,
        senderId: alice.deviceId,
      };
      const absolutePlaintext = new TextEncoder().encode(
        "AbsoluteJS to OpenMLS",
      );
      const protectedMessage = await aliceSession.protect(
        absolutePlaintext,
        absoluteToOpenMlsContext,
      );
      const unprotected = await call<{
        readonly authenticatedData: Uint8Array;
        readonly plaintext: Uint8Array;
      }>(client.unprotect.bind(client), {
        ciphertext: protectedMessage.bytes,
        stateId: remoteStateId,
      });
      if (
        !bytesEqual(
          requireBytes(unprotected.plaintext, "plaintext"),
          absolutePlaintext,
        ) ||
        !bytesEqual(
          requireBytes(unprotected.authenticatedData, "authenticatedData"),
          encodeContext(absoluteToOpenMlsContext),
        )
      )
        throw new Error("OpenMLS did not authenticate the AbsoluteJS message.");

      const openMlsToAbsoluteContext: AuthenticatedContext = {
        conversationId,
        purpose: "interop.openmls-to-absolute",
        securityEpoch: aliceSession.epoch,
        senderId: bob.deviceId,
      };
      const openMlsPlaintext = new TextEncoder().encode(
        "OpenMLS to AbsoluteJS",
      );
      const remoteProtected = await call<{ readonly ciphertext: Uint8Array }>(
        client.protect.bind(client),
        {
          authenticatedData: encodeContext(openMlsToAbsoluteContext),
          plaintext: openMlsPlaintext,
          stateId: remoteStateId,
        },
      );
      const processed = await aliceSession.process({
        authenticatedContext: openMlsToAbsoluteContext,
        bytes: requireBytes(remoteProtected.ciphertext, "ciphertext"),
        protocol: "MLS-1.0",
      });
      if (
        processed?.kind !== "application" ||
        !bytesEqual(processed.message.plaintext, openMlsPlaintext)
      )
        throw new Error("AbsoluteJS did not authenticate the OpenMLS message.");

      const receipt = Object.freeze({
        adapter: {
          packageName: mlsProviderManifest.packageName,
          version: mlsProviderManifest.version,
        },
        ciphersuite: MLS_CIPHERSUITE,
        completedAt: new Date().toISOString(),
        contract: 1,
        directions: Object.freeze([
          "absolutejs-to-openmls",
          "openmls-to-absolutejs",
        ]),
        harness: {
          repository: HARNESS_REPOSITORY,
          revision: HARNESS_REVISION,
        },
        implementation: input.implementation,
        passed: true,
        scenarios: Object.freeze([
          "adapter-created-group",
          "external-keypackage-admission",
          "welcome-join",
          "bidirectional-application-message",
          "authenticated-context-round-trip",
        ]),
      });
      const serialized = await formatText(JSON.stringify(receipt), {
        parser: "json",
      });
      await writeFile(input.output, serialized);
      process.stdout.write(serialized);
    } finally {
      await aliceSession.close();
    }
  } finally {
    if (client !== undefined && remoteStateId !== undefined) {
      try {
        await call(client.free.bind(client), { stateId: remoteStateId });
      } catch {
        // The disposable interop server remains the cleanup boundary.
      }
    }
    client?.close();
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
};

if (import.meta.main) {
  await main();
}
