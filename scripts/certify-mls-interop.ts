import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HARNESS_REVISION = "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a";
const HARNESS_REPOSITORY = "https://github.com/mlswg/mls-implementations.git";
const usage =
  "Usage: bun run certify:interop -- --client HOST:PORT --implementation NAME@VERSION#REVISION --client HOST:PORT --implementation NAME@VERSION#REVISION --config CONFIG --suite NUMBER [--output FILE]";

type ImplementationIdentity = {
  readonly name: string;
  readonly revision: string;
  readonly version: string;
};

type InteropArguments = {
  readonly clients: readonly [string, string];
  readonly config: string;
  readonly implementations: readonly [
    ImplementationIdentity,
    ImplementationIdentity,
  ];
  readonly output?: string;
  readonly suite: number;
};

export const parseImplementationIdentity = (
  value: string,
): ImplementationIdentity => {
  const revisionSeparator = value.lastIndexOf("#");
  const versionSeparator = value.lastIndexOf("@", revisionSeparator);
  const name = value.slice(0, versionSeparator);
  const version = value.slice(versionSeparator + 1, revisionSeparator);
  const revision = value.slice(revisionSeparator + 1);
  if (
    versionSeparator < 1 ||
    revisionSeparator <= versionSeparator + 1 ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) ||
    !/^[A-Za-z0-9][A-Za-z0-9.+_-]*$/.test(version) ||
    !/^[a-f0-9]{40}$/.test(revision)
  ) {
    throw new Error(usage);
  }
  return Object.freeze({ name, revision, version });
};

export const parseArguments = (values: readonly string[]): InteropArguments => {
  const clients: string[] = [];
  const implementations: ImplementationIdentity[] = [];
  let config: string | undefined;
  let output: string | undefined;
  let suite: number | undefined;
  for (let index = 0; index < values.length; index += 1) {
    const flag = values[index];
    const value = values[index + 1];
    if (
      (flag === "--client" ||
        flag === "--config" ||
        flag === "--implementation" ||
        flag === "--output" ||
        flag === "--suite") &&
      value !== undefined
    ) {
      if (flag === "--client") clients.push(value);
      else if (flag === "--implementation")
        implementations.push(parseImplementationIdentity(value));
      else if (flag === "--output") output = value;
      else if (flag === "--suite") suite = Number(value);
      else config = value;
      index += 1;
      continue;
    }
    throw new Error(usage);
  }
  if (
    clients.length !== 2 ||
    clients[0] === clients[1] ||
    implementations.length !== 2 ||
    implementations[0]!.name === implementations[1]!.name ||
    clients.some(
      (client) => !/^[a-zA-Z0-9.[\]_-]+:[1-9][0-9]{0,4}$/.test(client),
    ) ||
    config === undefined ||
    !/^[a-z0-9][a-z0-9_-]*$/.test(config) ||
    !Number.isSafeInteger(suite) ||
    suite! < 1 ||
    suite! > 65_535
  ) {
    throw new Error(usage);
  }
  return {
    clients: [clients[0]!, clients[1]!],
    config,
    implementations: [implementations[0]!, implementations[1]!],
    ...(output === undefined ? {} : { output }),
    suite: suite!,
  };
};

const run = async (
  command: readonly string[],
  cwd: string,
  echoOutput = true,
): Promise<{ readonly stderr: string; readonly stdout: string }> => {
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
  if (echoOutput && stdout.length > 0) process.stdout.write(stdout);
  if (echoOutput && stderr.length > 0) process.stderr.write(stderr);
  if (exitCode !== 0) {
    throw new Error(`${command[0]} exited with status ${exitCode}.`);
  }
  return { stderr, stdout };
};

type HarnessResults = {
  readonly scripts: Readonly<
    Record<
      string,
      readonly {
        readonly actors: Readonly<Record<string, string>>;
        readonly cipher_suite: number;
        readonly encrypt_flag: boolean;
        readonly failed_step?: number;
      }[]
    >
  >;
};

export const summarizeResults = (
  raw: string,
  expectedNames: readonly string[],
): {
  readonly assignments: number;
  readonly ciphersuites: readonly number[];
  readonly implementationNames: readonly string[];
  readonly scenarios: readonly string[];
} => {
  const parsed = JSON.parse(raw) as HarnessResults;
  const names = new Set<string>();
  const ciphersuites = new Set<number>();
  let assignments = 0;
  for (const results of Object.values(parsed.scripts)) {
    for (const result of results) {
      if (result.failed_step !== undefined)
        throw new Error("Harness output contains a failed step.");
      assignments += 1;
      ciphersuites.add(result.cipher_suite);
      for (const name of Object.values(result.actors)) names.add(name);
    }
  }
  const implementationNames = [...names].sort();
  const expected = [...expectedNames].sort();
  if (
    assignments < 2 ||
    implementationNames.length !== 2 ||
    implementationNames.some((name, index) => name !== expected[index])
  ) {
    throw new Error(
      `Harness participants ${JSON.stringify(implementationNames)} do not match ${JSON.stringify(expected)}.`,
    );
  }
  return Object.freeze({
    assignments,
    ciphersuites: Object.freeze([...ciphersuites].sort((a, b) => a - b)),
    implementationNames: Object.freeze(implementationNames),
    scenarios: Object.freeze(Object.keys(parsed.scripts).sort()),
  });
};

const main = async (): Promise<void> => {
  const input = parseArguments(Bun.argv.slice(2));
  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), "absolutejs-mls-interop-"),
  );
  const checkout = join(temporaryDirectory, "mls-implementations");
  const dockerfile = join(
    dirname(fileURLToPath(import.meta.url)),
    "interop",
    "Dockerfile.mls-runner",
  );
  const image = `absolutejs-mls-runner:${HARNESS_REVISION.slice(0, 12)}`;

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
    const configBytes = await Bun.file(
      join(checkout, "interop", "configs", `${input.config}.json`),
    ).bytes();
    await run(
      ["docker", "build", "--tag", image, "--file", dockerfile, "."],
      checkout,
    );
    const imageInspection = await run(
      ["docker", "image", "inspect", "--format={{.Id}}", image],
      checkout,
    );
    const result = await run(
      [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        image,
        "-fail-fast",
        "-client",
        input.clients[0],
        "-client",
        input.clients[1],
        "-config",
        `../configs/${input.config}.json`,
        "-suite",
        String(input.suite),
      ],
      checkout,
      false,
    );
    const summary = summarizeResults(
      result.stdout,
      input.implementations.map(({ name }) => name),
    );
    const receipt = Object.freeze({
      assignments: summary.assignments,
      ciphersuites: summary.ciphersuites,
      clients: input.clients.map((endpoint, index) => ({
        endpoint,
        implementation: input.implementations[index]!,
      })),
      completedAt: new Date().toISOString(),
      config: input.config,
      configDigestSha256: new Bun.CryptoHasher("sha256")
        .update(configBytes)
        .digest("hex"),
      contract: 1,
      harness: {
        repository: HARNESS_REPOSITORY,
        revision: HARNESS_REVISION,
        runnerImageDigest: imageInspection.stdout.trim(),
      },
      implementationNames: summary.implementationNames,
      outputDigestSha256: new Bun.CryptoHasher("sha256")
        .update(result.stdout)
        .digest("hex"),
      passed: true,
      scenarios: summary.scenarios,
      suite: input.suite,
    });
    const serialized = `${JSON.stringify(receipt, null, 2)}\n`;
    if (input.output !== undefined) await writeFile(input.output, serialized);
    process.stdout.write(serialized);
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
};

if (import.meta.main) await main();
