import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HARNESS_REVISION = "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a";
const HARNESS_REPOSITORY = "https://github.com/mlswg/mls-implementations.git";
const usage =
  "Usage: bun run certify:interop -- --client HOST:PORT --client HOST:PORT --config CONFIG";

type InteropArguments = {
  readonly clients: readonly [string, string];
  readonly config: string;
};

const parseArguments = (values: readonly string[]): InteropArguments => {
  const clients: string[] = [];
  let config: string | undefined;
  for (let index = 0; index < values.length; index += 1) {
    const flag = values[index];
    const value = values[index + 1];
    if ((flag === "--client" || flag === "--config") && value !== undefined) {
      if (flag === "--client") clients.push(value);
      else config = value;
      index += 1;
      continue;
    }
    throw new Error(usage);
  }
  if (
    clients.length !== 2 ||
    clients[0] === clients[1] ||
    clients.some(
      (client) => !/^[a-zA-Z0-9.[\]_-]+:[1-9][0-9]{0,4}$/.test(client),
    ) ||
    config === undefined ||
    !/^[a-z0-9][a-z0-9_-]*$/.test(config)
  ) {
    throw new Error(usage);
  }
  return { clients: [clients[0]!, clients[1]!], config };
};

const run = async (
  command: readonly string[],
  cwd: string,
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
  if (stdout.length > 0) process.stdout.write(stdout);
  if (stderr.length > 0) process.stderr.write(stderr);
  if (exitCode !== 0) {
    throw new Error(`${command[0]} exited with status ${exitCode}.`);
  }
  return { stderr, stdout };
};

const input = parseArguments(Bun.argv.slice(2));
const temporaryDirectory = await mkdtemp(
  join(tmpdir(), "absolutejs-mls-interop-"),
);
const checkout = join(temporaryDirectory, "mls-implementations");

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
  const configPath = join(
    checkout,
    "interop",
    "configs",
    `${input.config}.json`,
  );
  const result = await run(
    [
      "go",
      "run",
      "./interop/test-runner/main.go",
      "-client",
      input.clients[0],
      "-client",
      input.clients[1],
      "-config",
      configPath,
    ],
    checkout,
  );
  const digest = new Bun.CryptoHasher("sha256")
    .update(`${result.stdout}\n${result.stderr}`)
    .digest("hex");
  console.log(
    JSON.stringify({
      clients: input.clients,
      completedAt: new Date().toISOString(),
      config: input.config,
      harnessRevision: HARNESS_REVISION,
      outputDigestSha256: digest,
      passed: true,
    }),
  );
} finally {
  await rm(temporaryDirectory, { force: true, recursive: true });
}
