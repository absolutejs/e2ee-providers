import { describe, expect, test } from "bun:test";
import {
  parseArguments,
  parseImplementationIdentity,
  summarizeResults,
} from "./certify-mls-interop";

const revisionA = "a".repeat(40);
const revisionB = "b".repeat(40);

describe("MLS interoperability evidence", () => {
  test("parses exact implementation identities", () => {
    expect(
      parseImplementationIdentity(`ts-mls@2.0.0-rc.16#${revisionA}`),
    ).toEqual({
      name: "ts-mls",
      revision: revisionA,
      version: "2.0.0-rc.16",
    });
  });

  test("requires distinct endpoints and implementation names", () => {
    expect(() =>
      parseArguments([
        "--client",
        "localhost:50051",
        "--implementation",
        `OpenMLS@0.9.0#${revisionA}`,
        "--client",
        "localhost:50053",
        "--implementation",
        `OpenMLS@0.9.0#${revisionB}`,
        "--config",
        "welcome_join",
        "--suite",
        "1",
      ]),
    ).toThrow();
  });

  test("rejects declarations that do not match self-reported participants", () => {
    const output = JSON.stringify({
      scripts: {
        welcome: [
          {
            actors: { alice: "OpenMLS", bob: "OpenMLS" },
            cipher_suite: 1,
            encrypt_flag: true,
          },
          {
            actors: { alice: "OpenMLS", bob: "OpenMLS" },
            cipher_suite: 1,
            encrypt_flag: true,
          },
        ],
      },
    });

    expect(() => summarizeResults(output, ["OpenMLS", "ts-mls"])).toThrow(
      "do not match",
    );
  });

  test("summarizes role-permuting results without retaining transcripts", () => {
    const summary = summarizeResults(
      JSON.stringify({
        scripts: {
          welcome: [
            {
              actors: { alice: "OpenMLS", bob: "ts-mls" },
              cipher_suite: 1,
              encrypt_flag: true,
              transcript: [{ secret: "discarded" }],
            },
            {
              actors: { alice: "ts-mls", bob: "OpenMLS" },
              cipher_suite: 1,
              encrypt_flag: false,
              transcript: [{ secret: "discarded" }],
            },
          ],
        },
      }),
      ["OpenMLS", "ts-mls"],
    );

    expect(summary).toEqual({
      assignments: 2,
      ciphersuites: [1],
      implementationNames: ["OpenMLS", "ts-mls"],
      scenarios: ["welcome"],
    });
    expect(JSON.stringify(summary)).not.toContain("discarded");
  });
});
