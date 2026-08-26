import { describe, expect, test } from "bun:test";
import { parseArguments } from "./certify-mls-adapter-interop";

const revision = "a".repeat(40);

describe("MLS adapter interoperability evidence", () => {
  test("accepts an exact implementation identity on loopback", () => {
    expect(
      parseArguments([
        "--client",
        "localhost:59117",
        "--implementation",
        `OpenMLS@0.9.0#${revision}`,
        "--output",
        "mls/evidence/receipt.json",
      ]),
    ).toEqual({
      client: "localhost:59117",
      implementation: {
        name: "OpenMLS",
        revision,
        version: "0.9.0",
      },
      output: "mls/evidence/receipt.json",
    });
  });

  test.each([
    "openmls.example:59117",
    "0.0.0.0:59117",
    "localhost:0",
    "localhost:65536",
  ])("rejects unsafe or invalid endpoint %s", (endpoint) => {
    expect(() =>
      parseArguments([
        "--client",
        endpoint,
        "--implementation",
        `OpenMLS@0.9.0#${revision}`,
        "--output",
        "receipt.json",
      ]),
    ).toThrow();
  });
});
