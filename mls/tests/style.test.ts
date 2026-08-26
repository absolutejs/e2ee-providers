import { expect, test } from "bun:test";

test("public contracts use type aliases instead of interfaces", async () => {
  const declarations: string[] = [];
  const glob = new Bun.Glob("src/**/*.ts");

  for await (const path of glob.scan(".")) {
    const source = await Bun.file(path).text();
    if (/\binterface\s+[A-Za-z_$]/u.test(source)) declarations.push(path);
  }

  expect(declarations).toEqual([]);
});
