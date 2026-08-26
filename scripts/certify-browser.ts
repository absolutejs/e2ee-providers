import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium, type Browser } from "playwright";

type BrowserCertificationResult = {
  readonly error?: string;
  readonly ok: boolean;
};

const root = new URL("..", import.meta.url).pathname;
const outputDirectory = await mkdtemp(
  join(tmpdir(), "absolutejs-e2ee-browser-"),
);
let browser: Browser | undefined;

try {
  const build = await Bun.build({
    entrypoints: [
      join(root, "tests/browser/mls.ts"),
      join(root, "tests/browser/webcrypto.ts"),
    ],
    minify: true,
    outdir: outputDirectory,
    target: "browser",
  });
  if (!build.success) {
    throw new AggregateError(
      build.logs,
      "Browser certification bundle failed.",
    );
  }
  browser = await chromium.launch({ headless: true });
  for (const provider of ["mls", "webcrypto"] as const) {
    const page = await browser.newPage();
    await page.route("https://certification.absolutejs.invalid/", (route) =>
      route.fulfill({
        body: "<!doctype html><title>AbsoluteJS E2EE certification</title>",
        contentType: "text/html",
        status: 200,
      }),
    );
    await page.goto("https://certification.absolutejs.invalid/");
    const source = await readFile(
      join(outputDirectory, `${provider}.js`),
      "utf8",
    );
    await page.addScriptTag({ content: source });
    const result = await page.evaluate(async () => {
      const scope = globalThis as typeof globalThis & {
        __absoluteCertification?: Promise<BrowserCertificationResult>;
      };
      if (scope.__absoluteCertification === undefined) {
        return { error: "Certification promise missing.", ok: false };
      }
      return scope.__absoluteCertification;
    });
    await page.close();
    if (!result.ok) {
      throw new Error(
        `${provider} browser certification failed: ${result.error}`,
      );
    }
    console.log(`${provider}: Chromium certification passed`);
  }
} finally {
  await browser?.close();
  await rm(outputDirectory, { force: true, recursive: true });
}
