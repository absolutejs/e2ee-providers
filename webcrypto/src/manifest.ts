import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  maxPlaintextBytes?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams"],
    intents: [
      "encrypt a single-recipient envelope",
      "decrypt an RFC 9180 HPKE envelope",
    ],
    keywords: ["e2ee", "HPKE", "RFC 9180", "WebCrypto", "envelope"],
    protocols: ["HPKE"],
  },
  identity: {
    accent: "#0d9488",
    category: "security",
    description:
      "Experimental single-recipient RFC 9180 HPKE envelopes using WebCrypto-backed primitives.",
    docsUrl: "https://github.com/absolutejs/e2ee-providers/tree/main/webcrypto",
    name: "@absolutejs/e2ee-webcrypto",
    tagline: "Seal one-recipient envelopes with standards-backed HPKE.",
  },
  requires: {
    peers: [
      {
        name: "@absolutejs/e2ee",
        range: ">=0.1.0 <0.2",
        reason: "provider contract",
      },
    ],
  },
  settings: Type.Object(
    {
      maxPlaintextBytes: Type.Optional(
        Type.Integer({
          default: 1_048_576,
          description:
            "Maximum plaintext bytes accepted before sealing or after opening.",
          minimum: 1,
          title: "Maximum plaintext bytes",
        }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
