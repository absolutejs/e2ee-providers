import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "add RFC 9420 encrypted messaging",
      "create an MLS conversation",
      "manage encrypted conversation devices",
    ],
    keywords: ["e2ee", "MLS", "RFC 9420", "secure messaging", "ratchet"],
    protocols: ["MLS"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "Experimental RFC 9420 MLS messaging provider with explicit identity and state boundaries.",
    docsUrl: "https://github.com/absolutejs/e2ee-providers/tree/main/mls",
    name: "@absolutejs/e2ee-mls",
    tagline: "Exercise real MLS messaging behind the AbsoluteJS E2EE contract.",
  },
  settings: Type.Object({}, { additionalProperties: false }),
  wiring: [],
});
