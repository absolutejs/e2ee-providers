import { defineE2EEProviderManifest } from "@absolutejs/e2ee";

export const webcryptoProviderManifest = defineE2EEProviderManifest({
  contract: 1,
  costModel: "free",
  description:
    "Experimental RFC 9180 base-mode HPKE envelopes using WebCrypto-backed P-256, HKDF-SHA256, and AES-128-GCM.",
  id: "webcrypto",
  packageName: "@absolutejs/e2ee-webcrypto",
  protocols: ["RFC9180-BASE-P256-SHA256-AES128GCM"],
  roles: ["envelope"],
  runtimes: ["browser", "bun", "node"],
  security: {
    assurance: "experimental",
    forwardSecrecy: false,
    operatorCanDecrypt: false,
    postCompromiseSecurity: false,
    postQuantum: false,
    privateKeyProtection: "non-exportable",
    supportedModes: ["strict-e2ee", "managed-recovery"],
  },
  version: "0.2.2",
});
