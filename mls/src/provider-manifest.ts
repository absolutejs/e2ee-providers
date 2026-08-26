import { defineE2EEProviderManifest } from "@absolutejs/e2ee";

export const mlsProviderManifest = defineE2EEProviderManifest({
  contract: 1,
  costModel: "free",
  description: "Experimental RFC 9420 MLS messaging provider backed by ts-mls.",
  id: "mls",
  packageName: "@absolutejs/e2ee-mls",
  protocols: ["MLS-1.0"],
  roles: ["messaging"],
  runtimes: ["browser", "bun", "node"],
  security: {
    assurance: "experimental",
    forwardSecrecy: true,
    operatorCanDecrypt: false,
    postCompromiseSecurity: true,
    postQuantum: false,
    privateKeyProtection: "exportable",
    supportedModes: ["strict-e2ee", "managed-recovery"],
  },
  version: "0.4.0",
});
