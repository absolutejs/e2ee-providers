# Security policy

`@absolutejs/e2ee-mls` 0.x is experimental and must not protect production
secrets or safety-critical communications.

Current limitations:

- the underlying `ts-mls` implementation declares that it has not undergone a
  formal security audit;
- private signing keys and unsealed MLS state exist as exportable JavaScript
  bytes; callers must provide authenticated encryption through
  `stateProtection` before state can leave the provider;
- delayed application messages from a previous epoch are rejected;
- key transparency, out-of-band device verification, delivery, replay storage,
  abuse prevention, backup, and recovery are application responsibilities;
- only the RFC 9420 mandatory-to-implement classical ciphersuite is enabled;
- the package makes no post-quantum security claim.

The provider zeroes key material reported as consumed by the engine and zeroes
reachable session state on `close()`. JavaScript runtimes, garbage collectors,
copies made by callers, crash dumps, and swap can retain data; this is not a
hardware-backed or non-exportable key store.

An Authentication Service must validate the exact device credential and MLS
signature public key binding. A permissive service defeats endpoint
authentication even though message encryption still executes.

Do not report vulnerabilities through a public issue. Email
security@absolutejs.com with the affected version, reproduction, and impact.
Do not include real private keys, credentials, or message content.
