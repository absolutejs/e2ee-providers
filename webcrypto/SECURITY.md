# Security notes

This package is experimental and has not been independently audited by
AbsoluteJS. It wraps RFC 9180 operations supplied by `hpke@1.1.4` and does not
implement an encryption primitive itself.

The package provides single-recipient sealed envelopes. It does not provide MLS,
group messaging, forward secrecy across a conversation, post-compromise security,
identity verification, secure key storage, recovery, or transport.

Report vulnerabilities privately to security@absolutejs.com.
