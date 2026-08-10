# License signing keys

`license_signing_key.pem` is the **private** Ed25519 key used to sign real KingSec
license keys (`tools/issue_license.py`). It is generated once, kept only by
whoever issues licenses, and must **never** be committed to version control or
shipped with the application in any form.

This directory is gitignored (`.gitignore`: `keys/*.pem`) — only this README
is tracked, so the directory's existence and purpose are documented even
though its contents never are.

The corresponding **public** key is embedded as a constant
(`LICENSE_SIGNING_PUBLIC_KEY`) directly in `src/kingsec/domain/license.py` —
public keys are not secret, so shipping that constant with the app is correct
and expected; it's what lets every installed copy of KingSec verify a license
signature entirely offline, with no server round-trip.

If this key is ever lost or compromised, rotating it means: generate a new
keypair, update `LICENSE_SIGNING_PUBLIC_KEY` in a new release, and re-issue
every license under the new key (existing licenses signed with the old key
will fail verification against the new public key — this is the correct,
expected consequence of a key rotation, not a bug).
