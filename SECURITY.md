# Security

## Reporting a vulnerability

Please report security problems privately through
[GitHub's private vulnerability reporting](https://github.com/hdunl/r7z/security/advisories/new)
rather than in a public issue. Include the r7z version, the archive or steps that trigger
the problem if you can share them, and what an attacker could achieve. You will get an
answer within a week, and a fix is released as soon as it is ready, with credit if you
want it.

Archives are untrusted input, so anything that lets an archive write outside the
destination folder, run code, crash r7z or use unbounded memory or disk is in scope.

## Supported versions

Only the latest release gets fixes. The desktop app updates itself (see below), so
staying current takes one click.

## How releases are built

- Every release is built by [GitHub Actions](.github/workflows/release.yml) from a tagged
  commit, never on a developer machine, and the tests run before anything is published.
- Each release has a build provenance attestation that ties the files to the exact commit
  and workflow run that produced them. It is attached to the release as SLSA provenance
  (`.intoto.jsonl`) and as a Sigstore bundle (`.sigstore.json`). To check a download:

  ```
  gh attestation verify r7z-0.1.4-windows-x64.zip --repo hdunl/r7z
  ```

- `SHA256SUMS` lists the hash of every file in the release.
- Dependencies are locked in `Cargo.lock` and checked weekly against the RustSec advisory
  database; Dependabot proposes updates. The workflows pin third-party actions to exact
  commits.
- Archive parsing and recovery are fuzzed continuously with ClusterFuzzLite, and CodeQL
  scans every change. The ar, deb, lib and rpm test archives are built by the test code
  instead of being checked in, so no program-like binaries live in the repository.

## How updates work

Once a day (it can be turned off in Settings), the desktop app downloads two small files
from the latest GitHub release:

- `r7z-update.txt`, which names the release zip with its size and SHA-256;
- `r7z-update.sig`, an Ed25519 signature of that file.

The app checks the signature against a public key built into it, and only accepts a
version newer than the one running, so an older release cannot be pushed back on you. It
asks before installing (unless you turn on automatic installs), downloads the zip over
HTTPS using Windows' own TLS, checks its size and SHA-256 against the signed manifest, and
replaces `r7z-gui.exe` (and `r7z.exe`, if it sits in the same folder). If anything fails,
the old files stay in place.

The signing key never leaves the maintainer's control and the release workflow; a
compromised download server or a modified file is rejected because it cannot produce a
valid signature. The check sends no data beyond a normal HTTPS request to github.com with
the user agent `r7z/<version>`.

## Code signing

From 0.1.4, `r7z.exe`, `r7z-gui.exe`, `r7z_shell.dll` and the Windows 11 menu package
(`r7z-shell.msix`) are Authenticode-signed with a Public Trust certificate from
Microsoft's Artifact Signing service, and timestamped, so the signatures stay valid after
the certificate rotates. Signing happens in the release workflow, which signs in to Azure
with GitHub's OIDC token rather than a stored secret; Azure trusts that token only for the
`release` environment, which only version tags can use. The workflow fails the release if
any file is unsigned, untimestamped or signed by another certificate.

To check a file, open its Properties → Digital Signatures, or run
`Get-AuthenticodeSignature r7z-gui.exe` in PowerShell.
