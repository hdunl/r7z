"""Packages a release and signs its update manifest.

    python scripts/package_release.py v0.1.0 dist

Reads target/release/r7z.exe and r7z-gui.exe and writes to the output folder:

    r7z-0.1.0-windows-x64.zip   the programs, README and license
    SHA256SUMS                  hashes of everything above
    r7z-update.txt              manifest the desktop app's updater reads
    r7z-update.sig              Ed25519 signature of r7z-update.txt (hex)

The private key comes from the R7Z_UPDATE_KEY environment variable (PKCS#8 PEM). The script
refuses to sign when the key does not match the public key built into the app
(RELEASE_KEY in gui/src/update.rs), so a release can never ship an update that installed
copies would reject.
"""

import hashlib
import os
import re
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent


def cargo_version(manifest: Path) -> str:
    m = re.search(r'^version = "([^"]+)"', manifest.read_text(encoding="utf-8"), re.M)
    if not m:
        sys.exit(f"no version in {manifest}")
    return m.group(1)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    tag, out = sys.argv[1], Path(sys.argv[2])
    version = tag.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"tag {tag} is not vMAJOR.MINOR.PATCH")
    for manifest in (ROOT / "Cargo.toml", ROOT / "gui" / "Cargo.toml"):
        if cargo_version(manifest) != version:
            sys.exit(f"{manifest} is not at version {version}")

    pem = os.environ.get("R7Z_UPDATE_KEY", "").encode()
    if not pem:
        sys.exit("R7Z_UPDATE_KEY is not set")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("R7Z_UPDATE_KEY is not an Ed25519 key")
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    built_in = re.search(
        r'const RELEASE_KEY: &str = "([0-9a-f]{64})"',
        (ROOT / "gui" / "src" / "update.rs").read_text(encoding="utf-8"),
    )
    if not built_in or built_in.group(1) != public:
        sys.exit("R7Z_UPDATE_KEY does not match RELEASE_KEY in gui/src/update.rs")

    out.mkdir(parents=True, exist_ok=True)
    zip_name = f"r7z-{version}-windows-x64.zip"
    zip_path = out / zip_name
    files = {
        "r7z.exe": ROOT / "target" / "release" / "r7z.exe",
        "r7z-gui.exe": ROOT / "target" / "release" / "r7z-gui.exe",
        "README.md": ROOT / "README.md",
        "LICENSE": ROOT / "LICENSE",
    }
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, src in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, src.read_bytes())

    data = zip_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    manifest = (
        "r7z-update 1\n"
        f"version {version}\n"
        f"file {zip_name}\n"
        f"size {len(data)}\n"
        f"sha256 {digest}\n"
    ).encode()
    (out / "r7z-update.txt").write_bytes(manifest)
    signature = key.sign(manifest)
    key.public_key().verify(signature, manifest)
    (out / "r7z-update.sig").write_bytes((signature.hex() + "\n").encode())

    sums = [(digest, zip_name)]
    for name in ("r7z-update.txt", "r7z-update.sig"):
        sums.append((hashlib.sha256((out / name).read_bytes()).hexdigest(), name))
    # Unix line endings, so `sha256sum -c SHA256SUMS` works everywhere.
    (out / "SHA256SUMS").write_bytes("".join(f"{h}  {n}\n" for h, n in sums).encode())
    for p in sorted(out.iterdir()):
        print(f"{p.stat().st_size:>10}  {p.name}")


if __name__ == "__main__":
    main()
