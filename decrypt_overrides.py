#!/usr/bin/env python3

from __future__ import annotations

import argparse
import plistlib
import shutil
import sys
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY: bytes | None = None  # Will be loaded from --key-file argument

DEFAULT_OUTPUT_ROOT = Path("decrypted_overrides")
NONCE_LEN = 12
TAG_LEN = 16

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Recursively decrypt every *.enc file inside MobileAsset override "
            "bundles and reproduce the plaintext in a clean directory tree."
        )
    )
    ap.add_argument(
        "overrides_root",
        type=Path,
        help=(
            "Root of the override assets (e.g. "
            "/System/Library/AssetsV2/com_apple_MobileAsset_UAF_FM_Overrides/purpose_auto)"
        ),
    )
    ap.add_argument(
        "-o",
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help=f"Destination directory (default: {DEFAULT_OUTPUT_ROOT})",
    )
    ap.add_argument(
        "--nonce-len",
        type=int,
        default=NONCE_LEN,
        help="Nonce length in bytes (default 12)",
    )
    ap.add_argument(
        "--tag-len",
        type=int,
        default=TAG_LEN,
        help="Tag length in bytes (default 16)",
    )
    ap.add_argument(
        "-k",
        "--key-file",
        type=Path,
        required=True,
        help="Path to file containing 32-byte AES key encoded as 64 hex characters",
    )
    return ap.parse_args()


def decrypt_blob(
    blob: bytes,
    nonce_len: int = NONCE_LEN,
    tag_len: int = TAG_LEN,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt [nonce | ciphertext | tag] using the global KEY."""
    if len(blob) < nonce_len + tag_len:
        raise ValueError("Blob too small for specified nonce/tag lengths")

    nonce = blob[:nonce_len]
    tag = blob[-tag_len:]
    ciphertext = blob[nonce_len:-tag_len]

    assert KEY is not None, "Global KEY must be set before decryption" # mypy
    aesgcm = AESGCM(KEY)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)


def decrypt_file(
    enc_path: Path,
    out_path: Path,
    nonce_len: int = NONCE_LEN,
    tag_len: int = TAG_LEN,
) -> None:
    try:
        plaintext = decrypt_blob(enc_path.read_bytes(), nonce_len, tag_len)
    except Exception as exc:
        print(f"[warn] Failed to decrypt {enc_path}: {exc}", file=sys.stderr)
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(plaintext)
    print(
        f"[success] Decrypted {enc_path} -> {out_path} "
        f"({len(plaintext):,} bytes)",
        flush=True,
    )

def find_asset_dirs(root: Path) -> Iterable[Path]:
    """Yield every *.asset directory under *root*."""
    yield from (p for p in root.glob("**/*.asset") if p.is_dir())


def asset_specifier_from_plist(plist_path: Path) -> str | None:
    """Return AssetSpecifier string or None if missing/unreadable."""
    try:
        with plist_path.open("rb") as fp:
            data = plistlib.load(fp)
        return data.get("MobileAssetProperties", {}).get("AssetSpecifier")
    except Exception as exc:
        print(f"[warn] Could not parse {plist_path}: {exc}", file=sys.stderr)
        return None


def process_asset_bundle(
    asset_dir: Path, output_root: Path, nonce_len: int, tag_len: int
) -> None:
    info_plist = asset_dir / "Info.plist"
    if not info_plist.exists():
        print(f"[warn] Skipping {asset_dir}: Info.plist missing", file=sys.stderr)
        return

    specifier = asset_specifier_from_plist(info_plist)
    if not specifier:
        print(
            f"[warn] Skipping {asset_dir}: AssetSpecifier not found", file=sys.stderr
        )
        return

    dest_dir = output_root / specifier
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(info_plist, dest_dir / "Info.plist")

    src_data_root = asset_dir / "AssetData"
    if not src_data_root.exists():
        print(f"[info] {specifier}: no AssetData directory present", flush=True)
        return

    dest_data_root = dest_dir / "AssetData"

    for enc_path in src_data_root.rglob("*.enc"):
        relative = enc_path.relative_to(src_data_root)
        out_path = dest_data_root / relative.with_suffix("")  # drop .enc
        decrypt_file(enc_path, out_path, nonce_len, tag_len)

def main() -> None:
    args = parse_args()

    # Load AES-256-GCM key from the supplied key file
    global KEY
    try:
        key_hex = args.key_file.read_text().strip()
        KEY = bytes.fromhex(key_hex)
        if len(KEY) != 32:
            raise ValueError(f"Expected 32-byte key, got {len(KEY)} bytes")
    except Exception as exc:
        # try reading key file as binary if it fails as text
        try:
            KEY = args.key_file.read_bytes()
            assert KEY is not None, "KEY must be set after reading from file" # mypy
            if len(KEY) != 32:
                raise ValueError(f"Expected 32-byte key, got {len(KEY)} bytes")
        except Exception as exc:
            sys.exit(f"Failed to read key from {args.key_file}: {exc}")

    if not args.overrides_root.is_dir():
        sys.exit(f"Overrides root {args.overrides_root} does not exist or is not a directory")

    for asset in find_asset_dirs(args.overrides_root):
        process_asset_bundle(asset, args.output_root, args.nonce_len, args.tag_len)


if __name__ == "__main__":
    main()
