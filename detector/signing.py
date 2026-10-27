"""
AIDDS Detector — Role-manifest signing and verification (Ed25519).

Signature format stored in a manifest's ``signature`` field::

    ed25519:<key_id>:<base64 signature>

The signed message is the canonical JSON of the manifest *without* its ``signature`` field
(sorted keys, no whitespace), so the signature is independent of YAML formatting and comments.
Trusted public keys live in ``manifests/trusted_keys.json``::

    {"keys": {"<key_id>": "<base64 public key>"}}

CLI::

    python -m detector.signing init            # create a key pair, trust it, sign all manifests
    python -m detector.signing sign  FILE...   # re-sign manifests after editing them
    python -m detector.signing verify          # check every manifest in manifests/
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import json
import os
import pathlib
import re
import sys

import yaml
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from detector.schemas import RoleManifest


def canonical_bytes(manifest: RoleManifest) -> bytes:
    """Canonical byte string that is signed (signature field excluded)."""
    payload = manifest.model_dump(mode="json", exclude={"signature"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """Return ``(private_key_b64, public_key_b64)``."""
    sk = SigningKey.generate()
    return (
        base64.b64encode(bytes(sk)).decode("ascii"),
        base64.b64encode(bytes(sk.verify_key)).decode("ascii"),
    )


def sign_manifest(manifest: RoleManifest, key_id: str, private_key_b64: str) -> str:
    sk = SigningKey(base64.b64decode(private_key_b64))
    sig = sk.sign(canonical_bytes(manifest)).signature
    return f"ed25519:{key_id}:{base64.b64encode(sig).decode('ascii')}"


def verify_manifest(manifest: RoleManifest, trusted: dict[str, str]) -> tuple[bool, str]:
    """Check the manifest signature against the trusted keys. Returns ``(ok, reason)``."""
    parts = manifest.signature.split(":", 2)
    if len(parts) != 3 or parts[0] != "ed25519":
        return False, "signature missing or not in 'ed25519:<key_id>:<base64>' format"
    _, key_id, sig_b64 = parts
    pub = trusted.get(key_id)
    if pub is None:
        return False, f"signing key '{key_id}' is not trusted"
    try:
        VerifyKey(base64.b64decode(pub)).verify(
            canonical_bytes(manifest), base64.b64decode(sig_b64)
        )
    except (BadSignatureError, binascii.Error, ValueError):
        return False, "signature does not match manifest contents"
    return True, "ok"


def load_trusted_keys(path: str | pathlib.Path) -> dict[str, str]:
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    keys = data.get("keys", {})
    return {str(k): str(v) for k, v in keys.items()}


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

_SIG_LINE = re.compile(r"^signature:.*$", re.MULTILINE)


def _write_signature(path: pathlib.Path, signature: str) -> None:
    text = path.read_text(encoding="utf-8")
    line = f'signature: "{signature}"'
    if _SIG_LINE.search(text):
        text = _SIG_LINE.sub(lambda _m: line, text)
    else:
        text = text.rstrip("\n") + "\n\n" + line + "\n"
    path.write_text(text, encoding="utf-8")


def _load_manifest_file(path: pathlib.Path) -> RoleManifest:
    return RoleManifest.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def sign_files(files: list[pathlib.Path], key_id: str, private_key_b64: str) -> None:
    for f in files:
        m = _load_manifest_file(f)
        _write_signature(f, sign_manifest(m, key_id, private_key_b64))
        print(f"signed {f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AIDDS manifest signing")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="create a key pair, trust it and sign every manifest")
    init.add_argument("--manifests", default="manifests")
    init.add_argument("--key-id", default="aidds-owner")
    init.add_argument("--keys-dir", default="keys")

    sg = sub.add_parser("sign", help="sign manifest files with an existing private key")
    sg.add_argument("files", nargs="+")
    sg.add_argument("--key-id", default="aidds-owner")
    sg.add_argument("--key-file", default="keys/aidds-owner.key")

    vf = sub.add_parser("verify", help="verify every manifest in a directory")
    vf.add_argument("--manifests", default="manifests")
    vf.add_argument("--trusted", default="manifests/trusted_keys.json")

    args = parser.parse_args()

    if args.cmd == "init":
        mdir = pathlib.Path(args.manifests)
        keys_dir = pathlib.Path(args.keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv, pub = generate_keypair()
        key_file = keys_dir / f"{args.key_id}.key"
        key_file.write_text(priv + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(key_file, 0o600)
        trusted_path = mdir / "trusted_keys.json"
        trusted = load_trusted_keys(trusted_path)
        trusted[args.key_id] = pub
        trusted_path.write_text(json.dumps({"keys": trusted}, indent=2) + "\n", encoding="utf-8")
        sign_files(sorted(mdir.glob("*.yaml")), args.key_id, priv)
        print(f"private key: {key_file}  (KEEP SECRET - never commit it)")
        print(f"trusted keys: {trusted_path}")
    elif args.cmd == "sign":
        priv = pathlib.Path(args.key_file).read_text(encoding="utf-8").strip()
        sign_files([pathlib.Path(f) for f in args.files], args.key_id, priv)
    else:
        trusted = load_trusted_keys(args.trusted)
        bad = 0
        for f in sorted(pathlib.Path(args.manifests).glob("*.yaml")):
            ok, reason = verify_manifest(_load_manifest_file(f), trusted)
            print(f"{'OK  ' if ok else 'FAIL'} {f.name}: {reason}")
            bad += 0 if ok else 1
        sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
