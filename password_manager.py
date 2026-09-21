#!/usr/bin/env python3
"""A small local password generator and encrypted password manager."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import string
import sys
from pathlib import Path
from typing import Any

DEFAULT_VAULT = Path.home() / ".password_manager_vault.json"
FORMAT_VERSION = 1
PBKDF2_ITERATIONS = 310_000


def generate_password(
    length: int = 20,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Generate a password containing at least one character from each enabled set."""
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    groups = []
    if uppercase:
        groups.append(string.ascii_uppercase)
    if lowercase:
        groups.append(string.ascii_lowercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append("!@#$%^&*()-_=+[]{};:,.?/\\")
    if not groups:
        raise ValueError("Select at least one character type.")
    if len(groups) > length:
        raise ValueError("Length is smaller than the number of selected character types.")

    alphabet = "".join(groups)
    password = [secrets.choice(group) for group in groups]
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def evaluate_password(password: str) -> tuple[str, int]:
    """Return an English strength label and a simple score from 0 to 6."""
    if not password:
        return "Weak", 0

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    common = {"password", "123456", "qwerty", "admin", "letmein"}
    if password.lower() in common or len(set(password)) <= 2:
        score = min(score, 1)

    label = "Weak" if score <= 2 else "Medium" if score <= 4 else "Strong"
    return label, score


def _derive_key(master_password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", master_password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32
    )


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        output.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def _encrypt(payload: dict[str, Any], master_password: str) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key = _derive_key(master_password, salt)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    ciphertext = _xor_stream(plaintext, key, nonce)
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return {
        "version": FORMAT_VERSION,
        "kdf": "pbkdf2-sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def _decrypt(envelope: dict[str, Any], master_password: str) -> dict[str, Any]:
    try:
        if envelope["version"] != FORMAT_VERSION:
            raise ValueError("Unsupported vault version.")
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        expected_tag = base64.b64decode(envelope["tag"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("The vault file is corrupted or invalid.") from exc

    key = _derive_key(master_password, salt)
    actual_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise ValueError("The master password is incorrect or the vault is corrupted.")
    try:
        return json.loads(_xor_stream(ciphertext, key, nonce).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Unable to read vault data.") from exc


def load_vault(path: Path, master_password: str) -> dict[str, Any]:
    if not path.exists():
        return {"entries": []}
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read vault file: {exc}") from exc
    return _decrypt(envelope, master_password)


def save_vault(path: Path, vault: dict[str, Any], master_password: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(_encrypt(vault, master_password), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _master_password(confirm: bool = False) -> str:
    password = getpass.getpass("Master password: ")
    if not password:
        raise ValueError("The master password cannot be empty.")
    if confirm:
        repeated = getpass.getpass("Confirm master password: ")
        if password != repeated:
            raise ValueError("The master passwords do not match.")
    return password


def _cmd_generate(args: argparse.Namespace) -> None:
    password = generate_password(
        args.length,
        uppercase=args.uppercase,
        lowercase=args.lowercase,
        digits=args.digits,
        symbols=args.symbols,
    )
    label, score = evaluate_password(password)
    print(password)
    print(f"Strength: {label} ({score}/6)")


def _cmd_strength(_: argparse.Namespace) -> None:
    password = getpass.getpass("Password to evaluate: ")
    label, score = evaluate_password(password)
    print(f"Strength: {label} ({score}/6)")


def _cmd_add(args: argparse.Namespace) -> None:
    master = _master_password(confirm=not args.vault.exists())
    vault = load_vault(args.vault, master)
    entries = vault.setdefault("entries", [])
    existing = next((entry for entry in entries if entry["site"].lower() == args.site.lower()), None)
    entry = {"site": args.site, "username": args.username, "password": args.password}
    if existing:
        existing.update(entry)
        print("Entry updated.")
    else:
        entries.append(entry)
        print("Entry added.")
    save_vault(args.vault, vault, master)


def _cmd_search(args: argparse.Namespace) -> None:
    master = _master_password()
    vault = load_vault(args.vault, master)
    query = args.query.lower()
    matches = [entry for entry in vault.get("entries", []) if query in entry["site"].lower()]
    if not matches:
        print("No matching entries found.")
        return
    for entry in matches:
        print(f"Site: {entry['site']}\nUsername: {entry['username']}\nPassword: {entry['password']}\n")


def _cmd_list(args: argparse.Namespace) -> None:
    master = _master_password()
    vault = load_vault(args.vault, master)
    entries = vault.get("entries", [])
    if not entries:
        print("The vault is empty.")
        return
    for entry in entries:
        print(f"- {entry['site']} ({entry['username']})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Password generator and manager")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT, help="Path to the vault file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Generate a password")
    generate.add_argument("-l", "--length", type=int, default=20)
    generate.add_argument("--no-uppercase", dest="uppercase", action="store_false")
    generate.add_argument("--no-lowercase", dest="lowercase", action="store_false")
    generate.add_argument("--no-digits", dest="digits", action="store_false")
    generate.add_argument("--no-symbols", dest="symbols", action="store_false")
    generate.set_defaults(func=_cmd_generate, uppercase=True, lowercase=True, digits=True, symbols=True)

    strength = subparsers.add_parser("strength", help="Evaluate password strength")
    strength.set_defaults(func=_cmd_strength)

    add = subparsers.add_parser("add", help="Add or update an entry")
    add.add_argument("site")
    add.add_argument("username")
    add.add_argument("password", nargs="?", help="Leave empty to generate a password")
    add.set_defaults(func=_cmd_add)

    search = subparsers.add_parser("search", help="Search for an entry and show its password")
    search.add_argument("query")
    search.set_defaults(func=_cmd_search)

    list_entries = subparsers.add_parser("list", help="List sites and usernames without passwords")
    list_entries.set_defaults(func=_cmd_list)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "add" and not args.password:
        args.password = generate_password()
        print(f"Generated password: {args.password}")
    try:
        args.func(args)
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
