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
        raise ValueError("طول كلمة المرور يجب أن يكون 4 أحرف على الأقل.")

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
        raise ValueError("يجب اختيار نوع واحد من الأحرف على الأقل.")
    if len(groups) > length:
        raise ValueError("الطول أصغر من عدد أنواع الأحرف المختارة.")

    alphabet = "".join(groups)
    password = [secrets.choice(group) for group in groups]
    password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def evaluate_password(password: str) -> tuple[str, int]:
    """Return an Arabic strength label and a simple score from 0 to 5."""
    if not password:
        return "ضعيفة", 0

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

    label = "ضعيفة" if score <= 2 else "متوسطة" if score <= 4 else "قوية"
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
            raise ValueError("إصدار الخزنة غير مدعوم.")
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        expected_tag = base64.b64decode(envelope["tag"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("ملف الخزنة تالف أو غير صالح.") from exc

    key = _derive_key(master_password, salt)
    actual_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise ValueError("كلمة المرور الرئيسية غير صحيحة أو الخزنة تالفة.")
    try:
        return json.loads(_xor_stream(ciphertext, key, nonce).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("تعذر قراءة بيانات الخزنة.") from exc


def load_vault(path: Path, master_password: str) -> dict[str, Any]:
    if not path.exists():
        return {"entries": []}
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"تعذر قراءة ملف الخزنة: {exc}") from exc
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
    password = getpass.getpass("كلمة المرور الرئيسية: ")
    if not password:
        raise ValueError("كلمة المرور الرئيسية لا يمكن أن تكون فارغة.")
    if confirm:
        repeated = getpass.getpass("أكد كلمة المرور الرئيسية: ")
        if password != repeated:
            raise ValueError("كلمتا المرور غير متطابقتين.")
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
    print(f"القوة: {label} ({score}/6)")


def _cmd_strength(_: argparse.Namespace) -> None:
    password = getpass.getpass("كلمة المرور للتقييم: ")
    label, score = evaluate_password(password)
    print(f"القوة: {label} ({score}/6)")


def _cmd_add(args: argparse.Namespace) -> None:
    master = _master_password(confirm=not args.vault.exists())
    vault = load_vault(args.vault, master)
    entries = vault.setdefault("entries", [])
    existing = next((entry for entry in entries if entry["site"].lower() == args.site.lower()), None)
    entry = {"site": args.site, "username": args.username, "password": args.password}
    if existing:
        existing.update(entry)
        print("تم تحديث السجل.")
    else:
        entries.append(entry)
        print("تمت إضافة السجل.")
    save_vault(args.vault, vault, master)


def _cmd_search(args: argparse.Namespace) -> None:
    master = _master_password()
    vault = load_vault(args.vault, master)
    query = args.query.lower()
    matches = [entry for entry in vault.get("entries", []) if query in entry["site"].lower()]
    if not matches:
        print("لا توجد نتائج.")
        return
    for entry in matches:
        print(f"الموقع: {entry['site']}\nالحساب: {entry['username']}\nكلمة المرور: {entry['password']}\n")


def _cmd_list(args: argparse.Namespace) -> None:
    master = _master_password()
    vault = load_vault(args.vault, master)
    entries = vault.get("entries", [])
    if not entries:
        print("الخزنة فارغة.")
        return
    for entry in entries:
        print(f"- {entry['site']} ({entry['username']})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="مولّد ومدير كلمات المرور")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT, help="مسار ملف الخزنة")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="توليد كلمة مرور")
    generate.add_argument("-l", "--length", type=int, default=20)
    generate.add_argument("--no-uppercase", dest="uppercase", action="store_false")
    generate.add_argument("--no-lowercase", dest="lowercase", action="store_false")
    generate.add_argument("--no-digits", dest="digits", action="store_false")
    generate.add_argument("--no-symbols", dest="symbols", action="store_false")
    generate.set_defaults(func=_cmd_generate, uppercase=True, lowercase=True, digits=True, symbols=True)

    strength = subparsers.add_parser("strength", help="تقييم قوة كلمة مرور")
    strength.set_defaults(func=_cmd_strength)

    add = subparsers.add_parser("add", help="إضافة أو تحديث سجل")
    add.add_argument("site")
    add.add_argument("username")
    add.add_argument("password", nargs="?", help="اتركه فارغًا ليتم توليده")
    add.set_defaults(func=_cmd_add)

    search = subparsers.add_parser("search", help="البحث عن سجل وعرض كلمة المرور")
    search.add_argument("query")
    search.set_defaults(func=_cmd_search)

    list_entries = subparsers.add_parser("list", help="عرض المواقع والحسابات دون كلمات المرور")
    list_entries.set_defaults(func=_cmd_list)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "add" and not args.password:
        args.password = generate_password()
        print(f"تم توليد كلمة المرور: {args.password}")
    try:
        args.func(args)
    except (ValueError, OSError) as exc:
        print(f"خطأ: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
