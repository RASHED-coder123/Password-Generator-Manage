# Password Generator and Manager

A local command-line password manager written in Python. It has no external dependencies.

## Usage

```powershell
python E:\password_manager.py generate --length 24
```

Available commands:

```text
generate   Generate a password
strength   Evaluate a password (input is hidden)
add        Add or update a site, username, and password
search     Search for a site and show its credentials
list       List sites and usernames without showing passwords
```

Examples:

```powershell
# Generate a 16-character password without symbols
python E:\password_manager.py generate --length 16 --no-symbols

# Add an entry; omit the password to generate one automatically
python E:\password_manager.py add example.com user@example.com

# Add a specific password
python E:\password_manager.py add github.com user "MySecret!123"

# List saved sites, then search
python E:\password_manager.py list
python E:\password_manager.py search github
```

## Storage and security

The default vault is:

```text
%USERPROFILE%\.password_manager_vault.json
```

Use `--vault` before the command to choose a different location:

```powershell
python E:\password_manager.py --vault E:\vault.json list
```

Encryption keys are derived from the master password using PBKDF2-HMAC-SHA256 with a random salt. The data is also protected with HMAC to detect file tampering. The master password is never stored in the vault. Keep a backup of the vault file; losing the master password means losing access to the encrypted data.
