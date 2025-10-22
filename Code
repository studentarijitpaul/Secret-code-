"""
secret_code_generator.py
Generate and manage secure secret codes with expiry and hashing.
"""

import os
import time
import secrets
import string
import hashlib
import hmac
import logging
from typing import Dict, Optional

# ---------------- CONFIG ----------------
SECRET_KEY = os.environ.get("CODE_SECRET_KEY", "super_secret_key_change_this")
CODE_TTL_SECONDS = 600  # Code expires in 10 minutes
LOG_FILE = "secret_code.log"
# ----------------------------------------

# Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s"
)

# In-memory code store (identifier -> details)
_store: Dict[str, dict] = {}


# ---------- CORE UTILITIES ----------
def _hash_code(code: str, secret: str = SECRET_KEY) -> str:
    """Hash the code using HMAC-SHA256 (so raw code is not stored)."""
    return hmac.new(secret.encode(), code.encode(), hashlib.sha256).hexdigest()


def generate_secret_code(length: int = 10, symbols: bool = False, prefix: str = "") -> str:
    """
    Generate a cryptographically secure secret code.
    Options:
        - length: total length of code
        - symbols: whether to include special characters
        - prefix: optional string before code (e.g. "FITTECH-")
    """
    if length < 4:
        raise ValueError("Length must be at least 4")

    chars = string.ascii_uppercase + string.digits
    if symbols:
        chars += "!@#$%^&*"

    random_part = ''.join(secrets.choice(chars) for _ in range(length))
    return f"{prefix}{random_part}"


def create_secret_code(identifier: str, length: int = 10, symbols: bool = False, prefix: str = "") -> str:
    """Create and store a hashed code with expiry."""
    code = generate_secret_code(length, symbols, prefix)
    expiry = time.time() + CODE_TTL_SECONDS

    _store[identifier] = {
        "hash": _hash_code(code),
        "expires_at": expiry,
    }

    logging.info(f"Generated code for {identifier}, expires at {expiry}")
    return code


def verify_secret_code(identifier: str, provided_code: str) -> bool:
    """Verify a secret code for the given identifier."""
    meta = _store.get(identifier)
    now = time.time()

    if not meta:
        logging.warning(f"No code found for {identifier}")
        return False

    if now > meta["expires_at"]:
        logging.info(f"Code expired for {identifier}")
        _store.pop(identifier, None)
        return False

    expected_hash = meta["hash"]
    provided_hash = _hash_code(provided_code)

    if hmac.compare_digest(expected_hash, provided_hash):
        logging.info(f"Code verified for {identifier}")
        _store.pop(identifier, None)
        return True
    else:
        logging.warning(f"Invalid code for {identifier}")
        return False


# ---------- DEMO ----------
if __name__ == "__main__":
    print("🔐 Secret Code Generator Demo")

    identifier = input("Enter identifier (username, email, etc): ").strip()
    code = create_secret_code(identifier, length=8, symbols=False, prefix="FITTECH-")
    print(f"\n✅ Generated Secret Code: {code}")
    print("⚠️ (This will expire in 10 minutes)\n")

    user_input = input("Enter the secret code to verify: ").strip()
    if verify_secret_code(identifier, user_input):
        print("🎉 Verification successful!")
    else:
        print("❌ Invalid or expired code.")
