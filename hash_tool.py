
import hashlib
import hmac
import re
from pathlib import Path


# Common hash algorithms 
HASH_TYPES = {
    32: ["MD5", "NTLM"],
    40: ["SHA-1"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512"]
}


def identify_hash(hash_value):

    hash_value = hash_value.strip()

    # Check for bcrypt format
    bcrypt_pattern = r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"

    if re.fullmatch(bcrypt_pattern, hash_value):
        return {
            "input": hash_value,
            "format": "bcrypt",
            "length": len(hash_value),
            "candidates": ["bcrypt"],
            "status": "Recognized format"
        }

    # Check hexadecimal format
    if not re.fullmatch(r"[a-fA-F0-9]+", hash_value):
        return {
            "input": hash_value,
            "format": "Invalid",
            "length": len(hash_value),
            "candidates": [],
            "status": "Invalid hash format"
        }

    # Identify possible algorithms by length
    length = len(hash_value)

    candidates = HASH_TYPES.get(length, [])

    if candidates:
        status = "Possible algorithm match"
    else:
        status = "Unknown hash length"

    return {
        "input": hash_value,
        "format": "Hexadecimal",
        "length": length,
        "candidates": candidates,
        "status": status
    }


def calculate_file_hash(file_path, algorithm="sha256"):

    algorithm = algorithm.lower().replace("-", "")

    try:
        hasher = hashlib.new(algorithm)

    except ValueError:
        raise ValueError("Unsupported hashing algorithm.")

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError("File not found.")

    # Read the file in smaller chunks
    with path.open("rb") as file:

        for chunk in iter(lambda: file.read(4096), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def compare_hashes(hash_one, hash_two):

    hash_one = hash_one.strip().lower()
    hash_two = hash_two.strip().lower()

    if not hash_one or not hash_two:
        raise ValueError("Both hash values are required.")

    return hmac.compare_digest(hash_one, hash_two)
