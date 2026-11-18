
import unittest
import tempfile

from pathlib import Path

from hash_tool import (
    identify_hash,
    calculate_file_hash,
    compare_hashes
)


class TestHashTool(unittest.TestCase):

    def test_md5_identification(self):

        result = identify_hash(
            "5d41402abc4b2a76b9719d911017c592"
        )

        self.assertIn("MD5", result["candidates"])

    def test_sha256_identification(self):

        result = identify_hash(
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )

        self.assertIn("SHA-256", result["candidates"])

    def test_invalid_hash(self):

        result = identify_hash("hello world")

        self.assertEqual(
            result["format"],
            "Invalid"
        )

    def test_hash_comparison_match(self):

        self.assertTrue(
            compare_hashes("abc123", "ABC123")
        )

    def test_hash_comparison_different(self):

        self.assertFalse(
            compare_hashes("abc123", "def456")
        )

    def test_file_hashing(self):

        with tempfile.TemporaryDirectory() as folder:

            file_path = Path(folder) / "test.txt"

            file_path.write_text("hello world")

            result = calculate_file_hash(
                file_path,
                "sha256"
            )

            self.assertEqual(
                result,
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            )


if __name__ == "__main__":

    unittest.main()
