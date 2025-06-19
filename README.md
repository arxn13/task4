# AES-256 File Encryptor/Decryptor

This is a Python command-line tool to encrypt and decrypt files using AES-256 encryption with password-based key derivation.

## Features

- AES-256 encryption in CBC mode with PKCS7 padding.
- Password-based key derivation using PBKDF2 with a random salt.
- Encrypt and decrypt any file type.
- Simple CLI interface with password prompt or optional password argument.
- Proper exception handling for file errors, wrong passwords, and corrupted files.
- Comprehensive unit tests covering encryption, decryption, error handling, and edge cases.

## Requirements

- Python 3.7 or higher
- [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/) package

Install dependencies with:

```bash
pip install pycryptodome
```

## Usage

Encrypt a file:

```bash
python aes_file_encryptor.py encrypt <file_path>
```

Decrypt a file:

```bash
python aes_file_encryptor.py decrypt <file_path>
```

You will be prompted to enter the password. Alternatively, you can provide the password directly:

```bash
python aes_file_encryptor.py encrypt <file_path> --password yourpassword
python aes_file_encryptor.py decrypt <file_path> --password yourpassword
```

Encrypted files are saved with a `.enc` extension. Decrypted files remove the `.enc` extension or add `.dec` if not present.

## Testing

Unit tests are provided in `test_aes_file_encryptor.py`. Run tests with:

```bash
python -m unittest test_aes_file_encryptor.py
```

Tests cover:

- Encrypting and decrypting text, empty, and binary files.
- Handling wrong passwords.
- Handling missing files.

## License

This project is provided as-is under the MIT License.
import os
import unittest
import subprocess
import filecmp

class TestAESFileEncryptor(unittest.TestCase):
    """
    Unit tests for aes_file_encryptor.py CLI tool.
    Tests encryption, decryption, wrong password handling, and file not found errors.
    """

    def setUp(self):
        """
        Create sample files for testing:
        - text_file.txt: simple text content
        - empty_file.txt: empty file
        - binary_file.bin: 1KB random binary data
        """
        self.test_files = {
            "text_file.txt": b"Hello, this is a test file.",
            "empty_file.txt": b"",
            "binary_file.bin": os.urandom(1024),  # 1KB random binary data
        }
        for filename, content in self.test_files.items():
            with open(filename, "wb") as f:
                f.write(content)
        self.password = "testpassword"

    def tearDown(self):
        """
        Remove test files and any generated encrypted/decrypted files after tests.
        """
        for filename in self.test_files.keys():
            if os.path.exists(filename):
                os.remove(filename)
            enc_file = filename + ".enc"
            dec_file = filename
            if os.path.exists(enc_file):
                os.remove(enc_file)
            if os.path.exists(dec_file) and dec_file != filename:
                os.remove(dec_file)

    def run_encrypt(self, filename):
        """
        Run the CLI encrypt command on the given filename with the test password.
        """
        result = subprocess.run(
            ["python3", "aes_file_encryptor.py", "encrypt", filename, "--password", self.password],
            capture_output=True,
            text=True
        )
        return result

    def run_decrypt(self, filename, password=None):
        """
        Run the CLI decrypt command on the given filename with the specified password.
        If no password is provided, use the test password.
        """
        if password is None:
            password = self.password
        result = subprocess.run(
            ["python3", "aes_file_encryptor.py", "decrypt", filename, "--password", password],
            capture_output=True,
            text=True
        )
        return result

    def test_encrypt_decrypt(self):
        """
        Test encrypting and decrypting all sample files.
        Verify encrypted files are created and decrypted files match original content.
        """
        for filename in self.test_files.keys():
            # Encrypt
            enc_result = self.run_encrypt(filename)
            output = enc_result.stdout + enc_result.stderr
            self.assertIn("File encrypted successfully", output)
            enc_file = filename + ".enc"
            self.assertTrue(os.path.exists(enc_file))

            # Remove original file to test decryption output
            os.remove(filename)

            # Decrypt
            dec_result = self.run_decrypt(enc_file)
            output = dec_result.stdout + dec_result.stderr
            self.assertIn("File decrypted successfully", output)
            self.assertTrue(os.path.exists(filename))

            # Compare decrypted file with original content
            with open(filename, "rb") as f:
                decrypted_content = f.read()
            self.assertEqual(decrypted_content, self.test_files[filename])

    def test_wrong_password(self):
        """
        Test decrypting with a wrong password results in a decryption failure.
        """
        filename = "text_file.txt"
        self.run_encrypt(filename)
        enc_file = filename + ".enc"
        os.remove(filename)

        # Run decrypt with wrong password
        wrong_password = "wrongpassword"
        result = self.run_decrypt(enc_file, password=wrong_password)
        output = result.stdout + result.stderr
        self.assertIn("Decryption failed", output)

    def test_file_not_found(self):
        """
        Test encrypting and decrypting a nonexistent file results in file not found error.
        """
        result = subprocess.run(
            ["python3", "aes_file_encryptor.py", "encrypt", "nonexistent.file", "--password", self.password],
            capture_output=True,
            text=True
        )
        output = result.stdout + result.stderr
        self.assertIn("Error: File not found", output)

        result = subprocess.run(
            ["python3", "aes_file_encryptor.py", "decrypt", "nonexistent.file", "--password", self.password],
            capture_output=True,
            text=True
        )
        output = result.stdout + result.stderr
        self.assertIn("Error: File not found", output)

if __name__ == "__main__":
    unittest.main()
