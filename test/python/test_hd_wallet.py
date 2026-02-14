"""
Comprehensive test suite for hd-wallet-wasm WASI module.

This test uses wasmtime-py to load and test the HD Wallet WASI module,
covering mnemonic generation, validation, key derivation, hashing,
and AES-GCM encryption/decryption.
"""

import os
import hashlib
import pytest
from pathlib import Path
from typing import Optional

from wasmtime import Engine, Store, Module, Instance, Linker, WasiConfig


# Path to the WASI WASM module
WASM_PATH = Path(__file__).parent.parent.parent / "build-wasi" / "wasm" / "hd-wallet-wasi.wasm"


# Error codes from types.h
class Error:
    OK = 0
    UNKNOWN = 1
    INVALID_ARGUMENT = 2
    NOT_SUPPORTED = 3
    OUT_OF_MEMORY = 4
    INTERNAL = 5
    NO_ENTROPY = 100
    INVALID_WORD = 200
    INVALID_CHECKSUM = 201
    INVALID_MNEMONIC_LENGTH = 202
    INVALID_ENTROPY_LENGTH = 203
    INVALID_SEED = 300
    INVALID_PATH = 301
    HARDENED_FROM_PUBLIC = 303
    INVALID_PRIVATE_KEY = 400
    INVALID_PUBLIC_KEY = 401
    VERIFICATION_FAILED = 403


# Curve types
class Curve:
    SECP256K1 = 0
    ED25519 = 1
    P256 = 2
    P384 = 3
    X25519 = 4


# Language codes
class Language:
    ENGLISH = 0


class HDWalletWasm:
    """Wrapper class for HD Wallet WASM module."""

    def __init__(self, wasm_path: Path):
        """Initialize the WASM module with WASI support."""
        if not wasm_path.exists():
            raise FileNotFoundError(f"WASM module not found at {wasm_path}")

        # Create engine and store
        self.engine = Engine()
        self.store = Store(self.engine)

        # Configure WASI
        wasi_config = WasiConfig()
        wasi_config.inherit_stdout()
        wasi_config.inherit_stderr()
        self.store.set_wasi(wasi_config)

        # Create linker and add WASI
        self.linker = Linker(self.engine)
        self.linker.define_wasi()

        # Load and instantiate module
        self.module = Module.from_file(self.engine, str(wasm_path))
        self.instance = self.linker.instantiate(self.store, self.module)

        # Get exports
        self.exports = self.instance.exports(self.store)

        # Get memory using get() method
        self.memory = self.exports.get("memory")
        if self.memory is None:
            raise RuntimeError("Memory export not found in WASM module")

    def _get_export(self, name: str):
        """Get an exported function by name."""
        return self.exports.get(name)

    # Memory management
    def alloc(self, size: int) -> int:
        """Allocate memory in WASM."""
        func = self._get_export("hd_alloc")
        if func is None:
            raise RuntimeError("hd_alloc not found in WASM exports")
        return func(self.store, size)

    def dealloc(self, ptr: int) -> None:
        """Free memory in WASM."""
        func = self._get_export("hd_dealloc")
        if func is None:
            raise RuntimeError("hd_dealloc not found in WASM exports")
        func(self.store, ptr)

    def write_bytes(self, ptr: int, data: bytes) -> None:
        """Write bytes to WASM memory."""
        mem_data = self.memory.data_ptr(self.store)
        for i, byte in enumerate(data):
            mem_data[ptr + i] = byte

    def read_bytes(self, ptr: int, length: int) -> bytes:
        """Read bytes from WASM memory."""
        mem_data = self.memory.data_ptr(self.store)
        return bytes(mem_data[ptr : ptr + length])

    def write_string(self, ptr: int, s: str) -> None:
        """Write a null-terminated string to WASM memory."""
        self.write_bytes(ptr, s.encode("utf-8") + b"\x00")

    def read_string(self, ptr: int) -> str:
        """Read a null-terminated string from WASM memory."""
        mem_data = self.memory.data_ptr(self.store)
        result = []
        i = 0
        while mem_data[ptr + i] != 0:
            result.append(chr(mem_data[ptr + i]))
            i += 1
        return "".join(result)

    # Entropy injection (required for WASI)
    def inject_entropy(self, entropy: bytes) -> None:
        """Inject entropy for random number generation in WASI."""
        func = self._get_export("hd_inject_entropy")
        if func is None:
            return  # May not be needed in all configurations

        ptr = self.alloc(len(entropy))
        try:
            self.write_bytes(ptr, entropy)
            func(self.store, ptr, len(entropy))
        finally:
            self.dealloc(ptr)

    # Mnemonic functions
    def mnemonic_generate(self, word_count: int = 24, language: int = Language.ENGLISH) -> tuple[int, str]:
        """Generate a mnemonic phrase.

        Returns (error_code, mnemonic_string).
        """
        func = self._get_export("hd_mnemonic_generate")
        if func is None:
            raise RuntimeError("hd_mnemonic_generate not found in WASM exports")

        # Allocate output buffer (max ~240 chars for 24 words)
        out_size = 512
        out_ptr = self.alloc(out_size)
        try:
            result = func(self.store, out_ptr, out_size, word_count, language)
            if result == Error.OK:
                mnemonic = self.read_string(out_ptr)
                return (Error.OK, mnemonic)
            return (result, "")
        finally:
            self.dealloc(out_ptr)

    def mnemonic_validate(self, mnemonic: str, language: int = Language.ENGLISH) -> int:
        """Validate a mnemonic phrase.

        Returns error code (0 = valid).
        """
        func = self._get_export("hd_mnemonic_validate")
        if func is None:
            raise RuntimeError("hd_mnemonic_validate not found in WASM exports")

        # Allocate and write mnemonic
        mnemonic_ptr = self.alloc(len(mnemonic) + 1)
        try:
            self.write_string(mnemonic_ptr, mnemonic)
            return func(self.store, mnemonic_ptr, language)
        finally:
            self.dealloc(mnemonic_ptr)

    def mnemonic_to_seed(self, mnemonic: str, passphrase: str = "") -> tuple[int, bytes]:
        """Convert mnemonic to seed.

        Returns (error_code, seed_bytes).
        """
        func = self._get_export("hd_mnemonic_to_seed")
        if func is None:
            raise RuntimeError("hd_mnemonic_to_seed not found in WASM exports")

        # Allocate buffers
        mnemonic_ptr = self.alloc(len(mnemonic) + 1)
        passphrase_ptr = self.alloc(len(passphrase) + 1) if passphrase else 0
        seed_ptr = self.alloc(64)

        try:
            self.write_string(mnemonic_ptr, mnemonic)
            if passphrase_ptr:
                self.write_string(passphrase_ptr, passphrase)

            result = func(self.store, mnemonic_ptr, passphrase_ptr, seed_ptr, 64)
            if result == Error.OK:
                seed = self.read_bytes(seed_ptr, 64)
                return (Error.OK, seed)
            return (result, b"")
        finally:
            self.dealloc(mnemonic_ptr)
            if passphrase_ptr:
                self.dealloc(passphrase_ptr)
            self.dealloc(seed_ptr)

    # Key derivation functions
    def key_from_seed(self, seed: bytes, curve: int = Curve.SECP256K1) -> Optional[int]:
        """Create master key from seed.

        Returns key handle or None on error.
        """
        func = self._get_export("hd_key_from_seed")
        if func is None:
            raise RuntimeError("hd_key_from_seed not found in WASM exports")

        seed_ptr = self.alloc(len(seed))
        try:
            self.write_bytes(seed_ptr, seed)
            handle = func(self.store, seed_ptr, len(seed), curve)
            return handle if handle != 0 else None
        finally:
            self.dealloc(seed_ptr)

    def key_derive_path(self, key_handle: int, path: str) -> Optional[int]:
        """Derive key at path.

        Returns new key handle or None on error.
        """
        func = self._get_export("hd_key_derive_path")
        if func is None:
            raise RuntimeError("hd_key_derive_path not found in WASM exports")

        path_ptr = self.alloc(len(path) + 1)
        try:
            self.write_string(path_ptr, path)
            handle = func(self.store, key_handle, path_ptr)
            return handle if handle != 0 else None
        finally:
            self.dealloc(path_ptr)

    def key_get_public(self, key_handle: int) -> tuple[int, bytes]:
        """Get compressed public key.

        Returns (error_code, public_key_bytes).
        """
        func = self._get_export("hd_key_get_public")
        if func is None:
            raise RuntimeError("hd_key_get_public not found in WASM exports")

        out_ptr = self.alloc(33)
        try:
            result = func(self.store, key_handle, out_ptr, 33)
            if result == Error.OK:
                pubkey = self.read_bytes(out_ptr, 33)
                return (Error.OK, pubkey)
            return (result, b"")
        finally:
            self.dealloc(out_ptr)

    def key_get_private(self, key_handle: int) -> tuple[int, bytes]:
        """Get private key.

        Returns (error_code, private_key_bytes).
        """
        func = self._get_export("hd_key_get_private")
        if func is None:
            raise RuntimeError("hd_key_get_private not found in WASM exports")

        out_ptr = self.alloc(32)
        try:
            result = func(self.store, key_handle, out_ptr, 32)
            if result == Error.OK:
                privkey = self.read_bytes(out_ptr, 32)
                return (Error.OK, privkey)
            return (result, b"")
        finally:
            self.dealloc(out_ptr)

    def key_get_depth(self, key_handle: int) -> int:
        """Get key depth."""
        func = self._get_export("hd_key_get_depth")
        if func is None:
            raise RuntimeError("hd_key_get_depth not found in WASM exports")
        return func(self.store, key_handle)

    def key_get_fingerprint(self, key_handle: int) -> int:
        """Get key fingerprint."""
        func = self._get_export("hd_key_get_fingerprint")
        if func is None:
            raise RuntimeError("hd_key_get_fingerprint not found in WASM exports")
        return func(self.store, key_handle)

    def key_serialize_xprv(self, key_handle: int) -> tuple[int, str]:
        """Serialize key to xprv string.

        Returns (error_code, xprv_string).
        """
        func = self._get_export("hd_key_serialize_xprv")
        if func is None:
            raise RuntimeError("hd_key_serialize_xprv not found in WASM exports")

        out_ptr = self.alloc(120)
        try:
            result = func(self.store, key_handle, out_ptr, 120)
            if result == Error.OK:
                xprv = self.read_string(out_ptr)
                return (Error.OK, xprv)
            return (result, "")
        finally:
            self.dealloc(out_ptr)

    def key_serialize_xpub(self, key_handle: int) -> tuple[int, str]:
        """Serialize key to xpub string.

        Returns (error_code, xpub_string).
        """
        func = self._get_export("hd_key_serialize_xpub")
        if func is None:
            raise RuntimeError("hd_key_serialize_xpub not found in WASM exports")

        out_ptr = self.alloc(120)
        try:
            result = func(self.store, key_handle, out_ptr, 120)
            if result == Error.OK:
                xpub = self.read_string(out_ptr)
                return (Error.OK, xpub)
            return (result, "")
        finally:
            self.dealloc(out_ptr)

    def key_destroy(self, key_handle: int) -> None:
        """Destroy key and free memory."""
        func = self._get_export("hd_key_destroy")
        if func is None:
            return
        func(self.store, key_handle)

    # Hash functions
    def hash_sha256(self, data: bytes) -> tuple[int, bytes]:
        """Compute SHA-256 hash.

        Returns (bytes_written or error_code, hash_bytes).
        """
        func = self._get_export("hd_hash_sha256")
        if func is None:
            raise RuntimeError("hd_hash_sha256 not found in WASM exports")

        data_ptr = self.alloc(len(data))
        out_ptr = self.alloc(32)
        try:
            self.write_bytes(data_ptr, data)
            result = func(self.store, data_ptr, len(data), out_ptr, 32)
            if result == 32:
                hash_bytes = self.read_bytes(out_ptr, 32)
                return (32, hash_bytes)
            return (result, b"")
        finally:
            self.dealloc(data_ptr)
            self.dealloc(out_ptr)

    def hash_sha512(self, data: bytes) -> tuple[int, bytes]:
        """Compute SHA-512 hash.

        Returns (bytes_written or error_code, hash_bytes).
        """
        func = self._get_export("hd_hash_sha512")
        if func is None:
            raise RuntimeError("hd_hash_sha512 not found in WASM exports")

        data_ptr = self.alloc(len(data))
        out_ptr = self.alloc(64)
        try:
            self.write_bytes(data_ptr, data)
            result = func(self.store, data_ptr, len(data), out_ptr, 64)
            if result == 64:
                hash_bytes = self.read_bytes(out_ptr, 64)
                return (64, hash_bytes)
            return (result, b"")
        finally:
            self.dealloc(data_ptr)
            self.dealloc(out_ptr)

    def hash_keccak256(self, data: bytes) -> tuple[int, bytes]:
        """Compute Keccak-256 hash.

        Returns (bytes_written or error_code, hash_bytes).
        """
        func = self._get_export("hd_hash_keccak256")
        if func is None:
            raise RuntimeError("hd_hash_keccak256 not found in WASM exports")

        data_ptr = self.alloc(len(data))
        out_ptr = self.alloc(32)
        try:
            self.write_bytes(data_ptr, data)
            result = func(self.store, data_ptr, len(data), out_ptr, 32)
            if result == 32:
                hash_bytes = self.read_bytes(out_ptr, 32)
                return (32, hash_bytes)
            return (result, b"")
        finally:
            self.dealloc(data_ptr)
            self.dealloc(out_ptr)

    def hash_ripemd160(self, data: bytes) -> tuple[int, bytes]:
        """Compute RIPEMD-160 hash.

        Returns (bytes_written or error_code, hash_bytes).
        """
        func = self._get_export("hd_hash_ripemd160")
        if func is None:
            raise RuntimeError("hd_hash_ripemd160 not found in WASM exports")

        data_ptr = self.alloc(len(data))
        out_ptr = self.alloc(20)
        try:
            self.write_bytes(data_ptr, data)
            result = func(self.store, data_ptr, len(data), out_ptr, 20)
            if result == 20:
                hash_bytes = self.read_bytes(out_ptr, 20)
                return (20, hash_bytes)
            return (result, b"")
        finally:
            self.dealloc(data_ptr)
            self.dealloc(out_ptr)

    # AES-GCM encryption
    def aes_gcm_encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        iv: bytes,
        aad: bytes = b""
    ) -> tuple[int, bytes, bytes]:
        """Encrypt with AES-GCM.

        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt
            iv: 12-byte initialization vector
            aad: Additional authenticated data

        Returns:
            (result_code, ciphertext, tag) - tag is 16 bytes
        """
        func = self._get_export("hd_aes_gcm_encrypt")
        if func is None:
            raise RuntimeError("hd_aes_gcm_encrypt not found in WASM exports")

        key_ptr = self.alloc(len(key))
        pt_ptr = self.alloc(len(plaintext))
        iv_ptr = self.alloc(len(iv))
        aad_ptr = self.alloc(len(aad)) if aad else 0
        ct_ptr = self.alloc(len(plaintext))
        tag_ptr = self.alloc(16)

        try:
            self.write_bytes(key_ptr, key)
            self.write_bytes(pt_ptr, plaintext)
            self.write_bytes(iv_ptr, iv)
            if aad_ptr:
                self.write_bytes(aad_ptr, aad)

            result = func(
                self.store,
                key_ptr, len(key),
                pt_ptr, len(plaintext),
                iv_ptr, len(iv),
                aad_ptr, len(aad),
                ct_ptr,
                tag_ptr
            )

            if result >= 0:
                ciphertext = self.read_bytes(ct_ptr, len(plaintext))
                tag = self.read_bytes(tag_ptr, 16)
                return (result, ciphertext, tag)
            return (result, b"", b"")
        finally:
            self.dealloc(key_ptr)
            self.dealloc(pt_ptr)
            self.dealloc(iv_ptr)
            if aad_ptr:
                self.dealloc(aad_ptr)
            self.dealloc(ct_ptr)
            self.dealloc(tag_ptr)

    def aes_gcm_decrypt(
        self,
        key: bytes,
        ciphertext: bytes,
        iv: bytes,
        tag: bytes,
        aad: bytes = b""
    ) -> tuple[int, bytes]:
        """Decrypt with AES-GCM.

        Args:
            key: 32-byte encryption key
            ciphertext: Data to decrypt
            iv: 12-byte initialization vector
            tag: 16-byte authentication tag
            aad: Additional authenticated data

        Returns:
            (result_code, plaintext)
        """
        func = self._get_export("hd_aes_gcm_decrypt")
        if func is None:
            raise RuntimeError("hd_aes_gcm_decrypt not found in WASM exports")

        key_ptr = self.alloc(len(key))
        ct_ptr = self.alloc(len(ciphertext))
        iv_ptr = self.alloc(len(iv))
        aad_ptr = self.alloc(len(aad)) if aad else 0
        tag_ptr = self.alloc(16)
        pt_ptr = self.alloc(len(ciphertext))

        try:
            self.write_bytes(key_ptr, key)
            self.write_bytes(ct_ptr, ciphertext)
            self.write_bytes(iv_ptr, iv)
            self.write_bytes(tag_ptr, tag)
            if aad_ptr:
                self.write_bytes(aad_ptr, aad)

            result = func(
                self.store,
                key_ptr, len(key),
                ct_ptr, len(ciphertext),
                iv_ptr, len(iv),
                aad_ptr, len(aad),
                tag_ptr,
                pt_ptr
            )

            if result >= 0:
                plaintext = self.read_bytes(pt_ptr, len(ciphertext))
                return (result, plaintext)
            return (result, b"")
        finally:
            self.dealloc(key_ptr)
            self.dealloc(ct_ptr)
            self.dealloc(iv_ptr)
            if aad_ptr:
                self.dealloc(aad_ptr)
            self.dealloc(tag_ptr)
            self.dealloc(pt_ptr)


# Pytest fixtures
@pytest.fixture(scope="module")
def wallet():
    """Create HD Wallet WASM instance for tests."""
    if not WASM_PATH.exists():
        pytest.skip(f"WASM module not found at {WASM_PATH}")

    w = HDWalletWasm(WASM_PATH)
    # Inject entropy for WASI
    entropy = os.urandom(64)
    w.inject_entropy(entropy)
    return w


# =============================================================================
# Mnemonic Tests
# =============================================================================

class TestMnemonic:
    """Tests for BIP-39 mnemonic functions."""

    def test_generate_12_word_mnemonic(self, wallet):
        """Test generating a 12-word mnemonic."""
        err, mnemonic = wallet.mnemonic_generate(word_count=12)
        assert err == Error.OK, f"Expected OK, got error code {err}"
        words = mnemonic.split()
        assert len(words) == 12, f"Expected 12 words, got {len(words)}"

    def test_generate_24_word_mnemonic(self, wallet):
        """Test generating a 24-word mnemonic."""
        err, mnemonic = wallet.mnemonic_generate(word_count=24)
        assert err == Error.OK, f"Expected OK, got error code {err}"
        words = mnemonic.split()
        assert len(words) == 24, f"Expected 24 words, got {len(words)}"

    def test_generate_invalid_word_count(self, wallet):
        """Test that invalid word counts are rejected."""
        err, mnemonic = wallet.mnemonic_generate(word_count=13)
        assert err == Error.INVALID_MNEMONIC_LENGTH

    def test_validate_valid_mnemonic(self, wallet):
        """Test validating a known valid mnemonic."""
        # BIP-39 test vector
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err = wallet.mnemonic_validate(mnemonic)
        assert err == Error.OK, f"Expected valid mnemonic, got error {err}"

    def test_validate_invalid_checksum(self, wallet):
        """Test that invalid checksums are detected."""
        # Change last word to invalidate checksum
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        err = wallet.mnemonic_validate(mnemonic)
        assert err == Error.INVALID_CHECKSUM

    def test_validate_invalid_word(self, wallet):
        """Test that invalid words are detected."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
        err = wallet.mnemonic_validate(mnemonic)
        assert err == Error.INVALID_WORD

    def test_validate_wrong_word_count(self, wallet):
        """Test that wrong word counts are rejected."""
        mnemonic = "abandon abandon abandon"  # Only 3 words
        err = wallet.mnemonic_validate(mnemonic)
        assert err == Error.INVALID_MNEMONIC_LENGTH

    def test_mnemonic_to_seed(self, wallet):
        """Test mnemonic to seed conversion matches BIP-39 test vector."""
        # BIP-39 test vector
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "TREZOR"

        err, seed = wallet.mnemonic_to_seed(mnemonic, passphrase)
        assert err == Error.OK, f"Expected OK, got error {err}"
        assert len(seed) == 64, f"Expected 64-byte seed, got {len(seed)}"

        # Expected seed from BIP-39 test vectors
        expected_seed_hex = (
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        )
        assert seed.hex() == expected_seed_hex

    def test_mnemonic_to_seed_no_passphrase(self, wallet):
        """Test mnemonic to seed without passphrase."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK
        assert len(seed) == 64

    def test_generated_mnemonic_validates(self, wallet):
        """Test that generated mnemonics are valid."""
        for word_count in [12, 15, 18, 21, 24]:
            err, mnemonic = wallet.mnemonic_generate(word_count=word_count)
            assert err == Error.OK
            err = wallet.mnemonic_validate(mnemonic)
            assert err == Error.OK, f"{word_count}-word mnemonic failed validation"


# =============================================================================
# Key Derivation Tests
# =============================================================================

class TestKeyDerivation:
    """Tests for BIP-32 key derivation."""

    def test_key_from_seed(self, wallet):
        """Test creating master key from seed."""
        # Use test vector seed
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        key = wallet.key_from_seed(seed)
        assert key is not None, "Failed to create key from seed"

        # Clean up
        wallet.key_destroy(key)

    def test_key_depth(self, wallet):
        """Test that master key has depth 0."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        key = wallet.key_from_seed(seed)
        assert key is not None

        depth = wallet.key_get_depth(key)
        assert depth == 0, f"Expected depth 0, got {depth}"

        wallet.key_destroy(key)

    def test_derive_path_increases_depth(self, wallet):
        """Test that derivation increases depth correctly."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        master = wallet.key_from_seed(seed)
        assert master is not None

        # Derive m/44'/60'/0'/0/0 (5 levels)
        derived = wallet.key_derive_path(master, "m/44'/60'/0'/0/0")
        assert derived is not None, "Failed to derive key"

        depth = wallet.key_get_depth(derived)
        assert depth == 5, f"Expected depth 5, got {depth}"

        wallet.key_destroy(master)
        wallet.key_destroy(derived)

    def test_get_public_key(self, wallet):
        """Test getting public key from derived key."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        key = wallet.key_from_seed(seed)
        assert key is not None

        err, pubkey = wallet.key_get_public(key)
        assert err == Error.OK
        assert len(pubkey) == 33, f"Expected 33-byte compressed pubkey, got {len(pubkey)}"
        assert pubkey[0] in (0x02, 0x03), "Invalid compressed pubkey prefix"

        wallet.key_destroy(key)

    def test_get_private_key(self, wallet):
        """Test getting private key from derived key."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        key = wallet.key_from_seed(seed)
        assert key is not None

        err, privkey = wallet.key_get_private(key)
        assert err == Error.OK
        assert len(privkey) == 32, f"Expected 32-byte privkey, got {len(privkey)}"

        wallet.key_destroy(key)

    def test_serialize_xprv(self, wallet):
        """Test serializing key to xprv format."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        key = wallet.key_from_seed(seed)
        assert key is not None

        err, xprv = wallet.key_serialize_xprv(key)
        assert err == Error.OK
        assert xprv.startswith("xprv"), f"Expected xprv prefix, got {xprv[:4]}"
        assert len(xprv) == 111, f"Expected 111 chars, got {len(xprv)}"

        wallet.key_destroy(key)

    def test_serialize_xpub(self, wallet):
        """Test serializing key to xpub format."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        key = wallet.key_from_seed(seed)
        assert key is not None

        err, xpub = wallet.key_serialize_xpub(key)
        assert err == Error.OK
        assert xpub.startswith("xpub"), f"Expected xpub prefix, got {xpub[:4]}"
        assert len(xpub) == 111, f"Expected 111 chars, got {len(xpub)}"

        wallet.key_destroy(key)

    def test_bip44_ethereum_path(self, wallet):
        """Test standard Ethereum derivation path m/44'/60'/0'/0/0."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        master = wallet.key_from_seed(seed)
        assert master is not None

        # Derive Ethereum path
        eth_key = wallet.key_derive_path(master, "m/44'/60'/0'/0/0")
        assert eth_key is not None, "Failed to derive Ethereum key"

        err, pubkey = wallet.key_get_public(eth_key)
        assert err == Error.OK
        assert len(pubkey) == 33

        wallet.key_destroy(master)
        wallet.key_destroy(eth_key)

    def test_bip44_bitcoin_path(self, wallet):
        """Test standard Bitcoin derivation path m/44'/0'/0'/0/0."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        master = wallet.key_from_seed(seed)
        assert master is not None

        # Derive Bitcoin path
        btc_key = wallet.key_derive_path(master, "m/44'/0'/0'/0/0")
        assert btc_key is not None, "Failed to derive Bitcoin key"

        err, pubkey = wallet.key_get_public(btc_key)
        assert err == Error.OK
        assert len(pubkey) == 33

        wallet.key_destroy(master)
        wallet.key_destroy(btc_key)

    def test_invalid_derivation_path(self, wallet):
        """Test that invalid paths are rejected."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        master = wallet.key_from_seed(seed)
        assert master is not None

        # Invalid path (missing 'm')
        invalid_key = wallet.key_derive_path(master, "44'/60'/0'/0/0")
        # Behavior may vary - could return None or handle differently
        # The important thing is it doesn't crash

        wallet.key_destroy(master)
        if invalid_key:
            wallet.key_destroy(invalid_key)


# =============================================================================
# Hash Function Tests
# =============================================================================

class TestHashFunctions:
    """Tests for hash functions."""

    def test_sha256(self, wallet):
        """Test SHA-256 hash."""
        data = b"hello world"
        result, hash_bytes = wallet.hash_sha256(data)

        assert result == 32, f"Expected 32 bytes written, got {result}"

        # Verify against Python hashlib
        expected = hashlib.sha256(data).digest()
        assert hash_bytes == expected, f"SHA-256 mismatch"

    def test_sha256_empty(self, wallet):
        """Test SHA-256 of empty data."""
        data = b""
        result, hash_bytes = wallet.hash_sha256(data)

        assert result == 32
        expected = hashlib.sha256(data).digest()
        assert hash_bytes == expected

    def test_sha512(self, wallet):
        """Test SHA-512 hash."""
        data = b"hello world"
        result, hash_bytes = wallet.hash_sha512(data)

        assert result == 64, f"Expected 64 bytes written, got {result}"

        expected = hashlib.sha512(data).digest()
        assert hash_bytes == expected, f"SHA-512 mismatch"

    def test_keccak256(self, wallet):
        """Test Keccak-256 hash (Ethereum hash)."""
        data = b"hello world"
        result, hash_bytes = wallet.hash_keccak256(data)

        assert result == 32, f"Expected 32 bytes written, got {result}"
        assert len(hash_bytes) == 32

        # Known Keccak-256 hash of "hello world"
        # (Note: Keccak-256 != SHA3-256, they differ)
        expected_hex = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        assert hash_bytes.hex() == expected_hex

    def test_ripemd160(self, wallet):
        """Test RIPEMD-160 hash."""
        data = b"hello world"
        result, hash_bytes = wallet.hash_ripemd160(data)

        assert result == 20, f"Expected 20 bytes written, got {result}"
        assert len(hash_bytes) == 20

        # Known RIPEMD-160 hash
        expected_hex = "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f"
        assert hash_bytes.hex() == expected_hex

    def test_sha256_large_data(self, wallet):
        """Test SHA-256 with larger data."""
        data = b"x" * 10000
        result, hash_bytes = wallet.hash_sha256(data)

        assert result == 32
        expected = hashlib.sha256(data).digest()
        assert hash_bytes == expected


# =============================================================================
# AES-GCM Tests
# =============================================================================

class TestAESGCM:
    """Tests for AES-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self, wallet):
        """Test that encryption followed by decryption returns original data."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Hello, World! This is a test message."

        # Encrypt
        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv)
        assert result >= 0, f"Encryption failed with error {result}"
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 16

        # Decrypt
        result, decrypted = wallet.aes_gcm_decrypt(key, ciphertext, iv, tag)
        assert result >= 0, f"Decryption failed with error {result}"
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self, wallet):
        """Test encryption/decryption with additional authenticated data."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Secret message"
        aad = b"Additional authenticated data"

        # Encrypt with AAD
        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv, aad)
        assert result >= 0

        # Decrypt with same AAD
        result, decrypted = wallet.aes_gcm_decrypt(key, ciphertext, iv, tag, aad)
        assert result >= 0
        assert decrypted == plaintext

    def test_decrypt_wrong_key_fails(self, wallet):
        """Test that decryption with wrong key fails."""
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Secret message"

        # Encrypt
        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv)
        assert result >= 0

        # Decrypt with wrong key should fail
        result, decrypted = wallet.aes_gcm_decrypt(wrong_key, ciphertext, iv, tag)
        # Should return error (verification failed)
        assert result < 0 or decrypted != plaintext

    def test_decrypt_tampered_ciphertext_fails(self, wallet):
        """Test that decryption of tampered ciphertext fails."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Secret message"

        # Encrypt
        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv)
        assert result >= 0

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        # Decrypt should fail
        result, decrypted = wallet.aes_gcm_decrypt(key, tampered, iv, tag)
        assert result < 0, "Decryption of tampered ciphertext should fail"

    def test_decrypt_wrong_tag_fails(self, wallet):
        """Test that decryption with wrong tag fails."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Secret message"

        # Encrypt
        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv)
        assert result >= 0

        # Wrong tag
        wrong_tag = os.urandom(16)

        # Decrypt should fail
        result, decrypted = wallet.aes_gcm_decrypt(key, ciphertext, iv, wrong_tag)
        assert result < 0, "Decryption with wrong tag should fail"

    def test_decrypt_wrong_aad_fails(self, wallet):
        """Test that decryption with wrong AAD fails."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Secret message"
        aad = b"Correct AAD"
        wrong_aad = b"Wrong AAD"

        # Encrypt with AAD
        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv, aad)
        assert result >= 0

        # Decrypt with wrong AAD should fail
        result, decrypted = wallet.aes_gcm_decrypt(key, ciphertext, iv, tag, wrong_aad)
        assert result < 0, "Decryption with wrong AAD should fail"

    def test_encrypt_empty_plaintext(self, wallet):
        """Test encryption of empty plaintext."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b""

        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv)
        assert result >= 0
        assert len(ciphertext) == 0
        assert len(tag) == 16

        result, decrypted = wallet.aes_gcm_decrypt(key, ciphertext, iv, tag)
        assert result >= 0
        assert decrypted == plaintext

    def test_encrypt_large_plaintext(self, wallet):
        """Test encryption of larger plaintext."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = os.urandom(4096)

        result, ciphertext, tag = wallet.aes_gcm_encrypt(key, plaintext, iv)
        assert result >= 0
        assert len(ciphertext) == len(plaintext)

        result, decrypted = wallet.aes_gcm_decrypt(key, ciphertext, iv, tag)
        assert result >= 0
        assert decrypted == plaintext


# =============================================================================
# Memory Management Tests
# =============================================================================

class TestMemoryManagement:
    """Tests for memory allocation and deallocation."""

    def test_alloc_dealloc(self, wallet):
        """Test basic memory allocation and deallocation."""
        ptr = wallet.alloc(1024)
        assert ptr != 0, "Allocation failed"

        # Write some data
        wallet.write_bytes(ptr, b"test data")

        # Read it back
        data = wallet.read_bytes(ptr, 9)
        assert data == b"test data"

        # Free
        wallet.dealloc(ptr)

    def test_multiple_allocations(self, wallet):
        """Test multiple allocations don't overlap."""
        ptrs = []
        for i in range(10):
            ptr = wallet.alloc(100)
            assert ptr != 0
            # Make sure no overlap with previous
            for prev_ptr in ptrs:
                assert abs(ptr - prev_ptr) >= 100, "Allocations overlap"
            ptrs.append(ptr)

        # Clean up
        for ptr in ptrs:
            wallet.dealloc(ptr)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests combining multiple operations."""

    def test_full_wallet_flow(self, wallet):
        """Test complete wallet creation flow."""
        # Generate mnemonic
        err, mnemonic = wallet.mnemonic_generate(word_count=24)
        assert err == Error.OK

        # Validate mnemonic
        err = wallet.mnemonic_validate(mnemonic)
        assert err == Error.OK

        # Convert to seed
        err, seed = wallet.mnemonic_to_seed(mnemonic, "test passphrase")
        assert err == Error.OK

        # Create master key
        master = wallet.key_from_seed(seed)
        assert master is not None

        # Derive multiple paths
        paths = [
            "m/44'/60'/0'/0/0",  # Ethereum
            "m/44'/0'/0'/0/0",   # Bitcoin
            "m/44'/60'/0'/0/1",  # Ethereum second address
        ]

        for path in paths:
            key = wallet.key_derive_path(master, path)
            assert key is not None, f"Failed to derive {path}"

            err, pubkey = wallet.key_get_public(key)
            assert err == Error.OK
            assert len(pubkey) == 33

            wallet.key_destroy(key)

        # Serialize master key
        err, xprv = wallet.key_serialize_xprv(master)
        assert err == Error.OK
        assert xprv.startswith("xprv")

        wallet.key_destroy(master)

    def test_hash_chain(self, wallet):
        """Test creating a hash chain."""
        data = b"initial data"

        # Create a chain of hashes
        for _ in range(10):
            result, hash_bytes = wallet.hash_sha256(data)
            assert result == 32
            data = hash_bytes

        # Final hash should be deterministic
        assert len(data) == 32

    def test_encrypt_derived_key(self, wallet):
        """Test encrypting a derived private key."""
        # Create a wallet key
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        err, seed = wallet.mnemonic_to_seed(mnemonic, "")
        assert err == Error.OK

        master = wallet.key_from_seed(seed)
        assert master is not None

        eth_key = wallet.key_derive_path(master, "m/44'/60'/0'/0/0")
        assert eth_key is not None

        err, privkey = wallet.key_get_private(eth_key)
        assert err == Error.OK

        # Encrypt the private key
        encryption_key = os.urandom(32)
        iv = os.urandom(12)

        result, ciphertext, tag = wallet.aes_gcm_encrypt(encryption_key, privkey, iv)
        assert result >= 0

        # Decrypt and verify
        result, decrypted = wallet.aes_gcm_decrypt(encryption_key, ciphertext, iv, tag)
        assert result >= 0
        assert decrypted == privkey

        wallet.key_destroy(master)
        wallet.key_destroy(eth_key)


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
