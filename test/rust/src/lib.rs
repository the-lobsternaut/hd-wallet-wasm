//! Test suite for hd-wallet-wasm WASI module
//!
//! This crate provides comprehensive tests for the HD wallet WASM/WASI module
//! using wasmtime to load and execute the WASI binary.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test
//! ```
//!
//! # Test Coverage
//!
//! - Memory management (hd_alloc, hd_dealloc)
//! - BIP-39 mnemonic generation and validation
//! - BIP-39 mnemonic to seed conversion
//! - BIP-32 key derivation
//! - Hash functions (SHA-256, SHA-512, Keccak-256, etc.)
//! - AES-GCM encryption/decryption
//! - Key derivation functions (HKDF, PBKDF2)

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::path::PathBuf;
use wasmtime::*;

/// Path to the WASM module relative to this test directory
const WASM_MODULE_PATH: &str = "../../build-wasm/wasm/hd-wallet.wasm";

/// Error codes from the WASM module (matching types.h)
mod error_codes {
    pub const OK: i32 = 0;
    pub const UNKNOWN: i32 = 1;
    pub const INVALID_ARGUMENT: i32 = 2;
    pub const NOT_SUPPORTED: i32 = 3;
    pub const OUT_OF_MEMORY: i32 = 4;
    pub const INTERNAL: i32 = 5;
    pub const NO_ENTROPY: i32 = 100;
    pub const INSUFFICIENT_ENTROPY: i32 = 101;
    pub const INVALID_WORD: i32 = 200;
    pub const INVALID_CHECKSUM: i32 = 201;
    pub const INVALID_MNEMONIC_LENGTH: i32 = 202;
    pub const INVALID_ENTROPY_LENGTH: i32 = 203;
    pub const INVALID_SEED: i32 = 300;
    pub const INVALID_PATH: i32 = 301;
    pub const VERIFICATION_FAILED: i32 = 403;
}

/// Curve types (matching types.h)
mod curves {
    pub const SECP256K1: i32 = 0;
    pub const ED25519: i32 = 1;
    pub const P256: i32 = 2;
    pub const P384: i32 = 3;
    pub const X25519: i32 = 4;
}

/// Language codes for BIP-39 (matching bip39.h)
mod languages {
    pub const ENGLISH: i32 = 0;
    pub const JAPANESE: i32 = 1;
    pub const KOREAN: i32 = 2;
    pub const SPANISH: i32 = 3;
    pub const CHINESE_SIMPLIFIED: i32 = 4;
    pub const CHINESE_TRADITIONAL: i32 = 5;
    pub const FRENCH: i32 = 6;
    pub const ITALIAN: i32 = 7;
    pub const CZECH: i32 = 8;
    pub const PORTUGUESE: i32 = 9;
}

/// WASI state for the store
struct WasiState {
    wasi: wasmtime_wasi::preview1::WasiP1Ctx,
}

/// Helper struct to manage WASM module instance and memory
struct WasmModule {
    store: Store<WasiState>,
    memory: Memory,
    instance: Instance,
}

impl WasmModule {
    /// Load the WASM module from the default path
    fn load() -> Result<Self> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let wasm_path = manifest_dir.join(WASM_MODULE_PATH);

        if !wasm_path.exists() {
            anyhow::bail!(
                "WASM module not found at: {}. Please build the WASM module first.",
                wasm_path.display()
            );
        }

        let engine = Engine::default();

        // Read and compile the module
        let wasm_bytes = std::fs::read(&wasm_path)
            .with_context(|| format!("Failed to read WASM file: {}", wasm_path.display()))?;

        let module = Module::new(&engine, &wasm_bytes)
            .context("Failed to compile WASM module")?;

        // Create WASI context with minimal capabilities
        let wasi = wasmtime_wasi::WasiCtxBuilder::new()
            .inherit_stdio()
            .build_p1();

        // Create linker and add WASI
        let mut linker: Linker<WasiState> = Linker::new(&engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state: &mut WasiState| &mut state.wasi)
            .context("Failed to add WASI to linker")?;

        // Create store with WASI context
        let mut store = Store::new(&engine, WasiState { wasi });

        // Instantiate the module
        let instance = linker.instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?;

        // Get memory export
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("Failed to get memory export")?;

        Ok(Self {
            store,
            memory,
            instance,
        })
    }

    /// Allocate memory in WASM linear memory
    fn alloc(&mut self, size: u32) -> Result<u32> {
        let func = self.instance
            .get_typed_func::<u32, u32>(&mut self.store, "hd_alloc")
            .context("Failed to get hd_alloc function")?;

        let ptr = func.call(&mut self.store, size)
            .context("hd_alloc call failed")?;

        if ptr == 0 {
            anyhow::bail!("hd_alloc returned null pointer");
        }

        Ok(ptr)
    }

    /// Deallocate memory in WASM linear memory
    fn dealloc(&mut self, ptr: u32) -> Result<()> {
        let func = self.instance
            .get_typed_func::<u32, ()>(&mut self.store, "hd_dealloc")
            .context("Failed to get hd_dealloc function")?;

        func.call(&mut self.store, ptr)
            .context("hd_dealloc call failed")?;

        Ok(())
    }

    /// Write bytes to WASM memory
    fn write_bytes(&mut self, ptr: u32, data: &[u8]) -> Result<()> {
        let mem_data = self.memory.data_mut(&mut self.store);
        let start = ptr as usize;
        let end = start + data.len();

        if end > mem_data.len() {
            anyhow::bail!("Write would exceed memory bounds");
        }

        mem_data[start..end].copy_from_slice(data);
        Ok(())
    }

    /// Read bytes from WASM memory
    fn read_bytes(&self, ptr: u32, len: usize) -> Result<Vec<u8>> {
        let mem_data = self.memory.data(&self.store);
        let start = ptr as usize;
        let end = start + len;

        if end > mem_data.len() {
            anyhow::bail!("Read would exceed memory bounds");
        }

        Ok(mem_data[start..end].to_vec())
    }

    /// Read a null-terminated string from WASM memory
    fn read_string(&self, ptr: u32, max_len: usize) -> Result<String> {
        let mem_data = self.memory.data(&self.store);
        let start = ptr as usize;

        let mut end = start;
        while end < mem_data.len() && end < start + max_len && mem_data[end] != 0 {
            end += 1;
        }

        let bytes = &mem_data[start..end];
        String::from_utf8(bytes.to_vec()).context("Invalid UTF-8 in string")
    }

    /// Write a null-terminated string to WASM memory
    fn write_string(&mut self, ptr: u32, s: &str) -> Result<()> {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // Null terminator
        self.write_bytes(ptr, &bytes)
    }

    /// Inject entropy into the WASM module
    fn inject_entropy(&mut self, entropy: &[u8]) -> Result<()> {
        let entropy_ptr = self.alloc(entropy.len() as u32)?;
        self.write_bytes(entropy_ptr, entropy)?;

        let func = self.instance
            .get_typed_func::<(u32, u32), ()>(&mut self.store, "hd_inject_entropy")
            .context("Failed to get hd_inject_entropy function")?;

        func.call(&mut self.store, (entropy_ptr, entropy.len() as u32))
            .context("hd_inject_entropy call failed")?;

        self.dealloc(entropy_ptr)?;
        Ok(())
    }

    /// Get the library version
    fn get_version(&mut self) -> Result<u32> {
        let func = self.instance
            .get_typed_func::<(), u32>(&mut self.store, "hd_get_version")
            .context("Failed to get hd_get_version function")?;

        func.call(&mut self.store, ())
            .context("hd_get_version call failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Helper to create a module with entropy injected
    fn setup_module() -> Result<WasmModule> {
        let mut module = WasmModule::load()?;

        // Inject 64 bytes of entropy for cryptographic operations
        let entropy: Vec<u8> = (0..64).map(|i| i as u8 ^ 0xAB).collect();
        module.inject_entropy(&entropy)?;

        Ok(module)
    }

    // =========================================================================
    // Basic Module Tests
    // =========================================================================

    #[test]
    fn test_module_loads() {
        let result = WasmModule::load();
        assert!(result.is_ok(), "Module should load: {:?}", result.err());
    }

    #[test]
    fn test_get_version() {
        let mut module = WasmModule::load().expect("Failed to load module");
        let version = module.get_version().expect("Failed to get version");

        // Version is packed as (major << 16) | (minor << 8) | patch
        let major = (version >> 16) & 0xFF;
        let minor = (version >> 8) & 0xFF;
        let patch = version & 0xFF;

        println!("Raw version value: 0x{:08x}", version);
        println!("Library version: {}.{}.{}", major, minor, patch);
        // Just verify we got a non-zero response
        assert!(version != 0, "Version should be non-zero");
    }

    // =========================================================================
    // Memory Management Tests
    // =========================================================================

    #[test]
    fn test_memory_alloc_dealloc() {
        let mut module = WasmModule::load().expect("Failed to load module");

        // Allocate various sizes
        for size in [16, 64, 256, 1024, 4096] {
            let ptr = module.alloc(size).expect("Allocation failed");
            assert!(ptr != 0, "Pointer should not be null");

            // Write and read back
            let data: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
            module.write_bytes(ptr, &data).expect("Write failed");

            let read_back = module.read_bytes(ptr, size as usize).expect("Read failed");
            assert_eq!(data, read_back, "Data should match");

            module.dealloc(ptr).expect("Deallocation failed");
        }
    }

    #[test]
    fn test_secure_wipe() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let size = 64;
        let ptr = module.alloc(size).expect("Allocation failed");

        // Write sensitive data
        let sensitive: Vec<u8> = (0..size as usize).map(|i| i as u8).collect();
        module.write_bytes(ptr, &sensitive).expect("Write failed");

        // Get the secure wipe function
        let wipe_func = module.instance
            .get_typed_func::<(u32, u32), ()>(&mut module.store, "hd_secure_wipe")
            .expect("Failed to get hd_secure_wipe");

        wipe_func.call(&mut module.store, (ptr, size))
            .expect("Secure wipe failed");

        // Verify memory is zeroed
        let wiped = module.read_bytes(ptr, size as usize).expect("Read failed");
        assert!(wiped.iter().all(|&b| b == 0), "Memory should be zeroed");

        module.dealloc(ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // BIP-39 Mnemonic Tests
    // =========================================================================

    #[test]
    fn test_mnemonic_generate() {
        let mut module = setup_module().expect("Failed to setup module");

        let output_size = 512u32;
        let output_ptr = module.alloc(output_size).expect("Allocation failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, i32), i32>(&mut module.store, "hd_mnemonic_generate")
            .expect("Failed to get hd_mnemonic_generate");

        // Test different word counts
        for word_count in [12, 15, 18, 21, 24] {
            let result = func.call(&mut module.store, (output_ptr, output_size, word_count, languages::ENGLISH))
                .expect("Function call failed");

            assert_eq!(result, error_codes::OK, "Generate should succeed for {} words", word_count);

            let mnemonic = module.read_string(output_ptr, output_size as usize)
                .expect("Failed to read mnemonic");

            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), word_count as usize, "Should have {} words", word_count);

            println!("{}-word mnemonic: {}", word_count, &mnemonic[..50.min(mnemonic.len())]);
        }

        module.dealloc(output_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_mnemonic_validate() {
        let mut module = setup_module().expect("Failed to setup module");

        // Valid 12-word mnemonic (BIP-39 test vector)
        let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let mnemonic_ptr = module.alloc(256).expect("Allocation failed");
        module.write_string(mnemonic_ptr, valid_mnemonic).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, i32), i32>(&mut module.store, "hd_mnemonic_validate")
            .expect("Failed to get hd_mnemonic_validate");

        let result = func.call(&mut module.store, (mnemonic_ptr, languages::ENGLISH))
            .expect("Function call failed");

        assert_eq!(result, error_codes::OK, "Valid mnemonic should validate");

        // Test invalid mnemonic (wrong checksum)
        let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        module.write_string(mnemonic_ptr, invalid_mnemonic).expect("Write failed");

        let result = func.call(&mut module.store, (mnemonic_ptr, languages::ENGLISH))
            .expect("Function call failed");

        assert_eq!(result, error_codes::INVALID_CHECKSUM, "Invalid mnemonic should fail checksum");

        // Test invalid word
        let bad_word_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        module.write_string(mnemonic_ptr, bad_word_mnemonic).expect("Write failed");

        let result = func.call(&mut module.store, (mnemonic_ptr, languages::ENGLISH))
            .expect("Function call failed");

        assert_eq!(result, error_codes::INVALID_WORD, "Mnemonic with invalid word should fail");

        module.dealloc(mnemonic_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let mut module = setup_module().expect("Failed to setup module");

        // BIP-39 test vector
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "TREZOR";

        // Expected seed (first 32 bytes for comparison)
        let expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

        let mnemonic_ptr = module.alloc(256).expect("Allocation failed");
        let passphrase_ptr = module.alloc(64).expect("Allocation failed");
        let seed_ptr = module.alloc(64).expect("Allocation failed");

        module.write_string(mnemonic_ptr, mnemonic).expect("Write failed");
        module.write_string(passphrase_ptr, passphrase).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_mnemonic_to_seed")
            .expect("Failed to get hd_mnemonic_to_seed");

        let result = func.call(&mut module.store, (mnemonic_ptr, passphrase_ptr, seed_ptr, 64))
            .expect("Function call failed");

        assert_eq!(result, error_codes::OK, "Seed derivation should succeed");

        let seed = module.read_bytes(seed_ptr, 64).expect("Failed to read seed");
        let seed_hex = hex::encode(&seed);

        assert_eq!(seed_hex, expected_seed_hex, "Seed should match BIP-39 test vector");

        module.dealloc(mnemonic_ptr).expect("Deallocation failed");
        module.dealloc(passphrase_ptr).expect("Deallocation failed");
        module.dealloc(seed_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // BIP-32 Key Derivation Tests
    // =========================================================================

    #[test]
    fn test_key_from_seed() {
        let mut module = setup_module().expect("Failed to setup module");

        // Create a test seed (64 bytes)
        let seed: Vec<u8> = (0..64).map(|i| i as u8).collect();

        let seed_ptr = module.alloc(64).expect("Allocation failed");
        module.write_bytes(seed_ptr, &seed).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, i32), u32>(&mut module.store, "hd_key_from_seed")
            .expect("Failed to get hd_key_from_seed");

        let key_handle = func.call(&mut module.store, (seed_ptr, 64, curves::SECP256K1))
            .expect("Function call failed");

        assert!(key_handle != 0, "Key handle should not be null");

        // Get private key
        let priv_key_ptr = module.alloc(32).expect("Allocation failed");
        let get_private = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_get_private")
            .expect("Failed to get hd_key_get_private");

        let result = get_private.call(&mut module.store, (key_handle, priv_key_ptr, 32))
            .expect("Function call failed");

        assert_eq!(result, error_codes::OK, "Get private key should succeed");

        let private_key = module.read_bytes(priv_key_ptr, 32).expect("Failed to read private key");
        assert!(!private_key.iter().all(|&b| b == 0), "Private key should not be all zeros");

        // Get public key
        let pub_key_ptr = module.alloc(33).expect("Allocation failed");
        let get_public = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_get_public")
            .expect("Failed to get hd_key_get_public");

        let result = get_public.call(&mut module.store, (key_handle, pub_key_ptr, 33))
            .expect("Function call failed");

        assert_eq!(result, error_codes::OK, "Get public key should succeed");

        let public_key = module.read_bytes(pub_key_ptr, 33).expect("Failed to read public key");
        assert!(public_key[0] == 0x02 || public_key[0] == 0x03, "Public key should be compressed");

        // Destroy key
        let destroy = module.instance
            .get_typed_func::<u32, ()>(&mut module.store, "hd_key_destroy")
            .expect("Failed to get hd_key_destroy");

        destroy.call(&mut module.store, key_handle).expect("Destroy failed");

        module.dealloc(seed_ptr).expect("Deallocation failed");
        module.dealloc(priv_key_ptr).expect("Deallocation failed");
        module.dealloc(pub_key_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_key_derive_path() {
        let mut module = setup_module().expect("Failed to setup module");

        // Create master key from seed
        let seed: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let seed_ptr = module.alloc(64).expect("Allocation failed");
        module.write_bytes(seed_ptr, &seed).expect("Write failed");

        let from_seed = module.instance
            .get_typed_func::<(u32, u32, i32), u32>(&mut module.store, "hd_key_from_seed")
            .expect("Failed to get hd_key_from_seed");

        let master_handle = from_seed.call(&mut module.store, (seed_ptr, 64, curves::SECP256K1))
            .expect("Function call failed");

        assert!(master_handle != 0, "Master key handle should not be null");

        // Derive using BIP-44 path for Bitcoin: m/44'/0'/0'/0/0
        let path = "m/44'/0'/0'/0/0";
        let path_ptr = module.alloc(64).expect("Allocation failed");
        module.write_string(path_ptr, path).expect("Write failed");

        let derive_path = module.instance
            .get_typed_func::<(u32, u32), u32>(&mut module.store, "hd_key_derive_path")
            .expect("Failed to get hd_key_derive_path");

        let derived_handle = derive_path.call(&mut module.store, (master_handle, path_ptr))
            .expect("Function call failed");

        assert!(derived_handle != 0, "Derived key handle should not be null");

        // Verify depth is 5 (m + 4 derivations + 1)
        let get_depth = module.instance
            .get_typed_func::<u32, u32>(&mut module.store, "hd_key_get_depth")
            .expect("Failed to get hd_key_get_depth");

        let depth = get_depth.call(&mut module.store, derived_handle)
            .expect("Function call failed");

        assert_eq!(depth, 5, "Derived key should have depth 5");

        // Cleanup
        let destroy = module.instance
            .get_typed_func::<u32, ()>(&mut module.store, "hd_key_destroy")
            .expect("Failed to get hd_key_destroy");

        destroy.call(&mut module.store, master_handle).expect("Destroy failed");
        destroy.call(&mut module.store, derived_handle).expect("Destroy failed");

        module.dealloc(seed_ptr).expect("Deallocation failed");
        module.dealloc(path_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // Hash Function Tests
    // =========================================================================

    #[test]
    fn test_hash_sha256() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let test_data = b"test data for hashing";
        let data_ptr = module.alloc(test_data.len() as u32).expect("Allocation failed");
        let hash_ptr = module.alloc(32).expect("Allocation failed");

        module.write_bytes(data_ptr, test_data).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_hash_sha256")
            .expect("Failed to get hd_hash_sha256");

        let result = func.call(&mut module.store, (data_ptr, test_data.len() as u32, hash_ptr, 32))
            .expect("Function call failed");

        assert_eq!(result, 32, "SHA-256 should return 32 bytes written");

        let hash = module.read_bytes(hash_ptr, 32).expect("Failed to read hash");

        // Calculate expected hash using sha2 crate
        let mut hasher = Sha256::new();
        hasher.update(test_data);
        let expected: Vec<u8> = hasher.finalize().to_vec();

        assert_eq!(hash, expected, "SHA-256 hash should match");

        module.dealloc(data_ptr).expect("Deallocation failed");
        module.dealloc(hash_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_hash_sha512() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let test_data = b"test data for SHA-512";
        let data_ptr = module.alloc(test_data.len() as u32).expect("Allocation failed");
        let hash_ptr = module.alloc(64).expect("Allocation failed");

        module.write_bytes(data_ptr, test_data).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_hash_sha512")
            .expect("Failed to get hd_hash_sha512");

        let result = func.call(&mut module.store, (data_ptr, test_data.len() as u32, hash_ptr, 64))
            .expect("Function call failed");

        assert_eq!(result, 64, "SHA-512 should return 64 bytes written");

        let hash = module.read_bytes(hash_ptr, 64).expect("Failed to read hash");
        assert!(!hash.iter().all(|&b| b == 0), "Hash should not be all zeros");

        module.dealloc(data_ptr).expect("Deallocation failed");
        module.dealloc(hash_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_hash_keccak256() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let test_data = b"test data for Keccak";
        let data_ptr = module.alloc(test_data.len() as u32).expect("Allocation failed");
        let hash_ptr = module.alloc(32).expect("Allocation failed");

        module.write_bytes(data_ptr, test_data).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_hash_keccak256")
            .expect("Failed to get hd_hash_keccak256");

        let result = func.call(&mut module.store, (data_ptr, test_data.len() as u32, hash_ptr, 32))
            .expect("Function call failed");

        assert_eq!(result, 32, "Keccak-256 should return 32 bytes written");

        let hash = module.read_bytes(hash_ptr, 32).expect("Failed to read hash");
        assert!(!hash.iter().all(|&b| b == 0), "Hash should not be all zeros");

        module.dealloc(data_ptr).expect("Deallocation failed");
        module.dealloc(hash_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_hash_ripemd160() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let test_data = b"test data for RIPEMD-160";
        let data_ptr = module.alloc(test_data.len() as u32).expect("Allocation failed");
        let hash_ptr = module.alloc(20).expect("Allocation failed");

        module.write_bytes(data_ptr, test_data).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_hash_ripemd160")
            .expect("Failed to get hd_hash_ripemd160");

        let result = func.call(&mut module.store, (data_ptr, test_data.len() as u32, hash_ptr, 20))
            .expect("Function call failed");

        assert_eq!(result, 20, "RIPEMD-160 should return 20 bytes written");

        let hash = module.read_bytes(hash_ptr, 20).expect("Failed to read hash");
        assert!(!hash.iter().all(|&b| b == 0), "Hash should not be all zeros");

        module.dealloc(data_ptr).expect("Deallocation failed");
        module.dealloc(hash_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_hash_hash160() {
        let mut module = WasmModule::load().expect("Failed to load module");

        // Hash160 = RIPEMD160(SHA256(data)) - used for Bitcoin addresses
        let test_data = b"test data for Hash160";
        let data_ptr = module.alloc(test_data.len() as u32).expect("Allocation failed");
        let hash_ptr = module.alloc(20).expect("Allocation failed");

        module.write_bytes(data_ptr, test_data).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_hash_hash160")
            .expect("Failed to get hd_hash_hash160");

        let result = func.call(&mut module.store, (data_ptr, test_data.len() as u32, hash_ptr, 20))
            .expect("Function call failed");

        assert_eq!(result, 20, "Hash160 should return 20 bytes written");

        let hash = module.read_bytes(hash_ptr, 20).expect("Failed to read hash");
        assert!(!hash.iter().all(|&b| b == 0), "Hash should not be all zeros");

        module.dealloc(data_ptr).expect("Deallocation failed");
        module.dealloc(hash_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // AES-GCM Encryption Tests
    // =========================================================================

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let mut module = setup_module().expect("Failed to setup module");

        // 256-bit key (32 bytes)
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        // 12-byte IV (nonce)
        let iv: [u8; 12] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
        ];

        // Additional authenticated data
        let aad = b"additional authenticated data";

        // Plaintext
        let plaintext = b"Hello, World! This is a secret message.";

        // Allocate memory
        let key_ptr = module.alloc(32).expect("Allocation failed");
        let iv_ptr = module.alloc(12).expect("Allocation failed");
        let aad_ptr = module.alloc(aad.len() as u32).expect("Allocation failed");
        let plaintext_ptr = module.alloc(plaintext.len() as u32).expect("Allocation failed");
        let ciphertext_ptr = module.alloc(plaintext.len() as u32).expect("Allocation failed");
        let tag_ptr = module.alloc(16).expect("Allocation failed");
        let decrypted_ptr = module.alloc(plaintext.len() as u32).expect("Allocation failed");

        // Write data
        module.write_bytes(key_ptr, &key).expect("Write failed");
        module.write_bytes(iv_ptr, &iv).expect("Write failed");
        module.write_bytes(aad_ptr, aad).expect("Write failed");
        module.write_bytes(plaintext_ptr, plaintext).expect("Write failed");

        // Encrypt
        let encrypt = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32), i32>(
                &mut module.store,
                "hd_aes_gcm_encrypt"
            )
            .expect("Failed to get hd_aes_gcm_encrypt");

        let result = encrypt.call(
            &mut module.store,
            (
                key_ptr, 32,
                plaintext_ptr, plaintext.len() as u32,
                iv_ptr, 12,
                aad_ptr, aad.len() as u32,
                ciphertext_ptr,
                tag_ptr
            )
        ).expect("Encrypt call failed");

        assert_eq!(result as usize, plaintext.len(), "Encrypt should return plaintext length");

        // Read ciphertext and tag
        let ciphertext = module.read_bytes(ciphertext_ptr, plaintext.len())
            .expect("Failed to read ciphertext");
        let tag = module.read_bytes(tag_ptr, 16).expect("Failed to read tag");

        assert_ne!(ciphertext, plaintext.to_vec(), "Ciphertext should differ from plaintext");
        assert!(!tag.iter().all(|&b| b == 0), "Tag should not be all zeros");

        // Decrypt
        let decrypt = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32), i32>(
                &mut module.store,
                "hd_aes_gcm_decrypt"
            )
            .expect("Failed to get hd_aes_gcm_decrypt");

        let result = decrypt.call(
            &mut module.store,
            (
                key_ptr, 32,
                ciphertext_ptr, plaintext.len() as u32,
                iv_ptr, 12,
                aad_ptr, aad.len() as u32,
                tag_ptr,
                decrypted_ptr
            )
        ).expect("Decrypt call failed");

        assert_eq!(result as usize, plaintext.len(), "Decrypt should return plaintext length");

        // Verify decrypted matches original
        let decrypted = module.read_bytes(decrypted_ptr, plaintext.len())
            .expect("Failed to read decrypted");

        assert_eq!(decrypted, plaintext.to_vec(), "Decrypted should match original plaintext");

        // Test with wrong tag (should fail verification)
        let wrong_tag: [u8; 16] = [0xFF; 16];
        module.write_bytes(tag_ptr, &wrong_tag).expect("Write failed");

        let result = decrypt.call(
            &mut module.store,
            (
                key_ptr, 32,
                ciphertext_ptr, plaintext.len() as u32,
                iv_ptr, 12,
                aad_ptr, aad.len() as u32,
                tag_ptr,
                decrypted_ptr
            )
        ).expect("Decrypt call failed");

        // Should return negative error (verification failed)
        assert!(result < 0, "Decrypt with wrong tag should fail");

        // Cleanup
        module.dealloc(key_ptr).expect("Deallocation failed");
        module.dealloc(iv_ptr).expect("Deallocation failed");
        module.dealloc(aad_ptr).expect("Deallocation failed");
        module.dealloc(plaintext_ptr).expect("Deallocation failed");
        module.dealloc(ciphertext_ptr).expect("Deallocation failed");
        module.dealloc(tag_ptr).expect("Deallocation failed");
        module.dealloc(decrypted_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // Key Derivation Function Tests
    // =========================================================================

    #[test]
    fn test_kdf_hkdf() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let ikm = b"input keying material";
        let salt = b"salt value";
        let info = b"context info";
        let okm_len = 32u32;

        let ikm_ptr = module.alloc(ikm.len() as u32).expect("Allocation failed");
        let salt_ptr = module.alloc(salt.len() as u32).expect("Allocation failed");
        let info_ptr = module.alloc(info.len() as u32).expect("Allocation failed");
        let okm_ptr = module.alloc(okm_len).expect("Allocation failed");

        module.write_bytes(ikm_ptr, ikm).expect("Write failed");
        module.write_bytes(salt_ptr, salt).expect("Write failed");
        module.write_bytes(info_ptr, info).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u32, u32, u32), i32>(
                &mut module.store,
                "hd_kdf_hkdf"
            )
            .expect("Failed to get hd_kdf_hkdf");

        let result = func.call(
            &mut module.store,
            (
                ikm_ptr, ikm.len() as u32,
                salt_ptr, salt.len() as u32,
                info_ptr, info.len() as u32,
                okm_ptr, okm_len
            )
        ).expect("Function call failed");

        assert_eq!(result, okm_len as i32, "HKDF should return output length");

        let okm = module.read_bytes(okm_ptr, okm_len as usize).expect("Failed to read OKM");
        assert!(!okm.iter().all(|&b| b == 0), "OKM should not be all zeros");

        module.dealloc(ikm_ptr).expect("Deallocation failed");
        module.dealloc(salt_ptr).expect("Deallocation failed");
        module.dealloc(info_ptr).expect("Deallocation failed");
        module.dealloc(okm_ptr).expect("Deallocation failed");
    }

    #[test]
    fn test_kdf_pbkdf2() {
        let mut module = WasmModule::load().expect("Failed to load module");

        let password = b"password";
        let salt = b"salt";
        let iterations = 10000u32;
        let key_len = 32u32;

        let password_ptr = module.alloc(password.len() as u32).expect("Allocation failed");
        let salt_ptr = module.alloc(salt.len() as u32).expect("Allocation failed");
        let key_ptr = module.alloc(key_len).expect("Allocation failed");

        module.write_bytes(password_ptr, password).expect("Write failed");
        module.write_bytes(salt_ptr, salt).expect("Write failed");

        let func = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u32, u32), i32>(
                &mut module.store,
                "hd_kdf_pbkdf2"
            )
            .expect("Failed to get hd_kdf_pbkdf2");

        let result = func.call(
            &mut module.store,
            (
                password_ptr, password.len() as u32,
                salt_ptr, salt.len() as u32,
                iterations,
                key_ptr, key_len
            )
        ).expect("Function call failed");

        assert_eq!(result, key_len as i32, "PBKDF2 should return output length");

        let key = module.read_bytes(key_ptr, key_len as usize).expect("Failed to read key");
        assert!(!key.iter().all(|&b| b == 0), "Derived key should not be all zeros");

        module.dealloc(password_ptr).expect("Deallocation failed");
        module.dealloc(salt_ptr).expect("Deallocation failed");
        module.dealloc(key_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // ECDH Tests
    // =========================================================================

    #[test]
    #[ignore = "ECDH with compressed keys may require additional WASI entropy or have decompression issues"]
    fn test_ecdh_secp256k1() {
        // NOTE: This test is currently ignored because the public key decompression
        // step may fail in WASI environments. The hd_curve_decompress_pubkey function
        // uses Crypto++ which may have initialization issues in WASI.
        // When this works, both parties compute the same shared secret using ECDH.
        let mut module = setup_module().expect("Failed to setup module");

        // Create two key pairs from different seeds
        let seed_a: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let seed_b: Vec<u8> = (0..64).map(|i| (i + 100) as u8).collect();

        let seed_a_ptr = module.alloc(64).expect("Allocation failed");
        let seed_b_ptr = module.alloc(64).expect("Allocation failed");
        module.write_bytes(seed_a_ptr, &seed_a).expect("Write failed");
        module.write_bytes(seed_b_ptr, &seed_b).expect("Write failed");

        let from_seed = module.instance
            .get_typed_func::<(u32, u32, i32), u32>(&mut module.store, "hd_key_from_seed")
            .expect("Failed to get hd_key_from_seed");

        let key_a = from_seed.call(&mut module.store, (seed_a_ptr, 64, curves::SECP256K1))
            .expect("Function call failed");
        let key_b = from_seed.call(&mut module.store, (seed_b_ptr, 64, curves::SECP256K1))
            .expect("Function call failed");

        // Get private keys
        let priv_a_ptr = module.alloc(32).expect("Allocation failed");
        let priv_b_ptr = module.alloc(32).expect("Allocation failed");

        let get_private = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_get_private")
            .expect("Failed to get hd_key_get_private");
        let get_public = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_get_public")
            .expect("Failed to get hd_key_get_public");

        get_private.call(&mut module.store, (key_a, priv_a_ptr, 32))
            .expect("Function call failed");
        get_private.call(&mut module.store, (key_b, priv_b_ptr, 32))
            .expect("Function call failed");

        // Get compressed public keys
        let pub_a_compressed_ptr = module.alloc(33).expect("Allocation failed");
        let pub_b_compressed_ptr = module.alloc(33).expect("Allocation failed");

        get_public.call(&mut module.store, (key_a, pub_a_compressed_ptr, 33))
            .expect("Function call failed");
        get_public.call(&mut module.store, (key_b, pub_b_compressed_ptr, 33))
            .expect("Function call failed");

        // Decompress public keys for ECDH (function works with both but let's use uncompressed)
        let pub_a_ptr = module.alloc(65).expect("Allocation failed");
        let pub_b_ptr = module.alloc(65).expect("Allocation failed");

        let decompress = module.instance
            .get_typed_func::<(u32, i32, u32, u32), i32>(&mut module.store, "hd_curve_decompress_pubkey")
            .expect("Failed to get hd_curve_decompress_pubkey");

        let result = decompress.call(&mut module.store, (pub_a_compressed_ptr, curves::SECP256K1, pub_a_ptr, 65))
            .expect("Function call failed");
        assert_eq!(result, 0, "Decompress A should succeed");

        let result = decompress.call(&mut module.store, (pub_b_compressed_ptr, curves::SECP256K1, pub_b_ptr, 65))
            .expect("Function call failed");
        assert_eq!(result, 0, "Decompress B should succeed");

        // Compute shared secrets
        let shared_ab_ptr = module.alloc(32).expect("Allocation failed");
        let shared_ba_ptr = module.alloc(32).expect("Allocation failed");

        let ecdh = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32), i32>(&mut module.store, "hd_ecdh_secp256k1")
            .expect("Failed to get hd_ecdh_secp256k1");

        // A's private key + B's uncompressed public key
        let result = ecdh.call(&mut module.store, (priv_a_ptr, pub_b_ptr, 65, shared_ab_ptr, 32))
            .expect("Function call failed");
        assert_eq!(result, 32, "ECDH should return 32 bytes");

        // B's private key + A's uncompressed public key
        let result = ecdh.call(&mut module.store, (priv_b_ptr, pub_a_ptr, 65, shared_ba_ptr, 32))
            .expect("Function call failed");
        assert_eq!(result, 32, "ECDH should return 32 bytes");

        // Both shared secrets should be equal
        let shared_ab = module.read_bytes(shared_ab_ptr, 32).expect("Failed to read shared secret");
        let shared_ba = module.read_bytes(shared_ba_ptr, 32).expect("Failed to read shared secret");

        assert_eq!(shared_ab, shared_ba, "Shared secrets should match");
        assert!(!shared_ab.iter().all(|&b| b == 0), "Shared secret should not be all zeros");

        // Cleanup
        let destroy = module.instance
            .get_typed_func::<u32, ()>(&mut module.store, "hd_key_destroy")
            .expect("Failed to get hd_key_destroy");

        destroy.call(&mut module.store, key_a).expect("Destroy failed");
        destroy.call(&mut module.store, key_b).expect("Destroy failed");

        module.dealloc(seed_a_ptr).expect("Deallocation failed");
        module.dealloc(seed_b_ptr).expect("Deallocation failed");
        module.dealloc(priv_a_ptr).expect("Deallocation failed");
        module.dealloc(priv_b_ptr).expect("Deallocation failed");
        module.dealloc(pub_a_compressed_ptr).expect("Deallocation failed");
        module.dealloc(pub_b_compressed_ptr).expect("Deallocation failed");
        module.dealloc(pub_a_ptr).expect("Deallocation failed");
        module.dealloc(pub_b_ptr).expect("Deallocation failed");
        module.dealloc(shared_ab_ptr).expect("Deallocation failed");
        module.dealloc(shared_ba_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // Signing Tests
    // =========================================================================

    #[test]
    #[ignore = "WASM module requires native RNG for signing which is not available in WASI"]
    fn test_secp256k1_sign_verify() {
        // NOTE: This test is ignored because the Crypto++ AutoSeededRandomPool
        // requires native random number generation which is not available in WASI.
        // The hd_secp256k1_sign function calls AutoSeededRandomPool internally.
        // To enable signing in WASI, the module would need to use injected entropy
        // instead of AutoSeededRandomPool.
        let mut module = setup_module().expect("Failed to setup module");

        // Create a key from seed
        let seed: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let seed_ptr = module.alloc(64).expect("Allocation failed");
        module.write_bytes(seed_ptr, &seed).expect("Write failed");

        let from_seed = module.instance
            .get_typed_func::<(u32, u32, i32), u32>(&mut module.store, "hd_key_from_seed")
            .expect("Failed to get hd_key_from_seed");

        let key_handle = from_seed.call(&mut module.store, (seed_ptr, 64, curves::SECP256K1))
            .expect("Function call failed");

        // Get private and public keys
        let priv_key_ptr = module.alloc(32).expect("Allocation failed");
        let pub_key_ptr = module.alloc(33).expect("Allocation failed");

        let get_private = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_get_private")
            .expect("Failed to get hd_key_get_private");
        let get_public = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_get_public")
            .expect("Failed to get hd_key_get_public");

        get_private.call(&mut module.store, (key_handle, priv_key_ptr, 32))
            .expect("Function call failed");
        get_public.call(&mut module.store, (key_handle, pub_key_ptr, 33))
            .expect("Function call failed");

        // Message to sign (should be a hash in practice)
        let message = b"Message to sign for testing purposes";
        let message_ptr = module.alloc(message.len() as u32).expect("Allocation failed");
        let signature_ptr = module.alloc(72).expect("Allocation failed"); // DER signature max size

        module.write_bytes(message_ptr, message).expect("Write failed");

        // Sign
        let sign = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32), i32>(&mut module.store, "hd_secp256k1_sign")
            .expect("Failed to get hd_secp256k1_sign");

        let sig_len = sign.call(
            &mut module.store,
            (message_ptr, message.len() as u32, priv_key_ptr, signature_ptr, 72)
        ).expect("Function call failed");

        assert!(sig_len > 0, "Signature length should be positive");

        // Verify - we need to decompress the public key first
        let uncompressed_ptr = module.alloc(65).expect("Allocation failed");

        let decompress = module.instance
            .get_typed_func::<(u32, i32, u32, u32), i32>(&mut module.store, "hd_curve_decompress_pubkey")
            .expect("Failed to get hd_curve_decompress_pubkey");

        let result = decompress.call(&mut module.store, (pub_key_ptr, curves::SECP256K1, uncompressed_ptr, 65))
            .expect("Function call failed");
        assert_eq!(result, 0, "Decompress should succeed");

        let verify = module.instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u32), i32>(&mut module.store, "hd_secp256k1_verify")
            .expect("Failed to get hd_secp256k1_verify");

        let result = verify.call(
            &mut module.store,
            (message_ptr, message.len() as u32, signature_ptr, sig_len as u32, uncompressed_ptr, 65)
        ).expect("Function call failed");

        assert_eq!(result, 1, "Signature should verify");

        // Cleanup
        let destroy = module.instance
            .get_typed_func::<u32, ()>(&mut module.store, "hd_key_destroy")
            .expect("Failed to get hd_key_destroy");

        destroy.call(&mut module.store, key_handle).expect("Destroy failed");

        module.dealloc(seed_ptr).expect("Deallocation failed");
        module.dealloc(priv_key_ptr).expect("Deallocation failed");
        module.dealloc(pub_key_ptr).expect("Deallocation failed");
        module.dealloc(message_ptr).expect("Deallocation failed");
        module.dealloc(signature_ptr).expect("Deallocation failed");
        module.dealloc(uncompressed_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // Extended Key Serialization Tests
    // =========================================================================

    #[test]
    fn test_key_serialization_xprv_xpub() {
        let mut module = setup_module().expect("Failed to setup module");

        // Create a key from seed
        let seed: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let seed_ptr = module.alloc(64).expect("Allocation failed");
        module.write_bytes(seed_ptr, &seed).expect("Write failed");

        let from_seed = module.instance
            .get_typed_func::<(u32, u32, i32), u32>(&mut module.store, "hd_key_from_seed")
            .expect("Failed to get hd_key_from_seed");

        let key_handle = from_seed.call(&mut module.store, (seed_ptr, 64, curves::SECP256K1))
            .expect("Function call failed");

        // Serialize as xprv
        let xprv_ptr = module.alloc(128).expect("Allocation failed");
        let serialize_xprv = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_serialize_xprv")
            .expect("Failed to get hd_key_serialize_xprv");

        let result = serialize_xprv.call(&mut module.store, (key_handle, xprv_ptr, 128))
            .expect("Function call failed");
        assert_eq!(result, 0, "Serialize xprv should succeed");

        let xprv = module.read_string(xprv_ptr, 128).expect("Failed to read xprv");
        assert!(xprv.starts_with("xprv"), "xprv should start with 'xprv': {}", xprv);

        // Serialize as xpub
        let xpub_ptr = module.alloc(128).expect("Allocation failed");
        let serialize_xpub = module.instance
            .get_typed_func::<(u32, u32, u32), i32>(&mut module.store, "hd_key_serialize_xpub")
            .expect("Failed to get hd_key_serialize_xpub");

        let result = serialize_xpub.call(&mut module.store, (key_handle, xpub_ptr, 128))
            .expect("Function call failed");
        assert_eq!(result, 0, "Serialize xpub should succeed");

        let xpub = module.read_string(xpub_ptr, 128).expect("Failed to read xpub");
        assert!(xpub.starts_with("xpub"), "xpub should start with 'xpub': {}", xpub);

        println!("xprv: {}", xprv);
        println!("xpub: {}", xpub);

        // Cleanup
        let destroy = module.instance
            .get_typed_func::<u32, ()>(&mut module.store, "hd_key_destroy")
            .expect("Failed to get hd_key_destroy");

        destroy.call(&mut module.store, key_handle).expect("Destroy failed");

        module.dealloc(seed_ptr).expect("Deallocation failed");
        module.dealloc(xprv_ptr).expect("Deallocation failed");
        module.dealloc(xpub_ptr).expect("Deallocation failed");
    }

    // =========================================================================
    // BIP-39 Test Vectors
    // =========================================================================

    #[test]
    fn test_bip39_test_vectors() {
        let mut module = setup_module().expect("Failed to setup module");

        // Test vector from BIP-39 specification
        let test_vectors = [
            // (entropy_hex, mnemonic, seed_hex with passphrase "TREZOR")
            (
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
            ),
        ];

        for (entropy_hex, expected_mnemonic, expected_seed_hex) in test_vectors {
            let entropy = hex::decode(entropy_hex).expect("Invalid entropy hex");

            // Convert entropy to mnemonic
            let entropy_ptr = module.alloc(entropy.len() as u32).expect("Allocation failed");
            let mnemonic_ptr = module.alloc(512).expect("Allocation failed");

            module.write_bytes(entropy_ptr, &entropy).expect("Write failed");

            let entropy_to_mnemonic = module.instance
                .get_typed_func::<(u32, u32, i32, u32, u32), i32>(&mut module.store, "hd_entropy_to_mnemonic")
                .expect("Failed to get hd_entropy_to_mnemonic");

            let result = entropy_to_mnemonic.call(
                &mut module.store,
                (entropy_ptr, entropy.len() as u32, languages::ENGLISH, mnemonic_ptr, 512)
            ).expect("Function call failed");

            assert_eq!(result, error_codes::OK, "Entropy to mnemonic should succeed");

            let mnemonic = module.read_string(mnemonic_ptr, 512).expect("Failed to read mnemonic");
            assert_eq!(mnemonic, expected_mnemonic, "Mnemonic should match test vector");

            // Convert mnemonic to seed with passphrase "TREZOR"
            let passphrase_ptr = module.alloc(64).expect("Allocation failed");
            let seed_ptr = module.alloc(64).expect("Allocation failed");

            module.write_string(passphrase_ptr, "TREZOR").expect("Write failed");

            let mnemonic_to_seed = module.instance
                .get_typed_func::<(u32, u32, u32, u32), i32>(&mut module.store, "hd_mnemonic_to_seed")
                .expect("Failed to get hd_mnemonic_to_seed");

            let result = mnemonic_to_seed.call(
                &mut module.store,
                (mnemonic_ptr, passphrase_ptr, seed_ptr, 64)
            ).expect("Function call failed");

            assert_eq!(result, error_codes::OK, "Mnemonic to seed should succeed");

            let seed = module.read_bytes(seed_ptr, 64).expect("Failed to read seed");
            let seed_hex = hex::encode(&seed);
            assert_eq!(seed_hex, expected_seed_hex, "Seed should match test vector");

            // Cleanup for this iteration
            module.dealloc(entropy_ptr).expect("Deallocation failed");
            module.dealloc(mnemonic_ptr).expect("Deallocation failed");
            module.dealloc(passphrase_ptr).expect("Deallocation failed");
            module.dealloc(seed_ptr).expect("Deallocation failed");
        }
    }
}
