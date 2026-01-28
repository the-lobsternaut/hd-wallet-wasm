// Package hdwallet_test provides comprehensive tests for the hd-wallet-wasm WASI module
// using the wazero pure Go WebAssembly runtime.
package hdwallet_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// HDWallet wraps the WASM module instance and provides helper methods
type HDWallet struct {
	ctx      context.Context
	runtime  wazero.Runtime
	module   api.Module
	memory   api.Memory

	// Exported functions
	hdAlloc              api.Function
	hdDealloc            api.Function
	hdInjectEntropy      api.Function
	hdGetEntropyStatus   api.Function
	hdMnemonicGenerate   api.Function
	hdMnemonicValidate   api.Function
	hdMnemonicToSeed     api.Function
	hdKeyFromSeed        api.Function
	hdKeyDerivePath      api.Function
	hdKeyGetPrivate      api.Function
	hdKeyGetPublic       api.Function
	hdKeyDestroy         api.Function
	hdHashSha256         api.Function
	hdAesGcmEncrypt      api.Function
	hdAesGcmDecrypt      api.Function
}

// NewHDWallet creates a new HDWallet instance from the WASM module
func NewHDWallet(t *testing.T) *HDWallet {
	ctx := context.Background()

	// Create runtime
	runtime := wazero.NewRuntime(ctx)

	// Instantiate WASI
	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	// Find WASM file relative to test directory
	wasmPath := filepath.Join("..", "..", "build-wasm", "wasm", "hd-wallet.wasm")
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		// Try absolute path as fallback
		wasmPath = "/Users/tj/software/hd-wallet-wasm/build-wasm/wasm/hd-wallet.wasm"
		wasmBytes, err = os.ReadFile(wasmPath)
		if err != nil {
			t.Fatalf("Failed to read WASM file: %v", err)
		}
	}

	// Compile the module
	compiled, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		t.Fatalf("Failed to compile WASM module: %v", err)
	}

	// Instantiate the module
	config := wazero.NewModuleConfig().
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		WithStartFunctions() // Don't auto-run _start

	module, err := runtime.InstantiateModule(ctx, compiled, config)
	if err != nil {
		t.Fatalf("Failed to instantiate WASM module: %v", err)
	}

	hd := &HDWallet{
		ctx:     ctx,
		runtime: runtime,
		module:  module,
		memory:  module.Memory(),
	}

	// Get exported functions
	hd.hdAlloc = module.ExportedFunction("hd_alloc")
	hd.hdDealloc = module.ExportedFunction("hd_dealloc")
	hd.hdInjectEntropy = module.ExportedFunction("hd_inject_entropy")
	hd.hdGetEntropyStatus = module.ExportedFunction("hd_get_entropy_status")
	hd.hdMnemonicGenerate = module.ExportedFunction("hd_mnemonic_generate")
	hd.hdMnemonicValidate = module.ExportedFunction("hd_mnemonic_validate")
	hd.hdMnemonicToSeed = module.ExportedFunction("hd_mnemonic_to_seed")
	hd.hdKeyFromSeed = module.ExportedFunction("hd_key_from_seed")
	hd.hdKeyDerivePath = module.ExportedFunction("hd_key_derive_path")
	hd.hdKeyGetPrivate = module.ExportedFunction("hd_key_get_private")
	hd.hdKeyGetPublic = module.ExportedFunction("hd_key_get_public")
	hd.hdKeyDestroy = module.ExportedFunction("hd_key_destroy")
	hd.hdHashSha256 = module.ExportedFunction("hd_hash_sha256")
	hd.hdAesGcmEncrypt = module.ExportedFunction("hd_aes_gcm_encrypt")
	hd.hdAesGcmDecrypt = module.ExportedFunction("hd_aes_gcm_decrypt")

	// Verify required functions exist
	if hd.hdAlloc == nil {
		t.Fatal("hd_alloc function not found")
	}
	if hd.hdDealloc == nil {
		t.Fatal("hd_dealloc function not found")
	}

	return hd
}

// Close releases all resources
func (hd *HDWallet) Close() {
	if hd.module != nil {
		hd.module.Close(hd.ctx)
	}
	if hd.runtime != nil {
		hd.runtime.Close(hd.ctx)
	}
}

// Alloc allocates memory in WASM and returns the pointer
func (hd *HDWallet) Alloc(size uint32) (uint32, error) {
	results, err := hd.hdAlloc.Call(hd.ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("hd_alloc failed: %w", err)
	}
	ptr := uint32(results[0])
	if ptr == 0 {
		return 0, fmt.Errorf("hd_alloc returned null pointer")
	}
	return ptr, nil
}

// Dealloc frees memory in WASM
func (hd *HDWallet) Dealloc(ptr uint32) {
	if ptr != 0 {
		hd.hdDealloc.Call(hd.ctx, uint64(ptr))
	}
}

// WriteBytes writes bytes to WASM memory at the given pointer
func (hd *HDWallet) WriteBytes(ptr uint32, data []byte) error {
	if !hd.memory.Write(ptr, data) {
		return fmt.Errorf("failed to write %d bytes to WASM memory at 0x%x", len(data), ptr)
	}
	return nil
}

// ReadBytes reads bytes from WASM memory and returns a copy
func (hd *HDWallet) ReadBytes(ptr uint32, size uint32) ([]byte, error) {
	data, ok := hd.memory.Read(ptr, size)
	if !ok {
		return nil, fmt.Errorf("failed to read %d bytes from WASM memory at 0x%x", size, ptr)
	}
	// Always return a copy to avoid issues with internal memory references
	result := make([]byte, size)
	copy(result, data)
	return result, nil
}

// WriteString writes a null-terminated string to WASM memory
func (hd *HDWallet) WriteString(ptr uint32, s string) error {
	data := append([]byte(s), 0) // null-terminate
	return hd.WriteBytes(ptr, data)
}

// ReadString reads a null-terminated string from WASM memory
func (hd *HDWallet) ReadString(ptr uint32, maxLen uint32) (string, error) {
	data, err := hd.ReadBytes(ptr, maxLen)
	if err != nil {
		return "", err
	}
	// Find null terminator
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), nil
		}
	}
	return string(data), nil
}

// AllocAndWrite allocates memory and writes data to it
func (hd *HDWallet) AllocAndWrite(data []byte) (uint32, error) {
	ptr, err := hd.Alloc(uint32(len(data)))
	if err != nil {
		return 0, err
	}
	if err := hd.WriteBytes(ptr, data); err != nil {
		hd.Dealloc(ptr)
		return 0, err
	}
	return ptr, nil
}

// AllocAndWriteString allocates memory and writes a null-terminated string
func (hd *HDWallet) AllocAndWriteString(s string) (uint32, error) {
	data := append([]byte(s), 0)
	return hd.AllocAndWrite(data)
}

// InjectEntropy injects entropy into the WASM module
func (hd *HDWallet) InjectEntropy(entropy []byte) error {
	if hd.hdInjectEntropy == nil {
		return fmt.Errorf("hd_inject_entropy function not found")
	}

	ptr, err := hd.AllocAndWrite(entropy)
	if err != nil {
		return err
	}
	defer hd.Dealloc(ptr)

	_, err = hd.hdInjectEntropy.Call(hd.ctx, uint64(ptr), uint64(len(entropy)))
	return err
}

// GetEntropyStatus returns the current entropy status
func (hd *HDWallet) GetEntropyStatus() (int32, error) {
	if hd.hdGetEntropyStatus == nil {
		return 0, fmt.Errorf("hd_get_entropy_status function not found")
	}

	results, err := hd.hdGetEntropyStatus.Call(hd.ctx)
	if err != nil {
		return 0, err
	}
	return int32(results[0]), nil
}

// GenerateMnemonic generates a new mnemonic phrase
func (hd *HDWallet) GenerateMnemonic(wordCount int32, language int32) (string, error) {
	if hd.hdMnemonicGenerate == nil {
		return "", fmt.Errorf("hd_mnemonic_generate function not found")
	}

	// Allocate output buffer
	outputSize := uint32(512)
	outputPtr, err := hd.Alloc(outputSize)
	if err != nil {
		return "", err
	}
	defer hd.Dealloc(outputPtr)

	// Call function
	results, err := hd.hdMnemonicGenerate.Call(hd.ctx,
		uint64(outputPtr), uint64(outputSize),
		uint64(wordCount), uint64(language))
	if err != nil {
		return "", fmt.Errorf("hd_mnemonic_generate call failed: %w", err)
	}

	result := int32(results[0])
	if result < 0 {
		return "", fmt.Errorf("hd_mnemonic_generate returned error code: %d", result)
	}

	// Read mnemonic string
	return hd.ReadString(outputPtr, outputSize)
}

// ValidateMnemonic validates a mnemonic phrase
func (hd *HDWallet) ValidateMnemonic(mnemonic string, language int32) (int32, error) {
	if hd.hdMnemonicValidate == nil {
		return 0, fmt.Errorf("hd_mnemonic_validate function not found")
	}

	mnemonicPtr, err := hd.AllocAndWriteString(mnemonic)
	if err != nil {
		return 0, err
	}
	defer hd.Dealloc(mnemonicPtr)

	results, err := hd.hdMnemonicValidate.Call(hd.ctx, uint64(mnemonicPtr), uint64(language))
	if err != nil {
		return 0, fmt.Errorf("hd_mnemonic_validate call failed: %w", err)
	}

	return int32(results[0]), nil
}

// MnemonicToSeed converts a mnemonic to a 64-byte seed
func (hd *HDWallet) MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	if hd.hdMnemonicToSeed == nil {
		return nil, fmt.Errorf("hd_mnemonic_to_seed function not found")
	}

	mnemonicPtr, err := hd.AllocAndWriteString(mnemonic)
	if err != nil {
		return nil, err
	}
	defer hd.Dealloc(mnemonicPtr)

	passphrasePtr, err := hd.AllocAndWriteString(passphrase)
	if err != nil {
		return nil, err
	}
	defer hd.Dealloc(passphrasePtr)

	seedSize := uint32(64)
	seedPtr, err := hd.Alloc(seedSize)
	if err != nil {
		return nil, err
	}
	defer hd.Dealloc(seedPtr)

	results, err := hd.hdMnemonicToSeed.Call(hd.ctx,
		uint64(mnemonicPtr), uint64(passphrasePtr),
		uint64(seedPtr), uint64(seedSize))
	if err != nil {
		return nil, fmt.Errorf("hd_mnemonic_to_seed call failed: %w", err)
	}

	result := int32(results[0])
	if result != 0 {
		return nil, fmt.Errorf("hd_mnemonic_to_seed returned error code: %d", result)
	}

	return hd.ReadBytes(seedPtr, seedSize)
}

// KeyFromSeed creates an HD key from a seed
// Returns a 32-bit handle (even though wazero returns uint64)
func (hd *HDWallet) KeyFromSeed(seed []byte, curve int32) (uint32, error) {
	if hd.hdKeyFromSeed == nil {
		return 0, fmt.Errorf("hd_key_from_seed function not found")
	}

	seedPtr, err := hd.AllocAndWrite(seed)
	if err != nil {
		return 0, err
	}
	defer hd.Dealloc(seedPtr)

	results, err := hd.hdKeyFromSeed.Call(hd.ctx,
		uint64(seedPtr), uint64(len(seed)), uint64(curve))
	if err != nil {
		return 0, fmt.Errorf("hd_key_from_seed call failed: %w", err)
	}

	// Handle is a 32-bit pointer in WASM
	return uint32(results[0]), nil
}

// KeyDerivePath derives a key at a path
// Returns a 32-bit handle (even though wazero returns uint64)
func (hd *HDWallet) KeyDerivePath(keyHandle uint32, path string) (uint32, error) {
	if hd.hdKeyDerivePath == nil {
		return 0, fmt.Errorf("hd_key_derive_path function not found")
	}

	pathPtr, err := hd.AllocAndWriteString(path)
	if err != nil {
		return 0, err
	}
	defer hd.Dealloc(pathPtr)

	results, err := hd.hdKeyDerivePath.Call(hd.ctx, uint64(keyHandle), uint64(pathPtr))
	if err != nil {
		return 0, fmt.Errorf("hd_key_derive_path call failed: %w", err)
	}

	// Handle is a 32-bit pointer in WASM
	return uint32(results[0]), nil
}

// KeyGetPrivate gets the private key bytes
func (hd *HDWallet) KeyGetPrivate(keyHandle uint32) ([]byte, error) {
	if hd.hdKeyGetPrivate == nil {
		return nil, fmt.Errorf("hd_key_get_private function not found")
	}

	outSize := uint32(32)
	outPtr, err := hd.Alloc(outSize)
	if err != nil {
		return nil, err
	}

	results, err := hd.hdKeyGetPrivate.Call(hd.ctx, uint64(keyHandle), uint64(outPtr), uint64(outSize))
	if err != nil {
		hd.Dealloc(outPtr)
		return nil, fmt.Errorf("hd_key_get_private call failed: %w", err)
	}

	result := int32(results[0])
	if result != 0 {
		hd.Dealloc(outPtr)
		return nil, fmt.Errorf("hd_key_get_private returned error code: %d", result)
	}

	// Read immediately after call, then deallocate
	data, err := hd.ReadBytes(outPtr, 32)
	hd.Dealloc(outPtr)
	if err != nil {
		return nil, err
	}

	// Make a copy to avoid any memory issues
	result_copy := make([]byte, 32)
	copy(result_copy, data)
	return result_copy, nil
}

// KeyGetPublic gets the public key bytes (compressed, 33 bytes)
func (hd *HDWallet) KeyGetPublic(keyHandle uint32) ([]byte, error) {
	if hd.hdKeyGetPublic == nil {
		return nil, fmt.Errorf("hd_key_get_public function not found")
	}

	outSize := uint32(33) // compressed public key
	outPtr, err := hd.Alloc(outSize)
	if err != nil {
		return nil, err
	}

	results, err := hd.hdKeyGetPublic.Call(hd.ctx, uint64(keyHandle), uint64(outPtr), uint64(outSize))
	if err != nil {
		hd.Dealloc(outPtr)
		return nil, fmt.Errorf("hd_key_get_public call failed: %w", err)
	}

	result := int32(results[0])
	if result != 0 {
		hd.Dealloc(outPtr)
		return nil, fmt.Errorf("hd_key_get_public returned error code: %d", result)
	}

	// Read immediately after call, then deallocate
	data, err := hd.ReadBytes(outPtr, 33)
	hd.Dealloc(outPtr)
	if err != nil {
		return nil, err
	}

	// Make a copy to avoid any memory issues
	result_copy := make([]byte, 33)
	copy(result_copy, data)
	return result_copy, nil
}

// KeyDestroy destroys a key handle
func (hd *HDWallet) KeyDestroy(keyHandle uint32) {
	if hd.hdKeyDestroy != nil && keyHandle != 0 {
		hd.hdKeyDestroy.Call(hd.ctx, uint64(keyHandle))
	}
}

// HashSHA256 computes SHA-256 hash
func (hd *HDWallet) HashSHA256(data []byte) ([]byte, error) {
	if hd.hdHashSha256 == nil {
		return nil, fmt.Errorf("hd_hash_sha256 function not found")
	}

	dataPtr, err := hd.AllocAndWrite(data)
	if err != nil {
		return nil, err
	}
	defer hd.Dealloc(dataPtr)

	outSize := uint32(32)
	outPtr, err := hd.Alloc(outSize)
	if err != nil {
		return nil, err
	}
	defer hd.Dealloc(outPtr)

	results, err := hd.hdHashSha256.Call(hd.ctx,
		uint64(dataPtr), uint64(len(data)),
		uint64(outPtr), uint64(outSize))
	if err != nil {
		return nil, fmt.Errorf("hd_hash_sha256 call failed: %w", err)
	}

	result := int32(results[0])
	if result < 0 {
		return nil, fmt.Errorf("hd_hash_sha256 returned error code: %d", result)
	}

	return hd.ReadBytes(outPtr, outSize)
}

// AesGcmEncrypt encrypts data using AES-GCM
func (hd *HDWallet) AesGcmEncrypt(key, plaintext, iv, aad []byte) (ciphertext, tag []byte, err error) {
	if hd.hdAesGcmEncrypt == nil {
		return nil, nil, fmt.Errorf("hd_aes_gcm_encrypt function not found")
	}

	// Allocate memory for inputs
	keyPtr, err := hd.AllocAndWrite(key)
	if err != nil {
		return nil, nil, err
	}

	ptPtr, err := hd.AllocAndWrite(plaintext)
	if err != nil {
		hd.Dealloc(keyPtr)
		return nil, nil, err
	}

	ivPtr, err := hd.AllocAndWrite(iv)
	if err != nil {
		hd.Dealloc(keyPtr)
		hd.Dealloc(ptPtr)
		return nil, nil, err
	}

	var aadPtr uint32 = 0
	if len(aad) > 0 {
		aadPtr, err = hd.AllocAndWrite(aad)
		if err != nil {
			hd.Dealloc(keyPtr)
			hd.Dealloc(ptPtr)
			hd.Dealloc(ivPtr)
			return nil, nil, err
		}
	}

	// Allocate output buffers
	ctPtr, err := hd.Alloc(uint32(len(plaintext)))
	if err != nil {
		hd.Dealloc(keyPtr)
		hd.Dealloc(ptPtr)
		hd.Dealloc(ivPtr)
		if aadPtr != 0 {
			hd.Dealloc(aadPtr)
		}
		return nil, nil, err
	}

	tagPtr, err := hd.Alloc(16)
	if err != nil {
		hd.Dealloc(keyPtr)
		hd.Dealloc(ptPtr)
		hd.Dealloc(ivPtr)
		if aadPtr != 0 {
			hd.Dealloc(aadPtr)
		}
		hd.Dealloc(ctPtr)
		return nil, nil, err
	}

	// Call function
	results, err := hd.hdAesGcmEncrypt.Call(hd.ctx,
		uint64(keyPtr), uint64(len(key)),
		uint64(ptPtr), uint64(len(plaintext)),
		uint64(ivPtr), uint64(len(iv)),
		uint64(aadPtr), uint64(len(aad)),
		uint64(ctPtr), uint64(tagPtr))

	// Read results immediately before any deallocation
	var ctData, tagData []byte
	if err == nil {
		result := int32(results[0])
		if result >= 0 {
			ctData, _ = hd.ReadBytes(ctPtr, uint32(len(plaintext)))
			tagData, _ = hd.ReadBytes(tagPtr, 16)
		} else {
			err = fmt.Errorf("hd_aes_gcm_encrypt returned error code: %d", result)
		}
	} else {
		err = fmt.Errorf("hd_aes_gcm_encrypt call failed: %w", err)
	}

	// Now deallocate all memory
	hd.Dealloc(keyPtr)
	hd.Dealloc(ptPtr)
	hd.Dealloc(ivPtr)
	if aadPtr != 0 {
		hd.Dealloc(aadPtr)
	}
	hd.Dealloc(ctPtr)
	hd.Dealloc(tagPtr)

	if err != nil {
		return nil, nil, err
	}

	// Make copies
	ciphertext = make([]byte, len(plaintext))
	copy(ciphertext, ctData)
	tag = make([]byte, 16)
	copy(tag, tagData)

	return ciphertext, tag, nil
}

// AesGcmDecrypt decrypts data using AES-GCM
func (hd *HDWallet) AesGcmDecrypt(key, ciphertext, iv, aad, tag []byte) ([]byte, error) {
	if hd.hdAesGcmDecrypt == nil {
		return nil, fmt.Errorf("hd_aes_gcm_decrypt function not found")
	}

	// Allocate memory for inputs
	keyPtr, err := hd.AllocAndWrite(key)
	if err != nil {
		return nil, err
	}

	ctPtr, err := hd.AllocAndWrite(ciphertext)
	if err != nil {
		hd.Dealloc(keyPtr)
		return nil, err
	}

	ivPtr, err := hd.AllocAndWrite(iv)
	if err != nil {
		hd.Dealloc(keyPtr)
		hd.Dealloc(ctPtr)
		return nil, err
	}

	var aadPtr uint32 = 0
	if len(aad) > 0 {
		aadPtr, err = hd.AllocAndWrite(aad)
		if err != nil {
			hd.Dealloc(keyPtr)
			hd.Dealloc(ctPtr)
			hd.Dealloc(ivPtr)
			return nil, err
		}
	}

	tagPtr, err := hd.AllocAndWrite(tag)
	if err != nil {
		hd.Dealloc(keyPtr)
		hd.Dealloc(ctPtr)
		hd.Dealloc(ivPtr)
		if aadPtr != 0 {
			hd.Dealloc(aadPtr)
		}
		return nil, err
	}

	// Allocate output buffer
	ptPtr, err := hd.Alloc(uint32(len(ciphertext)))
	if err != nil {
		hd.Dealloc(keyPtr)
		hd.Dealloc(ctPtr)
		hd.Dealloc(ivPtr)
		if aadPtr != 0 {
			hd.Dealloc(aadPtr)
		}
		hd.Dealloc(tagPtr)
		return nil, err
	}

	// Call function
	results, callErr := hd.hdAesGcmDecrypt.Call(hd.ctx,
		uint64(keyPtr), uint64(len(key)),
		uint64(ctPtr), uint64(len(ciphertext)),
		uint64(ivPtr), uint64(len(iv)),
		uint64(aadPtr), uint64(len(aad)),
		uint64(tagPtr),
		uint64(ptPtr))

	// Read result immediately
	var ptData []byte
	var resultErr error
	if callErr != nil {
		resultErr = fmt.Errorf("hd_aes_gcm_decrypt call failed: %w", callErr)
	} else {
		result := int32(results[0])
		if result < 0 {
			resultErr = fmt.Errorf("hd_aes_gcm_decrypt returned error code: %d (verification failed)", result)
		} else {
			ptData, _ = hd.ReadBytes(ptPtr, uint32(len(ciphertext)))
		}
	}

	// Deallocate all memory
	hd.Dealloc(keyPtr)
	hd.Dealloc(ctPtr)
	hd.Dealloc(ivPtr)
	if aadPtr != 0 {
		hd.Dealloc(aadPtr)
	}
	hd.Dealloc(tagPtr)
	hd.Dealloc(ptPtr)

	if resultErr != nil {
		return nil, resultErr
	}

	// Make a copy
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ptData)
	return plaintext, nil
}

// =============================================================================
// Test Functions
// =============================================================================

func TestWASMLoading(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	t.Log("WASM module loaded successfully")
}

func TestMemoryAllocation(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Test allocation
	ptr, err := hd.Alloc(1024)
	if err != nil {
		t.Fatalf("Allocation failed: %v", err)
	}
	if ptr == 0 {
		t.Fatal("Allocation returned null pointer")
	}

	// Test write and read
	testData := []byte("Hello, WASM World!")
	if err := hd.WriteBytes(ptr, testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	readData, err := hd.ReadBytes(ptr, uint32(len(testData)))
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(testData, readData) {
		t.Errorf("Data mismatch: expected %q, got %q", testData, readData)
	}

	// Test deallocation (no error expected)
	hd.Dealloc(ptr)

	t.Log("Memory allocation/deallocation working correctly")
}

func TestEntropyInjection(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Check initial entropy status
	status, err := hd.GetEntropyStatus()
	if err != nil {
		t.Fatalf("GetEntropyStatus failed: %v", err)
	}
	t.Logf("Initial entropy status: %d", status)

	// Inject entropy
	entropy := make([]byte, 64)
	rand.Read(entropy)

	if err := hd.InjectEntropy(entropy); err != nil {
		t.Fatalf("InjectEntropy failed: %v", err)
	}

	// Check entropy status after injection
	status, err = hd.GetEntropyStatus()
	if err != nil {
		t.Fatalf("GetEntropyStatus after injection failed: %v", err)
	}

	if status < 2 {
		t.Errorf("Entropy status should be >= 2 after injection, got %d", status)
	}

	t.Logf("Entropy injected successfully, status: %d", status)
}

func TestMnemonicGeneration(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Inject entropy first
	entropy := make([]byte, 64)
	rand.Read(entropy)
	if err := hd.InjectEntropy(entropy); err != nil {
		t.Fatalf("InjectEntropy failed: %v", err)
	}

	testCases := []struct {
		name      string
		wordCount int32
		expected  int
	}{
		{"12 words", 12, 12},
		{"15 words", 15, 15},
		{"18 words", 18, 18},
		{"21 words", 21, 21},
		{"24 words", 24, 24},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mnemonic, err := hd.GenerateMnemonic(tc.wordCount, 0) // 0 = English
			if err != nil {
				t.Fatalf("GenerateMnemonic failed: %v", err)
			}

			words := strings.Fields(mnemonic)
			if len(words) != tc.expected {
				t.Errorf("Expected %d words, got %d: %s", tc.expected, len(words), mnemonic)
			}

			t.Logf("Generated %d-word mnemonic: %s", tc.wordCount, mnemonic)
		})
	}
}

func TestMnemonicValidation(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	testCases := []struct {
		name      string
		mnemonic  string
		expectOK  bool
	}{
		{
			name:     "Valid 12-word mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			expectOK: true,
		},
		{
			name:     "Valid 24-word mnemonic",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			expectOK: true,
		},
		{
			name:     "Invalid word",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid",
			expectOK: false,
		},
		{
			name:     "Wrong word count",
			mnemonic: "abandon abandon abandon",
			expectOK: false,
		},
		{
			name:     "Invalid checksum",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			expectOK: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := hd.ValidateMnemonic(tc.mnemonic, 0)
			if err != nil {
				t.Fatalf("ValidateMnemonic call failed: %v", err)
			}

			isValid := (result == 0)
			if isValid != tc.expectOK {
				t.Errorf("Validation result mismatch: expected valid=%v, got valid=%v (code=%d)",
					tc.expectOK, isValid, result)
			}
		})
	}
}

func TestMnemonicToSeed(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Test vector from BIP-39
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"

	seed, err := hd.MnemonicToSeed(mnemonic, passphrase)
	if err != nil {
		t.Fatalf("MnemonicToSeed failed: %v", err)
	}

	if len(seed) != 64 {
		t.Errorf("Expected 64-byte seed, got %d bytes", len(seed))
	}

	// Expected seed from BIP-39 test vector
	expectedHex := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	expected, _ := hex.DecodeString(expectedHex)

	if !bytes.Equal(seed, expected) {
		t.Errorf("Seed mismatch:\nExpected: %x\nGot:      %x", expected, seed)
	}

	t.Logf("Seed derived successfully: %x", seed)
}

func TestKeyDerivation(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Use test vector seed
	seedHex := "000102030405060708090a0b0c0d0e0f"
	seed, _ := hex.DecodeString(seedHex)

	// Pad seed to 64 bytes (BIP-32 typically uses 64-byte seeds from BIP-39)
	fullSeed := make([]byte, 64)
	copy(fullSeed, seed)

	// Create master key (curve 0 = secp256k1)
	keyHandle, err := hd.KeyFromSeed(fullSeed, 0)
	if err != nil {
		t.Fatalf("KeyFromSeed failed: %v", err)
	}
	if keyHandle == 0 {
		t.Fatal("KeyFromSeed returned null handle")
	}
	t.Logf("Key handle: 0x%x", keyHandle)
	defer hd.KeyDestroy(keyHandle)

	// Get master private key
	privKey, err := hd.KeyGetPrivate(keyHandle)
	if err != nil {
		t.Fatalf("KeyGetPrivate failed: %v", err)
	}
	t.Logf("Master private key: %x", privKey)

	// Get master public key
	pubKey, err := hd.KeyGetPublic(keyHandle)
	if err != nil {
		t.Fatalf("KeyGetPublic failed: %v", err)
	}
	t.Logf("Master public key: %x", pubKey)

	// Derive child key at m/44'/60'/0'/0/0 (Ethereum first address)
	derivedHandle, err := hd.KeyDerivePath(keyHandle, "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("KeyDerivePath failed: %v", err)
	}
	if derivedHandle == 0 {
		t.Fatal("KeyDerivePath returned null handle")
	}
	defer hd.KeyDestroy(derivedHandle)

	// Get derived private key
	derivedPrivKey, err := hd.KeyGetPrivate(derivedHandle)
	if err != nil {
		t.Fatalf("KeyGetPrivate (derived) failed: %v", err)
	}
	t.Logf("Derived private key (m/44'/60'/0'/0/0): %x", derivedPrivKey)

	// Get derived public key
	derivedPubKey, err := hd.KeyGetPublic(derivedHandle)
	if err != nil {
		t.Fatalf("KeyGetPublic (derived) failed: %v", err)
	}
	t.Logf("Derived public key (m/44'/60'/0'/0/0): %x", derivedPubKey)

	// Verify keys are different from master
	if bytes.Equal(privKey, derivedPrivKey) {
		t.Error("Derived private key should be different from master")
	}
	if bytes.Equal(pubKey, derivedPubKey) {
		t.Error("Derived public key should be different from master")
	}
}

func TestHashSHA256(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "Hello World",
			input:    "Hello World",
			expected: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
		},
		{
			name:     "Test vector",
			input:    "abc",
			expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := hd.HashSHA256([]byte(tc.input))
			if err != nil {
				t.Fatalf("HashSHA256 failed: %v", err)
			}

			expected, _ := hex.DecodeString(tc.expected)
			if !bytes.Equal(hash, expected) {
				t.Errorf("Hash mismatch:\nExpected: %x\nGot:      %x", expected, hash)
			}
		})
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Test data
	key := make([]byte, 32) // AES-256
	rand.Read(key)

	iv := make([]byte, 12) // GCM standard IV
	rand.Read(iv)

	plaintext := []byte("Hello, AES-GCM encryption test!")
	aad := []byte("additional authenticated data")

	// Encrypt
	ciphertext, tag, err := hd.AesGcmEncrypt(key, plaintext, iv, aad)
	if err != nil {
		t.Fatalf("AesGcmEncrypt failed: %v", err)
	}

	t.Logf("Plaintext:  %x", plaintext)
	t.Logf("Ciphertext: %x", ciphertext)
	t.Logf("Tag:        %x", tag)

	// Ciphertext should be different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted, err := hd.AesGcmDecrypt(key, ciphertext, iv, aad, tag)
	if err != nil {
		t.Fatalf("AesGcmDecrypt failed: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch:\nExpected: %x\nGot:      %x", plaintext, decrypted)
	}

	t.Log("AES-GCM encrypt/decrypt working correctly")
}

func TestAESGCMTamperDetection(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Test data
	key := make([]byte, 32)
	rand.Read(key)

	iv := make([]byte, 12)
	rand.Read(iv)

	plaintext := []byte("Secret message")
	aad := []byte("aad")

	// Encrypt
	ciphertext, tag, err := hd.AesGcmEncrypt(key, plaintext, iv, aad)
	if err != nil {
		t.Fatalf("AesGcmEncrypt failed: %v", err)
	}

	// Test 1: Tamper with ciphertext
	tamperedCT := make([]byte, len(ciphertext))
	copy(tamperedCT, ciphertext)
	tamperedCT[0] ^= 0xFF

	_, err = hd.AesGcmDecrypt(key, tamperedCT, iv, aad, tag)
	if err == nil {
		t.Error("Decryption should fail with tampered ciphertext")
	} else {
		t.Logf("Correctly detected tampered ciphertext: %v", err)
	}

	// Test 2: Tamper with tag
	tamperedTag := make([]byte, len(tag))
	copy(tamperedTag, tag)
	tamperedTag[0] ^= 0xFF

	_, err = hd.AesGcmDecrypt(key, ciphertext, iv, aad, tamperedTag)
	if err == nil {
		t.Error("Decryption should fail with tampered tag")
	} else {
		t.Logf("Correctly detected tampered tag: %v", err)
	}

	// Test 3: Tamper with AAD
	tamperedAAD := []byte("modified aad")

	_, err = hd.AesGcmDecrypt(key, ciphertext, iv, tamperedAAD, tag)
	if err == nil {
		t.Error("Decryption should fail with tampered AAD")
	} else {
		t.Logf("Correctly detected tampered AAD: %v", err)
	}
}

func TestAESGCMNoAAD(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// Test encryption without AAD
	key := make([]byte, 32)
	rand.Read(key)

	iv := make([]byte, 12)
	rand.Read(iv)

	plaintext := []byte("No AAD encryption test")

	// Encrypt without AAD
	ciphertext, tag, err := hd.AesGcmEncrypt(key, plaintext, iv, nil)
	if err != nil {
		t.Fatalf("AesGcmEncrypt without AAD failed: %v", err)
	}

	// Decrypt without AAD
	decrypted, err := hd.AesGcmDecrypt(key, ciphertext, iv, nil, tag)
	if err != nil {
		t.Fatalf("AesGcmDecrypt without AAD failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch without AAD:\nExpected: %x\nGot:      %x", plaintext, decrypted)
	}

	t.Log("AES-GCM without AAD working correctly")
}

func TestFullWorkflow(t *testing.T) {
	hd := NewHDWallet(t)
	defer hd.Close()

	// 1. Inject entropy
	entropy := make([]byte, 64)
	rand.Read(entropy)
	if err := hd.InjectEntropy(entropy); err != nil {
		t.Fatalf("InjectEntropy failed: %v", err)
	}

	// 2. Generate mnemonic
	mnemonic, err := hd.GenerateMnemonic(24, 0)
	if err != nil {
		t.Fatalf("GenerateMnemonic failed: %v", err)
	}
	t.Logf("Generated mnemonic: %s", mnemonic)

	// 3. Validate mnemonic
	result, err := hd.ValidateMnemonic(mnemonic, 0)
	if err != nil {
		t.Fatalf("ValidateMnemonic failed: %v", err)
	}
	if result != 0 {
		t.Fatalf("Generated mnemonic failed validation: %d", result)
	}

	// 4. Convert to seed
	seed, err := hd.MnemonicToSeed(mnemonic, "")
	if err != nil {
		t.Fatalf("MnemonicToSeed failed: %v", err)
	}
	t.Logf("Seed: %x", seed)

	// 5. Create master key
	keyHandle, err := hd.KeyFromSeed(seed, 0)
	if err != nil {
		t.Fatalf("KeyFromSeed failed: %v", err)
	}
	defer hd.KeyDestroy(keyHandle)

	// 6. Derive Bitcoin address path
	btcHandle, err := hd.KeyDerivePath(keyHandle, "m/44'/0'/0'/0/0")
	if err != nil {
		t.Fatalf("KeyDerivePath (BTC) failed: %v", err)
	}
	defer hd.KeyDestroy(btcHandle)

	btcPrivKey, err := hd.KeyGetPrivate(btcHandle)
	if err != nil {
		t.Fatalf("KeyGetPrivate (BTC) failed: %v", err)
	}
	t.Logf("Bitcoin private key: %x", btcPrivKey)

	// 7. Derive Ethereum address path
	ethHandle, err := hd.KeyDerivePath(keyHandle, "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("KeyDerivePath (ETH) failed: %v", err)
	}
	defer hd.KeyDestroy(ethHandle)

	ethPrivKey, err := hd.KeyGetPrivate(ethHandle)
	if err != nil {
		t.Fatalf("KeyGetPrivate (ETH) failed: %v", err)
	}
	t.Logf("Ethereum private key: %x", ethPrivKey)

	// 8. Hash something
	hash, err := hd.HashSHA256(seed)
	if err != nil {
		t.Fatalf("HashSHA256 failed: %v", err)
	}
	t.Logf("SHA256(seed): %x", hash)

	// 9. Encrypt/decrypt with AES-GCM
	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	iv := make([]byte, 12)
	rand.Read(iv)

	message := []byte("Encrypted wallet backup data")
	ciphertext, tag, err := hd.AesGcmEncrypt(aesKey, message, iv, nil)
	if err != nil {
		t.Fatalf("AesGcmEncrypt failed: %v", err)
	}

	decrypted, err := hd.AesGcmDecrypt(aesKey, ciphertext, iv, nil, tag)
	if err != nil {
		t.Fatalf("AesGcmDecrypt failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Fatal("Encryption/decryption roundtrip failed")
	}

	t.Log("Full workflow completed successfully")
}

// BenchmarkMnemonicGeneration benchmarks mnemonic generation
func BenchmarkMnemonicGeneration(b *testing.B) {
	hd := NewHDWallet(&testing.T{})
	defer hd.Close()

	entropy := make([]byte, 64)
	rand.Read(entropy)
	hd.InjectEntropy(entropy)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hd.GenerateMnemonic(24, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHashSHA256 benchmarks SHA-256 hashing
func BenchmarkHashSHA256(b *testing.B) {
	hd := NewHDWallet(&testing.T{})
	defer hd.Close()

	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hd.HashSHA256(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAESGCMEncrypt benchmarks AES-GCM encryption
func BenchmarkAESGCMEncrypt(b *testing.B) {
	hd := NewHDWallet(&testing.T{})
	defer hd.Close()

	key := make([]byte, 32)
	iv := make([]byte, 12)
	data := make([]byte, 1024)
	rand.Read(key)
	rand.Read(iv)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := hd.AesGcmEncrypt(key, data, iv, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
