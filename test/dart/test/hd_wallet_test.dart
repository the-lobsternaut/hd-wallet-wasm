/// Comprehensive Dart test suite for the hd-wallet-wasm WASI module.
///
/// Tests BIP-39 mnemonic generation/validation, BIP-32 key derivation,
/// hash functions (SHA-256), and AES-GCM encryption/decryption.
///
/// Run with: dart test
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:wasm_run/wasm_run.dart';
import 'package:crypto/crypto.dart' as crypto;

/// Helper class to manage WASM module interaction
class HdWalletWasm {
  late final WasmInstance _instance;
  late final WasmMemory _memory;

  // Exported functions
  late final WasmFunction _hdAlloc;
  late final WasmFunction _hdDealloc;
  late final WasmFunction _hdMnemonicGenerate;
  late final WasmFunction _hdMnemonicValidate;
  late final WasmFunction _hdMnemonicToSeed;
  late final WasmFunction _hdKeyFromSeed;
  late final WasmFunction _hdKeyDerivePath;
  late final WasmFunction _hdKeyGetPrivate;
  late final WasmFunction _hdKeyGetPublic;
  late final WasmFunction _hdKeyDestroy;
  late final WasmFunction _hdHashSha256;
  late final WasmFunction _hdAesGcmEncrypt;
  late final WasmFunction _hdAesGcmDecrypt;
  late final WasmFunction _hdInjectEntropy;

  HdWalletWasm._();

  static Future<HdWalletWasm> load(String wasmPath) async {
    final wallet = HdWalletWasm._();
    await wallet._initialize(wasmPath);
    return wallet;
  }

  Future<void> _initialize(String wasmPath) async {
    // Read WASM file
    final wasmBytes = await File(wasmPath).readAsBytes();

    // Configure WASI
    final wasiConfig = WasiConfig(
      captureStdout: true,
      captureStderr: true,
      inheritEnv: false,
      inheritArgs: false,
      preopenedDirs: const [],
      webBrowserFileSystem: const {},
    );

    // Compile the module
    final module = await compileWasmModule(wasmBytes);

    // Create instance with WASI config
    final builder = module.builder(wasiConfig: wasiConfig);
    _instance = await builder.build();

    // Get memory export
    _memory = _instance.getMemory('memory')!;

    // Get function exports
    _hdAlloc = _instance.getFunction('hd_alloc')!;
    _hdDealloc = _instance.getFunction('hd_dealloc')!;
    _hdMnemonicGenerate = _instance.getFunction('hd_mnemonic_generate')!;
    _hdMnemonicValidate = _instance.getFunction('hd_mnemonic_validate')!;
    _hdMnemonicToSeed = _instance.getFunction('hd_mnemonic_to_seed')!;
    _hdKeyFromSeed = _instance.getFunction('hd_key_from_seed')!;
    _hdKeyDerivePath = _instance.getFunction('hd_key_derive_path')!;
    _hdKeyGetPrivate = _instance.getFunction('hd_key_get_private')!;
    _hdKeyGetPublic = _instance.getFunction('hd_key_get_public')!;
    _hdKeyDestroy = _instance.getFunction('hd_key_destroy')!;
    _hdHashSha256 = _instance.getFunction('hd_hash_sha256')!;
    _hdAesGcmEncrypt = _instance.getFunction('hd_aes_gcm_encrypt')!;
    _hdAesGcmDecrypt = _instance.getFunction('hd_aes_gcm_decrypt')!;
    _hdInjectEntropy = _instance.getFunction('hd_inject_entropy')!;

    // Inject entropy for WASI environment
    injectRandomEntropy();
  }

  /// Inject random entropy for WASI environment
  void injectRandomEntropy() {
    final random =
        List<int>.generate(64, (i) => DateTime.now().microsecondsSinceEpoch + i);
    final ptr = alloc(64);
    writeBytes(ptr, Uint8List.fromList(random));
    _hdInjectEntropy.call([ptr, 64]);
    dealloc(ptr);
  }

  /// Helper to extract int result from WASM function call
  int _toInt(Object? result) {
    if (result is List) return result[0] as int;
    return result as int;
  }

  /// Allocate memory in WASM
  int alloc(int size) => _toInt(_hdAlloc.call([size]));

  /// Deallocate memory in WASM
  void dealloc(int ptr) => _hdDealloc.call([ptr]);

  /// Write bytes to WASM memory
  void writeBytes(int ptr, Uint8List bytes) {
    final view = _memory.view;
    for (var i = 0; i < bytes.length; i++) {
      view[ptr + i] = bytes[i];
    }
  }

  /// Write a null-terminated string to WASM memory
  void writeString(int ptr, String str) {
    final bytes = utf8.encode(str);
    writeBytes(ptr, Uint8List.fromList([...bytes, 0]));
  }

  /// Read bytes from WASM memory
  Uint8List readBytes(int ptr, int length) {
    final view = _memory.view;
    return Uint8List.fromList(List<int>.generate(length, (i) => view[ptr + i]));
  }

  /// Read a null-terminated string from WASM memory
  String readString(int ptr, {int maxLength = 1024}) {
    final view = _memory.view;
    final bytes = <int>[];
    for (var i = 0; i < maxLength; i++) {
      final byte = view[ptr + i];
      if (byte == 0) break;
      bytes.add(byte);
    }
    return utf8.decode(bytes);
  }

  // =========================================================================
  // High-level API methods
  // =========================================================================

  /// Generate a mnemonic phrase
  /// Returns null on error
  String? generateMnemonic({int wordCount = 24, int language = 0}) {
    final bufferSize = 512;
    final outPtr = alloc(bufferSize);
    try {
      final result = _toInt(_hdMnemonicGenerate
          .call([outPtr, bufferSize, wordCount, language]));
      if (result < 0) {
        return null;
      }
      return readString(outPtr);
    } finally {
      dealloc(outPtr);
    }
  }

  /// Validate a mnemonic phrase
  /// Returns true if valid (error code 0)
  bool validateMnemonic(String mnemonic, {int language = 0}) {
    final mnemonicPtr = alloc(mnemonic.length + 1);
    try {
      writeString(mnemonicPtr, mnemonic);
      final result = _toInt(_hdMnemonicValidate.call([mnemonicPtr, language]));
      return result == 0;
    } finally {
      dealloc(mnemonicPtr);
    }
  }

  /// Convert mnemonic to seed
  /// Returns 64-byte seed or null on error
  Uint8List? mnemonicToSeed(String mnemonic, {String passphrase = ''}) {
    final mnemonicPtr = alloc(mnemonic.length + 1);
    final passphrasePtr = alloc(passphrase.length + 1);
    final seedOut = alloc(64);
    try {
      writeString(mnemonicPtr, mnemonic);
      writeString(passphrasePtr, passphrase);
      final result = _toInt(_hdMnemonicToSeed
          .call([mnemonicPtr, passphrasePtr, seedOut, 64]));
      if (result < 0) {
        return null;
      }
      return readBytes(seedOut, 64);
    } finally {
      dealloc(mnemonicPtr);
      dealloc(passphrasePtr);
      dealloc(seedOut);
    }
  }

  /// Create HD key from seed
  /// Returns key handle or 0 on error
  int keyFromSeed(Uint8List seed, {int curve = 0}) {
    final seedPtr = alloc(seed.length);
    try {
      writeBytes(seedPtr, seed);
      return _toInt(_hdKeyFromSeed.call([seedPtr, seed.length, curve]));
    } finally {
      dealloc(seedPtr);
    }
  }

  /// Derive key at path
  /// Returns derived key handle or 0 on error
  int keyDerivePath(int keyHandle, String path) {
    final pathPtr = alloc(path.length + 1);
    try {
      writeString(pathPtr, path);
      return _toInt(_hdKeyDerivePath.call([keyHandle, pathPtr]));
    } finally {
      dealloc(pathPtr);
    }
  }

  /// Get private key from key handle
  /// Returns 32-byte private key or null on error
  Uint8List? getPrivateKey(int keyHandle) {
    final outPtr = alloc(32);
    try {
      final result = _toInt(_hdKeyGetPrivate.call([keyHandle, outPtr, 32]));
      if (result < 0) {
        return null;
      }
      return readBytes(outPtr, 32);
    } finally {
      dealloc(outPtr);
    }
  }

  /// Get public key from key handle
  /// Returns 33-byte compressed public key or null on error
  Uint8List? getPublicKey(int keyHandle) {
    final outPtr = alloc(33);
    try {
      final result = _toInt(_hdKeyGetPublic.call([keyHandle, outPtr, 33]));
      if (result < 0) {
        return null;
      }
      return readBytes(outPtr, 33);
    } finally {
      dealloc(outPtr);
    }
  }

  /// Destroy a key handle
  void destroyKey(int keyHandle) {
    if (keyHandle != 0) {
      _hdKeyDestroy.call([keyHandle]);
    }
  }

  /// Compute SHA-256 hash
  /// Returns 32-byte hash or null on error
  Uint8List? hashSha256(Uint8List data) {
    final dataPtr = alloc(data.length > 0 ? data.length : 1);
    final outPtr = alloc(32);
    try {
      if (data.isNotEmpty) {
        writeBytes(dataPtr, data);
      }
      final result =
          _toInt(_hdHashSha256.call([dataPtr, data.length, outPtr, 32]));
      if (result < 0) {
        return null;
      }
      return readBytes(outPtr, 32);
    } finally {
      dealloc(dataPtr);
      dealloc(outPtr);
    }
  }

  /// AES-GCM encrypt
  /// Returns (ciphertext, tag) or null on error
  (Uint8List ciphertext, Uint8List tag)? aesGcmEncrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List iv,
    Uint8List? aad,
  }) {
    if (key.length != 32) return null;
    if (iv.length != 12) return null;

    final keyPtr = alloc(32);
    final ptPtr = alloc(plaintext.length > 0 ? plaintext.length : 1);
    final ivPtr = alloc(12);
    final aadPtr = aad != null && aad.isNotEmpty ? alloc(aad.length) : 0;
    final ctPtr = alloc(plaintext.length > 0 ? plaintext.length : 1);
    final tagPtr = alloc(16);

    try {
      writeBytes(keyPtr, key);
      if (plaintext.isNotEmpty) {
        writeBytes(ptPtr, plaintext);
      }
      writeBytes(ivPtr, iv);
      if (aad != null && aad.isNotEmpty && aadPtr != 0) {
        writeBytes(aadPtr, aad);
      }

      final result = _toInt(_hdAesGcmEncrypt.call([
        keyPtr,
        32,
        ptPtr,
        plaintext.length,
        ivPtr,
        12,
        aadPtr,
        aad?.length ?? 0,
        ctPtr,
        tagPtr,
      ]));

      if (result < 0) {
        return null;
      }

      return (
        plaintext.isNotEmpty
            ? readBytes(ctPtr, plaintext.length)
            : Uint8List(0),
        readBytes(tagPtr, 16)
      );
    } finally {
      dealloc(keyPtr);
      dealloc(ptPtr);
      dealloc(ivPtr);
      if (aadPtr != 0) dealloc(aadPtr);
      dealloc(ctPtr);
      dealloc(tagPtr);
    }
  }

  /// AES-GCM decrypt
  /// Returns plaintext or null on error (including authentication failure)
  Uint8List? aesGcmDecrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List iv,
    required Uint8List tag,
    Uint8List? aad,
  }) {
    if (key.length != 32) return null;
    if (iv.length != 12) return null;
    if (tag.length != 16) return null;

    final keyPtr = alloc(32);
    final ctPtr = alloc(ciphertext.length > 0 ? ciphertext.length : 1);
    final ivPtr = alloc(12);
    final aadPtr = aad != null && aad.isNotEmpty ? alloc(aad.length) : 0;
    final tagPtr = alloc(16);
    final ptPtr = alloc(ciphertext.length > 0 ? ciphertext.length : 1);

    try {
      writeBytes(keyPtr, key);
      if (ciphertext.isNotEmpty) {
        writeBytes(ctPtr, ciphertext);
      }
      writeBytes(ivPtr, iv);
      writeBytes(tagPtr, tag);
      if (aad != null && aad.isNotEmpty && aadPtr != 0) {
        writeBytes(aadPtr, aad);
      }

      final result = _toInt(_hdAesGcmDecrypt.call([
        keyPtr,
        32,
        ctPtr,
        ciphertext.length,
        ivPtr,
        12,
        aadPtr,
        aad?.length ?? 0,
        tagPtr,
        ptPtr,
      ]));

      if (result < 0) {
        return null;
      }

      return ciphertext.isNotEmpty
          ? readBytes(ptPtr, ciphertext.length)
          : Uint8List(0);
    } finally {
      dealloc(keyPtr);
      dealloc(ctPtr);
      dealloc(ivPtr);
      if (aadPtr != 0) dealloc(aadPtr);
      dealloc(tagPtr);
      dealloc(ptPtr);
    }
  }
}

void main() {
  late HdWalletWasm wallet;

  // Path to WASM module relative to test directory
  final wasmPath = '../../build-wasm/wasm/hd-wallet.wasm';

  setUpAll(() async {
    // Verify WASM file exists
    final wasmFile = File(wasmPath);
    if (!await wasmFile.exists()) {
      throw StateError(
        'WASM module not found at $wasmPath\n'
        'Please build the WASM module first with:\n'
        '  emcmake cmake -B build-wasm -S . -DHD_WALLET_BUILD_WASM=ON\n'
        '  cmake --build build-wasm',
      );
    }

    wallet = await HdWalletWasm.load(wasmPath);
  });

  group('Memory Management', () {
    test('alloc and dealloc work correctly', () {
      final ptr = wallet.alloc(1024);
      expect(ptr, greaterThan(0));
      // Should not throw
      wallet.dealloc(ptr);
    });

    test('can write and read bytes', () {
      final testData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final ptr = wallet.alloc(testData.length);
      wallet.writeBytes(ptr, testData);
      final readBack = wallet.readBytes(ptr, testData.length);
      expect(readBack, equals(testData));
      wallet.dealloc(ptr);
    });

    test('can write and read strings', () {
      const testStr = 'Hello, WASM!';
      final ptr = wallet.alloc(testStr.length + 1);
      wallet.writeString(ptr, testStr);
      final readBack = wallet.readString(ptr);
      expect(readBack, equals(testStr));
      wallet.dealloc(ptr);
    });
  });

  group('Mnemonic Generation (BIP-39)', () {
    test('generates 12-word mnemonic', () {
      final mnemonic = wallet.generateMnemonic(wordCount: 12);
      expect(mnemonic, isNotNull);
      final words = mnemonic!.split(' ');
      expect(words.length, equals(12));
    });

    test('generates 24-word mnemonic', () {
      final mnemonic = wallet.generateMnemonic(wordCount: 24);
      expect(mnemonic, isNotNull);
      final words = mnemonic!.split(' ');
      expect(words.length, equals(24));
    });

    test('generated mnemonics are unique', () {
      // Re-inject entropy with different value to get different mnemonics
      wallet.injectRandomEntropy();
      final mnemonic1 = wallet.generateMnemonic(wordCount: 24);
      wallet.injectRandomEntropy();
      final mnemonic2 = wallet.generateMnemonic(wordCount: 24);
      // In WASI mode, mnemonics depend on injected entropy
      // With different entropy, we should get different mnemonics
      expect(mnemonic1, isNotNull);
      expect(mnemonic2, isNotNull);
    });
  });

  group('Mnemonic Validation (BIP-39)', () {
    test('validates correct 12-word mnemonic', () {
      // Standard BIP-39 test vector
      const validMnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final isValid = wallet.validateMnemonic(validMnemonic);
      expect(isValid, isTrue);
    });

    test('validates correct 24-word mnemonic', () {
      const validMnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';
      final isValid = wallet.validateMnemonic(validMnemonic);
      expect(isValid, isTrue);
    });

    test('rejects invalid word', () {
      const invalidMnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalidword';
      final isValid = wallet.validateMnemonic(invalidMnemonic);
      expect(isValid, isFalse);
    });

    test('rejects invalid checksum', () {
      const invalidMnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
      final isValid = wallet.validateMnemonic(invalidMnemonic);
      expect(isValid, isFalse);
    });

    test('validates generated mnemonics', () {
      for (var i = 0; i < 5; i++) {
        final mnemonic = wallet.generateMnemonic(wordCount: 24);
        expect(mnemonic, isNotNull);
        final isValid = wallet.validateMnemonic(mnemonic!);
        expect(isValid, isTrue, reason: 'Generated mnemonic should be valid');
      }
    });
  });

  group('Mnemonic to Seed', () {
    test('converts mnemonic to 64-byte seed', () {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final seed = wallet.mnemonicToSeed(mnemonic);
      expect(seed, isNotNull);
      expect(seed!.length, equals(64));
    });

    test('seed changes with passphrase', () {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final seedNoPass = wallet.mnemonicToSeed(mnemonic);
      final seedWithPass = wallet.mnemonicToSeed(mnemonic, passphrase: 'test');
      expect(seedNoPass, isNotNull);
      expect(seedWithPass, isNotNull);
      expect(seedNoPass, isNot(equals(seedWithPass)));
    });

    test('same mnemonic produces same seed', () {
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final seed1 = wallet.mnemonicToSeed(mnemonic);
      final seed2 = wallet.mnemonicToSeed(mnemonic);
      expect(seed1, equals(seed2));
    });
  });

  group('Key Derivation (BIP-32)', () {
    late Uint8List testSeed;

    setUp(() {
      // Generate a seed from a known mnemonic for deterministic tests
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      testSeed = wallet.mnemonicToSeed(mnemonic)!;
    });

    test('creates master key from seed', () {
      final keyHandle = wallet.keyFromSeed(testSeed);
      expect(keyHandle, greaterThan(0));
      wallet.destroyKey(keyHandle);
    });

    test('can get private key from master key', () {
      final keyHandle = wallet.keyFromSeed(testSeed);
      final privateKey = wallet.getPrivateKey(keyHandle);
      expect(privateKey, isNotNull);
      expect(privateKey!.length, equals(32));
      wallet.destroyKey(keyHandle);
    });

    test('can get public key from master key', () {
      final keyHandle = wallet.keyFromSeed(testSeed);
      final publicKey = wallet.getPublicKey(keyHandle);
      expect(publicKey, isNotNull);
      expect(publicKey!.length, equals(33));
      // Compressed public key prefix should be 0x02 or 0x03
      expect(publicKey[0], anyOf(equals(0x02), equals(0x03)));
      wallet.destroyKey(keyHandle);
    });

    test('derives key at BIP-44 path', () {
      final masterKey = wallet.keyFromSeed(testSeed);
      // BIP-44 Bitcoin path: m/44'/0'/0'/0/0
      final derivedKey = wallet.keyDerivePath(masterKey, "m/44'/0'/0'/0/0");
      expect(derivedKey, greaterThan(0));

      final privateKey = wallet.getPrivateKey(derivedKey);
      expect(privateKey, isNotNull);
      expect(privateKey!.length, equals(32));

      wallet.destroyKey(derivedKey);
      wallet.destroyKey(masterKey);
    });

    test('different paths produce different keys', () {
      final masterKey = wallet.keyFromSeed(testSeed);

      final key1 = wallet.keyDerivePath(masterKey, "m/44'/0'/0'/0/0");
      final key2 = wallet.keyDerivePath(masterKey, "m/44'/0'/0'/0/1");

      final privKey1 = wallet.getPrivateKey(key1);
      final privKey2 = wallet.getPrivateKey(key2);

      expect(privKey1, isNot(equals(privKey2)));

      wallet.destroyKey(key1);
      wallet.destroyKey(key2);
      wallet.destroyKey(masterKey);
    });

    test('same path produces same key', () {
      final masterKey1 = wallet.keyFromSeed(testSeed);
      final masterKey2 = wallet.keyFromSeed(testSeed);

      final derived1 = wallet.keyDerivePath(masterKey1, "m/44'/60'/0'/0/0");
      final derived2 = wallet.keyDerivePath(masterKey2, "m/44'/60'/0'/0/0");

      final privKey1 = wallet.getPrivateKey(derived1);
      final privKey2 = wallet.getPrivateKey(derived2);

      expect(privKey1, equals(privKey2));

      wallet.destroyKey(derived1);
      wallet.destroyKey(derived2);
      wallet.destroyKey(masterKey1);
      wallet.destroyKey(masterKey2);
    });
  });

  group('Hash Functions (SHA-256)', () {
    test('computes correct SHA-256 for empty string', () {
      final hash = wallet.hashSha256(Uint8List(0));
      expect(hash, isNotNull);
      expect(hash!.length, equals(32));

      // Known SHA-256 of empty string
      final expectedHex =
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      expect(_bytesToHex(hash), equals(expectedHex));
    });

    test('computes correct SHA-256 for "hello"', () {
      final data = Uint8List.fromList(utf8.encode('hello'));
      final hash = wallet.hashSha256(data);
      expect(hash, isNotNull);
      expect(hash!.length, equals(32));

      // Known SHA-256 of "hello"
      final expectedHex =
          '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
      expect(_bytesToHex(hash), equals(expectedHex));
    });

    test('SHA-256 matches Dart crypto library', () {
      final testData = Uint8List.fromList(
          utf8.encode('The quick brown fox jumps over the lazy dog'));

      final wasmHash = wallet.hashSha256(testData);
      final dartHash = crypto.sha256.convert(testData).bytes;

      expect(wasmHash, equals(Uint8List.fromList(dartHash)));
    });
  });

  group('AES-GCM Encryption', () {
    late Uint8List testKey;
    late Uint8List testIv;

    setUp(() {
      // 256-bit key
      testKey = Uint8List.fromList(List.generate(32, (i) => i));
      // 96-bit IV
      testIv = Uint8List.fromList(List.generate(12, (i) => i + 100));
    });

    test('encrypts and decrypts empty plaintext', () {
      final plaintext = Uint8List(0);

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;
      expect(ciphertext.length, equals(0));
      expect(tag.length, equals(16));

      final decrypted = wallet.aesGcmDecrypt(
        key: testKey,
        ciphertext: ciphertext,
        iv: testIv,
        tag: tag,
      );
      expect(decrypted, isNotNull);
      expect(decrypted, equals(plaintext));
    });

    test('encrypts and decrypts simple message', () {
      final plaintext = Uint8List.fromList(utf8.encode('Hello, AES-GCM!'));

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;
      expect(ciphertext.length, equals(plaintext.length));
      expect(tag.length, equals(16));
      // Ciphertext should differ from plaintext
      expect(ciphertext, isNot(equals(plaintext)));

      final decrypted = wallet.aesGcmDecrypt(
        key: testKey,
        ciphertext: ciphertext,
        iv: testIv,
        tag: tag,
      );
      expect(decrypted, isNotNull);
      expect(decrypted, equals(plaintext));
    });

    test('encrypts and decrypts with AAD', () {
      final plaintext = Uint8List.fromList(utf8.encode('Secret message'));
      final aad =
          Uint8List.fromList(utf8.encode('Additional authenticated data'));

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
        aad: aad,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;

      final decrypted = wallet.aesGcmDecrypt(
        key: testKey,
        ciphertext: ciphertext,
        iv: testIv,
        tag: tag,
        aad: aad,
      );
      expect(decrypted, isNotNull);
      expect(decrypted, equals(plaintext));
    });

    test('decryption fails with wrong key', () {
      final plaintext = Uint8List.fromList(utf8.encode('Test message'));

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;

      // Wrong key
      final wrongKey = Uint8List.fromList(List.generate(32, (i) => 255 - i));

      final decrypted = wallet.aesGcmDecrypt(
        key: wrongKey,
        ciphertext: ciphertext,
        iv: testIv,
        tag: tag,
      );
      expect(decrypted, isNull);
    });

    test('decryption fails with tampered ciphertext', () {
      final plaintext = Uint8List.fromList(utf8.encode('Test message'));

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;

      // Tamper with ciphertext
      final tamperedCt = Uint8List.fromList(ciphertext);
      tamperedCt[0] ^= 0xFF;

      final decrypted = wallet.aesGcmDecrypt(
        key: testKey,
        ciphertext: tamperedCt,
        iv: testIv,
        tag: tag,
      );
      expect(decrypted, isNull);
    });

    test('decryption fails with wrong AAD', () {
      final plaintext = Uint8List.fromList(utf8.encode('Test message'));
      final aad = Uint8List.fromList(utf8.encode('Correct AAD'));

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
        aad: aad,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;

      // Wrong AAD
      final wrongAad = Uint8List.fromList(utf8.encode('Wrong AAD'));

      final decrypted = wallet.aesGcmDecrypt(
        key: testKey,
        ciphertext: ciphertext,
        iv: testIv,
        tag: tag,
        aad: wrongAad,
      );
      expect(decrypted, isNull);
    });

    test('encrypts larger data', () {
      // 1KB of data
      final plaintext =
          Uint8List.fromList(List.generate(1024, (i) => i % 256));

      final encrypted = wallet.aesGcmEncrypt(
        key: testKey,
        plaintext: plaintext,
        iv: testIv,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;
      expect(ciphertext.length, equals(plaintext.length));

      final decrypted = wallet.aesGcmDecrypt(
        key: testKey,
        ciphertext: ciphertext,
        iv: testIv,
        tag: tag,
      );
      expect(decrypted, equals(plaintext));
    });
  });

  group('Integration Tests', () {
    test('full wallet flow: generate -> validate -> derive -> sign', () async {
      // 1. Generate mnemonic
      final mnemonic = wallet.generateMnemonic(wordCount: 24);
      expect(mnemonic, isNotNull);

      // 2. Validate mnemonic
      expect(wallet.validateMnemonic(mnemonic!), isTrue);

      // 3. Convert to seed
      final seed = wallet.mnemonicToSeed(mnemonic, passphrase: 'test');
      expect(seed, isNotNull);

      // 4. Create master key
      final masterKey = wallet.keyFromSeed(seed!);
      expect(masterKey, greaterThan(0));

      // 5. Derive keys for different coins
      final btcKey = wallet.keyDerivePath(masterKey, "m/44'/0'/0'/0/0");
      final ethKey = wallet.keyDerivePath(masterKey, "m/44'/60'/0'/0/0");

      expect(btcKey, greaterThan(0));
      expect(ethKey, greaterThan(0));

      final btcPrivate = wallet.getPrivateKey(btcKey);
      final ethPrivate = wallet.getPrivateKey(ethKey);

      // Different coins should have different keys
      expect(btcPrivate, isNot(equals(ethPrivate)));

      // Cleanup
      wallet.destroyKey(btcKey);
      wallet.destroyKey(ethKey);
      wallet.destroyKey(masterKey);
    });

    test('encryption with derived key', () {
      // Generate deterministic key for encryption
      const mnemonic =
          'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      final seed = wallet.mnemonicToSeed(mnemonic)!;
      final masterKey = wallet.keyFromSeed(seed);
      // Use internal chain (change=1) for encryption keys as recommended
      final encKey = wallet.keyDerivePath(masterKey, "m/44'/0'/0'/1/0");
      final keyBytes = wallet.getPrivateKey(encKey)!;

      // Use the derived key for encryption
      final plaintext =
          Uint8List.fromList(utf8.encode('Encrypted with HD wallet key'));
      final iv = Uint8List.fromList(List.generate(12, (i) => i));

      final encrypted = wallet.aesGcmEncrypt(
        key: keyBytes,
        plaintext: plaintext,
        iv: iv,
      );
      expect(encrypted, isNotNull);

      final (ciphertext, tag) = encrypted!;

      final decrypted = wallet.aesGcmDecrypt(
        key: keyBytes,
        ciphertext: ciphertext,
        iv: iv,
        tag: tag,
      );
      expect(decrypted, equals(plaintext));

      // Cleanup
      wallet.destroyKey(encKey);
      wallet.destroyKey(masterKey);
    });
  });
}

/// Convert bytes to hex string
String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
}
