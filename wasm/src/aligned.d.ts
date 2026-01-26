/**
 * HD Wallet WASM - Aligned Binary API Type Definitions
 *
 * Provides efficient batch operations using aligned, fixed-size structs
 * for zero-copy WASM interop.
 *
 * @module hd-wallet-wasm/aligned
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Elliptic curve types for aligned operations
 */
export enum AlignedCurve {
  SECP256K1 = 0,
  ED25519 = 1,
  P256 = 2,
  P384 = 3,
  X25519 = 4
}

/**
 * Error codes for aligned operations
 */
export enum AlignedError {
  OK = 0,
  UNKNOWN = 1,
  INVALID_ARGUMENT = 2,
  NOT_SUPPORTED = 3,
  OUT_OF_MEMORY = 4,
  INTERNAL = 5,
  NO_ENTROPY = 100,
  INSUFFICIENT_ENTROPY = 101,
  INVALID_WORD = 200,
  INVALID_CHECKSUM = 201,
  INVALID_MNEMONIC_LENGTH = 202,
  INVALID_ENTROPY_LENGTH = 203,
  INVALID_SEED = 300,
  INVALID_PATH = 301,
  INVALID_CHILD_INDEX = 302,
  HARDENED_FROM_PUBLIC = 303,
  INVALID_EXTENDED_KEY = 304,
  INVALID_PRIVATE_KEY = 400,
  INVALID_PUBLIC_KEY = 401,
  INVALID_SIGNATURE = 402,
  VERIFICATION_FAILED = 403,
  KEY_DERIVATION_FAILED = 404
}

// =============================================================================
// Size Constants
// =============================================================================

export const EXTENDEDKEYDATA_SIZE: number;
export const BATCHDERIVEREQUEST_SIZE: number;
export const DERIVEDKEYENTRY_SIZE: number;

// =============================================================================
// Result Types
// =============================================================================

/**
 * Result of a single key derivation
 */
export interface DerivedKey {
  /** Child index that was derived */
  index: number;
  /** Error code (AlignedError.OK on success) */
  error: AlignedError;
  /** Compressed public key (33 bytes), null on error */
  publicKey: Uint8Array | null;
  /** Private key (32 bytes), null on error or if base was neutered */
  privateKey: Uint8Array | null;
}

/**
 * Result of a single signing operation
 */
export interface SignatureResult {
  /** Index of the hash that was signed */
  index: number;
  /** Error code (AlignedError.OK on success) */
  error: AlignedError;
  /** Signature (64 bytes r||s format), null on error */
  signature: Uint8Array | null;
  /** Recovery ID for recoverable signatures (-1 if not applicable) */
  recoveryId: number;
}

/**
 * Result of a single signature verification
 */
export interface VerifyResult {
  /** Index of the entry that was verified */
  index: number;
  /** Whether the signature is valid */
  valid: boolean;
  /** Error code */
  error: AlignedError;
}

/**
 * Input for signature verification
 */
export interface VerifyEntry {
  /** 32-byte message hash */
  hash: Uint8Array;
  /** 64-byte signature */
  signature: Uint8Array;
}

/**
 * Base key data for batch operations
 */
export interface BaseKeyData {
  /** Elliptic curve */
  curve?: AlignedCurve;
  /** Key depth in derivation tree */
  depth?: number;
  /** Parent fingerprint */
  parentFingerprint?: number;
  /** Child index */
  childIndex?: number;
  /** Chain code (32 bytes) */
  chainCode: Uint8Array;
  /** Compressed public key (33 bytes) */
  publicKey: Uint8Array;
  /** Private key (32 bytes) */
  privateKey: Uint8Array;
}

// =============================================================================
// View Classes (from generated code)
// =============================================================================

export class ExtendedKeyDataView {
  constructor(buffer: ArrayBuffer, byteOffset?: number);
  static fromMemory(memory: WebAssembly.Memory, ptr: number): ExtendedKeyDataView;
  static fromBytes(bytes: Uint8Array, offset?: number): ExtendedKeyDataView;
  static allocate(): ExtendedKeyDataView;

  get curve(): AlignedCurve;
  set curve(v: AlignedCurve);
  get depth(): number;
  set depth(v: number);
  get parent_fingerprint(): number;
  set parent_fingerprint(v: number);
  get child_index(): number;
  set child_index(v: number);
  get chain_code_data(): Uint8Array;
  get public_key_data(): Uint8Array;
  get private_key_data(): Uint8Array;
  get has_private_key(): number;
  set has_private_key(v: number);

  toObject(): Record<string, unknown>;
  copyFrom(obj: Partial<Record<string, unknown>>): void;
  copyTo(dest: Uint8Array, offset?: number): void;
  getBytes(): Uint8Array;
}

export class BatchDeriveRequestView {
  constructor(buffer: ArrayBuffer, byteOffset?: number);
  static fromMemory(memory: WebAssembly.Memory, ptr: number): BatchDeriveRequestView;
  static fromBytes(bytes: Uint8Array, offset?: number): BatchDeriveRequestView;
  static allocate(): BatchDeriveRequestView;

  get base_key_curve(): AlignedCurve;
  set base_key_curve(v: AlignedCurve);
  get base_key_depth(): number;
  set base_key_depth(v: number);
  get base_key_parent_fingerprint(): number;
  set base_key_parent_fingerprint(v: number);
  get base_key_child_index(): number;
  set base_key_child_index(v: number);
  get base_key_chain_code_data(): Uint8Array;
  get base_key_public_key_data(): Uint8Array;
  get base_key_private_key_data(): Uint8Array;
  get base_key_has_private_key(): number;
  set base_key_has_private_key(v: number);
  get start_index(): number;
  set start_index(v: number);
  get count(): number;
  set count(v: number);
  get hardened(): number;
  set hardened(v: number);

  toObject(): Record<string, unknown>;
  copyFrom(obj: Partial<Record<string, unknown>>): void;
  copyTo(dest: Uint8Array, offset?: number): void;
  getBytes(): Uint8Array;
}

export class DerivedKeyEntryView {
  constructor(buffer: ArrayBuffer, byteOffset?: number);
  static fromMemory(memory: WebAssembly.Memory, ptr: number): DerivedKeyEntryView;
  static fromBytes(bytes: Uint8Array, offset?: number): DerivedKeyEntryView;
  static allocate(): DerivedKeyEntryView;

  get index(): number;
  set index(v: number);
  get error(): AlignedError;
  set error(v: AlignedError);
  get public_key_data(): Uint8Array;
  get private_key_data(): Uint8Array;

  toObject(): Record<string, unknown>;
  copyFrom(obj: Partial<Record<string, unknown>>): void;
  copyTo(dest: Uint8Array, offset?: number): void;
  getBytes(): Uint8Array;
}

export class DerivedKeyEntryArrayView implements Iterable<DerivedKeyEntryView> {
  constructor(buffer: ArrayBuffer, byteOffset: number, count: number);
  static fromMemory(memory: WebAssembly.Memory, ptr: number, count: number): DerivedKeyEntryArrayView;

  readonly length: number;
  at(index: number): DerivedKeyEntryView;
  [Symbol.iterator](): Iterator<DerivedKeyEntryView>;
}

// =============================================================================
// AlignedKeyDeriver
// =============================================================================

/**
 * Efficient batch key derivation using aligned binary format.
 */
export class AlignedKeyDeriver {
  /**
   * @param wasm - WASM module instance
   */
  constructor(wasm: unknown);

  /**
   * Derive multiple child keys from a base key in batch.
   *
   * @param baseKey - Base HDKey or BaseKeyData
   * @param startIndex - Starting child index
   * @param count - Number of keys to derive
   * @param hardened - Use hardened derivation
   * @returns Array of derived keys
   */
  deriveBatch(
    baseKey: BaseKeyData | { _handle: unknown },
    startIndex: number,
    count: number,
    hardened?: boolean
  ): DerivedKey[];

  /**
   * Generator for streaming key derivation.
   *
   * @param baseKey - Base HDKey or BaseKeyData
   * @param startIndex - Starting child index
   * @param batchSize - Keys per batch
   * @param hardened - Use hardened derivation
   * @yields Batches of derived keys
   */
  streamKeys(
    baseKey: BaseKeyData | { _handle: unknown },
    startIndex?: number,
    batchSize?: number,
    hardened?: boolean
  ): Generator<DerivedKey[], void, unknown>;
}

// =============================================================================
// AlignedSigner
// =============================================================================

/**
 * Efficient batch signing using aligned binary format.
 */
export class AlignedSigner {
  /**
   * @param wasm - WASM module instance
   */
  constructor(wasm: unknown);

  /**
   * Sign multiple message hashes with the same private key.
   *
   * @param privateKey - 32-byte private key
   * @param hashes - Array of 32-byte message hashes
   * @param curve - Elliptic curve
   * @returns Array of signature results
   */
  signBatch(
    privateKey: Uint8Array,
    hashes: Uint8Array[],
    curve?: AlignedCurve
  ): SignatureResult[];

  /**
   * Verify multiple signatures against the same public key.
   *
   * @param publicKey - 33-byte compressed public key
   * @param entries - Hash/signature pairs
   * @param curve - Elliptic curve
   * @returns Array of verification results
   */
  verifyBatch(
    publicKey: Uint8Array,
    entries: VerifyEntry[],
    curve?: AlignedCurve
  ): VerifyResult[];
}

// =============================================================================
// AlignedAPI
// =============================================================================

/**
 * Combined aligned API providing access to batch operations.
 */
export class AlignedAPI {
  /**
   * @param wasm - WASM module instance
   */
  constructor(wasm: unknown);

  /** Key deriver for batch derivation */
  readonly keyDeriver: AlignedKeyDeriver;

  /** Signer for batch signing/verification */
  readonly signer: AlignedSigner;

  /**
   * Convert HDKey to ExtendedKeyData bytes
   * @param hdKey - HDKey instance
   * @returns Extended key data bytes
   */
  keyToBytes(hdKey: { _handle: unknown }): Uint8Array;

  /** Size of DerivedKeyEntry struct */
  readonly derivedKeyEntrySize: number;

  /** Size of ExtendedKeyData struct */
  readonly extendedKeyDataSize: number;

  /** Size of BatchDeriveRequest struct */
  readonly batchDeriveRequestSize: number;
}

export default AlignedAPI;
