/**
 * HD Wallet WASM - TypeScript Definitions
 *
 * Comprehensive HD wallet implementation with:
 * - BIP-32/39/44/49/84 support
 * - Multi-curve cryptography (secp256k1, Ed25519, P-256, P-384, X25519)
 * - Multi-chain support (Bitcoin, Ethereum, Solana, Cosmos, Polkadot)
 * - Hardware wallet abstraction (requires bridge)
 * - Transaction building and signing
 */

// Import aligned API types
import { AlignedAPI } from './aligned';

// =============================================================================
// Module Types
// =============================================================================

export interface HDWalletModule {
  // Module info
  getVersion(): string;
  hasCryptopp(): boolean;
  isFipsMode(): boolean;
  getSupportedCoins(): string[];
  getSupportedCurves(): string[];

  // WASI bridge
  wasiHasFeature(feature: WasiFeature): boolean;
  wasiGetWarning(feature: WasiFeature): WasiWarning;
  wasiGetWarningMessage(feature: WasiFeature): string;

  // Entropy
  injectEntropy(entropy: Uint8Array): void;
  getEntropyStatus(): EntropyStatus;

  // BIP-39 Mnemonic
  mnemonic: MnemonicAPI;

  // BIP-32 HD Keys
  hdkey: HDKeyAPI;

  // Multi-curve cryptography
  curves: CurvesAPI;

  // Bitcoin
  bitcoin: BitcoinAPI;

  // Ethereum
  ethereum: EthereumAPI;

  // Cosmos
  cosmos: CosmosAPI;

  // Solana
  solana: SolanaAPI;

  // Polkadot
  polkadot: PolkadotAPI;

  // Hardware wallets (requires bridge)
  hardware: HardwareWalletAPI;

  // Keyring
  keyring: KeyringAPI;

  // Utilities
  utils: UtilsAPI;

  // Aligned binary API for efficient batch operations
  aligned: AlignedAPI;
}

// =============================================================================
// Enums
// =============================================================================

export enum Curve {
  SECP256K1 = 0,
  ED25519 = 1,
  P256 = 2,
  P384 = 3,
  X25519 = 4
}

export enum CoinType {
  BITCOIN = 0,
  BITCOIN_TESTNET = 1,
  LITECOIN = 2,
  DOGECOIN = 3,
  ETHEREUM = 60,
  ETHEREUM_CLASSIC = 61,
  COSMOS = 118,
  STELLAR = 148,
  BITCOIN_CASH = 145,
  POLKADOT = 354,
  KUSAMA = 434,
  SOLANA = 501,
  BINANCE = 714,
  CARDANO = 1815
}

export enum Language {
  ENGLISH = 0,
  JAPANESE = 1,
  KOREAN = 2,
  SPANISH = 3,
  CHINESE_SIMPLIFIED = 4,
  CHINESE_TRADITIONAL = 5,
  FRENCH = 6,
  ITALIAN = 7,
  CZECH = 8,
  PORTUGUESE = 9
}

export enum WasiFeature {
  RANDOM = 0,
  FILESYSTEM = 1,
  NETWORK = 2,
  USB_HID = 3,
  CLOCK = 4,
  ENVIRONMENT = 5
}

export enum WasiWarning {
  NONE = 0,
  NEEDS_ENTROPY = 1,
  NEEDS_BRIDGE = 2,
  NOT_AVAILABLE_WASI = 3,
  DISABLED_FIPS = 4,
  NEEDS_CAPABILITY = 5
}

export enum EntropyStatus {
  NOT_INITIALIZED = 0,
  INITIALIZED = 1,
  SUFFICIENT = 2
}

export enum BitcoinAddressType {
  P2PKH = 0,
  P2SH = 1,
  P2WPKH = 2,
  P2WSH = 3,
  P2TR = 4
}

export enum Network {
  MAINNET = 0,
  TESTNET = 1
}

// =============================================================================
// BIP-39 Mnemonic API
// =============================================================================

export interface MnemonicAPI {
  /**
   * Generate a random mnemonic phrase
   * @param wordCount Number of words (12, 15, 18, 21, or 24)
   * @param language Wordlist language
   * @throws If entropy not available (WASI) or invalid word count
   */
  generate(wordCount?: number, language?: Language): string;

  /**
   * Validate a mnemonic phrase
   */
  validate(mnemonic: string, language?: Language): boolean;

  /**
   * Convert mnemonic to 64-byte seed
   */
  toSeed(mnemonic: string, passphrase?: string): Uint8Array;

  /**
   * Convert mnemonic to entropy bytes
   */
  toEntropy(mnemonic: string, language?: Language): Uint8Array;

  /**
   * Convert entropy to mnemonic
   */
  fromEntropy(entropy: Uint8Array, language?: Language): string;

  /**
   * Get wordlist for language
   */
  getWordlist(language?: Language): string[];

  /**
   * Get word suggestions for autocomplete
   */
  suggestWords(prefix: string, language?: Language, maxSuggestions?: number): string[];

  /**
   * Check if word is in wordlist
   */
  checkWord(word: string, language?: Language): boolean;
}

// =============================================================================
// BIP-32 HD Key API
// =============================================================================

export interface HDKey {
  /** Derivation path */
  readonly path: string;

  /** Key depth in derivation tree */
  readonly depth: number;

  /** Parent fingerprint */
  readonly parentFingerprint: number;

  /** Child index */
  readonly childIndex: number;

  /** Is this a neutered (public-only) key? */
  readonly isNeutered: boolean;

  /** Elliptic curve */
  readonly curve: Curve;

  /** Get private key (throws if neutered) */
  privateKey(): Uint8Array;

  /** Get public key (compressed) */
  publicKey(): Uint8Array;

  /** Get public key (uncompressed) */
  publicKeyUncompressed(): Uint8Array;

  /** Get chain code */
  chainCode(): Uint8Array;

  /** Get key fingerprint */
  fingerprint(): number;

  /** Derive child key */
  deriveChild(index: number): HDKey;

  /** Derive child key (hardened) */
  deriveHardened(index: number): HDKey;

  /** Derive key at path */
  derivePath(path: string): HDKey;

  /** Get neutered (public-only) version */
  neutered(): HDKey;

  /** Serialize as xprv */
  toXprv(): string;

  /** Serialize as xpub */
  toXpub(): string;

  /** Securely wipe key from memory */
  wipe(): void;

  /** Clone key */
  clone(): HDKey;
}

export interface HDKeyAPI {
  /**
   * Create master key from seed
   */
  fromSeed(seed: Uint8Array, curve?: Curve): HDKey;

  /**
   * Parse extended private key
   */
  fromXprv(xprv: string): HDKey;

  /**
   * Parse extended public key
   */
  fromXpub(xpub: string): HDKey;

  /**
   * Build BIP-44 path
   */
  buildPath(purpose: number, coinType: number, account?: number, change?: number, index?: number): string;

  /**
   * Parse BIP-44 path
   */
  parsePath(path: string): {
    purpose: number;
    coinType: number;
    account: number;
    change: number;
    index: number;
  };
}

// =============================================================================
// Multi-Curve API
// =============================================================================

export interface CurvesAPI {
  /**
   * Derive public key from private key
   */
  publicKeyFromPrivate(privateKey: Uint8Array, curve: Curve): Uint8Array;

  /**
   * Compress public key
   */
  compressPublicKey(publicKey: Uint8Array, curve: Curve): Uint8Array;

  /**
   * Decompress public key
   */
  decompressPublicKey(publicKey: Uint8Array, curve: Curve): Uint8Array;

  // ECDSA (secp256k1)
  secp256k1: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    signRecoverable(message: Uint8Array, privateKey: Uint8Array): { signature: Uint8Array; recoveryId: number };
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    recover(message: Uint8Array, signature: Uint8Array, recoveryId: number): Uint8Array;
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };

  // EdDSA (Ed25519)
  ed25519: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  };

  // ECDSA (P-256)
  p256: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };

  // ECDSA (P-384)
  p384: {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };

  // X25519 (key exchange only)
  x25519: {
    ecdh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  };
}

// =============================================================================
// Bitcoin API
// =============================================================================

export interface BitcoinAPI {
  /**
   * Get address from public key
   */
  getAddress(publicKey: Uint8Array, type: BitcoinAddressType, network?: Network): string;

  /**
   * Validate Bitcoin address
   */
  validateAddress(address: string): boolean;

  /**
   * Decode Bitcoin address
   */
  decodeAddress(address: string): { type: BitcoinAddressType; hash: Uint8Array; network: Network };

  /**
   * Sign message (Bitcoin Signed Message format)
   */
  signMessage(message: string, privateKey: Uint8Array): string;

  /**
   * Verify signed message
   */
  verifyMessage(message: string, signature: string, address: string): boolean;

  /**
   * Transaction builder
   */
  tx: BitcoinTxBuilder;
}

export interface BitcoinTxBuilder {
  create(): BitcoinTx;
}

export interface BitcoinTx {
  addInput(txid: string, vout: number, sequence?: number): this;
  addOutput(address: string, amount: bigint): this;
  sign(inputIndex: number, privateKey: Uint8Array, redeemScript?: Uint8Array): this;
  serialize(): Uint8Array;
  getTxid(): string;
  getSize(): number;
  getVsize(): number;
}

// =============================================================================
// Ethereum API
// =============================================================================

export interface EthereumAPI {
  /**
   * Get address from public key
   */
  getAddress(publicKey: Uint8Array): string;

  /**
   * Get checksummed address (EIP-55)
   */
  getChecksumAddress(address: string): string;

  /**
   * Validate Ethereum address
   */
  validateAddress(address: string): boolean;

  /**
   * Sign message (EIP-191)
   */
  signMessage(message: string, privateKey: Uint8Array): string;

  /**
   * Sign typed data (EIP-712)
   */
  signTypedData(typedData: object, privateKey: Uint8Array): string;

  /**
   * Verify message signature
   */
  verifyMessage(message: string, signature: string): string;

  /**
   * Transaction builder
   */
  tx: EthereumTxBuilder;
}

export interface EthereumTxBuilder {
  create(params: {
    nonce: number;
    gasPrice?: bigint;
    gasLimit: bigint;
    to?: string;
    value?: bigint;
    data?: Uint8Array;
    chainId: number;
  }): EthereumTx;

  createEIP1559(params: {
    nonce: number;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
    gasLimit: bigint;
    to?: string;
    value?: bigint;
    data?: Uint8Array;
    chainId: number;
  }): EthereumTx;
}

export interface EthereumTx {
  sign(privateKey: Uint8Array): this;
  serialize(): Uint8Array;
  getHash(): string;
}

// =============================================================================
// Cosmos API
// =============================================================================

export interface CosmosAPI {
  getAddress(publicKey: Uint8Array, prefix?: string): string;
  validateAddress(address: string): boolean;
  signAmino(doc: object, privateKey: Uint8Array): object;
  signDirect(bodyBytes: Uint8Array, authInfoBytes: Uint8Array, chainId: string, accountNumber: bigint, privateKey: Uint8Array): object;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}

// =============================================================================
// Solana API
// =============================================================================

export interface SolanaAPI {
  getAddress(publicKey: Uint8Array): string;
  validateAddress(address: string): boolean;
  signMessage(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  verifyMessage(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

// =============================================================================
// Polkadot API
// =============================================================================

export interface PolkadotAPI {
  getAddress(publicKey: Uint8Array, ss58Prefix?: number): string;
  validateAddress(address: string): boolean;
  signMessage(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  verifyMessage(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

// =============================================================================
// Hardware Wallet API (requires bridge)
// =============================================================================

export interface HardwareWalletAPI {
  /**
   * Check if hardware wallet features are available
   * Returns false in WASI without bridge
   */
  isAvailable(): boolean;

  /**
   * Enumerate connected hardware wallets
   */
  enumerate(): Promise<HardwareWalletDevice[]>;

  /**
   * Connect to a hardware wallet
   */
  connect(devicePath: string): Promise<HardwareWallet>;
}

export interface HardwareWalletDevice {
  vendorId: number;
  productId: number;
  serialNumber: string;
  manufacturer: string;
  product: string;
  path: string;
}

export interface HardwareWallet {
  readonly vendor: string;
  readonly model: string;
  readonly firmwareVersion: string;
  readonly isConnected: boolean;

  getPublicKey(path: string, curve?: Curve): Promise<Uint8Array>;
  signTransaction(path: string, transaction: Uint8Array): Promise<Uint8Array>;
  signMessage(path: string, message: string): Promise<Uint8Array>;
  ping(): Promise<boolean>;
  disconnect(): void;
}

// =============================================================================
// Keyring API
// =============================================================================

export interface KeyringAPI {
  create(): Keyring;
}

export interface Keyring {
  addWallet(seed: Uint8Array, name?: string): string;
  removeWallet(id: string): void;
  getWalletCount(): number;
  getAccounts(walletId: string, coinType: CoinType, count?: number): string[];
  signTransaction(walletId: string, path: string, transaction: Uint8Array): Uint8Array;
  signMessage(walletId: string, path: string, message: Uint8Array): Uint8Array;
  destroy(): void;
}

// =============================================================================
// Utilities API
// =============================================================================

export interface UtilsAPI {
  // Hashing
  sha256(data: Uint8Array): Uint8Array;
  sha512(data: Uint8Array): Uint8Array;
  keccak256(data: Uint8Array): Uint8Array;
  ripemd160(data: Uint8Array): Uint8Array;
  hash160(data: Uint8Array): Uint8Array;
  blake2b(data: Uint8Array, outputLength?: number): Uint8Array;
  blake2s(data: Uint8Array, outputLength?: number): Uint8Array;

  // Key derivation
  hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array;
  pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Uint8Array;
  scrypt(password: Uint8Array, salt: Uint8Array, n: number, r: number, p: number, length: number): Uint8Array;

  // Encoding
  encodeBase58(data: Uint8Array): string;
  decodeBase58(str: string): Uint8Array;
  encodeBase58Check(data: Uint8Array): string;
  decodeBase58Check(str: string): Uint8Array;
  encodeBech32(hrp: string, data: Uint8Array): string;
  decodeBech32(str: string): { hrp: string; data: Uint8Array };
  encodeHex(data: Uint8Array): string;
  decodeHex(str: string): Uint8Array;
  encodeBase64(data: Uint8Array): string;
  decodeBase64(str: string): Uint8Array;

  // Memory
  secureWipe(data: Uint8Array): void;
}

// =============================================================================
// Module Initialization
// =============================================================================

/**
 * Initialize the HD Wallet WASM module
 */
export default function init(): Promise<HDWalletModule>;

/**
 * Create HD Wallet instance (alternative syntax)
 */
export function createHDWallet(): Promise<HDWalletModule>;
