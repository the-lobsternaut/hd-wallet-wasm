/**
 * HD Wallet UI — Pure Library
 *
 * Re-exports all pure (non-DOM) modules for programmatic use.
 * No UI or DOM dependencies.
 */

// Constants & configuration
export {
  cryptoConfig,
  coinTypeToConfig,
  buildSigningPath,
  buildEncryptionPath,
  getSigningKey,
  getEncryptionKey,
  WellKnownCoinType,
  PKI_STORAGE_KEY,
  STORED_WALLET_KEY,
  PASSKEY_CREDENTIAL_KEY,
  PASSKEY_WALLET_KEY,
} from './constants.js';

// Address derivation & utilities
export {
  toHexCompact,
  toHex,
  hexToBytes,
  ensureUint8Array,
  generateBtcAddress,
  generateEthAddress,
  generateSolAddress,
  generateXrpAddress,
  deriveEthAddress,
  deriveSuiAddress,
  deriveMonadAddress,
  deriveCardanoAddress,
  generateAddresses,
  generateAddressForCoin,
  truncateAddress,
  fetchBtcBalance,
  fetchEthBalance,
  fetchSolBalance,
  fetchSuiBalance,
  fetchMonadBalance,
  fetchAdaBalance,
  fetchXrpBalance,
} from './address-derivation.js';

// Wallet storage & encryption
export {
  default as WalletStorage,
  StorageMethod,
  isPasskeySupported,
  isPRFLikelySupported,
  registerPasskey,
  authenticatePasskey,
  getStorageMetadata,
  hasStoredWallet,
  getStorageMethod,
  storeWithPIN,
  retrieveWithPIN,
  storeWithPasskey,
  retrieveWithPasskey,
  clearStorage,
  migrateStorage,
} from './wallet-storage.js';
