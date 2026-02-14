# HD Wallet UI

Standalone HD wallet interface with glass morphism design. Supports BIP-32/39/44 key derivation across multiple blockchain networks.

## Features

- **Multi-chain support** -- BTC, ETH, SOL, SUI, Monad, Cardano (and more via HD derivation)
- **Three login methods** -- Password, BIP39 seed phrase, or stored wallet (PIN/Passkey)
- **HD key derivation** -- BIP44 paths with configurable network, account, and index
- **Secure storage** -- PIN (PBKDF2 + AES-256-GCM) or Passkey (WebAuthn PRF)
- **vCard generation** -- Export identity with cryptographic public keys
- **Live balance checking** -- Fetches balances from public blockchain APIs
- **Glass morphism UI** -- Frosted glass aesthetic with blurred background

## Quick Start

```bash
npm install
npm run dev
```

Opens on `http://localhost:3000`.

## Build

```bash
npm run build    # Output in dist/
npm run preview  # Preview the build
```

## Project Structure

```
wallet-ui/
├── index.html                  # Main HTML
├── src/
│   ├── app.js                  # Entry point, login/logout, UI handlers
│   ├── wallet-storage.js       # Encrypted wallet storage (PIN/Passkey)
│   ├── address-derivation.js   # Multi-chain address generation
│   └── constants.js            # Coin configs, explorer URLs, path helpers
├── styles/
│   ├── main.css                # Standalone demo site styles (global)
│   └── widget.css              # Namespaced embed styles (scoped to #hd-wallet-ui-container)
├── package.json
└── vite.config.js
```

## Embedding (Avoiding CSS Collisions)

If you're integrating the modal UI into an existing webpage, use the namespaced stylesheet export:

```js
import 'hd-wallet-ui/styles';
```

For the standalone demo site styling, use:

```js
import 'hd-wallet-ui/styles/demo';
```

## Usage Examples

### Address Derivation

```js
import {
  generateBtcAddress,
  generateEthAddress,
  generateSolAddress,
  deriveSuiAddress,
  deriveCardanoAddress,
} from './src/address-derivation.js';

// Bitcoin P2PKH from compressed secp256k1 pubkey
const btcAddr = generateBtcAddress(compressedPubKey);   // "1A1zP1..."

// Ethereum from secp256k1 (handles 33, 64, or 65 byte keys)
const ethAddr = generateEthAddress(compressedPubKey);   // "0x..."

// Solana from Ed25519 pubkey
const solAddr = generateSolAddress(ed25519PubKey);      // Base58 string

// SUI from Ed25519 with BLAKE2b
const suiAddr = deriveSuiAddress(ed25519PubKey, 'ed25519');  // "0x..."

// Cardano enterprise address (Bech32)
const adaAddr = deriveCardanoAddress(ed25519PubKey);    // "addr1..."
```

### Derivation Paths

```js
import { buildSigningPath, buildEncryptionPath } from './src/constants.js';

buildSigningPath(0, 0, 0);      // "m/44'/0'/0'/0/0"   (Bitcoin)
buildSigningPath(60, 0, 0);     // "m/44'/60'/0'/0/0"  (Ethereum)
buildEncryptionPath(0, 0, 0);   // "m/44'/0'/0'/1/0"   (encryption key)
```

### Coin Configuration

```js
import { cryptoConfig, coinTypeToConfig } from './src/constants.js';

cryptoConfig.btc.explorer;            // "https://blockstream.info/address/"
coinTypeToConfig[60].name;            // "Ethereum"
cryptoConfig.eth.formatBalance(1e18); // "1.000000 ETH"
```

### Wallet Storage

```js
import WalletStorage, { StorageMethod } from './src/wallet-storage.js';

// Store with PIN
await WalletStorage.storeWithPIN('123456', { type: 'seed', seedPhrase: '...' });

// Retrieve with PIN
const data = await WalletStorage.retrieveWithPIN('123456');

// Store with Passkey (WebAuthn PRF)
await WalletStorage.storeWithPasskey(walletData, {
  rpName: 'My Wallet',
  userName: 'user',
});

// Check storage status
const meta = WalletStorage.getStorageMetadata();
// { method: 'passkey', storedAt: 1706000000000, version: 2 }
```

### Balance Fetching

```js
import {
  fetchBtcBalance,
  fetchEthBalance,
  fetchSolBalance,
} from './src/address-derivation.js';

const { balance } = await fetchBtcBalance('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
// "50.00000000"

const { balance: ethBal } = await fetchEthBalance('0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe');
// "0.000000"
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `hd-wallet-wasm` | HD key derivation (BIP-32/39/44), WASM runtime |
| `@noble/curves` | secp256k1, ed25519, p256 elliptic curves |
| `@noble/hashes` | SHA-256, Keccak-256, RIPEMD-160, BLAKE2b |
| `@scure/base` | Base58, Base58Check encoding |
| `@scure/bip32` | BIP-32 extended key derivation |
| `bip39` | BIP-39 mnemonic generation/validation |
| `qrcode` | QR code rendering for addresses and vCards |
| `vcard-cryptoperson` | vCard 4.0 with cryptographic keys |
| `buffer` | Buffer polyfill for browser |

## Tests

```bash
npm test
```

Runs unit tests for address derivation, Bech32 encoding, and coin configuration. See [test/](test/) for details.

## License

Same as parent `hd-wallet-wasm` repository.
