import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  root: '.',
  base: './',
  resolve: {
    alias: {
      '@wallet': resolve(__dirname, 'src'),
      '@sds': resolve(__dirname, '..', '..', 'spacedatastandards.org'),
    },
  },
  optimizeDeps: {
    include: ['qrcode', 'buffer', 'vcard-cryptoperson'],
    exclude: ['hd-wallet-wasm'],
  },
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
      },
      external: ['fs', 'url', 'path', 'module', 'crypto'],
      onwarn(warning, warn) {
        if (warning.code === 'MODULE_LEVEL_DIRECTIVE' ||
            (warning.message && warning.message.includes('has been externalized for browser compatibility'))) {
          return;
        }
        warn(warning);
      },
    },
  },
  server: {
    port: 3494,
    open: true,
    fs: {
      allow: [
        resolve(__dirname, '..'),
        resolve(__dirname, '..', '..', 'spacedatastandards.org'),
      ],
    },
    proxy: {
      '/api/blockchain': {
        target: 'https://blockchain.info',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/blockchain/, ''),
      },
      '/api/eth': {
        target: 'https://cloudflare-eth.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/eth/, ''),
      },
      '/api/solana/official': {
        target: 'https://api.mainnet-beta.solana.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/solana\/official/, ''),
      },
      '/api/solana/publicnode': {
        target: 'https://solana-rpc.publicnode.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/solana\/publicnode/, ''),
      },
      '/api/solana/helius': {
        target: 'https://mainnet.helius-rpc.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/solana\/helius/, ''),
      },
      /* Commented out — BTC/ETH/SOL only for now
      '/api/sui': { target: 'https://fullnode.mainnet.sui.io:443', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/sui/, '') },
      '/api/monad': { target: 'https://testnet-rpc.monad.xyz', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/monad/, '') },
      '/api/koios': { target: 'https://api.koios.rest', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/koios/, '') },
      '/api/xrp': { target: 'https://s1.ripple.com:51234', changeOrigin: true, rewrite: (path) => path.replace(/^\/api\/xrp/, '') },
      */
      '/api/coinbase': {
        target: 'https://api.coinbase.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/coinbase/, ''),
      },
      '/api/hiro': {
        target: 'https://api.hiro.so',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/hiro/, ''),
      },
    },
  },
  publicDir: 'public',
});
