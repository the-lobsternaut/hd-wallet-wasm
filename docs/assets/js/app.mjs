/**
 * HD Wallet WASM Documentation - Main Application Logic
 *
 * Handles:
 * - Theme toggling (dark/light mode)
 * - Navigation handling
 * - Code example copying
 * - WASM module loading (with graceful fallback)
 */

// =============================================================================
// Theme Management
// =============================================================================

const THEME_KEY = 'hd-wallet-docs-theme';

/**
 * Get the current theme preference
 * @returns {'dark' | 'light'}
 */
export function getTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === 'light' || stored === 'dark') {
    return stored;
  }
  // Check system preference
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    return 'light';
  }
  return 'dark';
}

/**
 * Set the theme
 * @param {'dark' | 'light'} theme
 */
export function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem(THEME_KEY, theme);
  updateThemeToggleIcons(theme);
}

/**
 * Toggle between dark and light themes
 */
export function toggleTheme() {
  const current = getTheme();
  setTheme(current === 'dark' ? 'light' : 'dark');
}

/**
 * Update theme toggle button icons
 * @param {'dark' | 'light'} theme
 */
function updateThemeToggleIcons(theme) {
  const toggles = document.querySelectorAll('.theme-toggle');
  toggles.forEach(toggle => {
    const sunIcon = toggle.querySelector('.icon-sun');
    const moonIcon = toggle.querySelector('.icon-moon');
    if (sunIcon && moonIcon) {
      sunIcon.style.display = theme === 'dark' ? 'block' : 'none';
      moonIcon.style.display = theme === 'light' ? 'block' : 'none';
    }
  });
}

/**
 * Initialize theme system
 */
export function initTheme() {
  const theme = getTheme();
  setTheme(theme);

  // Listen for system theme changes
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem(THEME_KEY)) {
        setTheme(e.matches ? 'dark' : 'light');
      }
    });
  }

  // Bind toggle buttons
  document.querySelectorAll('.theme-toggle').forEach(btn => {
    btn.addEventListener('click', toggleTheme);
  });
}

// =============================================================================
// Navigation
// =============================================================================

/**
 * Initialize mobile menu toggle
 */
export function initNavigation() {
  const menuToggle = document.querySelector('.mobile-menu-toggle');
  const nav = document.querySelector('.navbar-nav');

  if (menuToggle && nav) {
    menuToggle.addEventListener('click', () => {
      nav.classList.toggle('open');
      const isOpen = nav.classList.contains('open');
      menuToggle.setAttribute('aria-expanded', String(isOpen));
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
      if (!nav.contains(e.target) && !menuToggle.contains(e.target)) {
        nav.classList.remove('open');
        menuToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // Mark current page as active in nav
  const currentPath = window.location.pathname;
  document.querySelectorAll('.navbar-nav a, .docs-nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && currentPath.endsWith(href.replace(/^\.\.?\//, ''))) {
      link.classList.add('active');
    }
  });
}

// =============================================================================
// Code Copy Functionality
// =============================================================================

/**
 * Copy text to clipboard
 * @param {string} text
 * @returns {Promise<boolean>}
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      document.body.removeChild(textarea);
      return true;
    } catch {
      document.body.removeChild(textarea);
      return false;
    }
  }
}

/**
 * Initialize code copy buttons
 */
export function initCodeCopy() {
  document.querySelectorAll('.code-copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const codeBlock = btn.closest('.code-block');
      const pre = codeBlock?.querySelector('pre');
      if (!pre) return;

      const code = pre.textContent || '';
      const success = await copyToClipboard(code);

      if (success) {
        btn.classList.add('copied');
        const originalTitle = btn.getAttribute('title');
        btn.setAttribute('title', 'Copied!');

        // Update icon to checkmark
        const icon = btn.querySelector('svg');
        if (icon) {
          icon.innerHTML = '<path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>';
        }

        setTimeout(() => {
          btn.classList.remove('copied');
          btn.setAttribute('title', originalTitle || 'Copy code');
          if (icon) {
            icon.innerHTML = '<rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="2" fill="none"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" stroke-width="2" fill="none"/>';
          }
        }, 2000);
      }
    });
  });
}

// =============================================================================
// WASM Module Loading
// =============================================================================

/**
 * @typedef {Object} WasmStatus
 * @property {'loading' | 'ready' | 'error' | 'unavailable'} status
 * @property {any} module
 * @property {string} [error]
 */

/** @type {WasmStatus} */
let wasmState = {
  status: 'loading',
  module: null,
  error: undefined
};

/** @type {Set<(status: WasmStatus) => void>} */
const wasmListeners = new Set();

/**
 * Subscribe to WASM status changes
 * @param {(status: WasmStatus) => void} callback
 * @returns {() => void} Unsubscribe function
 */
export function subscribeToWasmStatus(callback) {
  wasmListeners.add(callback);
  callback(wasmState);
  return () => wasmListeners.delete(callback);
}

/**
 * Update WASM status and notify listeners
 * @param {Partial<WasmStatus>} update
 */
function updateWasmStatus(update) {
  wasmState = { ...wasmState, ...update };
  wasmListeners.forEach(cb => cb(wasmState));
}

/**
 * Get the WASM module if available
 * @returns {any | null}
 */
export function getWasmModule() {
  return wasmState.module;
}

/**
 * Check if WASM is ready
 * @returns {boolean}
 */
export function isWasmReady() {
  return wasmState.status === 'ready';
}

/**
 * Load the WASM module
 * @param {string} [wasmPath] Path to the WASM module
 * @returns {Promise<any>}
 */
export async function loadWasmModule(wasmPath = '../../../wasm/dist/hd-wallet-wasm.js') {
  try {
    updateWasmStatus({ status: 'loading' });

    // Try to dynamically import the module
    const module = await import(wasmPath);
    const wallet = await (module.default || module.createHDWallet)();

    updateWasmStatus({ status: 'ready', module: wallet });
    return wallet;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to load WASM module';
    updateWasmStatus({ status: 'error', error: errorMessage });
    console.warn('WASM module not available:', errorMessage);
    throw error;
  }
}

/**
 * Initialize WASM status display elements
 */
export function initWasmStatus() {
  const statusElements = document.querySelectorAll('.wasm-status');

  subscribeToWasmStatus((status) => {
    statusElements.forEach(el => {
      el.classList.remove('loading', 'ready', 'error');
      el.classList.add(status.status);

      const icon = el.querySelector('.wasm-status-icon');
      const text = el.querySelector('.wasm-status-text');

      if (icon) {
        switch (status.status) {
          case 'loading':
            icon.innerHTML = '<div class="spinner"></div>';
            break;
          case 'ready':
            icon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
            break;
          case 'error':
          case 'unavailable':
            icon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>';
            break;
        }
      }

      if (text) {
        switch (status.status) {
          case 'loading':
            text.textContent = 'Loading WASM module...';
            break;
          case 'ready':
            text.textContent = 'WASM module ready';
            break;
          case 'error':
            text.textContent = `WASM unavailable: ${status.error || 'Unknown error'}`;
            break;
          case 'unavailable':
            text.textContent = 'WASM module not available (demo mode)';
            break;
        }
      }
    });
  });
}

// =============================================================================
// Demo Utilities
// =============================================================================

/**
 * Generate a mock mnemonic for demo purposes (when WASM not available)
 * @param {number} wordCount
 * @returns {string}
 */
export function generateMockMnemonic(wordCount = 24) {
  // This is NOT cryptographically secure - only for UI demo
  const mockWords = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
    'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
    'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
    'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
    'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album'
  ];

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    const randomIndex = Math.floor(Math.random() * mockWords.length);
    words.push(mockWords[randomIndex]);
  }
  return words.join(' ');
}

/**
 * Generate mock entropy hex string
 * @param {number} bytes
 * @returns {string}
 */
export function generateMockEntropy(bytes = 32) {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < bytes * 2; i++) {
    result += chars[Math.floor(Math.random() * 16)];
  }
  return result;
}

/**
 * Generate mock seed hex string
 * @returns {string}
 */
export function generateMockSeed() {
  return generateMockEntropy(64);
}

/**
 * Generate mock extended key
 * @param {boolean} isPublic
 * @returns {string}
 */
export function generateMockExtendedKey(isPublic = false) {
  const prefix = isPublic ? 'xpub' : 'xprv';
  const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let result = prefix;
  for (let i = 0; i < 107; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

/**
 * Convert bytes to hex string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to bytes
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Debounce function
 * @param {Function} fn
 * @param {number} delay
 * @returns {Function}
 */
export function debounce(fn, delay) {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), delay);
  };
}

// =============================================================================
// Syntax Highlighting (Basic)
// =============================================================================

const TOKEN_PATTERNS = [
  { pattern: /\/\/.*$/gm, className: 'token-comment' },
  { pattern: /\/\*[\s\S]*?\*\//g, className: 'token-comment' },
  { pattern: /(["'`])(?:(?!\1)[^\\]|\\.)*\1/g, className: 'token-string' },
  { pattern: /\b(const|let|var|function|async|await|return|if|else|for|while|class|export|import|from|new|throw|try|catch|finally|typeof|instanceof)\b/g, className: 'token-keyword' },
  { pattern: /\b(true|false|null|undefined|NaN|Infinity)\b/g, className: 'token-boolean' },
  { pattern: /\b\d+\.?\d*\b/g, className: 'token-number' },
  { pattern: /\b([A-Z][a-zA-Z0-9]*)\b/g, className: 'token-class' },
  { pattern: /\b([a-z_$][a-zA-Z0-9_$]*)\s*(?=\()/g, className: 'token-function' },
];

/**
 * Apply basic syntax highlighting to code
 * @param {string} code
 * @param {string} [language]
 * @returns {string}
 */
export function highlightCode(code, language = 'javascript') {
  let highlighted = escapeHtml(code);

  // Apply token patterns in order (comments first to avoid conflicts)
  TOKEN_PATTERNS.forEach(({ pattern, className }) => {
    highlighted = highlighted.replace(pattern, (match) => {
      // Don't double-highlight
      if (match.includes('class="token-')) return match;
      return `<span class="${className}">${match}</span>`;
    });
  });

  return highlighted;
}

/**
 * Escape HTML entities
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  const entities = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return str.replace(/[&<>"']/g, char => entities[char]);
}

/**
 * Initialize syntax highlighting for all code blocks
 */
export function initSyntaxHighlighting() {
  document.querySelectorAll('pre code').forEach(block => {
    const language = block.className.match(/language-(\w+)/)?.[1] || 'javascript';
    block.innerHTML = highlightCode(block.textContent || '', language);
  });
}

// =============================================================================
// Smooth Scroll for Anchor Links
// =============================================================================

export function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      const href = anchor.getAttribute('href');
      if (!href || href === '#') return;

      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.pushState(null, '', href);
      }
    });
  });
}

// =============================================================================
// Initialize All
// =============================================================================

/**
 * Initialize all application features
 */
export function initApp() {
  // Wait for DOM to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => initApp());
    return;
  }

  initTheme();
  initNavigation();
  initCodeCopy();
  initWasmStatus();
  initSyntaxHighlighting();
  initSmoothScroll();
}

// Auto-initialize when script is loaded
initApp();
