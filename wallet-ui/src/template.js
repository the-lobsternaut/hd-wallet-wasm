export function getModalHTML() {
  return `
  <!-- Keys Modal -->
  <div id="keys-modal" class="modal">
  <div class="modal-glass modal-wide">
      <div class="modal-header"><div class="account-header-info"><div class="account-header-top"><h3>Account</h3><h3 class="account-total-value" id="account-total-value"></h3></div><div class="account-address-row"><span class="account-address-label">xpub</span><code class="account-address-display" id="account-address-display"></code><button class="account-address-copy" id="account-address-copy" title="Copy xpub"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></div></div><button class="modal-close">&times;</button></div>
      <div class="modal-tabs">
        <button class="modal-tab active" data-modal-tab="vcard-tab-content">Identity</button>
        <button class="modal-tab" data-modal-tab="keys-tab-content">Keys</button>
        <button class="modal-tab" data-modal-tab="trust-tab-content">Trust Map</button>
        <button class="modal-tab" data-modal-tab="bond-tab-content">Bond</button>
        <button class="modal-tab" data-modal-tab="messaging-tab-content">Messaging</button>
      </div>
      <div class="modal-body">
        <div id="keys-tab-content" class="modal-tab-content">
          <div id="memory-info-box" class="memory-info-box" style="display:none"><div class="memory-info-content"><p><strong>Your keys never leave your device.</strong></p></div><button class="wallet-info-close" id="memory-info-close" title="Close">&times;</button></div>
          <div class="xpub-section">
            <div class="xpub-header">
              <h4 class="section-label">Extended Public Key (xpub)</h4>
              <div class="wallet-info-icon-wrap" id="xpub-info-toggle" title="What is an xpub?"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="0.75"/><text x="8" y="8" text-anchor="middle" dominant-baseline="central" font-size="11" fill="currentColor">i</text></svg></div>
              <div class="memory-notice-row"><span class="memory-notice-label">Local Storage Only</span><div class="wallet-info-icon-wrap" id="memory-info-toggle" title="What does this mean?"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="0.75"/><text x="8" y="8" text-anchor="middle" dominant-baseline="central" font-size="11" fill="currentColor">i</text></svg></div></div>
            </div>
            <div id="xpub-info-box" class="xpub-info-box" style="display:none"><div class="xpub-info-content"><p><strong>Your xpub is your public identity root.</strong></p></div><button class="wallet-info-close" id="xpub-info-close" title="Close">&times;</button></div>
            <div class="key-value-row">
              <code id="keys-xpub" class="key-value truncate"></code>
              <button class="copy-key-btn" data-copy="keys-xpub" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
            </div>
          </div>
          <div class="keys-section hd-section">
            <h4 class="section-label">HD Wallet Derivation (BIP44)</h4>
            <div class="hd-controls-row">
              <div class="hd-control-group"><label>Network</label>
                <select id="hd-coin" class="glass-select compact">
                  <option value="0" data-symbol="BTC" data-name="Bitcoin">Bitcoin</option>
                  <option value="60" data-symbol="ETH" data-name="Ethereum">Ethereum</option>
                  <option value="501" data-symbol="SOL" data-name="Solana">Solana</option>
                  <!-- Commented out — BTC/ETH/SOL only for now
                  <option value="2" data-symbol="LTC" data-name="Litecoin">Litecoin</option>
                  <option value="145" data-symbol="BCH" data-name="Bitcoin Cash">Bitcoin Cash</option>
                  <option value="3" data-symbol="DOGE" data-name="Dogecoin">Dogecoin</option>
                  <option value="118" data-symbol="ATOM" data-name="Cosmos">Cosmos</option>
                  <option value="330" data-symbol="ALGO" data-name="Algorand">Algorand</option>
                  <option value="354" data-symbol="DOT" data-name="Polkadot">Polkadot</option>
                  <option value="1815" data-symbol="ADA" data-name="Cardano">Cardano</option>
                  <option value="144" data-symbol="XRP" data-name="Ripple">Ripple (XRP)</option>
                  -->
                </select>
              </div>
              <div class="hd-control-group"><label>Account</label><input type="number" id="hd-account" class="glass-input compact hd-num-input" value="0" min="0" step="1"></div>
              <div class="hd-control-group"><label>Index</label><input type="number" id="hd-index" class="glass-input compact hd-num-input" value="0" min="0" step="1"></div>
            </div>
            <div id="hd-not-initialized" class="hd-not-initialized" style="display: none;"><p>HD wallet not initialized. Please log in with a password or seed phrase.</p></div>
            <div id="derived-result" class="derived-result" style="display: none;">
              <div class="hd-key-row"><div class="hd-key-label">Signing</div><div class="hd-key-path"><code id="signing-path">m/44'/0'/0'/0'/0'</code></div><div class="hd-key-value"><code id="signing-pubkey" class="truncate"></code><button class="copy-btn" data-copy="signing-pubkey" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button></div></div>
              <div class="hd-key-row"><div class="hd-key-label">Encryption</div><div class="hd-key-path"><code id="encryption-path">m/44'/0'/0'/1'/0'</code></div><div class="hd-key-value"><code id="encryption-pubkey" class="truncate"></code><button class="copy-btn" data-copy="encryption-pubkey" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button></div></div>
              <div class="hd-address-row"><div class="hd-address-info"><span class="crypto-icon" id="derived-icon"></span><span class="crypto-name" id="derived-crypto-name">Bitcoin</span><code id="derived-address" class="hd-address"></code><a id="derived-explorer-link" href="#" target="_blank" class="explorer-link" title="View on Explorer"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg></a></div><div class="qr-section"><canvas id="address-qr" width="64" height="64"></canvas></div></div>
            </div>
          </div>
          <details class="keys-section collapsible-section">
            <summary class="section-label collapsible-header"><span>HD Wallet Root</span></summary>
            <div class="collapsible-content">
              <div class="key-item"><label>Master Public Key (xpub)</label><div class="key-value-row"><code id="wallet-xpub" class="key-value truncate"></code><button class="copy-key-btn" data-copy="wallet-xpub" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></div></div>
              <div class="key-item sensitive"><label>Master Private Key (xprv)</label><div class="key-value-row"><code id="wallet-xprv" class="key-value truncate blurred" data-revealed="false"></code><button class="reveal-key-btn" data-target="wallet-xprv" title="Reveal"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button><button class="copy-key-btn" data-copy="wallet-xprv" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></div></div>
              <div class="key-item sensitive"><label>Seed Phrase (BIP39)</label><div class="key-value-row"><code id="wallet-seed-phrase" class="key-value seed-phrase blurred" data-revealed="false"></code><button class="reveal-key-btn" data-target="wallet-seed-phrase" title="Reveal"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button><button class="copy-key-btn" data-copy="wallet-seed-phrase" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></div></div>
              <div class="export-section"><div class="export-dropdown"><button class="glass-btn small export-btn" id="export-wallet-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Export Wallet</button><div class="export-menu" id="export-menu"><button class="export-option" data-format="mnemonic"><span class="export-label">BIP39 Mnemonic</span></button><button class="export-option" data-format="xpub"><span class="export-label">Extended Public Key</span></button><button class="export-option" data-format="xprv"><span class="export-label">Extended Private Key</span></button></div></div></div>
            </div>
          </details>
        </div>
        <div id="vcard-tab-content" class="modal-tab-content active">
          <div id="vcard-form-view">
            <div class="identity-card">
              <div class="identity-card-photo">
                <div class="photo-preview" id="vcard-photo-preview">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="photo-placeholder-icon">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                  </svg>
                  <video id="vcard-camera-video" autoplay playsinline style="display:none;width:100%;height:100%;object-fit:contain;"></video>
                  <div id="vcard-photo-actions" class="photo-actions">
                    <label class="glass-btn small" for="vcard-photo-input">Upload</label>
                    <button id="vcard-camera-btn" class="glass-btn small" style="display:none;">Take Photo</button>
                    <button id="vcard-camera-capture" class="glass-btn small primary" style="display:none;">Capture</button>
                    <button id="vcard-camera-cancel" class="glass-btn small" style="display:none;">Cancel</button>
                    <button id="vcard-photo-remove" class="glass-btn small" style="display:none;">Remove</button>
                  </div>
                  <button type="button" id="vcard-photo-edit-btn" class="photo-edit-overlay" title="Edit Photo">
                    <svg class="photo-edit-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    <svg class="photo-close-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                  </button>
                </div>
                <input type="file" id="vcard-photo-input" accept="image/*" hidden>
              </div>
              <div class="identity-card-info" id="identity-card-info">
                <button class="identity-edit-btn" id="identity-edit-btn" title="Edit Identity">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                </button>
                <div class="identity-card-name" id="identity-card-name">--</div>
                <div class="identity-card-detail" id="identity-card-title"></div>
                <div class="identity-card-detail" id="identity-card-org"></div>
                <div class="identity-card-detail" id="identity-card-email"></div>
                <div class="identity-card-detail" id="identity-card-phone"></div>
              </div>
            </div>

            <div class="vcard-actions-footer">
              <div class="vcard-split-btn-group">
                <button id="generate-vcard" class="glass-btn vcard-split-btn vcard-split-export">Export vCard</button>
                <label class="glass-btn vcard-split-btn vcard-split-import" for="vcf-import-input">Import vCard</label>
                <input type="file" id="vcf-import-input" accept=".vcf,text/vcard" hidden>
              </div>
            </div>

            <div id="vcf-import-result" class="vcf-import-result" style="display: none;">
              <h4 class="section-label">Imported Contact</h4>
              <div class="vcf-import-card">
                <div class="vcf-import-photo" id="vcf-import-photo"></div>
                <div class="vcf-import-fields" id="vcf-import-fields"></div>
              </div>
              <div id="vcf-import-sig-status" class="vcard-sig-badge" style="display:none;"></div>
            </div>
          </div>

          <div id="vcard-edit-view" class="identity-edit-view" style="display: none;">
            <div class="identity-edit-scroll">
            <div class="identity-form">
              <div class="vcard-form-stack">
                <div class="vcard-form-row name-row">
                  <div class="vcard-input-group vcard-input-sm">
                    <label>Prefix</label>
                    <input type="text" id="vcard-prefix" class="vcard-input" placeholder="Mr.">
                  </div>
                  <div class="vcard-input-group">
                    <label>First Name</label>
                    <input type="text" id="vcard-firstname" class="vcard-input" placeholder="John">
                  </div>
                  <div class="vcard-input-group">
                    <label>Middle</label>
                    <input type="text" id="vcard-middlename" class="vcard-input" placeholder="A.">
                  </div>
                </div>
                <div class="vcard-form-row name-row-2">
                  <div class="vcard-input-group">
                    <label>Last Name</label>
                    <input type="text" id="vcard-lastname" class="vcard-input" placeholder="Doe">
                  </div>
                  <div class="vcard-input-group vcard-input-sm">
                    <label>Suffix</label>
                    <input type="text" id="vcard-suffix" class="vcard-input" placeholder="Jr.">
                  </div>
                </div>
                <div class="vcard-input-group">
                  <label>Nickname</label>
                  <input type="text" id="vcard-nickname" class="vcard-input" placeholder="e.g., Johnny, Ace">
                </div>
                <div class="vcard-form-row">
                  <div class="vcard-input-group">
                    <label>Email</label>
                    <input type="email" id="vcard-email" class="vcard-input" placeholder="john@example.com">
                  </div>
                  <div class="vcard-input-group">
                    <label>Phone</label>
                    <input type="tel" id="vcard-phone" class="vcard-input" placeholder="+1 555-0100">
                  </div>
                </div>
                <div class="vcard-form-row">
                  <div class="vcard-input-group">
                    <label>Organization</label>
                    <input type="text" id="vcard-org" class="vcard-input" placeholder="Company Name">
                  </div>
                  <div class="vcard-input-group">
                    <label>Job Title</label>
                    <input type="text" id="vcard-title" class="vcard-input" placeholder="Software Engineer">
                  </div>
                </div>
                <div class="vcard-input-group">
                  <label>Street Address</label>
                  <input type="text" id="vcard-street" class="vcard-input" placeholder="123 Main St">
                </div>
                <div class="vcard-form-row">
                  <div class="vcard-input-group">
                    <label>City</label>
                    <input type="text" id="vcard-city" class="vcard-input" placeholder="San Francisco">
                  </div>
                  <div class="vcard-input-group vcard-input-sm">
                    <label>State</label>
                    <input type="text" id="vcard-region" class="vcard-input" placeholder="CA">
                  </div>
                  <div class="vcard-input-group vcard-input-sm">
                    <label>ZIP</label>
                    <input type="text" id="vcard-postal" class="vcard-input" placeholder="94102">
                  </div>
                </div>
                <div class="vcard-input-group">
                  <label>Country</label>
                  <input type="text" id="vcard-country" class="vcard-input" placeholder="United States">
                </div>
              </div>
            </div>
            </div>
            <div class="identity-edit-actions">
              <button id="identity-save-btn" class="glass-btn primary">Save</button>
              <button id="identity-back-btn" class="glass-btn">Back</button>
            </div>
          </div>

          <div id="vcard-result-view" style="display: none;">
            <div class="vcard-view-toggle">
              <button id="vcard-toggle-qr" class="vcard-toggle-btn active">QR</button>
              <button id="vcard-toggle-raw" class="vcard-toggle-btn">Raw</button>
            </div>
            <div class="qr-container"><canvas id="qr-code"></canvas></div>
            <pre id="vcard-raw-view" class="vcard-raw-view" style="display:none;"></pre>
            <div id="vcard-sig-badge" class="vcard-sig-badge sig-verified" style="display:none;">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              Signed with Ed25519
            </div>
            <div class="vcard-result-actions">
              <button id="download-vcard" class="glass-btn primary">Download .vcf</button>
              <button id="copy-vcard" class="glass-btn">Copy</button>
            </div>
            <button id="vcard-back-btn" class="glass-btn vcard-back-btn">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M19 12H5M12 19l-7-7 7-7"/>
              </svg> Back to Editor
            </button>
          </div>
        </div>
        <!-- Trust Map Tab -->
        <div id="trust-tab-content" class="modal-tab-content">
          <!-- Collapsible Trust Levels -->
          <details class="trust-levels-box" open>
            <summary class="trust-levels-header">
              <span>Trust Levels</span>
              <svg class="chevron-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </summary>
            <div class="trust-levels-badges">
              <span class="trust-badge trust-ultimate">Ultimate</span>
              <span class="trust-badge trust-full">Full</span>
              <span class="trust-badge trust-marginal">Marginal</span>
              <span class="trust-badge trust-unknown">Unknown</span>
              <span class="trust-badge trust-never">Never</span>
            </div>
          </details>

          <!-- Actions bar -->
          <div class="trust-actions-bar">
            <button id="establish-trust-btn" class="glass-btn small primary">+ Establish Trust</button>
            <button id="trust-rules-btn" class="glass-btn small"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v1m0 16v1m-8-9H3m18 0h-1m-2.636-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707"/><circle cx="12" cy="12" r="4"/></svg> Rules</button>
            <div class="trust-actions-right">
              <button id="trust-export-btn" class="glass-btn small" title="Export trust data"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>
              <label class="glass-btn small" for="trust-import-input" title="Import trust data"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg></label>
              <input type="file" id="trust-import-input" accept=".json,.trust.json" hidden>
            </div>
          </div>

          <!-- Trust scan status -->
          <div id="trust-scan-status" class="trust-scan-status">
            <span class="trust-scan-dot"></span>
            <span id="trust-scan-label">Scanning...</span>
            <span id="trust-scan-count" class="trust-scan-count"></span>
          </div>

          <!-- Scrollable Trust List -->
          <div id="trust-list" class="trust-list">
            <div id="trust-list-empty" class="trust-list-empty">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity="0.3">
                <circle cx="12" cy="5" r="3"/><circle cx="6" cy="15" r="3"/><circle cx="18" cy="15" r="3"/>
                <line x1="12" y1="8" x2="8" y2="12"/><line x1="12" y1="8" x2="16" y2="12"/>
              </svg>
              <p>No trust relationships found yet.</p>
              <p class="trust-list-subtitle">Relationships will appear here as your addresses are scanned.</p>
            </div>
          </div>
        </div>

        <!-- Security Bond Tab -->
        <div id="bond-tab-content" class="modal-tab-content">
          <div class="bond-intro">
            <h4 class="section-label">Trust Proof</h4>
            <p>Holding value on your keys signals commitment and reduces Sybil risk. Your total balance across all networks serves as proof of stake in the trust network.</p>
          </div>
          <div class="bond-networks-grid">
            <div class="bond-network-card" id="bond-btc-card">
              <div class="bond-net-header"><span class="bond-net-name">Bitcoin</span><span class="bond-net-balance" id="bond-btc-balance">--</span></div>
              <a href="#" id="bond-btc-explorer" class="bond-net-address" target="_blank" rel="noopener"><code id="bond-btc-address">--</code></a>
            </div>
            <div class="bond-network-card" id="bond-eth-card">
              <div class="bond-net-header"><span class="bond-net-name">Ethereum</span><span class="bond-net-balance" id="bond-eth-balance">--</span></div>
              <a href="#" id="bond-eth-explorer" class="bond-net-address" target="_blank" rel="noopener"><code id="bond-eth-address">--</code></a>
            </div>
            <div class="bond-network-card" id="bond-sol-card">
              <div class="bond-net-header"><span class="bond-net-name">Solana</span><span class="bond-net-balance" id="bond-sol-balance">--</span></div>
              <a href="#" id="bond-sol-explorer" class="bond-net-address" target="_blank" rel="noopener"><code id="bond-sol-address">--</code></a>
            </div>
            <!-- Commented out — BTC/ETH/SOL only for now
            <div class="bond-network-card" id="bond-sui-card">...</div>
            <div class="bond-network-card" id="bond-monad-card">...</div>
            <div class="bond-network-card" id="bond-ada-card">...</div>
            <div class="bond-network-card" id="bond-xrp-card">...</div>
            -->
          </div>
        </div>

        <!-- Messaging Tab (Encrypt + Decrypt) -->
        <div id="messaging-tab-content" class="modal-tab-content">
          <div class="messaging-sub-tabs">
            <button class="messaging-sub-tab active" data-messaging-sub="encrypt-sub">Encrypt</button>
            <button class="messaging-sub-tab" data-messaging-sub="decrypt-sub">Decrypt</button>
          </div>
          <div id="encrypt-sub" class="messaging-sub-content active">
            <!-- Encrypt Step 1: Compose -->
            <div id="encrypt-step-compose" class="encrypt-step">
              <div class="encrypt-tab-intro">
                <h4 class="section-label">Encrypt a Message</h4>
                <p>ECDH key agreement + HKDF + AES-256-GCM (ECIES)</p>
              </div>
              <div class="encrypt-keys-section">
                <div class="encrypt-key-row">
                  <div class="encrypt-key-card glass-card">
                    <div class="encrypt-key-header">
                      <span class="encrypt-role-badge sender">Sender (You)</span>
                    </div>
                    <div class="encrypt-key-detail">
                      <label>Encryption Public Key</label>
                      <code id="encrypt-sender-pubkey" class="truncate">--</code>
                    </div>
                    <div class="encrypt-key-detail">
                      <label>Derivation Path</label>
                      <code id="encrypt-sender-path">--</code>
                    </div>
                  </div>
                  <div class="encrypt-key-card glass-card">
                    <div class="encrypt-key-header">
                      <span class="encrypt-role-badge recipient">Recipient</span>
                    </div>
                    <div class="encrypt-key-detail">
                      <label>Recipient Public Key (hex)</label>
                      <div class="encrypt-recipient-input-row">
                        <input type="text" id="encrypt-recipient-pubkey" class="glass-input compact" placeholder="Paste recipient's secp256k1 public key (hex)">
                        <button id="encrypt-use-self" class="glass-btn small" title="Use your own key (for testing)">Self</button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="encrypt-message-section">
                <div class="encrypt-input-group">
                  <label class="section-label">Message</label>
                  <textarea id="encrypt-plaintext" class="glass-input glass-textarea" rows="3" placeholder="Enter a message to encrypt..."></textarea>
                </div>
                <div class="encrypt-actions">
                  <button id="encrypt-btn" class="glass-btn primary" disabled>Encrypt</button>
                </div>
              </div>
            </div>
            <!-- Encrypt Step 2: Result -->
            <div id="encrypt-step-result" class="encrypt-step" style="display:none;">
              <div class="encrypt-step-header">
                <button id="encrypt-back-btn" class="glass-btn small encrypt-back-btn"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back</button>
                <h4 class="section-label">Encrypted Payload</h4>
              </div>
              <div class="encrypt-output-fields">
                <div class="encrypt-field"><label>Ciphertext</label><code id="encrypt-out-ciphertext" class="encrypt-out-value truncate"></code><button class="copy-btn" data-copy="encrypt-out-ciphertext" title="Copy"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button></div>
                <div class="encrypt-field"><label>Auth Tag</label><code id="encrypt-out-tag" class="encrypt-out-value truncate"></code></div>
                <div class="encrypt-field"><label>IV (nonce)</label><code id="encrypt-out-iv" class="encrypt-out-value truncate"></code></div>
                <div class="encrypt-field"><label>HKDF Salt</label><code id="encrypt-out-salt" class="encrypt-out-value truncate"></code></div>
                <div class="encrypt-field"><label>Sender Public Key</label><code id="encrypt-out-sender-pub" class="encrypt-out-value truncate"></code></div>
              </div>
              <div class="encrypt-bundle-group">
                <div class="encrypt-format-toggle">
                  <label class="section-label">Payload Bundle</label>
                  <div class="encrypt-format-btns">
                    <button class="glass-btn small encrypt-fmt-btn active" data-format="json">JSON</button>
                    <button class="glass-btn small encrypt-fmt-btn" data-format="flatbuffer">FlatBuffer</button>
                  </div>
                </div>
                <div class="encrypt-format-info">
                  <span id="encrypt-format-label" class="encrypt-format-label">EME (Encrypted Message Envelope) — SpaceDataStandards.org</span>
                </div>
                <textarea id="encrypt-bundle" class="glass-input glass-textarea" rows="4" readonly></textarea>
                <div class="encrypt-bundle-actions">
                  <button class="glass-btn small" id="encrypt-copy-bundle">Copy</button>
                  <button class="glass-btn small" id="encrypt-download-bundle">Download</button>
                </div>
              </div>
            </div>
          </div>
          <div id="decrypt-sub" class="messaging-sub-content">
            <!-- Decrypt Step 1: Input -->
            <div id="decrypt-step-input" class="encrypt-step">
              <div class="encrypt-tab-intro">
                <h4 class="section-label">Decrypt a Message</h4>
                <p>Paste an EME payload (JSON or base64 FlatBuffer) to decrypt with your key.</p>
              </div>
              <textarea id="decrypt-payload" class="glass-input glass-textarea" rows="6" placeholder='Paste EME JSON or base64 FlatBuffer here...'></textarea>
              <div class="encrypt-actions">
                <button id="decrypt-btn" class="glass-btn primary" disabled>Decrypt</button>
              </div>
            </div>
            <!-- Decrypt Step 2: Result -->
            <div id="decrypt-step-result" class="encrypt-step" style="display:none;">
              <div class="encrypt-step-header">
                <button id="decrypt-back-btn" class="glass-btn small encrypt-back-btn"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back</button>
                <h4 class="section-label">Decrypted Message</h4>
              </div>
              <div class="decrypt-result">
                <div class="decrypt-result-value" id="decrypt-result-value"></div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <!-- Login Modal -->
  <div id="login-modal" class="modal">
    <div class="modal-glass login-modal-content">
      <div class="modal-header"><h3>Login</h3><button class="modal-close">&times;</button></div>
      <div id="wallet-info-box" class="wallet-info-box">
        <div id="wallet-info-expanded" class="wallet-info-expanded"><div class="wallet-info-content"><strong>Decentralized Wallet</strong> — Your credentials never leave your browser.</div><button class="wallet-info-close" id="wallet-info-dismiss" title="Dismiss">&times;</button></div>
        <div id="wallet-info-collapsed" class="wallet-info-collapsed" style="display:none"><span>Decentralized Wallet</span><div class="wallet-info-icon-wrap"><svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="0.75"/><text x="8" y="8" text-anchor="middle" dominant-baseline="central" font-size="11" fill="currentColor">i</text></svg></div></div>
      </div>
      <div class="modal-body">
        <div class="method-tabs">
          <button class="method-tab active" data-method="password">Password</button>
          <button class="method-tab" data-method="seed">Seed Phrase</button>
          <button class="method-tab" data-method="stored" id="stored-tab" style="display: none;">Stored</button>
        </div>
        <form id="password-method" class="method-content active" onsubmit="return false;">
          <div class="glass-input-group"><input type="text" id="wallet-username" class="glass-input" placeholder="Username" autocomplete="username"></div>
          <div class="glass-input-group">
            <input type="password" id="wallet-password" class="glass-input" placeholder="Password (24+ chars)" autocomplete="new-password">
            <div class="entropy-bar"><div class="entropy-fill" id="strength-fill"></div><div class="entropy-threshold"></div></div>
            <span class="entropy-label"><span id="entropy-bits">0</span> bits entropy</span>
          </div>
          <div class="remember-wallet-group">
            <label class="glass-checkbox"><input type="checkbox" id="remember-wallet-password"><span class="checkmark"></span><span>Remember wallet</span></label>
            <div class="remember-options" id="remember-options-password" style="display: none;">
              <div class="remember-method-selector"><button type="button" class="remember-method-btn" data-method="pin" data-target="password">PIN</button><button type="button" class="remember-method-btn active" data-method="passkey" data-target="password" id="passkey-btn-password">Passkey</button></div>
              <div class="pin-input-group" id="pin-group-password" style="display: none;"><input type="password" id="pin-input-password" class="glass-input pin-input" placeholder="6-digit PIN" maxlength="6" inputmode="numeric" pattern="[0-9]*"></div>
              <div class="passkey-info" id="passkey-info-password"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v3H7V7a5 5 0 0 1 5-5z"/><rect x="3" y="10" width="18" height="12" rx="2"/><circle cx="12" cy="16" r="1"/></svg><span>Use Face ID, Touch ID, or device PIN</span></div>
            </div>
          </div>
          <button id="derive-from-password" class="glass-btn primary full-width" disabled type="button">Login</button>
        </form>
        <div id="seed-method" class="method-content">
          <div class="glass-input-group"><textarea id="seed-phrase" class="glass-input glass-textarea" rows="3" placeholder="Enter 12 or 24 word seed phrase..."></textarea><div class="seed-actions"><button id="generate-seed" class="glass-btn small">Generate</button><button id="validate-seed" class="glass-btn small">Validate</button></div></div>
          <div class="remember-wallet-group">
            <label class="glass-checkbox"><input type="checkbox" id="remember-wallet-seed"><span class="checkmark"></span><span>Remember wallet</span></label>
            <div class="remember-options" id="remember-options-seed" style="display: none;">
              <div class="remember-method-selector"><button type="button" class="remember-method-btn" data-method="pin" data-target="seed">PIN</button><button type="button" class="remember-method-btn active" data-method="passkey" data-target="seed" id="passkey-btn-seed">Passkey</button></div>
              <div class="pin-input-group" id="pin-group-seed" style="display: none;"><input type="password" id="pin-input-seed" class="glass-input pin-input" placeholder="6-digit PIN" maxlength="6" inputmode="numeric" pattern="[0-9]*"></div>
              <div class="passkey-info" id="passkey-info-seed"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v3H7V7a5 5 0 0 1 5-5z"/><rect x="3" y="10" width="18" height="12" rx="2"/><circle cx="12" cy="16" r="1"/></svg><span>Use Face ID, Touch ID, or device PIN</span></div>
            </div>
          </div>
          <button id="derive-from-seed" class="glass-btn primary full-width" disabled>Login</button>
        </div>
        <div id="stored-method" class="method-content">
          <div class="stored-wallet-info"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><p>Encrypted wallet found</p><span class="stored-wallet-date" id="stored-wallet-date"></span></div>
          <div id="stored-pin-section"><div class="glass-input-group"><input type="password" id="pin-input-unlock" class="glass-input pin-input-large" placeholder="Enter 6-digit PIN" maxlength="6" inputmode="numeric" pattern="[0-9]*"></div><button id="unlock-stored-wallet" class="glass-btn primary full-width" disabled>Unlock with PIN</button></div>
          <div id="stored-passkey-section" style="display: none;"><button id="unlock-with-passkey" class="glass-btn primary full-width passkey-unlock-btn"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v3H7V7a5 5 0 0 1 5-5z"/><rect x="3" y="10" width="18" height="12" rx="2"/><circle cx="12" cy="16" r="1"/></svg> Unlock with Passkey</button></div>
          <div class="stored-divider" id="stored-divider" style="display: none;"><span>or</span></div>
          <button id="forget-stored-wallet" class="glass-btn secondary full-width">Forget Wallet</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Loading Overlay -->
  <div id="loading-overlay" class="loading-overlay">
    <div class="loading-spinner"></div>
    <span id="status">Loading WASM modules...</span>
  </div>

  <!-- Photo remove confirmation modal -->
  <div id="photo-remove-confirm-modal" class="modal">
    <div class="modal-glass" style="max-width:340px;padding:24px;text-align:center;">
      <p style="margin:0 0 20px;font-size:1rem;color:var(--white-70);">Are you sure you want to remove this photo?</p>
      <div style="display:flex;gap:12px;justify-content:center;">
        <button id="photo-remove-yes" class="glass-btn small" style="background:rgba(239,68,68,0.2);border-color:rgba(239,68,68,0.4);color:#f87171;">Remove</button>
        <button id="photo-remove-no" class="glass-btn small">Cancel</button>
      </div>
    </div>
  </div>`;
}
