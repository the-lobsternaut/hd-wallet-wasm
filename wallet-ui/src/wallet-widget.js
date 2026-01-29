/**
 * HD Wallet Web Component
 *
 * Usage:
 *   <script type="module" src="wallet-widget.js"></script>
 *   <wallet-widget auto-open></wallet-widget>
 *
 * Attributes:
 *   auto-open  — auto-open login modal if stored wallet found (default: true)
 */

import css from '../styles/main.css?inline';
import template from './wallet-template.html?raw';
import { init } from './app.js';

class WalletWidget extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    // Inject styles
    const style = document.createElement('style');
    style.textContent = css;
    this.shadowRoot.appendChild(style);

    // Inject Google Fonts into light DOM (fonts don't load from Shadow DOM)
    if (!document.querySelector('link[href*="fonts.googleapis.com/css2?family=SF"]')) {
      const preconnect1 = document.createElement('link');
      preconnect1.rel = 'preconnect';
      preconnect1.href = 'https://fonts.googleapis.com';
      document.head.appendChild(preconnect1);

      const preconnect2 = document.createElement('link');
      preconnect2.rel = 'preconnect';
      preconnect2.href = 'https://fonts.gstatic.com';
      preconnect2.crossOrigin = '';
      document.head.appendChild(preconnect2);

      const fontLink = document.createElement('link');
      fontLink.rel = 'stylesheet';
      fontLink.href = "https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@400;500;600;700&family=SF+Mono:wght@400;500&display=swap";
      document.head.appendChild(fontLink);
    }

    // Inject template
    const container = document.createElement('div');
    container.innerHTML = template;
    this.shadowRoot.appendChild(container);

    // Initialize the wallet app with this shadow root as the DOM root
    init(this.shadowRoot);
  }
}

customElements.define('wallet-widget', WalletWidget);

export default WalletWidget;
