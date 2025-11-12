// ==UserScript==
// @name         Elite Pentest Framework 2025 - Modular Edition
// @namespace    http://tampermonkey.net/
// @version      11.0.0
// @description  Professional Modular Security Testing Framework - GitHub Integrated
// @author       Elite Security Team 2025
// @match        https://*/*
// @match        http://*/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_xmlhttpRequest
// @grant        GM_openInTab
// @grant        GM_download
// @grant        unsafeWindow
// @connect      *
// @connect      raw.githubusercontent.com
// @connect      github.com
// @run-at       document-start
// @require      https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/ResponseAnalyzer.js
// @require      https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/WAFDetector.js
// @require      https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/PayloadManager.js
// ==/UserScript==

/**
 * ════════════════════════════════════════════════════════════════════════════
 * Elite Pentest Framework 2025 - Main Coordinator
 * ════════════════════════════════════════════════════════════════════════════
 * 
 * HOW TO USE:
 * 1. Upload modules/ folder to your GitHub repository
 * 2. Update @require URLs above with your GitHub raw URLs
 * 3. Install this script in Tampermonkey
 * 4. Press Ctrl+Shift+E to open dashboard
 * 
 * GITHUB SETUP:
 * 1. Create repo: https://github.com/yourusername/elite-pentest
 * 2. Upload all files from modules/ folder
 * 3. Get raw URLs: Click file → Raw button → Copy URL
 * 4. Update @require URLs in this script
 * 
 * ALTERNATIVE (Local Files):
 * Change @require to: file:///C:/Users/Moiz/pentest/modules/ModuleName.js
 */

(function() {
  'use strict';

  // ════════════════════════════════════════════════════════════════════════════
  // 🎯 CONFIGURATION & INITIALIZATION
  // ════════════════════════════════════════════════════════════════════════════

  const CONFIG = {
    VERSION: '11.0.0',
    
    // Module URLs (GitHub: Nevrkin/Another-XSS)
    MODULES: {
      ResponseAnalyzer: 'https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/ResponseAnalyzer.js',
      WAFDetector: 'https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/WAFDetector.js',
      PayloadManager: 'https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/PayloadManager.js'
    },

    // Testing Configuration
    TESTING: {
      MAX_THREADS: 3,
      REQUEST_TIMEOUT: 15000,
      PAYLOAD_DELAY: 500,
      CONFIDENCE_THRESHOLD: 70
    },

    // Attack Vectors (Enable/Disable)
    VECTORS: {
      XSS: true,
      SQLI: true,
      XXE: false,
      SSRF: true,
      IDOR: false,
      LFI: true,
      RCE: true,
      SSTI: true,
      CRLF: false,
      OPEN_REDIRECT: true,
      NOSQL: false
    },

    // PayloadManager Sources
    PAYLOAD_SOURCES: {
      xss: ['seclists_basic', 'payloadbox'],
      sqli: ['seclists_mysql', 'seclists_generic'],
      lfi: ['seclists_linux', 'payloadbox'],
      ssrf: ['seclists', 'payloadbox'],
      rce: ['seclists_unix', 'payloadbox']
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // 🔧 MODULE LOADER
  // ════════════════════════════════════════════════════════════════════════════

  class ModuleLoader {
    constructor() {
      this.modules = {};
      this.loaded = false;
    }

    async init() {
      console.log('[Elite] Initializing modules...');

      try {
        // Initialize core modules
        this.modules.analyzer = new ResponseAnalyzer();
        this.modules.wafDetector = new WAFDetector();
        this.modules.payloadManager = new PayloadManager();

        this.loaded = true;
        console.log('[Elite] ✓ All modules loaded successfully');
        
        return true;
      } catch (error) {
        console.error('[Elite] Module initialization failed:', error);
        return false;
      }
    }

    getModule(name) {
      return this.modules[name];
    }

    isLoaded() {
      return this.loaded;
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🎯 VULNERABILITY SCANNER
  // ════════════════════════════════════════════════════════════════════════════

  class VulnerabilityScanner {
    constructor(modules) {
      this.analyzer = modules.analyzer;
      this.wafDetector = modules.wafDetector;
      this.payloadManager = modules.payloadManager;
      this.results = [];
      this.baseline = null;
      this.scanning = false;
    }

    async initialize(url) {
      console.log('[Scanner] Initializing...');

      // Capture baseline
      this.baseline = await this.analyzer.captureBaseline(url);

      // Detect WAF
      await this.wafDetector.detect(url);

      console.log('[Scanner] Ready');
    }

    async scanParameter(url, parameter, vulnTypes = ['xss', 'sqli']) {
      const results = [];

      for (const vulnType of vulnTypes) {
        if (!CONFIG.VECTORS[vulnType.toUpperCase()]) continue;

        console.log(`[Scanner] Testing ${parameter} for ${vulnType.toUpperCase()}...`);

        // Get payloads
        const payloads = await this.payloadManager.getPayloads(vulnType, {
          sources: CONFIG.PAYLOAD_SOURCES[vulnType] || 'all',
          limit: 100
        });

        // Test each payload
        for (const payload of payloads) {
          try {
            // Apply WAF bypass if needed
            const processedPayload = this.wafDetector.detectedWAF
              ? this.wafDetector.applyBypass(payload, 'auto', vulnType)
              : payload;

            // Build test URL
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, processedPayload);

            // Make request
            const response = await this.analyzer.makeRequest(testUrl.toString());

            // Analyze response
            const analysis = this.analyzer.analyzeResponse(
              response,
              processedPayload,
              vulnType,
              this.baseline
            );

            if (analysis.vulnerable) {
              const vuln = {
                type: vulnType.toUpperCase(),
                parameter: parameter,
                payload: processedPayload,
                confidence: analysis.confidence,
                evidence: analysis.evidence,
                url: testUrl.toString(),
                indicators: analysis.indicators,
                timestamp: Date.now()
              };

              results.push(vuln);
              console.log(`[Scanner] ✓ ${vulnType.toUpperCase()} found! Confidence: ${analysis.confidence}%`);
            }

            // Delay between requests
            await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
          } catch (error) {
            console.error(`[Scanner] Error testing payload:`, error);
          }
        }
      }

      return results;
    }

    async fullScan(url, parameters, vulnTypes = null) {
      this.scanning = true;
      this.results = [];

      await this.initialize(url);

      const types = vulnTypes || Object.keys(CONFIG.VECTORS).filter(k => CONFIG.VECTORS[k]).map(k => k.toLowerCase());

      for (const param of parameters) {
        const paramResults = await this.scanParameter(url, param, types);
        this.results.push(...paramResults);
      }

      this.scanning = false;
      console.log(`[Scanner] Scan complete! Found ${this.results.length} vulnerabilities`);

      return this.results;
    }

    getResults() {
      return this.results;
    }

    isScanning() {
      return this.scanning;
    }

    sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🎨 ENHANCED DASHBOARD
  // ════════════════════════════════════════════════════════════════════════════

  class Dashboard {
    constructor(modules) {
      this.modules = modules;
      this.scanner = new VulnerabilityScanner(modules);
      this.isVisible = false;
    }

    create() {
      const dashboard = document.createElement('div');
      dashboard.id = 'elite-dashboard';
      dashboard.innerHTML = this.getHTML();

      document.body.appendChild(dashboard);
      this.attachStyles();
      this.attachEvents();
      this.makeDraggable(dashboard);

      console.log('[Elite] Dashboard created. Press Ctrl+Shift+E to toggle');
    }

    generateVectorCheckboxes() {
      return Object.keys(CONFIG.VECTORS).map(v => {
        const checked = CONFIG.VECTORS[v] ? 'checked' : '';
        return `<label class="elite-checkbox-label">
                  <input type="checkbox" class="elite-checkbox" data-vector="${v.toLowerCase()}" ${checked}>
                  <span class="checkbox-text">${v}</span>
                </label>`;
      }).join('');
    }

    getHTML() {
      const vectorCheckboxes = this.generateVectorCheckboxes();
      return `
        <div class="elite-header">
          <div class="elite-title">
            <span class="elite-icon">🛡️</span>
            Elite Pentest v${CONFIG.VERSION}
            <span class="elite-status" id="elite-status">Ready</span>
          </div>
          <div class="elite-controls">
            <button class="elite-btn-icon" id="elite-minimize" title="Minimize">−</button>
            <button class="elite-btn-icon" id="elite-close" title="Close">×</button>
          </div>
        </div>

        <div class="elite-body" id="elite-body">
          <!-- Quick Scan -->
          <div class="elite-section">
            <div class="elite-section-header">
              <h3>🎯 Quick Scan</h3>
            </div>
            <div class="elite-section-content">
              <input type="text" class="elite-input" id="elite-url" placeholder="Target URL" value="${window.location.href}">
              <input type="text" class="elite-input" id="elite-params" placeholder="Parameters (comma-separated)">
              <div class="elite-btn-group">
                <button class="elite-btn elite-btn-primary" id="elite-scan-btn">
                  <span class="btn-icon">🚀</span> Start Scan
                </button>
                <button class="elite-btn elite-btn-secondary" id="elite-auto-detect-btn">
                  <span class="btn-icon">🔍</span> Auto-Detect
                </button>
              </div>
            </div>
          </div>

          <!-- Attack Vectors -->
          <div class="elite-section">
            <div class="elite-section-header">
              <h3>⚙️ Attack Vectors</h3>
              <button class="elite-btn-small" id="elite-toggle-all">Toggle All</button>
            </div>
            <div class="elite-section-content">
              <div class="elite-checkbox-grid">
                ${vectorCheckboxes}
              </div>
            </div>
          </div>

          <!-- Payload Sources -->
          <div class="elite-section elite-collapsible">
            <div class="elite-section-header" data-collapse="payload-sources">
              <h3>📦 Payload Sources</h3>
              <span class="collapse-icon">▼</span>
            </div>
            <div class="elite-section-content" id="payload-sources">
              <div class="elite-info-box">
                <div class="info-item">
                  <span class="info-label">SecLists:</span>
                  <span class="info-value">✓ Active</span>
                </div>
                <div class="info-item">
                  <span class="info-label">PayloadsAllTheThings:</span>
                  <span class="info-value">✓ Active</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Cache:</span>
                  <span class="info-value" id="cache-status">Empty</span>
                </div>
              </div>
              <button class="elite-btn elite-btn-secondary" id="elite-clear-cache">
                <span class="btn-icon">🗑️</span> Clear Cache
              </button>
            </div>
          </div>

          <!-- WAF Detection -->
          <div class="elite-section elite-collapsible">
            <div class="elite-section-header" data-collapse="waf-detection">
              <h3>🛡️ WAF Detection</h3>
              <span class="collapse-icon">▼</span>
            </div>
            <div class="elite-section-content" id="waf-detection">
              <div id="waf-info" class="elite-info-box">
                <div class="info-item">
                  <span class="info-label">Status:</span>
                  <span class="info-value" id="waf-status">Not detected</span>
                </div>
              </div>
              <button class="elite-btn elite-btn-secondary" id="elite-detect-waf">
                <span class="btn-icon">🔍</span> Detect WAF
              </button>
            </div>
          </div>

          <!-- Results -->
          <div class="elite-section">
            <div class="elite-section-header">
              <h3>📊 Scan Results</h3>
              <div class="elite-badge" id="results-count">0 found</div>
            </div>
            <div class="elite-section-content">
              <div class="elite-results" id="elite-results">
                <div class="empty-state">
                  <div class="empty-icon">🔍</div>
                  <p>No scan results yet</p>
                  <small>Configure your scan and click "Start Scan"</small>
                </div>
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div class="elite-section">
            <div class="elite-btn-group">
              <button class="elite-btn elite-btn-success" id="elite-export-json">
                <span class="btn-icon">💾</span> Export JSON
              </button>
              <button class="elite-btn elite-btn-success" id="elite-export-csv">
                <span class="btn-icon">📄</span> Export CSV
              </button>
              <button class="elite-btn elite-btn-warning" id="elite-clear-results">
                <span class="btn-icon">🗑️</span> Clear
              </button>
            </div>
          </div>

          <!-- Footer -->
          <div class="elite-footer">
            <span>Elite Pentest Framework ${CONFIG.VERSION}</span>
            <span>GitHub Integrated • SecLists Powered</span>
          </div>
        </div>
      `;
    }

    attachStyles() {
      const style = document.createElement('style');
      style.textContent = `
        #elite-dashboard {
          position: fixed;
          top: 20px;
          right: 20px;
          width: 450px;
          max-height: 90vh;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          border-radius: 12px;
          color: #fff;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          z-index: 2147483647;
          box-shadow: 0 20px 60px rgba(0,0,0,0.4);
          display: none;
          overflow: hidden;
        }

        #elite-dashboard.visible {
          display: flex;
          flex-direction: column;
        }

        #elite-dashboard.minimized .elite-body {
          display: none;
        }

        .elite-header {
          background: rgba(0,0,0,0.3);
          padding: 15px 20px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: move;
          border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .elite-title {
          display: flex;
          align-items: center;
          gap: 10px;
          font-weight: 600;
          font-size: 16px;
        }

        .elite-icon {
          font-size: 20px;
        }

        .elite-status {
          font-size: 11px;
          background: rgba(76,175,80,0.3);
          color: #4caf50;
          padding: 2px 8px;
          border-radius: 10px;
          font-weight: normal;
        }

        .elite-status.scanning {
          background: rgba(255,152,0,0.3);
          color: #ff9800;
        }

        .elite-controls {
          display: flex;
          gap: 5px;
        }

        .elite-btn-icon {
          background: rgba(255,255,255,0.1);
          border: none;
          color: white;
          width: 28px;
          height: 28px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 18px;
          line-height: 1;
          transition: all 0.2s;
        }

        .elite-btn-icon:hover {
          background: rgba(255,255,255,0.2);
        }

        .elite-body {
          overflow-y: auto;
          max-height: calc(90vh - 60px);
          padding: 20px;
        }

        .elite-section {
          background: rgba(255,255,255,0.1);
          border-radius: 8px;
          margin-bottom: 15px;
          overflow: hidden;
        }

        .elite-section-header {
          padding: 12px 15px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          background: rgba(0,0,0,0.2);
          cursor: pointer;
        }

        .elite-section-header h3 {
          margin: 0;
          font-size: 14px;
          font-weight: 600;
        }

        .collapse-icon {
          transition: transform 0.3s;
        }

        .elite-section.collapsed .collapse-icon {
          transform: rotate(-90deg);
        }

        .elite-section.collapsed .elite-section-content {
          display: none;
        }

        .elite-section-content {
          padding: 15px;
        }

        .elite-input {
          width: 100%;
          padding: 10px 12px;
          border-radius: 6px;
          border: 1px solid rgba(255,255,255,0.2);
          background: rgba(255,255,255,0.1);
          color: white;
          margin-bottom: 10px;
          font-size: 13px;
        }

        .elite-input::placeholder {
          color: rgba(255,255,255,0.5);
        }

        .elite-btn-group {
          display: flex;
          gap: 10px;
        }

        .elite-btn {
          flex: 1;
          padding: 10px 15px;
          border-radius: 6px;
          border: none;
          font-weight: 600;
          font-size: 13px;
          cursor: pointer;
          transition: all 0.2s;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 6px;
        }

        .elite-btn-primary {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }

        .elite-btn-secondary {
          background: rgba(255,255,255,0.15);
          color: white;
        }

        .elite-btn-success {
          background: rgba(76,175,80,0.3);
          color: #4caf50;
        }

        .elite-btn-warning {
          background: rgba(255,152,0,0.3);
          color: #ff9800;
        }

        .elite-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }

        .elite-btn:active {
          transform: translateY(0);
        }

        .elite-btn-small {
          padding: 4px 10px;
          border-radius: 4px;
          border: none;
          background: rgba(255,255,255,0.15);
          color: white;
          font-size: 11px;
          cursor: pointer;
        }

        .elite-checkbox-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
        }

        .elite-checkbox-label {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
          padding: 8px;
          border-radius: 6px;
          background: rgba(255,255,255,0.05);
          transition: background 0.2s;
        }

        .elite-checkbox-label:hover {
          background: rgba(255,255,255,0.1);
        }

        .elite-checkbox {
          width: 16px;
          height: 16px;
          cursor: pointer;
        }

        .checkbox-text {
          font-size: 13px;
        }

        .elite-info-box {
          background: rgba(0,0,0,0.2);
          padding: 12px;
          border-radius: 6px;
          margin-bottom: 10px;
        }

        .info-item {
          display: flex;
          justify-content: space-between;
          padding: 6px 0;
          font-size: 12px;
        }

        .info-label {
          opacity: 0.8;
        }

        .info-value {
          font-weight: 600;
        }

        .elite-badge {
          background: rgba(255,255,255,0.2);
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 11px;
          font-weight: 600;
        }

        .elite-results {
          max-height: 300px;
          overflow-y: auto;
          background: rgba(0,0,0,0.2);
          border-radius: 6px;
          padding: 10px;
        }

        .empty-state {
          text-align: center;
          padding: 40px 20px;
          opacity: 0.6;
        }

        .empty-icon {
          font-size: 48px;
          margin-bottom: 10px;
        }

        .empty-state p {
          margin: 0 0 5px 0;
          font-size: 14px;
        }

        .empty-state small {
          font-size: 11px;
          opacity: 0.7;
        }

        .elite-vuln {
          background: rgba(244,67,54,0.2);
          border-left: 3px solid #f44336;
          padding: 12px;
          margin-bottom: 10px;
          border-radius: 6px;
        }

        .vuln-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .vuln-type {
          font-weight: 600;
          color: #f44336;
          font-size: 13px;
        }

        .vuln-confidence {
          background: rgba(255,255,255,0.2);
          padding: 2px 8px;
          border-radius: 10px;
          font-size: 11px;
        }

        .vuln-param {
          font-size: 12px;
          margin: 4px 0;
        }

        .vuln-payload {
          font-size: 11px;
          font-family: 'Courier New', monospace;
          background: rgba(0,0,0,0.3);
          padding: 6px;
          border-radius: 4px;
          margin: 6px 0;
          word-break: break-all;
        }

        .vuln-evidence {
          font-size: 11px;
          opacity: 0.8;
          margin-top: 6px;
        }

        .elite-footer {
          background: rgba(0,0,0,0.3);
          padding: 12px 20px;
          font-size: 11px;
          text-align: center;
          display: flex;
          justify-content: space-between;
          border-top: 1px solid rgba(255,255,255,0.1);
        }

        /* Scrollbar */
        .elite-body::-webkit-scrollbar,
        .elite-results::-webkit-scrollbar {
          width: 8px;
        }

        .elite-body::-webkit-scrollbar-track,
        .elite-results::-webkit-scrollbar-track {
          background: rgba(0,0,0,0.2);
          border-radius: 4px;
        }

        .elite-body::-webkit-scrollbar-thumb,
        .elite-results::-webkit-scrollbar-thumb {
          background: rgba(255,255,255,0.3);
          border-radius: 4px;
        }

        .elite-body::-webkit-scrollbar-thumb:hover,
        .elite-results::-webkit-scrollbar-thumb:hover {
          background: rgba(255,255,255,0.4);
        }
      `;
      document.head.appendChild(style);
    }

    attachEvents() {
      // Close button
      document.getElementById('elite-close').addEventListener('click', () => this.toggle());

      // Minimize button
      document.getElementById('elite-minimize').addEventListener('click', () => {
        document.getElementById('elite-dashboard').classList.toggle('minimized');
      });

      // Scan button
      document.getElementById('elite-scan-btn').addEventListener('click', () => this.startScan());

      // Auto-detect button
      document.getElementById('elite-auto-detect-btn').addEventListener('click', () => this.autoDetect());

      // Toggle all vectors
      document.getElementById('elite-toggle-all').addEventListener('click', () => this.toggleAllVectors());

      // Clear cache
      document.getElementById('elite-clear-cache').addEventListener('click', () => this.clearCache());

      // Detect WAF
      document.getElementById('elite-detect-waf').addEventListener('click', () => this.detectWAF());

      // Export buttons
      document.getElementById('elite-export-json').addEventListener('click', () => this.exportResults('json'));
      document.getElementById('elite-export-csv').addEventListener('click', () => this.exportResults('csv'));
      document.getElementById('elite-clear-results').addEventListener('click', () => this.clearResults());

      // Collapsible sections
      document.querySelectorAll('[data-collapse]').forEach(header => {
        header.addEventListener('click', () => {
          header.parentElement.classList.toggle('collapsed');
        });
      });

      // Keyboard shortcut
      document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && e.key === 'E') {
          e.preventDefault();
          this.toggle();
        }
      });
    }

    toggle() {
      this.isVisible = !this.isVisible;
      document.getElementById('elite-dashboard').classList.toggle('visible', this.isVisible);
    }

    autoDetect() {
      const url = new URL(window.location.href);
      const params = Array.from(url.searchParams.keys());
      
      if (params.length > 0) {
        document.getElementById('elite-params').value = params.join(', ');
        this.showNotification(`✓ Detected ${params.length} parameter(s)`, 'success');
      } else {
        this.showNotification('⚠️ No parameters found in URL', 'warning');
      }
    }

    async startScan() {
      const url = document.getElementById('elite-url').value;
      const paramsInput = document.getElementById('elite-params').value;

      if (!url || !paramsInput) {
        this.showNotification('⚠️ Please enter URL and parameters', 'error');
        return;
      }

      const params = paramsInput.split(',').map(p => p.trim());

      // Get enabled vectors
      const enabledVectors = [];
      document.querySelectorAll('.elite-checkbox:checked').forEach(cb => {
        enabledVectors.push(cb.dataset.vector);
      });

      if (enabledVectors.length === 0) {
        this.showNotification('⚠️ Please select at least one attack vector', 'error');
        return;
      }

      // Update UI
      document.getElementById('elite-status').textContent = 'Scanning...';
      document.getElementById('elite-status').classList.add('scanning');
      document.getElementById('elite-results').innerHTML = '<div class="empty-state"><div class="empty-icon">🔄</div><p>Scanning in progress...</p></div>';

      try {
        const results = await this.scanner.fullScan(url, params, enabledVectors);
        this.displayResults(results);
        this.showNotification(`✓ Scan complete! Found ${results.length} vulnerabilities`, 'success');
      } catch (error) {
        this.showNotification('❌ Scan failed: ' + error.message, 'error');
        console.error('[Elite] Scan error:', error);
      } finally {
        document.getElementById('elite-status').textContent = 'Ready';
        document.getElementById('elite-status').classList.remove('scanning');
      }
    }

    displayResults(results) {
      const resultsDiv = document.getElementById('elite-results');
      const countBadge = document.getElementById('results-count');

      countBadge.textContent = `${results.length} found`;

      if (results.length === 0) {
        resultsDiv.innerHTML = '<div class="empty-state"><div class="empty-icon">✓</div><p>No vulnerabilities found</p></div>';
        return;
      }

      let html = '';
      results.forEach(vuln => {
        html += `
          <div class="elite-vuln">
            <div class="vuln-header">
              <span class="vuln-type">${vuln.type}</span>
              <span class="vuln-confidence">${vuln.confidence}%</span>
            </div>
            <div class="vuln-param"><strong>Parameter:</strong> ${vuln.parameter}</div>
            <div class="vuln-payload"><code>${this.escapeHtml(vuln.payload.substring(0, 100))}${vuln.payload.length > 100 ? '...' : ''}</code></div>
            ${vuln.evidence && vuln.evidence.length > 0 ? `
              <div class="vuln-evidence">
                <strong>Evidence:</strong> ${vuln.evidence.slice(0, 2).map(e => this.escapeHtml(e.substring(0, 80))).join(' • ')}
              </div>
            ` : ''}
          </div>
        `;
      });

      resultsDiv.innerHTML = html;
    }

    toggleAllVectors() {
      const checkboxes = document.querySelectorAll('.elite-checkbox');
      const allChecked = Array.from(checkboxes).every(cb => cb.checked);
      checkboxes.forEach(cb => cb.checked = !allChecked);
    }

    clearCache() {
      this.modules.payloadManager.clearCache();
      this.showNotification('✓ Payload cache cleared', 'success');
    }

    async detectWAF() {
      const url = document.getElementById('elite-url').value;
      if (!url) return;

      document.getElementById('waf-status').textContent = 'Detecting...';

      try {
        const result = await this.modules.wafDetector.detect(url);

        if (result.detected) {
          document.getElementById('waf-status').innerHTML = `
            <span style="color:#f44336">${result.waf}</span>
            <br><small>Confidence: ${result.confidence}% • Severity: ${result.severity}</small>
          `;
          this.showNotification(`⚠️ WAF Detected: ${result.waf}`, 'warning');
        } else {
          document.getElementById('waf-status').textContent = 'Not detected';
          this.showNotification('✓ No WAF detected', 'success');
        }
      } catch (error) {
        document.getElementById('waf-status').textContent = 'Error';
        this.showNotification('❌ WAF detection failed', 'error');
      }
    }

    exportResults(format) {
      const results = this.scanner.getResults();
      if (results.length === 0) {
        this.showNotification('⚠️ No results to export', 'warning');
        return;
      }

      let data, filename, mimeType;

      if (format === 'json') {
        data = JSON.stringify(results, null, 2);
        filename = `elite-scan-${Date.now()}.json`;
        mimeType = 'application/json';
      } else if (format === 'csv') {
        data = 'Type,Parameter,Payload,Confidence,URL\n';
        results.forEach(r => {
          data += `"${r.type}","${r.parameter}","${r.payload.replace(/"/g, '""')}",${r.confidence},"${r.url}"\n`;
        });
        filename = `elite-scan-${Date.now()}.csv`;
        mimeType = 'text/csv';
      }

      GM_download({
        url: `data:${mimeType};charset=utf-8,${encodeURIComponent(data)}`,
        name: filename,
        saveAs: true
      });

      this.showNotification(`✓ Exported as ${filename}`, 'success');
    }

    clearResults() {
      this.scanner.results = [];
      document.getElementById('elite-results').innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div><p>No scan results yet</p></div>';
      document.getElementById('results-count').textContent = '0 found';
      this.showNotification('✓ Results cleared', 'success');
    }

    showNotification(message, type = 'info') {
      console.log(`[Elite] ${message}`);
      // Could add toast notifications here
    }

    escapeHtml(text) {
      const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
      return text.replace(/[&<>"']/g, m => map[m]);
    }

    makeDraggable(element) {
      let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
      const header = element.querySelector('.elite-header');

      header.onmousedown = dragMouseDown;

      function dragMouseDown(e) {
        if (e.target.classList.contains('elite-btn-icon')) return;
        e.preventDefault();
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        document.onmousemove = elementDrag;
      }

      function elementDrag(e) {
        e.preventDefault();
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        element.style.top = (element.offsetTop - pos2) + "px";
        element.style.left = (element.offsetLeft - pos1) + "px";
        element.style.right = 'auto';
      }

      function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
      }
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🚀 INITIALIZATION
  // ════════════════════════════════════════════════════════════════════════════

  async function init() {
    console.log(`%c[Elite Pentest Framework v${CONFIG.VERSION}]`, 'color: #667eea; font-weight: bold; font-size: 14px');
    console.log('%cPress Ctrl+Shift+E to open dashboard', 'color: #999');

    // Load modules
    const loader = new ModuleLoader();
    const loaded = await loader.init();

    if (!loaded) {
      console.error('[Elite] Failed to load modules');
      return;
    }

    // Wait for page load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        const dashboard = new Dashboard(loader.modules);
        dashboard.create();
      });
    } else {
      const dashboard = new Dashboard(loader.modules);
      dashboard.create();
    }
  }

  // Start
  init();

})();
