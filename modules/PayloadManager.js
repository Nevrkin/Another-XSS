/**
 * ════════════════════════════════════════════════════════════════════════════
 * PayloadManager.js - Advanced Payload Management with GitHub Integration
 * ════════════════════════════════════════════════════════════════════════════
 * Part of Elite Pentest Framework 2025
 * GitHub: https://github.com/Nevrkin/Another-XSS/blob/main/modules/PayloadManager.js
 * 
 * Features:
 * - Fetch payloads from GitHub (SecLists, PayloadsAllTheThings, etc.)
 * - Local caching with expiration
 * - Custom payload lists
 * - Payload filtering and categorization
 */

class PayloadManager {
  constructor() {
    this.version = '1.0.0';
    this.cache = new Map();
    this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
    this.loading = new Set();
    
    // Default payload sources (GitHub raw URLs)
    this.payloadSources = this.initPayloadSources();
    
    console.log(`[PayloadManager v${this.version}] Module loaded`);
  }

  /**
   * Initialize default payload sources from GitHub
   */
  initPayloadSources() {
    return {
      xss: {
        seclists_basic: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Filters-Evasion.txt',
        seclists_polyglot: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Polyglots.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt',
        swisskyrepo: 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md'
      },
      
      sqli: {
        seclists_mysql: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/quick-SQLi.txt',
        seclists_generic: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt',
        seclists_time_based: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/time-based-sql-injection.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_SQLI.txt',
        swisskyrepo: 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md'
      },

      lfi: {
        seclists_linux: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
        seclists_windows: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
        seclists_php: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/rfi-lfi-payload-list/master/LFI/list.txt'
      },

      rce: {
        seclists_unix: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/command-injection-payload-list.txt',
        swisskyrepo: 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md'
      },

      ssrf: {
        seclists: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/ssrf-payload-list/master/ssrf-payload-list.txt',
        swisskyrepo: 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md'
      },

      xxe: {
        seclists: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XXE-Fuzzing.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/xxe-injection-payload-list/master/xxe-payload-list.txt',
        swisskyrepo: 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/README.md'
      },

      ssti: {
        seclists: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-special-vars.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/ssti-payload-list/master/ssti-payload-list.txt',
        swisskyrepo: 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md'
      },

      open_redirect: {
        seclists: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/UnvalidatedRedirects.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/open-redirect-payload-list/master/open-redirect-payload-list.txt'
      },

      crlf: {
        seclists: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/CRLF-Injection.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/crlf-injection-payload-list/master/crlf-payload-list.txt'
      },

      nosql: {
        seclists: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/NoSQL.txt',
        payloadbox: 'https://raw.githubusercontent.com/payloadbox/nosql-injection-payload-list/master/nosql-payload-list.txt'
      }
    };
  }

  /**
   * Get payloads for a specific vulnerability type
   * @param {String} vulnType - Vulnerability type (xss, sqli, lfi, etc.)
   * @param {Object} options - Options {sources: ['seclists', 'payloadbox'], cache: true, limit: 1000}
   * @returns {Promise<Array>} Array of payloads
   */
  async getPayloads(vulnType, options = {}) {
    const defaults = {
      sources: 'all',
      cache: true,
      limit: 1000,
      filter: null
    };

    const config = { ...defaults, ...options };

    console.log(`[PayloadManager] Fetching ${vulnType} payloads...`);

    // Check cache first
    if (config.cache) {
      const cached = this.getFromCache(vulnType);
      if (cached) {
        console.log(`[PayloadManager] Using cached ${vulnType} payloads (${cached.length} entries)`);
        return this.filterPayloads(cached, config);
      }
    }

    // Get payload sources
    const sources = this.payloadSources[vulnType];
    if (!sources) {
      console.warn(`[PayloadManager] No sources found for ${vulnType}`);
      return [];
    }

    // Fetch from sources
    const allPayloads = [];
    const sourceKeys = config.sources === 'all' 
      ? Object.keys(sources) 
      : (Array.isArray(config.sources) ? config.sources : [config.sources]);

    for (const sourceKey of sourceKeys) {
      const url = sources[sourceKey];
      if (!url) continue;

      try {
        const payloads = await this.fetchFromURL(url);
        console.log(`[PayloadManager] ✓ Loaded ${payloads.length} payloads from ${sourceKey}`);
        allPayloads.push(...payloads);
      } catch (error) {
        console.warn(`[PayloadManager] Failed to load from ${sourceKey}:`, error.message);
      }
    }

    // Remove duplicates
    const uniquePayloads = [...new Set(allPayloads)];
    console.log(`[PayloadManager] Total unique payloads: ${uniquePayloads.length}`);

    // Cache the results
    if (config.cache) {
      this.saveToCache(vulnType, uniquePayloads);
    }

    return this.filterPayloads(uniquePayloads, config);
  }

  /**
   * Fetch payloads from URL
   */
  async fetchFromURL(url) {
    // Check if already loading
    if (this.loading.has(url)) {
      throw new Error('Already loading from this URL');
    }

    this.loading.add(url);

    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: 'GET',
        url: url,
        timeout: 30000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        onload: (response) => {
          this.loading.delete(url);

          if (response.status !== 200) {
            reject(new Error(`HTTP ${response.status}`));
            return;
          }

          try {
            const payloads = this.parsePayloads(response.responseText, url);
            resolve(payloads);
          } catch (error) {
            reject(error);
          }
        },
        onerror: (error) => {
          this.loading.delete(url);
          reject(new Error('Network error'));
        },
        ontimeout: () => {
          this.loading.delete(url);
          reject(new Error('Request timeout'));
        }
      });
    });
  }

  /**
   * Parse payloads from response text
   */
  parsePayloads(text, url) {
    // Check if it's a markdown file (README.md)
    if (url.endsWith('.md')) {
      return this.parseMarkdown(text);
    }

    // Regular text file - split by lines
    const lines = text.split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => {
        // Remove empty lines and comments
        return line.length > 0 && 
               !line.startsWith('#') && 
               !line.startsWith('//') &&
               !line.startsWith('<!--');
      });

    return lines;
  }

  /**
   * Parse payloads from markdown files
   */
  parseMarkdown(markdown) {
    const payloads = [];
    
    // Extract code blocks
    const codeBlockRegex = /```[^\n]*\n([\s\S]*?)```/g;
    let match;
    
    while ((match = codeBlockRegex.exec(markdown)) !== null) {
      const content = match[1].trim();
      const lines = content.split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line.length > 0);
      
      payloads.push(...lines);
    }

    // Extract inline code
    const inlineCodeRegex = /`([^`]+)`/g;
    while ((match = inlineCodeRegex.exec(markdown)) !== null) {
      const code = match[1].trim();
      if (code.length > 5) { // Avoid short snippets
        payloads.push(code);
      }
    }

    return [...new Set(payloads)];
  }

  /**
   * Filter payloads based on options
   */
  filterPayloads(payloads, options) {
    let filtered = payloads;

    // Apply custom filter function
    if (options.filter && typeof options.filter === 'function') {
      filtered = filtered.filter(options.filter);
    }

    // Apply limit
    if (options.limit && filtered.length > options.limit) {
      filtered = filtered.slice(0, options.limit);
    }

    return filtered;
  }

  /**
   * Get payloads from cache
   */
  getFromCache(vulnType) {
    const cacheKey = `payloads_${vulnType}`;
    
    try {
      const cached = GM_getValue(cacheKey);
      if (!cached) return null;

      const data = JSON.parse(cached);
      
      // Check if cache is expired
      if (Date.now() - data.timestamp > this.cacheExpiry) {
        GM_deleteValue(cacheKey);
        return null;
      }

      return data.payloads;
    } catch (error) {
      console.error('[PayloadManager] Cache read error:', error);
      return null;
    }
  }

  /**
   * Save payloads to cache
   */
  saveToCache(vulnType, payloads) {
    const cacheKey = `payloads_${vulnType}`;
    
    try {
      const data = {
        payloads: payloads,
        timestamp: Date.now()
      };

      GM_setValue(cacheKey, JSON.stringify(data));
      console.log(`[PayloadManager] Cached ${payloads.length} ${vulnType} payloads`);
    } catch (error) {
      console.error('[PayloadManager] Cache write error:', error);
    }
  }

  /**
   * Clear cache for specific vulnerability type or all
   */
  clearCache(vulnType = null) {
    if (vulnType) {
      GM_deleteValue(`payloads_${vulnType}`);
      console.log(`[PayloadManager] Cleared cache for ${vulnType}`);
    } else {
      // Clear all payload caches
      for (const type of Object.keys(this.payloadSources)) {
        GM_deleteValue(`payloads_${type}`);
      }
      console.log('[PayloadManager] Cleared all payload caches');
    }
  }

  /**
   * Add custom payload source
   */
  addCustomSource(vulnType, sourceName, url) {
    if (!this.payloadSources[vulnType]) {
      this.payloadSources[vulnType] = {};
    }

    this.payloadSources[vulnType][sourceName] = url;
    console.log(`[PayloadManager] Added custom source: ${sourceName} for ${vulnType}`);
    
    // Clear cache to force reload
    this.clearCache(vulnType);
  }

  /**
   * Remove custom source
   */
  removeCustomSource(vulnType, sourceName) {
    if (this.payloadSources[vulnType] && this.payloadSources[vulnType][sourceName]) {
      delete this.payloadSources[vulnType][sourceName];
      console.log(`[PayloadManager] Removed source: ${sourceName}`);
      this.clearCache(vulnType);
    }
  }

  /**
   * Get all available sources
   */
  getSources(vulnType = null) {
    if (vulnType) {
      return this.payloadSources[vulnType] || {};
    }
    return this.payloadSources;
  }

  /**
   * Import custom payload list from text
   */
  importCustomPayloads(vulnType, payloadsText) {
    const payloads = payloadsText.split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.length > 0);

    // Add to cache
    const existing = this.getFromCache(vulnType) || [];
    const combined = [...existing, ...payloads];
    const unique = [...new Set(combined)];

    this.saveToCache(vulnType, unique);
    
    console.log(`[PayloadManager] Imported ${payloads.length} custom ${vulnType} payloads`);
    return unique.length;
  }

  /**
   * Export current payloads to text
   */
  async exportPayloads(vulnType, format = 'txt') {
    const payloads = await this.getPayloads(vulnType, { cache: true });

    if (format === 'txt') {
      return payloads.join('\n');
    } else if (format === 'json') {
      return JSON.stringify(payloads, null, 2);
    } else if (format === 'csv') {
      return payloads.map(p => `"${p.replace(/"/g, '""')}"`).join('\n');
    }

    return payloads.join('\n');
  }

  /**
   * Get payload statistics
   */
  async getStats(vulnType) {
    const payloads = await this.getPayloads(vulnType, { cache: true });
    
    return {
      total: payloads.length,
      avgLength: Math.round(payloads.reduce((sum, p) => sum + p.length, 0) / payloads.length),
      maxLength: Math.max(...payloads.map(p => p.length)),
      minLength: Math.min(...payloads.map(p => p.length)),
      sources: Object.keys(this.payloadSources[vulnType] || {}).length
    };
  }

  /**
   * Search payloads by keyword
   */
  async searchPayloads(vulnType, keyword, caseSensitive = false) {
    const payloads = await this.getPayloads(vulnType, { cache: true });
    
    const searchTerm = caseSensitive ? keyword : keyword.toLowerCase();
    
    return payloads.filter(p => {
      const payload = caseSensitive ? p : p.toLowerCase();
      return payload.includes(searchTerm);
    });
  }

  /**
   * Get recommended payloads for specific context
   */
  async getRecommended(vulnType, context = null) {
    const payloads = await this.getPayloads(vulnType, { cache: true });

    // Context-specific filtering
    if (context === 'html' && vulnType === 'xss') {
      return payloads.filter(p => p.includes('<') && p.includes('>'));
    } else if (context === 'attribute' && vulnType === 'xss') {
      return payloads.filter(p => p.includes('"') || p.includes("'"));
    } else if (context === 'time_based' && vulnType === 'sqli') {
      return payloads.filter(p => /SLEEP|WAITFOR|BENCHMARK/i.test(p));
    } else if (context === 'error_based' && vulnType === 'sqli') {
      return payloads.filter(p => /UNION|SELECT|AND|OR/i.test(p));
    }

    // Return top payloads by default
    return payloads.slice(0, 50);
  }

  /**
   * Validate payload source URLs
   */
  async validateSources(vulnType = null) {
    const results = [];
    const sources = vulnType ? { [vulnType]: this.payloadSources[vulnType] } : this.payloadSources;

    for (const [type, sourceList] of Object.entries(sources)) {
      for (const [name, url] of Object.entries(sourceList)) {
        try {
          await this.fetchFromURL(url);
          results.push({ type, name, url, status: 'ok' });
        } catch (error) {
          results.push({ type, name, url, status: 'failed', error: error.message });
        }
      }
    }

    return results;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PayloadManager;
}
