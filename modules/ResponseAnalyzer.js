/**
 * ════════════════════════════════════════════════════════════════════════════
 * ResponseAnalyzer.js - Advanced Response Analysis & False Positive Reduction
 * ════════════════════════════════════════════════════════════════════════════
 * Part of Elite Pentest Framework 2025
 * GitHub: https://github.com/Nevrkin/Another-XSS/blob/main/modules/ResponseAnalyzer.js
 */

class ResponseAnalyzer {
  constructor() {
    this.version = '1.0.0';
    this.baselineResponses = new Map();
    this.errorSignatures = this.initErrorSignatures();
    console.log(`[ResponseAnalyzer v${this.version}] Module loaded`);
  }

  /**
   * Initialize comprehensive error signatures for different vulnerability types
   */
  initErrorSignatures() {
    return {
      sqli: [
        // MySQL errors
        /SQL syntax.*?MySQL/i,
        /Warning.*?mysql_/i,
        /MySQLSyntaxErrorException/i,
        /mysql_fetch_array\(\)/i,
        /mysql_num_rows\(\)/i,
        /You have an error in your SQL syntax/i,
        /supplied argument is not a valid MySQL/i,
        
        // PostgreSQL errors
        /PostgreSQL.*?ERROR/i,
        /Warning.*?pg_/i,
        /pg_query\(\)/i,
        /pg_exec\(\)/i,
        /unterminated quoted string/i,
        
        // MSSQL errors
        /Microsoft SQL Server/i,
        /ODBC SQL Server Driver/i,
        /SQLServer JDBC Driver/i,
        /Unclosed quotation mark/i,
        /\[SQL Server\]/i,
        /Incorrect syntax near/i,
        
        // Oracle errors
        /ORA-\d{5}/i,
        /Oracle error/i,
        /quoted string not properly terminated/i,
        
        // SQLite errors
        /SQLite3::SQLException/i,
        /sqlite_/i,
        /SQLITE_ERROR/i,
        
        // Generic SQL errors
        /SQL error/i,
        /database error/i,
        /Query failed/i,
        /mysql error/i
      ],

      xxe: [
        /java\.io\.FileNotFoundException/i,
        /java\.net\.MalformedURLException/i,
        /org\.xml\.sax\.SAXParseException/i,
        /XML.*?parse.*?error/i,
        /root:.*?:0:0:/,
        /\[boot loader\]/i,
        /\[fonts\]/i,
        /\[extensions\]/i
      ],

      path_traversal: [
        /root:.*?:0:0:/,
        /\[boot loader\]/i,
        /\[fonts\]/i,
        /\[extensions\]/i,
        /<\?php/i,
        /Warning.*?failed to open stream/i,
        /No such file or directory/i,
        /include_path/i,
        /open_basedir restriction/i,
        /Failed opening required/i
      ],

      rce: [
        /uid=\d+\([^)]+\) gid=\d+\([^)]+\)/,
        /root:.*?:0:0:/,
        /www-data/i,
        /sh: .*?: command not found/i,
        /PING.*?bytes of data/i,
        /bash: /i,
        /Microsoft Windows \[Version/i,
        /Directory of [C-Z]:\\/i
      ],

      ssti: [
        /TemplateSyntaxError/i,
        /UndefinedError/i,
        /jinja2\.exceptions/i,
        /freemarker\.template/i,
        /velocity\.exception/i,
        /TemplateException/i
      ],

      ldap: [
        /javax\.naming\.NameNotFoundException/i,
        /LDAPException/i,
        /com\.sun\.jndi\.ldap/i,
        /Invalid DN syntax/i
      ],

      xpath: [
        /XPathException/i,
        /SimpleXMLElement/i,
        /xmlXPathEval/i,
        /XPath syntax error/i
      ]
    };
  }

  /**
   * Capture baseline response for comparison
   */
  async captureBaseline(url, method = 'GET', data = null, headers = {}) {
    try {
      const response = await this.makeRequest(url, method, data, headers);
      const key = `${method}:${url}`;
      
      this.baselineResponses.set(key, {
        status: response.status,
        length: response.body.length,
        headers: response.headers,
        time: response.time,
        body: response.body,
        hash: this.hashResponse(response.body)
      });

      console.log(`[ResponseAnalyzer] Baseline captured for ${url} (${response.time}ms, ${response.body.length} bytes)`);
      return response;
    } catch (error) {
      console.error('[ResponseAnalyzer] Baseline capture failed:', error);
      return null;
    }
  }

  /**
   * Analyze response for vulnerability indicators with confidence scoring
   * @param {Object} response - HTTP response object
   * @param {String} payload - The injected payload
   * @param {String} vulnerabilityType - Type of vulnerability being tested
   * @param {Object} baseline - Baseline response for comparison
   * @returns {Object} Analysis result with confidence score
   */
  analyzeResponse(response, payload, vulnerabilityType, baseline = null) {
    const result = {
      vulnerable: false,
      confidence: 0,
      indicators: [],
      falsePositive: false,
      evidence: [],
      responseTime: response.time,
      statusCode: response.status
    };

    // Check for error-based indicators
    const errorCheck = this.checkErrorSignatures(response.body, vulnerabilityType);
    if (errorCheck.found) {
      result.indicators.push('error_signature');
      result.confidence += 40;
      result.evidence.push(...errorCheck.matches);
    }

    // Time-based analysis
    if (vulnerabilityType === 'sqli' || vulnerabilityType === 'rce') {
      const timingResult = this.analyzeTimingAnomaly(response, baseline, payload);
      if (timingResult.isAnomaly) {
        result.indicators.push('timing_anomaly');
        result.confidence += timingResult.confidence;
        result.evidence.push(timingResult.evidence);
      }
    }

    // Content difference analysis
    if (baseline) {
      const diff = this.calculateContentDifference(response.body, baseline.body);
      if (diff.significant) {
        result.indicators.push('content_difference');
        result.confidence += 20;
        result.evidence.push(`Content diff: ${diff.percentage}% (${diff.byteDiff} bytes)`);
      }
    }

    // Vulnerability-specific checks
    switch (vulnerabilityType) {
      case 'xss':
        const xssCheck = this.verifyXSSExecution(response.body, payload);
        if (xssCheck.confirmed) {
          result.indicators.push('xss_confirmed');
          result.confidence += 50;
          result.evidence.push(`XSS in ${xssCheck.context}`);
        } else if (xssCheck.reflected) {
          result.indicators.push('xss_reflected');
          result.confidence += 20;
          if (xssCheck.executableContext) {
            result.confidence += 30;
            result.evidence.push(`Reflected in executable context: ${xssCheck.context}`);
          } else {
            result.evidence.push('Reflected but not in executable context');
            result.falsePositive = true;
          }
        }
        break;

      case 'sqli':
        const sqliCheck = this.verifySQLInjection(response, payload, baseline);
        if (sqliCheck.confirmed) {
          result.indicators.push('sqli_confirmed');
          result.confidence += 50;
          result.evidence.push(...sqliCheck.evidence);
        }
        break;

      case 'ssrf':
        const ssrfCheck = this.verifySSRF(response);
        if (ssrfCheck.confirmed) {
          result.indicators.push('ssrf_confirmed');
          result.confidence += ssrfCheck.confidence;
          result.evidence.push(...ssrfCheck.evidence);
        }
        break;

      case 'lfi':
        const lfiCheck = this.verifyLFI(response);
        if (lfiCheck.confirmed) {
          result.indicators.push('lfi_confirmed');
          result.confidence += lfiCheck.confidence;
          result.evidence.push(...lfiCheck.evidence);
        }
        break;
    }

    // False positive checks
    const fpCheck = this.checkFalsePositives(response, payload, vulnerabilityType);
    if (fpCheck.isFalsePositive) {
      result.falsePositive = true;
      result.confidence = Math.max(0, result.confidence - 40);
      result.evidence.push(`⚠️ ${fpCheck.reason}`);
    }

    // Final verdict (70% confidence threshold)
    result.vulnerable = result.confidence >= 70 && !result.falsePositive;

    return result;
  }

  /**
   * Verify XSS execution with context analysis
   */
  verifyXSSExecution(responseBody, payload) {
    const result = {
      confirmed: false,
      reflected: false,
      executableContext: false,
      context: ''
    };

    // Check if payload is reflected
    if (!responseBody.includes(payload)) {
      return result;
    }

    result.reflected = true;

    // Check for XSS marker (if using marker-based payloads)
    if (payload.includes('window.__xss_confirmed') || payload.includes('_xss_marker_')) {
      // In real scenario, this would be checked via DOM
      result.confirmed = true;
      result.executableContext = true;
      result.context = 'JavaScript execution confirmed';
      return result;
    }

    // Find context of reflection
    const contexts = this.findPayloadContexts(responseBody, payload);

    for (const context of contexts) {
      if (context.type === 'script' && !context.inString) {
        result.executableContext = true;
        result.confirmed = true;
        result.context = 'JavaScript context (outside string)';
      } else if (context.type === 'attribute' && context.isEventHandler) {
        result.executableContext = true;
        result.confirmed = true;
        result.context = 'Event handler attribute';
      } else if (context.type === 'html' && payload.match(/<[^>]+>/)) {
        result.executableContext = true;
        result.confirmed = true;
        result.context = 'HTML injection';
      }
    }

    return result;
  }

  /**
   * Find all contexts where payload appears in HTML
   */
  findPayloadContexts(html, payload) {
    const contexts = [];
    const escapedPayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escapedPayload, 'g');
    let match;

    while ((match = regex.exec(html)) !== null) {
      const pos = match.index;
      const before = html.substring(Math.max(0, pos - 100), pos);
      const after = html.substring(pos + payload.length, Math.min(html.length, pos + payload.length + 100));

      let context = { type: 'text', inString: false, isEventHandler: false };

      // Check if inside script tag
      if (/<script[^>]*>/i.test(before) && !</script>/i.test(before.split(/<script[^>]*>/i).pop())) {
        context.type = 'script';
        const scriptContent = before.split(/<script[^>]*>/i).pop();
        const singleQuotes = (scriptContent.match(/'/g) || []).length;
        const doubleQuotes = (scriptContent.match(/"/g) || []).length;
        context.inString = (singleQuotes % 2 === 1) || (doubleQuotes % 2 === 1);
      }
      // Check if inside HTML attribute
      else if (/<[^>]*$/.test(before) && /[^<]*>/.test(after)) {
        context.type = 'attribute';
        const attrMatch = before.match(/\s+(on\w+)\s*=\s*["']?[^"']*$/i);
        if (attrMatch) {
          context.isEventHandler = true;
        }
      }
      // Check if inside HTML tag content
      else if (/>\s*$/.test(before) && /\s*</.test(after)) {
        context.type = 'html';
      }

      contexts.push(context);
    }

    return contexts;
  }

  /**
   * Verify SQL injection with multiple techniques
   */
  verifySQLInjection(response, payload, baseline) {
    const result = {
      confirmed: false,
      evidence: []
    };

    // Error-based SQLi
    if (this.checkErrorSignatures(response.body, 'sqli').found) {
      result.confirmed = true;
      result.evidence.push('SQL error message detected');
    }

    // Time-based blind SQLi
    if (payload.match(/SLEEP|WAITFOR|BENCHMARK|pg_sleep/i)) {
      const expectedDelay = this.extractDelayFromPayload(payload);
      if (response.time >= expectedDelay * 1000 - 500) {
        result.confirmed = true;
        result.evidence.push(`Time-based SQLi confirmed (${response.time}ms delay, expected: ~${expectedDelay}s)`);
      }
    }

    // Boolean-based blind SQLi
    if (baseline && payload.match(/AND ['"]?\d+['"]?=['"]?\d+/i)) {
      const isTrue = this.isTrueCondition(payload);
      const lengthDiff = Math.abs(response.body.length - baseline.body.length);
      
      if (isTrue && lengthDiff < 100) {
        result.evidence.push('Boolean SQLi: TRUE condition matches baseline');
      } else if (!isTrue && lengthDiff > 100) {
        result.confirmed = true;
        result.evidence.push(`Boolean SQLi: FALSE condition differs (${lengthDiff} bytes)`);
      }
    }

    // Union-based SQLi
    if (payload.match(/UNION.*SELECT/i)) {
      if (response.body.length > (baseline?.body.length || 0) + 100) {
        result.confirmed = true;
        result.evidence.push('Union-based SQLi: Response size increased significantly');
      }
    }

    return result;
  }

  /**
   * Verify SSRF vulnerability
   */
  verifySSRF(response) {
    const result = { confirmed: false, confidence: 0, evidence: [] };

    const indicators = [
      { pattern: /169\.254\.169\.254/i, score: 40, desc: 'Cloud metadata endpoint accessed' },
      { pattern: /ami-[a-z0-9]+/i, score: 35, desc: 'AWS AMI ID detected' },
      { pattern: /"access_token"\s*:\s*"/i, score: 40, desc: 'Access token in response' },
      { pattern: /root:.*?:0:0:/i, score: 50, desc: 'Unix passwd file via SSRF' },
      { pattern: /\[boot loader\]/i, score: 50, desc: 'Windows boot.ini via SSRF' },
      { pattern: /"AccessKeyId"\s*:\s*"/i, score: 40, desc: 'AWS credentials' },
      { pattern: /"private_key"/i, score: 35, desc: 'Private key exposed' }
    ];

    for (const indicator of indicators) {
      if (indicator.pattern.test(response.body)) {
        result.confidence += indicator.score;
        result.evidence.push(indicator.desc);
      }
    }

    result.confirmed = result.confidence >= 70;
    return result;
  }

  /**
   * Verify LFI vulnerability
   */
  verifyLFI(response) {
    const result = { confirmed: false, confidence: 0, evidence: [] };

    const indicators = [
      { pattern: /root:.*?:0:0:/i, score: 50, desc: 'Unix /etc/passwd file' },
      { pattern: /\[boot loader\]/i, score: 50, desc: 'Windows boot.ini' },
      { pattern: /\[fonts\]/i, score: 40, desc: 'Windows win.ini' },
      { pattern: /<\?php[\s\r\n]/i, score: 35, desc: 'PHP source code' },
      { pattern: /mysql_connect\s*\(/i, score: 30, desc: 'Database configuration' },
      { pattern: /define\s*\(\s*['"]DB_PASSWORD['"]/i, score: 35, desc: 'Database credentials' },
      { pattern: /-----BEGIN RSA PRIVATE KEY-----/i, score: 50, desc: 'Private key file' }
    ];

    for (const indicator of indicators) {
      if (indicator.pattern.test(response.body)) {
        result.confidence += indicator.score;
        result.evidence.push(indicator.desc);
      }
    }

    result.confirmed = result.confidence >= 70;
    return result;
  }

  /**
   * Check for error signatures in response
   */
  checkErrorSignatures(responseBody, vulnerabilityType) {
    const result = { found: false, matches: [] };
    const signatures = this.errorSignatures[vulnerabilityType] || [];
    
    for (const pattern of signatures) {
      const matches = responseBody.match(pattern);
      if (matches) {
        result.found = true;
        result.matches.push(matches[0].substring(0, 200));
      }
    }

    return result;
  }

  /**
   * Analyze timing anomaly for blind injection
   */
  analyzeTimingAnomaly(response, baseline, payload) {
    const result = { isAnomaly: false, confidence: 0, evidence: '' };

    if (!baseline || !baseline.time) {
      return result;
    }

    const diff = response.time - baseline.time;
    const expectedDelay = this.extractDelayFromPayload(payload);

    // Time-based attack with explicit delay
    if (expectedDelay > 0) {
      const expectedMs = expectedDelay * 1000;
      if (response.time >= expectedMs - 500 && response.time <= expectedMs + 2000) {
        result.isAnomaly = true;
        result.confidence = 35;
        result.evidence = `Timing matches expected delay: ${response.time}ms (expected: ${expectedMs}ms)`;
      }
    }
    // General timing anomaly
    else if (diff > 3000) {
      result.isAnomaly = true;
      result.confidence = 20;
      result.evidence = `Significant delay: ${response.time}ms (baseline: ${baseline.time}ms, diff: ${diff}ms)`;
    }

    return result;
  }

  /**
   * Extract expected delay from time-based payload
   */
  extractDelayFromPayload(payload) {
    const sleepMatch = payload.match(/SLEEP\s*\(\s*(\d+)\s*\)/i);
    if (sleepMatch) return parseInt(sleepMatch[1]);

    const waitforMatch = payload.match(/WAITFOR\s+DELAY\s+['"]0:0:(\d+)['"]/i);
    if (waitforMatch) return parseInt(waitforMatch[1]);

    const benchmarkMatch = payload.match(/BENCHMARK\s*\(\s*(\d+)/i);
    if (benchmarkMatch) {
      const iterations = parseInt(benchmarkMatch[1]);
      return Math.ceil(iterations / 1000000);
    }

    return 0;
  }

  /**
   * Check if SQL condition is TRUE
   */
  isTrueCondition(payload) {
    return payload.match(/=['"]?1['"]?/) !== null || 
           payload.match(/=1\s*--/) !== null ||
           payload.match(/AND\s+1=1/i) !== null;
  }

  /**
   * Calculate content difference percentage
   */
  calculateContentDifference(body1, body2) {
    if (!body2) return { significant: false, percentage: 0, byteDiff: 0 };

    const len1 = body1.length;
    const len2 = body2.length;
    const diff = Math.abs(len1 - len2);
    const percentage = (diff / Math.max(len1, len2)) * 100;

    return {
      significant: percentage > 10,
      percentage: percentage.toFixed(2),
      byteDiff: diff
    };
  }

  /**
   * Check for false positives
   */
  checkFalsePositives(response, payload, vulnerabilityType) {
    const result = { isFalsePositive: false, reason: '' };

    // Check if response is a client error
    if (response.status >= 400 && response.status < 500) {
      if (vulnerabilityType === 'xss' || vulnerabilityType === 'sqli') {
        // Check if it's a legitimate error vs WAF block
        if (!this.isWAFBlocked(response)) {
          result.isFalsePositive = true;
          result.reason = `HTTP ${response.status} error page`;
          return result;
        }
      }
    }

    // Check if payload is HTML-encoded
    if (vulnerabilityType === 'xss') {
      const encodedPayload = this.htmlEncode(payload);
      if (response.body.includes(encodedPayload) && !response.body.includes(payload)) {
        result.isFalsePositive = true;
        result.reason = 'Payload properly sanitized (HTML-encoded)';
        return result;
      }

      // Check if inside HTML comment
      if (this.isInHTMLComment(response.body, payload)) {
        result.isFalsePositive = true;
        result.reason = 'Payload reflected in HTML comment';
        return result;
      }
    }

    // Check if WAF blocked the request
    if (this.isWAFBlocked(response)) {
      result.isFalsePositive = true;
      result.reason = 'Request blocked by WAF/Security filter';
      return result;
    }

    // Check for generic error pages
    if (this.isGenericErrorPage(response)) {
      result.isFalsePositive = true;
      result.reason = 'Generic error page (not vulnerability-specific)';
      return result;
    }

    return result;
  }

  /**
   * Check if request was blocked by WAF
   */
  isWAFBlocked(response) {
    const wafIndicators = [
      /cloudflare/i, /access denied/i, /forbidden/i,
      /security policy/i, /firewall/i, /mod_security/i,
      /imperva/i, /akamai/i, /blocked by/i,
      /request rejected/i, /security violation/i
    ];

    if (response.status === 403 || response.status === 406 || response.status === 419) {
      for (const pattern of wafIndicators) {
        if (pattern.test(response.body) || pattern.test(response.headers)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if response is a generic error page
   */
  isGenericErrorPage(response) {
    const genericPatterns = [
      /404 not found/i,
      /page not found/i,
      /the page you are looking for/i,
      /this page does not exist/i
    ];

    return genericPatterns.some(pattern => pattern.test(response.body));
  }

  /**
   * Check if payload is inside HTML comment
   */
  isInHTMLComment(html, payload) {
    const commentPattern = /<!--[\s\S]*?-->/g;
    const comments = html.match(commentPattern) || [];
    return comments.some(comment => comment.includes(payload));
  }

  /**
   * HTML encode string
   */
  htmlEncode(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  /**
   * Hash response body for comparison
   */
  hashResponse(body) {
    let hash = 0;
    for (let i = 0; i < body.length; i++) {
      const char = body.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash;
  }

  /**
   * Make HTTP request (using GM_xmlhttpRequest)
   */
  async makeRequest(url, method = 'GET', data = null, headers = {}) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();

      GM_xmlhttpRequest({
        method: method,
        url: url,
        data: data,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          ...headers
        },
        timeout: 15000,
        onload: (response) => {
          resolve({
            status: response.status,
            headers: response.responseHeaders,
            body: response.responseText,
            time: Date.now() - startTime
          });
        },
        onerror: (error) => reject(error),
        ontimeout: () => reject(new Error('Request timeout'))
      });
    });
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ResponseAnalyzer;
}
