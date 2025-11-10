# 🏗️ Elite Pentest Framework - Architecture

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Browser (Chrome/Firefox)                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Tampermonkey Extension                   │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │            EliteMain.js (Coordinator)                 │  │ │
│  │  │                                                        │  │ │
│  │  │  ┌──────────────────────────────────────────────┐    │  │ │
│  │  │  │           Dashboard (UI Layer)               │    │  │ │
│  │  │  │  • Event Handling                            │    │  │ │
│  │  │  │  • Results Display                           │    │  │ │
│  │  │  │  • Configuration                             │    │  │ │
│  │  │  └──────────────────────────────────────────────┘    │  │ │
│  │  │                        ↓                              │  │ │
│  │  │  ┌──────────────────────────────────────────────┐    │  │ │
│  │  │  │      VulnerabilityScanner (Core Engine)      │    │  │ │
│  │  │  │  • Scan Coordination                         │    │  │ │
│  │  │  │  • Parameter Testing                         │    │  │ │
│  │  │  │  • Result Collection                         │    │  │ │
│  │  │  └──────────────────────────────────────────────┘    │  │ │
│  │  │         ↓              ↓              ↓               │  │ │
│  │  └─────────┼──────────────┼──────────────┼───────────────┘  │ │
│  │            ↓              ↓              ↓                  │ │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │ │
│  │  │  Response   │  │     WAF      │  │    Payload      │   │ │
│  │  │  Analyzer   │  │   Detector   │  │    Manager      │   │ │
│  │  └─────────────┘  └──────────────┘  └─────────────────┘   │ │
│  │         ↓                ↓                    ↓            │ │
│  └─────────┼────────────────┼────────────────────┼────────────┘ │
│            ↓                ↓                    ↓              │
└────────────┼────────────────┼────────────────────┼──────────────┘
             ↓                ↓                    ↓
    ┌────────────────┐  ┌──────────┐     ┌──────────────────┐
    │  Target Site   │  │ WAF/IPS  │     │  GitHub (APIs)   │
    │  HTTP Requests │  │ Detection│     │  • SecLists      │
    │  Response Data │  │ Bypass   │     │  • PayloadBox    │
    └────────────────┘  └──────────┘     │  • Swisskyrepo   │
                                          └──────────────────┘
```

---

## 🔄 Data Flow Diagram

```
User Action (Ctrl+Shift+E)
       ↓
Dashboard Opens
       ↓
User Configures Scan
  • URL
  • Parameters
  • Attack Vectors
       ↓
Click "Start Scan"
       ↓
┌──────────────────────────────────────────┐
│    VulnerabilityScanner.initialize()      │
│  1. Capture baseline response            │
│  2. Detect WAF                            │
└──────────────────────────────────────────┘
       ↓
┌──────────────────────────────────────────┐
│   PayloadManager.getPayloads()           │
│  1. Check cache                           │
│  2. Fetch from GitHub                     │
│  3. Parse & deduplicate                   │
│  4. Cache results                         │
└──────────────────────────────────────────┘
       ↓
For each parameter:
  For each payload:
    ↓
    ┌──────────────────────────────────────┐
    │  WAFDetector.applyBypass()           │
    │  • Check if WAF detected             │
    │  • Apply encoding/obfuscation        │
    └──────────────────────────────────────┘
    ↓
    ┌──────────────────────────────────────┐
    │  Send HTTP Request                    │
    │  • Build test URL                     │
    │  • Inject payload                     │
    │  • Record timing                      │
    └──────────────────────────────────────┘
    ↓
    ┌──────────────────────────────────────┐
    │  ResponseAnalyzer.analyzeResponse()  │
    │  1. Check error signatures           │
    │  2. Analyze timing                   │
    │  3. Compare with baseline            │
    │  4. Check context (XSS)              │
    │  5. Calculate confidence             │
    │  6. Check false positives            │
    └──────────────────────────────────────┘
    ↓
    If vulnerable (confidence ≥ 70%):
      ↓
      Add to results[]
      ↓
      Display in dashboard
       ↓
Scan Complete
  ↓
Generate Report
  ↓
Export (JSON/CSV)
```

---

## 🧩 Module Architecture

### ResponseAnalyzer.js

```
ResponseAnalyzer
├── initErrorSignatures()
│   ├── SQL injection patterns (MySQL, PostgreSQL, MSSQL, Oracle)
│   ├── XXE error patterns
│   ├── Path traversal patterns
│   ├── RCE output patterns
│   └── SSTI error patterns
│
├── captureBaseline(url)
│   ├── Make initial request
│   ├── Store response metadata
│   └── Calculate response hash
│
├── analyzeResponse(response, payload, vulnType, baseline)
│   ├── checkErrorSignatures()
│   │   └── Match against 100+ patterns
│   ├── analyzeTimingAnomaly()
│   │   ├── Compare response times
│   │   └── Verify blind injection delays
│   ├── calculateContentDifference()
│   │   └── Compare response lengths/hashes
│   ├── verifyXSSExecution()
│   │   ├── findPayloadContexts()
│   │   │   ├── Check script context
│   │   │   ├── Check attribute context
│   │   │   └── Check HTML context
│   │   └── Determine if executable
│   ├── verifySQLInjection()
│   │   ├── Check error-based
│   │   ├── Verify time-based
│   │   ├── Test boolean-based
│   │   └── Validate union-based
│   └── checkFalsePositives()
│       ├── Detect HTML encoding
│       ├── Identify WAF blocks
│       ├── Check HTML comments
│       └── Detect generic errors
│
└── Confidence Scoring
    ├── Error signature: +40
    ├── Timing anomaly: +35
    ├── Content difference: +20
    ├── XSS confirmed: +50
    ├── SQLi confirmed: +50
    └── False positive: -40
```

### WAFDetector.js

```
WAFDetector
├── initWAFSignatures()
│   ├── Cloudflare (headers, body, status)
│   ├── Akamai (headers, body)
│   ├── AWS WAF (headers)
│   ├── Imperva (headers, cookies)
│   ├── F5 BIG-IP (headers, body)
│   ├── ModSecurity (headers, body)
│   ├── Wordfence (headers, cookies)
│   ├── Sucuri (headers, body)
│   ├── Barracuda (headers)
│   ├── FortiWeb (headers)
│   ├── DotDefender (headers)
│   └── CloudFront (headers)
│
├── initBypassTechniques()
│   ├── Encoding
│   │   ├── URL encoding
│   │   ├── Double URL encoding
│   │   ├── Unicode
│   │   ├── Hex
│   │   ├── HTML entities
│   │   └── Mixed encoding
│   ├── Case Manipulation
│   │   ├── Random case
│   │   └── Alternating case
│   ├── Comment Injection
│   │   ├── MySQL comments (/**/)
│   │   └── Multiline comments
│   ├── Whitespace Manipulation
│   │   ├── Tabs
│   │   ├── Newlines
│   │   └── Mixed whitespace
│   ├── Concatenation
│   │   ├── SQL concat (UN'+'ION)
│   │   └── Double quote concat
│   ├── Obfuscation
│   │   ├── XSS with backticks
│   │   ├── XSS with eval
│   │   └── SQL with CHAR()
│   └── Null Byte
│       ├── Append (%00)
│       ├── Prepend
│       └── Middle insertion
│
├── detect(url)
│   ├── Send test payloads
│   ├── Check response headers
│   ├── Analyze response body
│   ├── Check status codes
│   ├── Check cookies
│   └── Calculate confidence score
│
├── applyBypass(payload, technique, vulnType)
│   ├── Auto-select for detected WAF
│   └── Apply specific technique
│
└── isBlocked(response)
    ├── Check status codes (403, 406, 419)
    └── Check block indicators
```

### PayloadManager.js

```
PayloadManager
├── initPayloadSources()
│   ├── XSS
│   │   ├── SecLists basic
│   │   ├── SecLists polyglot
│   │   ├── PayloadBox
│   │   └── Swisskyrepo
│   ├── SQL Injection
│   │   ├── SecLists MySQL
│   │   ├── SecLists generic
│   │   ├── SecLists time-based
│   │   └── PayloadBox
│   ├── LFI
│   │   ├── SecLists Linux
│   │   ├── SecLists Windows
│   │   └── PayloadBox
│   ├── SSRF
│   │   ├── SecLists
│   │   └── PayloadBox
│   └── [More vulnerability types...]
│
├── getPayloads(vulnType, options)
│   ├── Check cache
│   ├── If not cached:
│   │   ├── fetchFromURL()
│   │   │   ├── GM_xmlhttpRequest
│   │   │   └── parsePayloads()
│   │   ├── Deduplicate
│   │   └── saveToCache()
│   └── Return filtered payloads
│
├── Cache Management
│   ├── getFromCache()
│   ├── saveToCache()
│   ├── clearCache()
│   └── Cache expiry: 24h
│
├── Custom Sources
│   ├── addCustomSource()
│   ├── removeCustomSource()
│   └── importCustomPayloads()
│
└── Utilities
    ├── searchPayloads()
    ├── getRecommended()
    ├── exportPayloads()
    └── validateSources()
```

---

## 🔀 Component Interactions

### Scan Workflow

```
User → Dashboard → VulnerabilityScanner
                          ↓
                    ┌─────┴─────┐
                    ↓           ↓
              PayloadManager  WAFDetector
                    ↓           ↓
              [Payloads]    [Bypass Info]
                    ↓           ↓
                    └─────┬─────┘
                          ↓
                  Build Test Request
                          ↓
                    Target Website
                          ↓
                    HTTP Response
                          ↓
                  ResponseAnalyzer
                          ↓
                  ┌───────┴────────┐
                  ↓                ↓
          Check Signatures    Calculate
          Analyze Context     Confidence
                  ↓                ↓
                  └───────┬────────┘
                          ↓
                  Vulnerability?
                    ↓         ↓
                  Yes        No
                    ↓         ↓
              Add to      Continue
              Results      Testing
                    ↓
                Dashboard
                (Display)
```

### Module Dependencies

```
EliteMain.js
    ├── requires → ResponseAnalyzer.js
    ├── requires → WAFDetector.js
    ├── requires → PayloadManager.js
    │
    ├── creates → Dashboard
    │   └── uses → VulnerabilityScanner
    │       ├── uses → ResponseAnalyzer
    │       ├── uses → WAFDetector
    │       └── uses → PayloadManager
    │
    └── provides → User Interface
```

---

## 💾 Data Storage

### LocalStorage Keys

```
GM_setValue/GM_getValue Storage:

payloads_xss
  ├── payloads: Array<string>
  ├── timestamp: number
  └── expires: 24h

payloads_sqli
payloads_lfi
payloads_ssrf
... (per vulnerability type)

waf_detection_cache
  ├── url: string
  ├── waf: string
  ├── confidence: number
  └── timestamp: number
```

### Runtime State

```
VulnerabilityScanner
  ├── analyzer: ResponseAnalyzer
  ├── wafDetector: WAFDetector
  ├── payloadManager: PayloadManager
  ├── results: Array<Vulnerability>
  ├── baseline: Response
  └── scanning: boolean

ResponseAnalyzer
  ├── baselineResponses: Map<string, Response>
  └── errorSignatures: Object

WAFDetector
  ├── detectedWAF: string | null
  ├── wafSignatures: Object
  └── bypassTechniques: Object

PayloadManager
  ├── cache: Map<string, Array<string>>
  ├── loading: Set<string>
  └── payloadSources: Object
```

---

## 🔌 API Interfaces

### ResponseAnalyzer API

```javascript
class ResponseAnalyzer {
  // Capture baseline for comparison
  async captureBaseline(url, method='GET', data=null): Promise<Response>
  
  // Analyze response for vulnerabilities
  analyzeResponse(
    response: Response,
    payload: string,
    vulnerabilityType: string,
    baseline: Response
  ): AnalysisResult
  
  // Make HTTP request
  async makeRequest(url, method='GET', data=null, headers={}): Promise<Response>
}

// Types
interface Response {
  status: number
  headers: string
  body: string
  time: number
}

interface AnalysisResult {
  vulnerable: boolean
  confidence: number
  indicators: Array<string>
  falsePositive: boolean
  evidence: Array<string>
}
```

### WAFDetector API

```javascript
class WAFDetector {
  // Detect WAF on target
  async detect(url: string): Promise<DetectionResult>
  
  // Apply bypass technique to payload
  applyBypass(
    payload: string,
    technique: string = 'auto',
    vulnerabilityType: string = 'xss'
  ): string
  
  // Test multiple bypass techniques
  async testBypass(
    url: string,
    parameter: string,
    payload: string,
    vulnerabilityType: string
  ): Promise<Array<BypassResult>>
  
  // Get available techniques
  getBypassTechniques(): Array<Technique>
}

// Types
interface DetectionResult {
  detected: boolean
  waf?: string
  confidence?: number
  severity?: string
}

interface BypassResult {
  technique: string
  payload: string
  blocked: boolean
  success: boolean
}
```

### PayloadManager API

```javascript
class PayloadManager {
  // Get payloads for vulnerability type
  async getPayloads(
    vulnType: string,
    options: PayloadOptions = {}
  ): Promise<Array<string>>
  
  // Add custom payload source
  addCustomSource(
    vulnType: string,
    sourceName: string,
    url: string
  ): void
  
  // Import custom payloads
  importCustomPayloads(
    vulnType: string,
    payloadsText: string
  ): number
  
  // Search payloads
  async searchPayloads(
    vulnType: string,
    keyword: string,
    caseSensitive: boolean = false
  ): Promise<Array<string>>
  
  // Get recommended payloads
  async getRecommended(
    vulnType: string,
    context: string = null
  ): Promise<Array<string>>
  
  // Cache management
  clearCache(vulnType: string = null): void
}

// Types
interface PayloadOptions {
  sources?: Array<string> | 'all'
  cache?: boolean
  limit?: number
  filter?: Function
}
```

---

## 🚦 State Machine

```
[IDLE]
  │
  ↓ User opens dashboard (Ctrl+Shift+E)
[READY]
  │
  ↓ User clicks "Start Scan"
[INITIALIZING]
  ├─→ Capture baseline
  ├─→ Detect WAF
  └─→ Load payloads
  │
  ↓ All initialized
[SCANNING]
  │
  ├─→ For each parameter
  │   └─→ For each payload
  │       ├─→ Apply bypass
  │       ├─→ Send request
  │       ├─→ Analyze response
  │       └─→ If vulnerable: Record
  │
  ↓ All tests complete
[COMPLETE]
  │
  ├─→ Display results
  ├─→ Allow export
  └─→ Back to READY
```

---

## 🔒 Security Considerations

### Input Validation

```
User Input (URL, Parameters)
    ↓
Sanitization
    ├─→ Validate URL format
    ├─→ Check parameter names
    └─→ Limit length
    ↓
Safe to use
```

### Request Safety

```
HTTP Request
    ├─→ Timeout: 15 seconds
    ├─→ Rate limiting: 500ms delay
    ├─→ Error handling: Try/catch
    └─→ Retry limit: 2 attempts
```

### Data Privacy

```
Results Storage
    ├─→ Local only (GM_setValue)
    ├─→ No external transmission
    ├─→ User controls exports
    └─→ Clearable at any time
```

---

## 📊 Performance Optimization

### Caching Strategy

```
Request Flow:
1. Check cache → Cache hit? → Return cached
                     ↓ No
2. Fetch from GitHub
3. Parse & deduplicate
4. Save to cache (24h TTL)
5. Return results
```

### Parallel Processing

```
Scan Execution:
├─→ Thread 1: Test parameter 1
├─→ Thread 2: Test parameter 2
└─→ Thread 3: Test parameter 3

Each thread:
  ├─→ Sequential payloads
  └─→ Configurable delay (500ms)
```

### Memory Management

```
Cache Limits:
├─→ Payloads: 1000 per type
├─→ Results: Unlimited (user-managed)
├─→ Baseline: 1 per scan
└─→ Auto-cleanup on scan start
```

---

## 🔄 Update & Maintenance

### Module Updates

```
GitHub Repo
    ↓
User pushes changes
    ↓
Raw URLs updated automatically
    ↓
Tampermonkey @require refetch
    ↓
Users get latest version
```

### Cache Invalidation

```
Payload Cache:
├─→ Automatic: 24h expiry
├─→ Manual: Clear cache button
└─→ On source update: Auto-clear

WAF Cache:
└─→ Per-URL basis
```

---

This architecture provides a solid foundation for professional penetration testing with modularity, extensibility, and maintainability at its core.
