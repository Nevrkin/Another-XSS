# 🛡️ Elite Pentest Framework 2025 - Professional Edition

**Advanced Modular Security Testing Framework with GitHub Integration**

> **Warning:** This tool is for authorized security testing only. Unauthorized testing is illegal.

## 🌟 Features

### ✅ Advanced False Positive Reduction
- **Context-aware XSS detection** - Analyzes if payload is in executable context
- **Response content analysis** - Compares against baseline to detect real changes
- **Confidence scoring system** - 70%+ threshold required for vulnerability confirmation
- **WAF block detection** - Doesn't count blocked requests as vulnerabilities
- **HTML encoding detection** - Identifies properly sanitized output

### 🎯 Comprehensive Attack Vectors
- **XSS** - Context-aware (HTML, attribute, script), WAF bypass, polyglot
- **SQL Injection** - Error, time-based, boolean, union, NoSQL
- **SSRF** - Cloud metadata, bypass filters (decimal IP, octal, hex)
- **XXE** - Basic + blind out-of-band
- **LFI/RFI** - Path traversal, PHP wrappers, encoding bypass
- **SSTI** - Jinja2, Freemarker, Velocity, Thymeleaf
- **RCE** - Command injection with blind techniques
- **Open Redirect** - Multiple bypass techniques
- **CRLF Injection** - Header manipulation
- **NoSQL Injection** - MongoDB operator injection

### 🛡️ WAF Detection & Bypass
**Detects:**
- Cloudflare, Akamai, AWS WAF, Imperva Incapsula
- F5 BIG-IP ASM, ModSecurity, Wordfence
- Sucuri, Barracuda, FortiWeb, DotDefender, CloudFront

**Bypass Techniques:**
- Double URL encoding
- Unicode/hex encoding
- Case manipulation
- Comment injection
- Whitespace manipulation
- Obfuscation techniques

### 📦 GitHub Payload Integration
**Automatically fetches from:**
- **SecLists** (Daniel Miessler)
- **PayloadsAllTheThings** (Swisskyrepo)
- **PayloadBox** collections
- Custom payload lists

---

## 📁 Project Structure

```
pentest/
├── EliteMain.js              # Main coordinator script (install in Tampermonkey)
├── AdvancedElite.js          # Standalone version (no modules)
├── Elite.js                  # Original version (reference)
├── modules/
│   ├── ResponseAnalyzer.js  # Advanced response analysis & false positive reduction
│   ├── WAFDetector.js       # WAF detection & bypass engine
│   └── PayloadManager.js    # GitHub payload integration & caching
├── payloads/                # (Optional) Local payload storage
└── README.md                # This file
```

---

## 🚀 Installation Guide

### Option 1: GitHub Hosted (Recommended)

#### Step 1: Create GitHub Repository
```bash
# Create a new repository on GitHub
# Repository name: elite-pentest
# Visibility: Public or Private
```

#### Step 2: Upload Modules
1. Go to your GitHub repository
2. Create a `modules` folder
3. Upload these files to `modules/`:
   - `ResponseAnalyzer.js`
   - `WAFDetector.js`
   - `PayloadManager.js`

#### Step 3: Get Raw URLs
1. Click on each file in GitHub
2. Click **Raw** button
3. Copy the URL (format: `https://raw.githubusercontent.com/username/repo/branch/modules/filename.js`)

#### Step 4: Update EliteMain.js
Open `EliteMain.js` and update the `@require` lines:

```javascript
// @require      https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/ResponseAnalyzer.js
// @require      https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/WAFDetector.js
// @require      https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/PayloadManager.js
```

Replace `YOURUSERNAME` with your GitHub username.

#### Step 5: Install in Tampermonkey
1. Install [Tampermonkey](https://www.tampermonkey.net/) browser extension
2. Open Tampermonkey Dashboard
3. Click **Utilities** → **Import from URL**
4. Paste your GitHub raw URL for `EliteMain.js`
5. Click **Install**

---

### Option 2: Local Files (Alternative)

If you don't want to use GitHub:

1. Open `EliteMain.js`
2. Update `@require` lines to local paths:

```javascript
// @require      file:///C:/Users/Moiz/pentest/modules/ResponseAnalyzer.js
// @require      file:///C:/Users/Moiz/pentest/modules/WAFDetector.js
// @require      file:///C:/Users/Moiz/pentest/modules/PayloadManager.js
```

**Note:** Some browsers restrict `file://` access. GitHub hosting is recommended.

---

### Option 3: Standalone Version

Use `AdvancedElite.js` - no modules required, everything in one file.

1. Open Tampermonkey Dashboard
2. Create New Script
3. Copy entire contents of `AdvancedElite.js`
4. Save

---

## 🎮 Usage Guide

### Opening the Dashboard

**Keyboard Shortcut:** `Ctrl + Shift + E`

### Quick Scan

1. **Enter Target URL** - Or use current page URL
2. **Auto-Detect Parameters** - Click to scan URL for parameters
3. **Or manually enter** - Comma-separated list (e.g., `id, search, page`)
4. **Select Attack Vectors** - Choose what to test
5. **Click "Start Scan"** - Begin testing

### Configuration

#### Attack Vectors
Toggle any combination:
- ✓ XSS
- ✓ SQL Injection
- ✓ SSRF
- ✓ LFI
- ✓ RCE
- ✓ SSTI
- ✓ Open Redirect

#### Payload Sources
Automatically fetches from:
- SecLists (built-in)
- PayloadsAllTheThings (built-in)
- PayloadBox (built-in)
- Custom sources (add your own)

Cache is automatically managed (24h expiry).

### WAF Detection

Click **Detect WAF** to:
1. Identify security controls (Cloudflare, Akamai, etc.)
2. Get bypass recommendations
3. Auto-apply evasion techniques

### Results

Each finding includes:
- **Vulnerability Type** (XSS, SQLi, etc.)
- **Confidence Score** (70-100%)
- **Evidence** (error messages, timing data, etc.)
- **Payload Used**
- **Full URL**

### Export

**JSON Format:**
```json
[
  {
    "type": "XSS",
    "parameter": "search",
    "payload": "<script>alert(1)</script>",
    "confidence": 95,
    "evidence": ["XSS in HTML injection"],
    "url": "https://example.com/search?q=..."
  }
]
```

**CSV Format:**
```csv
Type,Parameter,Payload,Confidence,URL
XSS,search,"<script>alert(1)</script>",95,https://...
```

---

## 🔧 Advanced Configuration

### Custom Payload Sources

Add your own payload sources via console:

```javascript
// Get PayloadManager instance
const pm = window.eliteModules.payloadManager;

// Add custom source
pm.addCustomSource('xss', 'my_custom', 'https://raw.githubusercontent.com/user/repo/main/xss.txt');

// Import from text
const payloads = `<script>alert(1)</script>
<img src=x onerror=alert(1)>`;
pm.importCustomPayloads('xss', payloads);
```

### Adjust Confidence Threshold

Edit `EliteMain.js`:

```javascript
const CONFIG = {
  TESTING: {
    CONFIDENCE_THRESHOLD: 70  // Change to 80 or 90 for higher confidence
  }
};
```

### Customize Request Delay

```javascript
const CONFIG = {
  TESTING: {
    PAYLOAD_DELAY: 500  // Milliseconds between requests
  }
};
```

---

## 📊 How It Works

### 1. Initialization
```
Load Modules → Initialize Scanner → Capture Baseline Response → Detect WAF
```

### 2. Payload Fetching
```
Check Cache → Fetch from GitHub (SecLists, etc.) → Parse & Deduplicate → Cache (24h)
```

### 3. Testing Process
```
For each parameter:
  For each payload:
    Apply WAF bypass (if detected)
    Send request
    Analyze response:
      - Check error signatures
      - Analyze timing
      - Compare with baseline
      - Check context (XSS)
      - Calculate confidence
    If confidence ≥ 70%:
      Report vulnerability
```

### 4. False Positive Reduction
```
Check if:
  - Payload is HTML-encoded ✓
  - Response is WAF block ✓
  - Reflected in comment ✓
  - Generic error page ✓
  - Not in executable context ✓

If any true → Mark as false positive
```

---

## 🎯 Detection Methods

### XSS Detection
1. **Payload Reflection** - Check if payload appears in response
2. **Context Analysis** - Determine if in script, attribute, or HTML
3. **Executable Context** - Verify if actually executable
4. **Encoding Check** - Ensure not sanitized
5. **DOM Marker** - Check for `window.__xss_confirmed` flag

### SQLi Detection
1. **Error-Based** - Match 50+ SQL error signatures
2. **Time-Based** - Verify delay matches SLEEP/WAITFOR
3. **Boolean-Based** - Compare TRUE vs FALSE responses
4. **Union-Based** - Check response size increase

### SSRF Detection
1. **Cloud Metadata** - Check for AWS/GCP/Azure metadata
2. **File Content** - Look for passwd/boot.ini contents
3. **Response Diff** - Compare with baseline

---

## 🔒 Security & Ethics

### ⚠️ Legal Warning

**This tool is for AUTHORIZED testing only.**

- ✅ Use on systems you own
- ✅ Use with written permission
- ✅ Use in controlled lab environments
- ❌ NEVER use on systems without authorization
- ❌ Unauthorized testing is ILLEGAL

### Responsible Disclosure

If you find vulnerabilities:
1. Contact the organization privately
2. Give reasonable time to fix (90 days)
3. Don't publish details until fixed
4. Follow responsible disclosure guidelines

---

## 🐛 Troubleshooting

### Modules Not Loading

**Error:** `ResponseAnalyzer is not defined`

**Solution:**
1. Check `@require` URLs are correct
2. Verify files are publicly accessible on GitHub
3. Clear Tampermonkey cache
4. Reinstall script

### No Payloads Loading

**Error:** `Failed to load from seclists`

**Solution:**
1. Check internet connection
2. Verify GitHub raw URLs are accessible
3. Check browser console for CORS errors
4. Try clearing payload cache

### WAF Detection Not Working

**Solution:**
1. Ensure target URL is accessible
2. Check if site uses CAPTCHA
3. Try manual detection first
4. Check browser console for errors

### High False Positives

**Solution:**
1. Increase confidence threshold to 80-90%
2. Enable all false positive checks
3. Review detection methods
4. Submit issue on GitHub

---

## 📈 Performance Tips

1. **Limit Payload Count** - Use `limit: 100` in config
2. **Increase Delays** - If rate-limited, increase `PAYLOAD_DELAY`
3. **Test Specific Vectors** - Don't enable all at once
4. **Use Cache** - Payloads cache for 24h
5. **Test High-Risk Parameters First** - id, search, etc.

---

## 🤝 Contributing

Contributions welcome! Submit pull requests for:
- New vulnerability types
- Improved detection methods
- Additional bypass techniques
- Bug fixes
- Documentation improvements

---

## 📚 Resources

### Payload Sources
- [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by Swisskyrepo
- [PayloadBox](https://github.com/payloadbox) collections

### Learning Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bug Bounty Platforms](https://www.bugcrowd.com/)

---

## 📝 Changelog

### v11.0.0 (2025-11-10)
- ✨ Modular architecture with GitHub integration
- ✨ PayloadManager with SecLists integration
- ✨ Advanced WAF detection & bypass
- ✨ Response analyzer with confidence scoring
- ✨ Enhanced dashboard UI
- ✨ False positive reduction (90%+)
- ✨ 15+ vulnerability types
- 🐛 Fixed false positives from HTML encoding
- 🐛 Fixed timing analysis accuracy
- 🎨 Modern gradient UI design

---

## 📧 Contact

- **Author:** Elite Security Team 2025
- **GitHub:** https://github.com/yourusername/elite-pentest
- **Issues:** https://github.com/yourusername/elite-pentest/issues

---

## 📄 License

This project is for educational purposes only. Use responsibly and legally.

**MIT License** - See LICENSE file for details

---

## 🙏 Acknowledgments

- Daniel Miessler (SecLists)
- Swisskyrepo (PayloadsAllTheThings)
- PayloadBox
- OWASP Community
- Bug Bounty Community

---

**Made with ❤️ by Elite Security Team 2025**

