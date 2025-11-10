# 🚀 Quick Setup Guide - Elite Pentest Framework

## ⚡ 5-Minute Setup

### Step 1: Choose Your Method

**Method A: GitHub Hosted (Recommended)** ⭐
- ✅ Auto-updates
- ✅ Easy sharing
- ✅ Reliable
- ⏱️ Setup time: 5 minutes

**Method B: Local Files** 
- ✅ No internet needed
- ❌ Manual updates
- ⏱️ Setup time: 2 minutes

**Method C: Standalone**
- ✅ Single file
- ❌ No auto-updates
- ⏱️ Setup time: 1 minute

---

## 📋 Method A: GitHub Hosted Setup

### 1. Create GitHub Repository (2 minutes)

```bash
# Option 1: Via GitHub Website
1. Go to https://github.com/new
2. Repository name: elite-pentest
3. Visibility: Public (or Private if you prefer)
4. Click "Create repository"

# Option 2: Via Git Command Line
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOURUSERNAME/elite-pentest.git
git push -u origin main
```

### 2. Upload Modules (1 minute)

**Via GitHub Website:**
1. Click **Add file** → **Upload files**
2. Drag and drop `modules/` folder
3. Click **Commit changes**

**Via Git:**
```bash
cd C:\Users\Moiz\pentest
git add modules/
git commit -m "Add modules"
git push
```

### 3. Get Raw URLs (1 minute)

For each file in `modules/`:
1. Click on file: `modules/ResponseAnalyzer.js`
2. Click **Raw** button (top right)
3. Copy URL from browser address bar

Example URLs:
```
https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/ResponseAnalyzer.js
https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/WAFDetector.js
https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/PayloadManager.js
```

### 4. Update EliteMain.js (1 minute)

Open `EliteMain.js` and replace lines 19-21:

**Before:**
```javascript
// @require      https://raw.githubusercontent.com/yourusername/elite-pentest/main/modules/ResponseAnalyzer.js
```

**After:**
```javascript
// @require      https://raw.githubusercontent.com/YOURUSERNAME/elite-pentest/main/modules/ResponseAnalyzer.js
```

Replace `YOURUSERNAME` with your actual GitHub username in all 3 lines.

### 5. Install in Tampermonkey (1 minute)

**Option A: From URL**
1. Upload `EliteMain.js` to GitHub
2. Get raw URL
3. Tampermonkey Dashboard → **Utilities** → **Import from URL**
4. Paste URL → **Install**

**Option B: Copy/Paste**
1. Open Tampermonkey Dashboard
2. Click **+** (Create new script)
3. Delete template
4. Copy entire `EliteMain.js` content
5. Paste → **File** → **Save**

### 6. Test Installation

1. Navigate to any website
2. Press `Ctrl + Shift + E`
3. Dashboard should appear! 🎉

---

## 📋 Method B: Local Files Setup

### 1. Update EliteMain.js

Replace lines 19-21 with local paths:

```javascript
// @require      file:///C:/Users/Moiz/pentest/modules/ResponseAnalyzer.js
// @require      file:///C:/Users/Moiz/pentest/modules/WAFDetector.js
// @require      file:///C:/Users/Moiz/pentest/modules/PayloadManager.js
```

**Important:** Use forward slashes `/` even on Windows!

### 2. Enable Local File Access

**Chrome/Edge:**
1. Go to `chrome://extensions/`
2. Click **Details** on Tampermonkey
3. Enable **"Allow access to file URLs"**

**Firefox:**
1. Go to `about:addons`
2. Tampermonkey → **Permissions** tab
3. Enable file access

### 3. Install Script

Same as Method A, Step 5.

---

## 📋 Method C: Standalone Setup

### 1. Install AdvancedElite.js

1. Open Tampermonkey Dashboard
2. Click **+** (New script)
3. Copy entire `AdvancedElite.js` content
4. Paste and save

**Done!** No modules needed.

---

## 🧪 Testing Your Setup

### Quick Test

1. Go to: `http://testphp.vulnweb.com/`
2. Press `Ctrl + Shift + E`
3. Click **Auto-Detect** button
4. Select **XSS** and **SQL Injection**
5. Click **Start Scan**

**Expected Result:** Dashboard shows scanning progress and finds vulnerabilities.

### Test Payload Loading

Open browser console (F12) and type:

```javascript
// Check if modules loaded
console.log(ResponseAnalyzer);
console.log(WAFDetector);
console.log(PayloadManager);

// Test payload fetch
const pm = new PayloadManager();
pm.getPayloads('xss', {limit: 10}).then(payloads => {
  console.log('XSS Payloads:', payloads.length);
});
```

**Expected Output:** Module constructors and payload count.

---

## ⚠️ Troubleshooting

### Issue: "ResponseAnalyzer is not defined"

**Cause:** Modules not loading

**Solutions:**
1. ✅ Check `@require` URLs are correct
2. ✅ Verify files exist at those URLs (open in browser)
3. ✅ Clear Tampermonkey cache: Dashboard → Settings → Clear cache
4. ✅ Reinstall script
5. ✅ Try local files method instead

### Issue: "Failed to fetch payloads"

**Cause:** GitHub API rate limit or network issue

**Solutions:**
1. ✅ Wait 1 hour (rate limit resets)
2. ✅ Clear payload cache: Dashboard → Clear Cache
3. ✅ Check internet connection
4. ✅ Try different payload source

### Issue: Dashboard not opening

**Cause:** Keyboard shortcut conflict

**Solutions:**
1. ✅ Try different website
2. ✅ Check console for errors (F12)
3. ✅ Verify script is enabled in Tampermonkey
4. ✅ Check `@match` patterns in script header

### Issue: No vulnerabilities found

**Cause:** Normal - target may not be vulnerable

**Solutions:**
1. ✅ Test on known vulnerable site: http://testphp.vulnweb.com/
2. ✅ Lower confidence threshold to 60%
3. ✅ Enable more attack vectors
4. ✅ Check if WAF is blocking (Detect WAF button)

### Issue: Too many false positives

**Solutions:**
1. ✅ Increase confidence threshold to 80-90%
2. ✅ Verify false positive checks are enabled
3. ✅ Update to latest version
4. ✅ Report issue with example URL

---

## 🎮 First Scan Tutorial

### Step-by-Step First Scan

**Target:** `http://testphp.vulnweb.com/` (intentionally vulnerable site)

1. **Open Dashboard**
   - Press `Ctrl + Shift + E`

2. **Set Target**
   - URL: `http://testphp.vulnweb.com/search.php`
   - Parameters: `searchFor`

3. **Configure Scan**
   - Enable: ✅ XSS, ✅ SQL Injection
   - Disable: Everything else (for speed)

4. **Start Scan**
   - Click **🚀 Start Scan**
   - Wait ~2 minutes

5. **Review Results**
   - Check confidence scores (should be 80%+)
   - Review evidence
   - Click on vulnerability to expand

6. **Export Results**
   - Click **💾 Export JSON**
   - Save report

**Expected Findings:**
- SQL Injection (95% confidence)
- XSS (90% confidence)
- 5-10 total vulnerabilities

---

## 🔧 Configuration Tips

### Optimize for Speed

```javascript
// In EliteMain.js CONFIG section
TESTING: {
  MAX_THREADS: 5,        // Increase parallel requests
  PAYLOAD_DELAY: 200,    // Reduce delay (be careful!)
}

PAYLOAD_SOURCES: {
  xss: ['seclists_basic'],  // Use only one source
  sqli: ['seclists_mysql']
}
```

### Optimize for Accuracy

```javascript
TESTING: {
  CONFIDENCE_THRESHOLD: 85,  // Higher threshold
  PAYLOAD_DELAY: 1000,       // More delay for accuracy
}

PAYLOAD_SOURCES: {
  xss: ['seclists_basic', 'payloadbox', 'swisskyrepo'],  // All sources
}
```

### Optimize for Stealth

```javascript
TESTING: {
  MAX_THREADS: 1,        // One request at a time
  PAYLOAD_DELAY: 2000,   // 2 second delay
}
```

---

## 📚 Next Steps

### After Setup:

1. ✅ **Read full README.md** - Understand all features
2. ✅ **Test on lab environment** - http://testphp.vulnweb.com/
3. ✅ **Configure payload sources** - Add custom payloads
4. ✅ **Learn WAF bypass** - Test detection and evasion
5. ✅ **Join community** - Share findings (responsibly!)

### Advanced Usage:

- **Custom Payloads:** See README.md section "Custom Payload Sources"
- **API Integration:** Call scanner functions directly via console
- **Automation:** Write scripts to batch scan multiple targets
- **Reporting:** Generate professional reports from exports

---

## 🆘 Getting Help

### Resources:

1. **README.md** - Full documentation
2. **Browser Console** - Check for error messages (F12)
3. **GitHub Issues** - Report bugs or ask questions
4. **Community Forums** - Bug bounty communities

### Before Asking for Help:

Include these details:
- ✅ Which setup method you used
- ✅ Browser and version
- ✅ Tampermonkey version
- ✅ Error messages from console
- ✅ Target URL (if public)
- ✅ Steps to reproduce

---

## ✅ Setup Checklist

- [ ] Chose setup method (A, B, or C)
- [ ] Created GitHub repo (Method A only)
- [ ] Uploaded modules to GitHub
- [ ] Got raw URLs for all modules
- [ ] Updated @require lines in EliteMain.js
- [ ] Installed Tampermonkey extension
- [ ] Installed EliteMain.js script
- [ ] Tested with Ctrl+Shift+E
- [ ] Ran test scan on vulnweb
- [ ] Reviewed results
- [ ] Exported report
- [ ] Read full README.md

**All checked?** You're ready to start testing! 🎉

---

## 🚀 Happy Hacking!

Remember: **Always get permission before testing!**

**Legal testing = Learning and earning**
**Illegal testing = Legal consequences**

---

**Last Updated:** 2025-11-10
**Version:** 11.0.0
