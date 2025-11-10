# 🚀 Quick Installation Guide

## Elite Pentest Framework 2025 - Installation for Another-XSS Repository

### ⚡ Quick Start (5 Minutes)

#### Step 1: Install Tampermonkey
- **Chrome/Edge**: [Chrome Web Store](https://chrome.google.com/webstore/detail/tampermonkey/)
- **Firefox**: [Firefox Add-ons](https://addons.mozilla.org/firefox/addon/tampermonkey/)

#### Step 2: Install the Script

**Option A: Direct Install (Easiest)**
1. Open Tampermonkey Dashboard
2. Click **"+"** (Create new script)
3. Delete the template
4. Copy the entire content of `EliteMain.js`
5. Paste and Save (Ctrl+S)

**Option B: From URL**
```
https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/EliteMain.js
```
1. Tampermonkey → Utilities → Import from URL
2. Paste URL above → Install

#### Step 3: Test It!
1. Visit any website
2. Press **Ctrl + Shift + E**
3. Dashboard should appear! 🎉

---

## 🧪 Test Your Installation

### Quick Test
1. Go to: `http://testphp.vulnweb.com/search.php`
2. Press `Ctrl + Shift + E`
3. Click **Auto-Detect** button
4. Enable **XSS** and **SQL Injection**
5. Click **Start Scan**
6. Wait 2-3 minutes
7. Review results (should find vulnerabilities)

---

## 📦 Files in This Repository

```
Another-XSS/
├── EliteMain.js              ⭐ Main script (Install this in Tampermonkey)
├── AdvancedElite.js          📦 Standalone version (no modules needed)
├── modules/                  🔧 Core modules (auto-loaded)
│   ├── ResponseAnalyzer.js
│   ├── WAFDetector.js
│   └── PayloadManager.js
├── payloads/                 💾 Custom payloads
├── README.md                 📖 Full documentation
├── SETUP_GUIDE.md            🚀 Detailed setup
└── INSTALL.md                ⚡ This file
```

---

## 🎯 What You Get

✅ **Advanced XSS Detection** - 90%+ accuracy with context analysis
✅ **SQL Injection Testing** - Error, time-based, boolean, union
✅ **15+ Vulnerability Types** - SSRF, LFI, RCE, SSTI, XXE, etc.
✅ **WAF Detection & Bypass** - 12+ security controls
✅ **GitHub Integration** - 1000+ payloads from SecLists
✅ **Professional Reports** - JSON/CSV export

---

## 🔧 Configuration

All URLs are pre-configured for this repository:
```
https://raw.githubusercontent.com/Nevrkin/Another-XSS/main/modules/
```

No additional setup needed! Just install and use.

---

## ⌨️ Keyboard Shortcuts

- **Ctrl + Shift + E** - Open/Close dashboard
- **Esc** - Close dashboard

---

## 🆘 Troubleshooting

### Dashboard Won't Open
- Verify Tampermonkey is installed and enabled
- Check script is enabled (green dot in Tampermonkey)
- Try different website
- Check browser console (F12) for errors

### Modules Not Loading
- Check internet connection
- Verify GitHub URLs are accessible
- Clear Tampermonkey cache (Dashboard → Settings)
- Reinstall script

### No Vulnerabilities Found
- Normal! Test on: http://testphp.vulnweb.com/
- Lower confidence threshold (edit EliteMain.js)
- Enable more attack vectors

---

## 📚 Learn More

- **README.md** - Complete feature documentation
- **SETUP_GUIDE.md** - Detailed setup instructions
- **ARCHITECTURE.md** - Technical architecture
- **DEPLOYMENT_CHECKLIST.md** - Advanced configuration

---

## ⚖️ Legal Notice

**⚠️ For Authorized Testing Only**

This tool is for:
- ✅ Testing systems you own
- ✅ Bug bounty programs with permission
- ✅ Educational purposes in controlled environments

Unauthorized testing is illegal!

---

## 🎓 Support

- **Issues**: [GitHub Issues](https://github.com/Nevrkin/Another-XSS/issues)
- **Documentation**: See README.md
- **Updates**: Watch this repository

---

## 🚀 Ready to Start?

1. ✅ Tampermonkey installed
2. ✅ EliteMain.js installed
3. ✅ Tested with Ctrl+Shift+E
4. ✅ Ran test scan

**You're ready to start ethical hacking!**

---

**Version:** 11.0.0  
**Repository:** https://github.com/Nevrkin/Another-XSS  
**License:** Educational Use Only
