# 📱 Mobile App Analyzer

A self-contained desktop tool for analyzing Android APK and iOS IPA files.  
No external tools required — everything runs locally in your browser.

---

## Quick Start

```bash
python3 launch.py
```

The browser opens automatically at `http://127.0.0.1:7432`

---

## Features

### Android APK Analysis
- **Extraction** — Unpacks the APK (ZIP) safely, preventing path traversal
- **Manifest** — Parses `AndroidManifest.xml` (both text and binary XML)
  - Package ID, version, min/target SDK
  - Permissions (highlights dangerous ones)
  - Activities, Services, Receivers, Providers
- **DEX Analysis** — Parses `.dex` Dalvik bytecode headers
  - String pool extraction (up to 50k strings per DEX)
  - Class name enumeration and categorization (app / 3rd-party / framework)
  - Interesting string detection: URLs, API keys, file paths, crypto mentions
- **Native Libraries** — ELF `.so` analysis
  - Architecture detection (ARM, ARM64, x86, x86_64)
  - String extraction and flagging
- **Resources** — Assets, `res/`, SQLite databases, certificates
- **Security Checks**
  - Dangerous permissions
  - `debuggable=true`, `allowBackup`, cleartext traffic
  - HTTP URLs in code, hardcoded credential patterns

### iOS IPA Analysis
- **Extraction** — Unpacks the IPA, locates `.app` bundle
- **Info.plist** — Full parse: bundle ID, version, URL schemes, ATS config, privacy keys
- **Entitlements** — Parses `.entitlements` files and `embedded.mobileprovision`
- **Mach-O Binary** — Fat binary / universal binary parsing
  - Architecture slice enumeration (ARM64, x86_64…)
  - Load command walking: linked frameworks and dylibs
  - String extraction and classification
  - ObjC class name extraction from `__objc_classname`
- **Resources** — `.plist` files, storyboards, SQLite, certs
- **Security Checks**
  - `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsInWebContent`
  - HTTP URLs in binary, hardcoded credential patterns, privacy usage

### Universal Features
- **File Explorer** — Full tree with syntax-highlighted viewer (XML, Java, Swift, JSON…)
- **Search** — Full-text search across all extracted text files
- **Interesting Strings** — Categorized table: URLs, API keys, hosts, crypto, paths
- **Export** — JSON report or self-contained HTML security report
- **Project History** — All analyses saved and accessible from sidebar
- **Logging** — Every session logged to `~/.mobile_analyzer/logs/`

---

## Project Storage

```
~/.mobile_analyzer/
├── projects/           # One folder per analyzed app
│   └── MyApp_20250101/
│       ├── original/   # Original unmodified APK/IPA
│       ├── extracted/  # Extracted files (clearly labeled)
│       └── report.json # Analysis report
├── uploads/            # Temporary upload staging
├── reports/            # Exported HTML reports
└── logs/               # Session logs
```

**Original files are always preserved.** Extracted, decompiled, and generated content is clearly separated in different directories.

---

## Legal Notice

This tool performs **static analysis only** using standard file format parsing:
- ZIP/APK/IPA extraction (standard archive format)
- DEX header and string pool reading (documented format)
- Mach-O load command parsing (documented ABI)
- plist / XML / manifest reading

It does **not**:
- Bypass DRM, strip code signing, or defeat encryption
- Crack licensing systems or remove copy protection
- Reconstruct proprietary source code from obfuscated binaries
- Execute or emulate app code

Only analyze apps you own, have permission to test, or are authorized to assess  
(e.g., penetration testing, security research under a signed agreement).

---

## Optional Enhancements

For deeper analysis, install these optional tools:

| Tool | Purpose |
|------|---------|
| `apktool` | Full binary XML decode, resource decompile |
| `jadx` | DEX → readable Java decompilation |
| `aapt2` | Resource table parsing |
| `strings` (GNU) | Faster string extraction |
| `objdump` | Symbol tables from native libs |
| `yara-python` | YARA rule-based malware scanning |

The analyzer auto-detects these if present in `$PATH` (plugin hooks ready).

---

## Requirements

- Python 3.8+
- Flask (`pip install flask`)
- A modern browser (auto-opened)

---

*Built for penetration testers and security researchers.*  
*Respect intellectual property and applicable laws.*
