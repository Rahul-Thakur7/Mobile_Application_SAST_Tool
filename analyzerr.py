#!/usr/bin/env python3
"""
Mobile App Analyzer - Main Application
A desktop tool for analyzing Android APK and iOS IPA files.
"""

import os, sys, json, zipfile, struct, re, hashlib, sqlite3, plistlib
import threading, subprocess, time, logging, shutil, mimetypes, base64
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, send_file
from werkzeug.utils import secure_filename

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_DIR = Path.home() / ".mobile_analyzer" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"session_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("MobileAnalyzer")

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path.home() / ".mobile_analyzer"
PROJECTS   = BASE_DIR / "projects"
UPLOADS    = BASE_DIR / "uploads"
REPORTS    = BASE_DIR / "reports"
for d in (PROJECTS, UPLOADS, REPORTS):
    d.mkdir(parents=True, exist_ok=True)

ALLOWED_EXT = {".apk", ".ipa"}
MAX_FILE_MB = 500

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024
app.secret_key = os.urandom(24)

# ── Utility helpers ───────────────────────────────────────────────────────────

def file_hash(path: Path, algo="sha256") -> str:
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "error"


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def safe_read(path: Path, max_bytes=256*1024) -> str:
    """Read a file safely, returning text or placeholder."""
    try:
        raw = path.read_bytes()[:max_bytes]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace")
    except Exception as e:
        return f"[Error reading file: {e}]"


def is_text_file(path: Path) -> bool:
    mime, _ = mimetypes.guess_type(str(path))
    if mime and mime.startswith("text"):
        return True
    text_exts = {
        ".xml", ".java", ".kt", ".js", ".ts", ".html", ".css", ".json",
        ".plist", ".yaml", ".yml", ".txt", ".md", ".smali", ".gradle",
        ".properties", ".cfg", ".ini", ".sh", ".py", ".rb", ".go",
        ".swift", ".m", ".h", ".c", ".cpp", ".entitlements", ".strings"
    }
    return path.suffix.lower() in text_exts


# ══════════════════════════════════════════════════════════════════════════════
# Android APK Analysis
# ══════════════════════════════════════════════════════════════════════════════

class APKAnalyzer:
    """Analyzes Android APK files using pure Python + optional external tools."""

    PERMISSION_DANGEROUS = {
        "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
        "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        "READ_PHONE_STATE", "CALL_PHONE", "ADD_VOICEMAIL", "USE_SIP",
        "CAMERA", "BODY_SENSORS",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS",
        "RECORD_AUDIO", "READ_CALENDAR", "WRITE_CALENDAR",
        "USE_BIOMETRIC", "USE_FINGERPRINT",
    }

    def __init__(self, apk_path: Path, project_dir: Path):
        self.apk_path = apk_path
        self.project_dir = project_dir
        self.extracted_dir = project_dir / "extracted"
        self.report = {}

    # ── Extraction ────────────────────────────────────────────────────────────

    def extract(self) -> dict:
        log.info(f"Extracting APK: {self.apk_path}")
        self.extracted_dir.mkdir(parents=True, exist_ok=True)

        file_list = []
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for info in zf.infolist():
                    # Security: prevent path traversal
                    safe_name = info.filename.replace("..", "__").lstrip("/")
                    dest = self.extracted_dir / safe_name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if not info.is_dir():
                        try:
                            data = zf.read(info.filename)
                            dest.write_bytes(data)
                            file_list.append({
                                "path": safe_name,
                                "size": info.file_size,
                                "compressed": info.compress_size,
                                "crc": hex(info.CRC),
                            })
                        except Exception as e:
                            log.warning(f"Could not extract {info.filename}: {e}")
        except zipfile.BadZipFile as e:
            return {"error": f"Not a valid ZIP/APK: {e}"}

        log.info(f"Extracted {len(file_list)} files")
        return {"files": file_list, "count": len(file_list)}

    # ── Manifest parsing ──────────────────────────────────────────────────────

    def parse_manifest(self) -> dict:
        """Parse AndroidManifest.xml - handles both text and binary XML."""
        manifest_path = self.extracted_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return {"error": "AndroidManifest.xml not found"}

        raw = manifest_path.read_bytes()

        # Try text XML first
        if raw[:5] != b"\x03\x00\x08\x00":
            try:
                return self._parse_text_manifest(raw.decode("utf-8", errors="replace"))
            except Exception as e:
                pass

        # Binary XML - parse it
        try:
            return self._parse_binary_manifest(raw)
        except Exception as e:
            log.warning(f"Binary manifest parse failed: {e}")
            return {"raw_hex": raw[:512].hex(), "note": "Binary XML - use aapt for full decode"}

    def _parse_text_manifest(self, text: str) -> dict:
        result = {
            "package": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "permissions": [],
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "features": [],
            "raw": text[:8000],
        }
        pkg = re.search(r'package="([^"]+)"', text)
        if pkg: result["package"] = pkg.group(1)
        vn  = re.search(r'versionName="([^"]+)"', text)
        if vn: result["version_name"] = vn.group(1)
        vc  = re.search(r'versionCode="([^"]+)"', text)
        if vc: result["version_code"] = vc.group(1)
        minsdk = re.search(r'minSdkVersion="([^"]+)"', text)
        if minsdk: result["min_sdk"] = minsdk.group(1)
        tgt = re.search(r'targetSdkVersion="([^"]+)"', text)
        if tgt: result["target_sdk"] = tgt.group(1)

        perms = re.findall(r'uses-permission[^>]+android:name="([^"]+)"', text)
        for p in perms:
            short = p.split(".")[-1]
            result["permissions"].append({
                "name": p,
                "dangerous": short in self.PERMISSION_DANGEROUS
            })

        for comp in ["activity", "service", "receiver", "provider"]:
            names = re.findall(rf'<{comp}[^>]+android:name="([^"]+)"', text)
            result["components"][f"{comp}s"] = names
        return result

    def _parse_binary_manifest(self, data: bytes) -> dict:
        if len(data) < 8 or data[:4] != b"\x03\x00\x08\x00":
            return {}
        result = {"package": "", "permissions": [], "components": {}}
        try:
            strings_start = struct.unpack("<I", data[12:16])[0]
            if strings_start < len(data):
                strings = data[strings_start:strings_start+8192].split(b"\x00")
                for s in strings[:100]:
                    try:
                        text = s.decode("utf-16-le").rstrip("\x00")
                        if text.startswith(("com.", "android.")):
                            if result["package"] == "":
                                result["package"] = text
                    except:
                        pass
        except:
            pass
        return result

    def analyze_dex(self) -> dict:
        """Analyze DEX files for strings, classes, interesting data."""
        dex_list = list(self.extracted_dir.glob("**/*.dex"))
        if not dex_list:
            return {"count": 0}

        result = {
            "count": len(dex_list),
            "strings_sample": [],
            "class_names": [],
            "interesting_strings": {
                "urls": [],
                "api_keys_patterns": [],
                "network_hosts": [],
                "file_paths": [],
                "crypto_mentions": [],
            }
        }

        for dex_path in dex_list[:3]:
            try:
                data = dex_path.read_bytes()
                if len(data) > 100:
                    strings = self._extract_dex_strings(data)
                    result["strings_sample"].extend(strings[:100])
                    self._categorize_strings(strings, result["interesting_strings"])
            except Exception as e:
                log.warning(f"DEX parse error: {e}")

        return result

    def _extract_dex_strings(self, data: bytes) -> list:
        strings = []
        try:
            if len(data) >= 0x20:
                strings_size = struct.unpack("<I", data[0x18:0x1c])[0]
                strings_start = struct.unpack("<I", data[0x1c:0x20])[0]
                if strings_start < len(data):
                    section = data[strings_start:strings_start + strings_size*100]
                    for chunk in section.split(b"\x00"):
                        try:
                            s = chunk.decode("utf-8", errors="ignore").strip()
                            if len(s) > 3:
                                strings.append(s)
                        except:
                            pass
        except:
            pass
        return strings[:1000]

    def _categorize_strings(self, strings: list, categories: dict):
        for s in strings:
            if s.startswith("http"):
                categories["urls"].append(s)
            elif re.search(r"(api_key|apiKey|API_KEY|secret|token|key)", s, re.I):
                categories["api_keys_patterns"].append(s)
            elif re.search(r"([a-z0-9.-]+\.(com|net|org|io|dev))", s, re.I):
                categories["network_hosts"].append(s)
            elif "/" in s and len(s) > 5:
                categories["file_paths"].append(s)
            if re.search(r"(aes|rsa|sha|md5|crypto|cipher|encrypt)", s, re.I):
                categories["crypto_mentions"].append(s)

        for k in categories:
            categories[k] = list(set(categories[k][:50]))

    def analyze_native(self) -> dict:
        """Analyze native .so libraries."""
        so_files = list(self.extracted_dir.glob("**/*.so"))
        if not so_files:
            return {"count": 0}

        result = {"count": len(so_files), "architectures": set(), "strings_sample": []}
        for so_path in so_files[:5]:
            try:
                data = so_path.read_bytes(100)
                if data[:4] == b"\x7fELF":
                    ei_class = data[4]
                    arch = {1: "32-bit", 2: "64-bit"}.get(ei_class, "unknown")
                    e_machine = struct.unpack("<H", data[18:20])[0]
                    arch_name = {0x28: "ARM", 0xb7: "ARM64", 0x03: "x86", 0x3e: "x86_64"}.get(e_machine, "unknown")
                    result["architectures"].add(f"{arch_name} {arch}")
                    strings = self._extract_elf_strings(so_path.read_bytes()[:256*1024])
                    result["strings_sample"].extend(strings[:20])
            except Exception as e:
                log.warning(f"SO parse error: {e}")

        result["architectures"] = list(result["architectures"])
        result["strings_sample"] = list(set(result["strings_sample"]))
        return result

    def _extract_elf_strings(self, data: bytes) -> list:
        strings = []
        current = b""
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) > 4:
                    strings.append(current.decode("utf-8", errors="ignore"))
                current = b""
        return strings[:100]

    def analyze_resources(self) -> dict:
        """Scan for SQLite, certs, assets."""
        result = {"databases": [], "certificates": [], "assets": []}
        for f in self.extracted_dir.rglob("*"):
            if not f.is_file():
                continue
            name = f.name.lower()
            if name.endswith(".db") or name.endswith(".sqlite"):
                result["databases"].append(str(f.relative_to(self.extracted_dir)))
            elif name.endswith(".pem") or name.endswith(".cer") or name.endswith(".crt"):
                result["certificates"].append(str(f.relative_to(self.extracted_dir)))
            elif f.parent.name == "assets":
                result["assets"].append(str(f.relative_to(self.extracted_dir)))
        return result

    def security_checks(self, manifest: dict) -> dict:
        """Find security issues."""
        findings = []

        perms = manifest.get("permissions", [])
        dangerous = [p for p in perms if p.get("dangerous")]
        if dangerous:
            findings.append({
                "severity": "medium",
                "title": "Dangerous Permissions",
                "description": f"{len(dangerous)} dangerous permissions requested",
                "items": [p["name"] for p in dangerous]
            })

        manifest_raw = manifest.get("raw", "")
        if "debuggable" in manifest_raw and 'debuggable="true"' in manifest_raw:
            findings.append({
                "severity": "high",
                "title": "Debuggable App",
                "description": "App is debuggable in production"
            })

        if "allowBackup" in manifest_raw and 'allowBackup="true"' in manifest_raw:
            findings.append({
                "severity": "medium",
                "title": "Backup Allowed",
                "description": "Device backup includes app data"
            })

        if "http://" in manifest_raw:
            findings.append({
                "severity": "info",
                "title": "Cleartext Traffic",
                "description": "HTTP (unencrypted) URLs detected"
            })

        return {"findings": findings, "count": len(findings)}

    def analyze(self) -> dict:
        start = time.time()
        result = {
            "type": "apk",
            "file": self.apk_path.name,
            "size": human_size(self.apk_path.stat().st_size),
            "hash": file_hash(self.apk_path),
            "analyzed": datetime.now().isoformat(),
        }
        result["extraction"] = self.extract()
        result["manifest"]   = self.parse_manifest()
        result["dex"]        = self.analyze_dex()
        result["native"]     = self.analyze_native()
        result["resources"]  = self.analyze_resources()
        result["security"]   = self.security_checks(result["manifest"])
        result["analysis_time"] = f"{time.time()-start:.1f}s"

        report_path = self.project_dir / "report.json"
        report_path.write_text(json.dumps(result, indent=2, default=str))
        log.info(f"APK analysis done in {result['analysis_time']}")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# iOS IPA Analysis
# ══════════════════════════════════════════════════════════════════════════════

class IPAAnalyzer:
    """Analyzes iOS IPA files."""

    def __init__(self, ipa_path: Path, project_dir: Path):
        self.ipa_path = ipa_path
        self.project_dir = project_dir
        self.extracted_dir = project_dir / "extracted"
        self.report = {}

    def extract(self) -> dict:
        log.info(f"Extracting IPA: {self.ipa_path}")
        self.extracted_dir.mkdir(parents=True, exist_ok=True)
        file_list = []

        try:
            with zipfile.ZipFile(self.ipa_path, "r") as zf:
                for info in zf.infolist():
                    safe_name = info.filename.replace("..", "__").lstrip("/")
                    dest = self.extracted_dir / safe_name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if not info.is_dir():
                        try:
                            data = zf.read(info.filename)
                            dest.write_bytes(data)
                            file_list.append({
                                "path": safe_name,
                                "size": info.file_size,
                            })
                        except Exception as e:
                            log.warning(f"IPA extract error: {e}")
        except zipfile.BadZipFile as e:
            return {"error": f"Invalid IPA: {e}"}

        log.info(f"Extracted {len(file_list)} files from IPA")
        return {"files": file_list, "count": len(file_list)}

    def parse_info_plist(self) -> dict:
        """Parse Info.plist from the .app bundle."""
        app_dirs = list(self.extracted_dir.glob("**/Payload/*.app"))
        if not app_dirs:
            return {"error": "No .app bundle found"}

        app_dir = app_dirs[0]
        plist_path = app_dir / "Info.plist"
        if not plist_path.exists():
            return {"error": "Info.plist not found"}

        try:
            plist_data = plistlib.loads(plist_path.read_bytes())
            return {
                "bundle_id": plist_data.get("CFBundleIdentifier", ""),
                "bundle_name": plist_data.get("CFBundleName", ""),
                "version": plist_data.get("CFBundleShortVersionString", ""),
                "build": plist_data.get("CFBundleVersion", ""),
                "min_os": plist_data.get("MinimumOSVersion", ""),
                "url_schemes": plist_data.get("CFBundleURLTypes", []),
                "ats": plist_data.get("NSAppTransportSecurity", {}),
                "privacy_keys": {k: v for k, v in plist_data.items() if k.startswith("NSPrivacy")},
            }
        except Exception as e:
            log.warning(f"Plist parse error: {e}")
            return {"error": str(e)}

    def parse_entitlements(self) -> dict:
        """Parse entitlements from embedded.mobileprovision or entitlements file."""
        ent_paths = list(self.extracted_dir.glob("**/embedded.entitlements"))
        if not ent_paths:
            ent_paths = list(self.extracted_dir.glob("**/entitlements.plist"))

        if not ent_paths:
            return {}

        try:
            ent_data = plistlib.loads(ent_paths[0].read_bytes())
            return {"entitlements": list(ent_data.keys())}
        except Exception:
            return {}

    def analyze_macho(self) -> dict:
        """Analyze Mach-O binary for architectures, linked frameworks, strings."""
        macho_files = list(self.extracted_dir.glob("**/Payload/*.app/*"))
        result = {"architectures": [], "frameworks": [], "strings_sample": []}

        for f in macho_files:
            if not f.is_file():
                continue
            try:
                data = f.read_bytes(512)
                if data[:4] == b"\xcf\xfa\xed\xfe" or data[:4] == b"\xfe\xed\xfa\xcf":
                    result["architectures"].append(f.name)
                    try:
                        strings = [s for s in f.read_bytes(256*1024).split(b"\x00") if 20 < len(s) < 200]
                        result["strings_sample"].extend([str(s, errors="ignore") for s in strings[:50]])
                    except:
                        pass
            except Exception:
                pass

        result["strings_sample"] = list(set(result["strings_sample"]))[:50]
        return result

    def analyze_resources(self) -> dict:
        """Find plist, sqlite, assets, certs."""
        result = {"plist_files": [], "databases": [], "certs": []}
        for f in self.extracted_dir.rglob("*"):
            if not f.is_file():
                continue
            name = f.name.lower()
            if name.endswith(".plist"):
                result["plist_files"].append(str(f.relative_to(self.extracted_dir)))
            elif name.endswith(".db") or name.endswith(".sqlite"):
                result["databases"].append(str(f.relative_to(self.extracted_dir)))
            elif name.endswith(".cer") or name.endswith(".pem"):
                result["certs"].append(str(f.relative_to(self.extracted_dir)))
        return result

    def security_checks(self, plist: dict, macho: dict) -> dict:
        """Check for security issues."""
        findings = []

        ats = plist.get("ats", {})
        if ats.get("NSAllowsArbitraryLoads"):
            findings.append({
                "severity": "high",
                "title": "ATS Disabled",
                "description": "App Transport Security disabled - allows all HTTP"
            })

        if ats.get("NSAllowsArbitraryLoadsInWebContent"):
            findings.append({
                "severity": "medium",
                "title": "Web Content HTTP Allowed",
                "description": "UIWebView/WKWebView can load HTTP content"
            })

        return {"findings": findings, "count": len(findings)}

    def analyze(self) -> dict:
        start = time.time()
        result = {
            "type": "ipa",
            "file": self.ipa_path.name,
            "size": human_size(self.ipa_path.stat().st_size),
            "hash": file_hash(self.ipa_path),
            "analyzed": datetime.now().isoformat(),
        }

        result["extraction"]   = self.extract()
        result["info_plist"]   = self.parse_info_plist()
        result["entitlements"] = self.parse_entitlements()
        result["macho"]        = self.analyze_macho()
        result["resources"]    = self.analyze_resources()
        result["security"]     = self.security_checks(result["info_plist"], result["macho"])
        result["analysis_time"] = f"{time.time()-start:.1f}s"

        report_path = self.project_dir / "report.json"
        report_path.write_text(json.dumps(result, indent=2, default=str))
        log.info(f"IPA analysis done in {result['analysis_time']}")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# File Tree Builder
# ══════════════════════════════════════════════════════════════════════════════

def build_file_tree(root: Path, rel_root: Path = None, max_files=2000) -> list:
    if rel_root is None: rel_root = root
    tree = []
    count = 0

    def walk(p: Path, depth: int):
        nonlocal count
        if count > max_files: return
        try:
            entries = sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
        except PermissionError:
            return
        for entry in entries:
            if count > max_files: break
            try:
                rel = str(entry.relative_to(rel_root)).replace("\\", "/")  # FIXED: normalize path separators
                if entry.is_dir():
                    tree.append({"type": "dir", "path": rel, "name": entry.name, "depth": depth})
                    walk(entry, depth + 1)
                else:
                    size = entry.stat().st_size
                    tree.append({
                        "type": "file",
                        "path": rel,
                        "name": entry.name,
                        "size": human_size(size),
                        "size_bytes": size,
                        "depth": depth,
                        "ext": entry.suffix.lower(),
                    })
                    count += 1
            except Exception:
                pass

    walk(root, 0)
    return tree


# ══════════════════════════════════════════════════════════════════════════════
# Flask Routes
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/projects")
def list_projects():
    projects = []
    for p in sorted(PROJECTS.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_dir():
            report = p / "report.json"
            info = {"id": p.name, "name": p.name, "path": str(p), "has_report": report.exists()}
            if report.exists():
                try:
                    r = json.loads(report.read_text())
                    info["type"] = r.get("type", "")
                    info["file"] = r.get("file", "")
                    info["size"] = r.get("size", "")
                    pkg = r.get("manifest", {}).get("package") or r.get("info_plist", {}).get("bundle_id", "")
                    info["package"] = pkg
                except Exception:
                    pass
            projects.append(info)
    return jsonify(projects)

@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    fname = secure_filename(f.filename)
    ext = Path(fname).suffix.lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"error": f"Unsupported file type: {ext}. Only .apk and .ipa are supported."}), 400

    # Save upload
    up_path = UPLOADS / fname
    f.save(str(up_path))
    log.info(f"Uploaded: {fname}")

    # Analyze
    proj_name = f"{Path(fname).stem}_{datetime.now():%Y%m%d_%H%M%S}"
    proj_dir = PROJECTS / proj_name
    proj_dir.mkdir(parents=True, exist_ok=True)

    (proj_dir / "original").mkdir(exist_ok=True)
    shutil.copy(str(up_path), str(proj_dir / "original" / fname))

    try:
        if ext == ".apk":
            analyzer = APKAnalyzer(up_path, proj_dir)
            result = analyzer.analyze()
        else:
            analyzer = IPAAnalyzer(up_path, proj_dir)
            result = analyzer.analyze()
        log.info(f"Analysis complete: {proj_name}")
        return jsonify({"project_id": proj_name, "result": result})
    except Exception as e:
        log.error(f"Analysis failed: {e}")
        shutil.rmtree(str(proj_dir))
        return jsonify({"error": f"Analysis failed: {e}"}), 500

@app.route("/api/project/<proj_id>")
def get_project(proj_id):
    proj_dir = PROJECTS / secure_filename(proj_id)
    report = proj_dir / "report.json"
    if not report.exists():
        return jsonify({"error": "Project not found"}), 404
    return jsonify(json.loads(report.read_text()))

@app.route("/api/project/<proj_id>/tree")
def get_file_tree(proj_id):
    proj_dir = PROJECTS / secure_filename(proj_id)
    ext_dir  = proj_dir / "extracted"
    if not ext_dir.exists():
        return jsonify([])
    tree = build_file_tree(ext_dir, ext_dir)
    return jsonify(tree)

@app.route("/api/project/<proj_id>/file")
def read_file(proj_id):
    proj_dir = PROJECTS / secure_filename(proj_id)
    rel_path = request.args.get("path", "")
    if not rel_path:
        return jsonify({"error": "No path provided"}), 400

    # FIXED: Normalize path separators (handle both / and \)
    rel_path = rel_path.replace("\\", "/")
    
    # Security: prevent directory traversal
    full_path = (proj_dir / "extracted" / rel_path).resolve()
    allowed   = (proj_dir / "extracted").resolve()
    
    log.debug(f"File request: proj={proj_id}, rel_path={rel_path}, full_path={full_path}, allowed={allowed}")
    
    if not str(full_path).startswith(str(allowed)):
        log.warning(f"Access denied: {full_path} not under {allowed}")
        return jsonify({"error": "Access denied"}), 403

    if not full_path.exists():
        log.warning(f"File not found: {full_path}")
        # List available files for debugging
        try:
            available = list((proj_dir / "extracted").rglob("*"))[:10]
            available_paths = [str(p.relative_to(proj_dir / "extracted")) for p in available if p.is_file()]
            return jsonify({
                "error": f"File not found: {rel_path}",
                "requested_path": str(full_path),
                "available_sample": available_paths
            }), 404
        except:
            return jsonify({"error": "File not found"}), 404

    size = full_path.stat().st_size
    if is_text_file(full_path) or size < 1024*1024:
        content = safe_read(full_path)
        return jsonify({"content": content, "size": human_size(size), "type": "text"})
    else:
        return jsonify({"content": f"[Binary file - {human_size(size)}]", "size": human_size(size), "type": "binary"})

@app.route("/api/project/<proj_id>/search")
def search_project(proj_id):
    proj_dir = PROJECTS / secure_filename(proj_id)
    ext_dir  = proj_dir / "extracted"
    query    = request.args.get("q", "").strip()
    if not query or len(query) < 2:
        return jsonify({"results": []})

    results = []
    pattern = re.compile(re.escape(query), re.IGNORECASE)

    for f in ext_dir.rglob("*"):
        if not f.is_file(): continue
        if f.stat().st_size > 5*1024*1024: continue
        if not is_text_file(f): continue
        try:
            text = f.read_text(errors="replace")
            matches = []
            for i, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    matches.append({"line": i, "text": line.strip()[:200]})
                if len(matches) >= 5: break
            if matches:
                results.append({
                    "file": str(f.relative_to(ext_dir)).replace("\\", "/"),
                    "matches": matches,
                })
            if len(results) >= 50: break
        except Exception:
            pass

    return jsonify({"results": results, "query": query})

@app.route("/api/project/<proj_id>/export")
def export_report(proj_id):
    proj_dir = PROJECTS / secure_filename(proj_id)
    report   = proj_dir / "report.json"
    if not report.exists():
        return jsonify({"error": "No report"}), 404

    fmt = request.args.get("format", "json")
    if fmt == "json":
        return send_file(str(report), as_attachment=True, download_name=f"{proj_id}_report.json")
    elif fmt == "html":
        html = generate_html_report(json.loads(report.read_text()), proj_id)
        rpath = REPORTS / f"{proj_id}_report.html"
        rpath.write_text(html)
        return send_file(str(rpath), as_attachment=True, download_name=f"{proj_id}_report.html")
    return jsonify({"error": "Unknown format"}), 400

@app.route("/api/project/<proj_id>/delete", methods=["DELETE"])
def delete_project(proj_id):
    proj_dir = PROJECTS / secure_filename(proj_id)
    if proj_dir.exists():
        shutil.rmtree(str(proj_dir))
        log.info(f"Deleted project: {proj_id}")
    return jsonify({"ok": True})


def generate_html_report(data: dict, proj_id: str) -> str:
    """Generate a self-contained HTML report."""
    app_type = data.get("type", "unknown").upper()
    pkg = (data.get("manifest", {}).get("package") or
           data.get("info_plist", {}).get("bundle_id", "Unknown"))
    findings = (data.get("security", {}).get("findings", []))
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    info_count = sum(1 for f in findings if f["severity"] == "info")

    findings_html = ""
    for f in findings:
        color = {"high": "#ef4444", "medium": "#f97316", "info": "#3b82f6"}.get(f["severity"], "#888")
        findings_html += f"""
        <div style="margin-bottom:12px;padding:12px;background:#1a1a2e;border-left:3px solid {color};border-radius:4px">
            <div style="font-weight:600;color:#e2e8f0">{f['title']}</div>
            <div style="font-size:12px;color:#a0aec0;margin-top:4px">{f.get('description', '')}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{proj_id} - Security Report</title>
    <style>
        body {{ font-family: monospace; background: #0f0f1e; color: #e2e8f0; padding: 40px; line-height: 1.6; }}
        .header {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #a78bfa; margin-bottom: 8px; }}
        .meta {{ color: #64748b; font-size: 12px; margin-bottom: 24px; }}
        .section {{ max-width: 900px; margin: 24px auto; }}
        .section h2 {{ color: #a78bfa; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; border-bottom: 1px solid #2a2a45; padding-bottom: 8px; }}
        .score {{ font-size: 32px; font-weight: 700; color: #a78bfa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📱 {app_type} Security Analysis Report</h1>
        <div class="meta">
            <div>Package: <b>{pkg}</b></div>
            <div>Generated: {datetime.now().isoformat()}</div>
        </div>
    </div>

    <div class="section">
        <h2>Findings</h2>
        <div style="margin-bottom:16px">
            <span style="margin-right:24px">High: <b style="color:#ef4444">{high}</b></span>
            <span style="margin-right:24px">Medium: <b style="color:#f97316">{medium}</b></span>
            <span>Info: <b style="color:#3b82f6">{info_count}</b></span>
        </div>
        {findings_html}
    </div>

    <div class="section">
        <h2>Raw Data</h2>
        <pre style="background:#1a1a2e;padding:12px;border-radius:4px;overflow-x:auto;font-size:11px">{json.dumps(data, indent=2, default=str)[:5000]}</pre>
    </div>
</body>
</html>"""
    return html


# ══════════════════════════════════════════════════════════════════════════════
# HTML Template
# ══════════════════════════════════════════════════════════════════════════════

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mobile App Analyzer</title>
  <style>
:root {
  --bg: #0f0f1e;
  --surface: #12121f;
  --surface2: #1a1a2e;
  --surface3: #222236;
  --border: #2a2a45;
  --accent: #7c3aed;
  --accent-light: #a78bfa;
  --accent-glow: rgba(124,58,237,0.3);
  --text: #e2e8f0;
  --text-muted: #64748b;
  --text-dim: #475569;
  --red: #ef4444;
  --orange: #f97316;
  --green: #22c55e;
  --blue: #3b82f6;
  --yellow: #eab308;
  --sidebar-w: 280px;
  --panel-w: 340px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; display: flex; flex-direction: column; font-size: 13px; }

/* ── Top Bar ── */
.topbar { display: flex; align-items: center; gap: 12px; padding: 0 16px; height: 48px; background: var(--surface); border-bottom: 1px solid var(--border); flex-shrink: 0; z-index: 100; }
.logo { display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 700; color: var(--accent-light); letter-spacing: -0.3px; }
.logo svg { opacity: 0.9; }
.topbar-sep { width: 1px; height: 24px; background: var(--border); }
.topbar-btn { display: flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); cursor: pointer; font-size: 12px; font-family: inherit; transition: all 0.15s; }
.topbar-btn:hover { border-color: var(--accent); color: var(--accent-light); background: var(--accent-glow); }
.topbar-btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.topbar-btn.primary:hover { background: #6d28d9; }
#search-bar { flex: 1; max-width: 400px; display: flex; align-items: center; gap: 8px; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 0 12px; }
#search-bar input { flex: 1; background: none; border: none; outline: none; color: var(--text); font-family: inherit; font-size: 12px; padding: 7px 0; }
#search-bar input::placeholder { color: var(--text-dim); }
.spacer { flex: 1; }

/* ── Main Layout ── */
.main { display: flex; flex: 1; overflow: hidden; }

/* ── Left Sidebar ── */
.sidebar { width: var(--sidebar-w); background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; overflow: hidden; flex-shrink: 0; }
.sidebar-header { padding: 12px 16px; font-size: 10px; letter-spacing: 1.5px; color: var(--text-muted); text-transform: uppercase; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
.projects-list { overflow-y: auto; flex: 1; }
.proj-item { padding: 10px 16px; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.1s; }
.proj-item:hover { background: var(--surface2); }
.proj-item.active { background: var(--surface3); border-left: 3px solid var(--accent); }
.proj-name { font-weight: 600; font-size: 12px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.proj-meta { color: var(--text-muted); font-size: 11px; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.proj-badge { display: inline-block; font-size: 9px; padding: 1px 6px; border-radius: 3px; font-weight: 700; letter-spacing: 0.5px; margin-right: 4px; }
.badge-apk { background: #164e26; color: var(--green); }
.badge-ipa { background: #1a1a4e; color: #818cf8; }

/* ── Center Content ── */
.content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.tab-bar { display: flex; gap: 0; padding: 0 16px; background: var(--surface); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.tab { padding: 10px 16px; font-size: 12px; cursor: pointer; border-bottom: 2px solid transparent; color: var(--text-muted); transition: all 0.15s; white-space: nowrap; }
.tab:hover { color: var(--text); }
.tab.active { color: var(--accent-light); border-bottom-color: var(--accent); }
.panels { flex: 1; overflow: hidden; position: relative; }
.panel { position: absolute; inset: 0; overflow-y: auto; display: none; padding: 20px; }
.panel.active { display: block; }

/* ── Welcome Screen ── */
.welcome { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; gap: 24px; }
.welcome-icon { width: 80px; height: 80px; background: var(--accent-glow); border: 2px solid var(--accent); border-radius: 20px; display: flex; align-items: center; justify-content: center; font-size: 36px; }
.welcome h2 { color: var(--accent-light); font-size: 22px; }
.welcome p { color: var(--text-muted); text-align: center; max-width: 400px; line-height: 1.6; }
.drop-zone { border: 2px dashed var(--border); border-radius: 16px; padding: 40px 60px; text-align: center; cursor: pointer; transition: all 0.2s; }
.drop-zone:hover, .drop-zone.dragover { border-color: var(--accent); background: var(--accent-glow); }
.drop-zone h3 { color: var(--text); margin-bottom: 8px; }
.drop-zone p { color: var(--text-muted); font-size: 12px; }
#file-input { display: none; }

/* ── Overview Panel ── */
.overview-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.card { background: var(--surface2); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.card h3 { color: var(--accent-light); font-size: 11px; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 12px; display: flex; align-items: center; gap: 6px; }
.meta-row { display: flex; gap: 8px; margin-bottom: 6px; align-items: flex-start; }
.meta-key { color: var(--text-muted); min-width: 120px; font-size: 11px; flex-shrink: 0; }
.meta-val { color: var(--text); font-size: 11px; word-break: break-all; }
.meta-val.mono { font-family: inherit; font-size: 10px; color: var(--text-dim); }
.perm-list { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
.perm-tag { font-size: 10px; padding: 2px 8px; border-radius: 4px; }
.perm-dangerous { background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }
.perm-normal { background: rgba(100,116,139,0.15); color: var(--text-muted); border: 1px solid var(--border); }

/* ── Security Panel ── */
.finding { display: flex; gap: 12px; padding: 12px; background: var(--surface2); border-radius: 8px; margin-bottom: 8px; border-left: 3px solid; }
.finding.high { border-color: var(--red); }
.finding.medium { border-color: var(--orange); }
.finding.info { border-color: var(--blue); }
.finding.low { border-color: var(--green); }
.finding-badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; letter-spacing: 0.5px; align-self: flex-start; flex-shrink: 0; }
.finding.high .finding-badge { background: rgba(239,68,68,0.2); color: var(--red); }
.finding.medium .finding-badge { background: rgba(249,115,22,0.2); color: var(--orange); }
.finding.info .finding-badge { background: rgba(59,130,246,0.2); color: var(--blue); }
.finding-title { font-size: 12px; font-weight: 600; color: var(--text); }
.finding-detail { font-size: 11px; color: var(--text-muted); margin-top: 4px; word-break: break-all; }
.finding-cat { font-size: 10px; color: var(--text-dim); margin-top: 2px; }
.score-ring { position: relative; display: flex; align-items: center; justify-content: center; width: 100px; height: 100px; }
.score-label { position: absolute; font-size: 24px; font-weight: 700; }
.summary-bar { display: flex; gap: 12px; margin-bottom: 20px; }

/* ── File Viewer ── */
.code-viewer { background: var(--surface2); border-radius: 8px; overflow: hidden; display: flex; flex-direction: column; }
.code-header { padding: 12px 16px; background: var(--surface3); border-bottom: 1px solid var(--border); font-size: 11px; color: var(--text-muted); display: flex; align-items: center; gap: 8px; }
.code-content { flex: 1; overflow-y: auto; padding: 12px 16px; }
.code { white-space: pre-wrap; word-break: break-word; font-size: 11px; line-height: 1.5; color: var(--text); }

/* ── Strings Table ── */
.section-title { font-size: 12px; font-weight: 700; color: var(--text); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.string-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.string-table th { padding: 8px 12px; background: var(--surface2); color: var(--text-muted); text-align: left; border-bottom: 1px solid var(--border); font-weight: 600; }
.string-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
.string-table tr:hover { background: var(--surface2); }
.tag { display: inline-block; font-size: 9px; font-weight: 700; padding: 2px 6px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.5px; }
.tag-url { background: rgba(59,130,246,0.15); color: var(--blue); }
.tag-key { background: rgba(239,68,68,0.15); color: var(--red); }
.tag-host { background: rgba(249,115,22,0.15); color: var(--orange); }
.tag-path { background: rgba(34,197,94,0.15); color: var(--green); }
.tag-crypto { background: rgba(168,85,247,0.15); color: #d8b4fe; }

/* ── Search Results ── */
.search-result { margin-bottom: 16px; padding: 12px; background: var(--surface2); border-radius: 8px; }
.search-file { font-weight: 600; color: var(--accent-light); margin-bottom: 8px; font-size: 12px; }
.search-match { display: flex; gap: 8px; font-size: 11px; margin-left: 12px; margin-bottom: 4px; }
.line-num { color: var(--text-dim); min-width: 40px; }
.match-text { color: var(--text-muted); flex: 1; }
.search-hl { background: rgba(234,179,8,0.3); color: var(--yellow); font-weight: 600; }

/* ── Right Panel ── */
.right-panel { width: var(--panel-w); background: var(--surface); border-left: 1px solid var(--border); display: none; flex-direction: column; flex-shrink: 0; overflow: hidden; }
.right-header { padding: 12px 16px; font-size: 10px; letter-spacing: 1.5px; color: var(--text-muted); text-transform: uppercase; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.right-content { flex: 1; overflow-y: auto; padding: 12px 16px; }
.info-section { margin-bottom: 16px; }
.info-section h4 { font-size: 10px; letter-spacing: 1px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; }
.info-pill { display: flex; gap: 8px; margin-bottom: 6px; font-size: 11px; }
.info-pill .k { color: var(--text-muted); min-width: 80px; }
.info-pill .v { color: var(--text); word-break: break-all; }

/* ── Tree ── */
.tree-node { padding: 4px 12px; cursor: pointer; transition: all 0.1s; font-size: 11px; display: flex; align-items: center; gap: 6px; }
.tree-node:hover { background: var(--surface2); }
.tree-node.selected { background: var(--accent-glow); color: var(--accent-light); }
.tree-node.dir { color: var(--text); }
.tree-node.file { color: var(--text-muted); }

/* ── Utils ── */
.empty-state { text-align: center; color: var(--text-muted); padding: 40px 20px; }
.loading-overlay { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px; }
.spinner { width: 24px; height: 24px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.loading-text { margin-top: 12px; font-size: 12px; color: var(--text-muted); }
.toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 16px; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; font-size: 12px; z-index: 1000; animation: slideIn 0.2s ease-out; }
@keyframes slideIn { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
  </style>
</head>
<body>

<!-- Top Bar -->
<div class="topbar">
  <div class="logo">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12c0 4.41 3.04 8.14 7.13 9.28-.04-.4-.07-.82-.07-1.28 0-1.43.27-2.8.76-4.08-3.18-1.05-5.49-4.05-5.49-7.57C4.34 5.78 7.57 2 11.5 2h1v4.68c-.78-.28-1.62-.43-2.5-.43-3.87 0-7 3.13-7 7 0 1.93.78 3.68 2.05 4.95-1.42-1.42-2.3-3.38-2.3-5.58 0-4.42 3.58-8 8-8s8 3.58 8 8v4.5h2.5c.55 0 1-.45 1-1V12C22 6.48 17.52 2 12 2z"/>
    </svg>
    Mobile App Analyzer
  </div>
  <div class="topbar-sep"></div>
  <button class="topbar-btn primary" onclick="document.getElementById('file-input').click()">↑ Open APK / IPA</button>
  <input type="file" id="file-input" accept=".apk,.ipa" onchange="handleFileSelect(this)">
  <div id="search-bar">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input type="text" id="search-input" placeholder="Search in project… (Ctrl+F)" onkeydown="handleSearchKey(event)">
  </div>
  <div class="spacer"></div>
  <button class="topbar-btn" onclick="exportReport('json')" id="btn-export-json" style="display:none">
    ↓ JSON
  </button>
  <button class="topbar-btn" onclick="exportReport('html')" id="btn-export-html" style="display:none">
    ↓ HTML Report
  </button>
  <button class="topbar-btn" onclick="deleteProject()" id="btn-delete" style="display:none" style="color:var(--red)">
    🗑
  </button>
</div>

<!-- Main -->
<div class="main">

  <!-- Sidebar -->
  <div class="sidebar">
    <div class="sidebar-header">
      Projects
      <span id="proj-count" style="color:var(--text-dim)">0</span>
    </div>
    <div class="projects-list" id="projects-list">
      <div class="empty-state">No projects yet.<br>Open an APK or IPA to start.</div>
    </div>
  </div>

  <!-- Center Content -->
  <div class="content">
    <div class="tab-bar" id="tab-bar" style="display:none">
      <div class="tab active" onclick="switchTab('overview')">Overview</div>
      <div class="tab" onclick="switchTab('security')">Security</div>
      <div class="tab" onclick="switchTab('files')">Files</div>
      <div class="tab" onclick="switchTab('strings')">Strings</div>
      <div class="tab" onclick="switchTab('search-results')">Search</div>
    </div>

    <div class="panels">
      <!-- Welcome -->
      <div id="panel-welcome" class="panel active">
        <div class="welcome">
          <div class="welcome-icon">📱</div>
          <h2>Mobile App Analyzer</h2>
          <p>Drop an Android APK or iOS IPA file to begin deep analysis. Extracts metadata, permissions, entitlements, binaries, certificates, databases, and security findings.</p>
          <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
            <h3>Drop file here or click to browse</h3>
            <p>Supports .apk (Android) and .ipa (iOS) · Max 500 MB</p>
          </div>
        </div>
      </div>

      <!-- Overview -->
      <div id="panel-overview" class="panel">
        <div id="overview-content"></div>
      </div>

      <!-- Security -->
      <div id="panel-security" class="panel">
        <div id="security-content"></div>
      </div>

      <!-- Files -->
      <div id="panel-files" class="panel" style="padding:0">
        <div id="files-split" style="display:flex;height:100%;overflow:hidden">
          <div id="file-tree-panel" style="width:280px;border-right:1px solid var(--border);overflow-y:auto;padding:8px;flex-shrink:0"></div>
          <div id="file-viewer" style="flex:1;overflow:auto;padding:16px">
            <div class="empty-state" style="margin-top:80px">Select a file to view its contents</div>
          </div>
        </div>
      </div>

      <!-- Strings -->
      <div id="panel-strings" class="panel">
        <div id="strings-content"></div>
      </div>

      <!-- Search Results -->
      <div id="panel-search-results" class="panel">
        <div id="search-results-content">
          <div class="empty-state">Use the search bar above (Ctrl+F) to search within the project.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Right Panel -->
  <div class="right-panel" id="right-panel" style="display:none">
    <div class="right-header">File Info</div>
    <div class="right-content" id="right-content"></div>
  </div>
</div>

<script>
// ── State ────────────────────────────────────────────────────────────────────
let state = { currentProject: null, report: null, activeTab: 'overview', pollTimer: null };

// ── Init ─────────────────────────────────────────────────────────────────────
window.addEventListener('load', () => {
  loadProjects();
  setupDragDrop();
  setupSearch();
});

// ── File Upload ───────────────────────────────────────────────────────────────
async function handleFileSelect(input) {
  const f = input.files[0];
  if (!f) return;
  input.value = '';

  showToast(`Uploading ${f.name}…`, 'info');
  const fd = new FormData();
  fd.append('file', f);

  try {
    const res = await fetch('/api/upload', {method: 'POST', body: fd});
    const data = await res.json();
    if (!res.ok) { showToast(data.error, 'error'); return; }

    state.currentProject = data.project_id;
    state.report = data.result;
    document.getElementById('tab-bar').style.display = 'flex';
    document.getElementById('btn-export-json').style.display = 'block';
    document.getElementById('btn-export-html').style.display = 'block';
    document.getElementById('btn-delete').style.display = 'block';
    showPanel('overview');
    switchTab('overview');
    renderOverview();
    loadProjects();
    showToast('Analysis complete!', 'success');
  } catch (e) {
    showToast(`Upload failed: ${e.message}`, 'error');
  }
}

function setupDragDrop() {
  const zone = document.getElementById('drop-zone');
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => {
    document.addEventListener(evt, e => e.preventDefault());
    zone.addEventListener(evt, e => e.preventDefault());
  });
  ['dragenter', 'dragover'].forEach(evt => {
    zone.addEventListener(evt, () => zone.classList.add('dragover'));
  });
  ['dragleave', 'drop'].forEach(evt => {
    zone.addEventListener(evt, () => zone.classList.remove('dragover'));
  });
  zone.addEventListener('drop', e => {
    const f = e.dataTransfer.files[0];
    if (f) {
      const input = document.getElementById('file-input');
      input.files = e.dataTransfer.files;
      handleFileSelect(input);
    }
  });
}

// ── Project Loading ────────────────────────────────────────────────────────────
async function loadProjects() {
  const res = await fetch('/api/projects');
  const projects = await res.json();
  const list = document.getElementById('projects-list');
  document.getElementById('proj-count').textContent = projects.length;

  if (!projects.length) {
    list.innerHTML = '<div class="empty-state">No projects yet.<br>Open an APK or IPA to start.</div>';
    return;
  }

  list.innerHTML = projects.map(p => `
    <div class="proj-item ${p.id === state.currentProject ? 'active' : ''}" onclick="selectProject('${esc(p.id)}')">
      <div class="proj-name">
        <span class="proj-badge badge-${p.type}">${p.type}</span>
        ${esc(p.name)}
      </div>
      <div class="proj-meta">${esc(p.package)}</div>
    </div>`).join('');
}

async function selectProject(proj_id) {
  state.currentProject = proj_id;
  const res = await fetch(`/api/project/${proj_id}`);
  state.report = await res.json();
  document.getElementById('tab-bar').style.display = 'flex';
  document.getElementById('btn-export-json').style.display = 'block';
  document.getElementById('btn-export-html').style.display = 'block';
  document.getElementById('btn-delete').style.display = 'block';
  showPanel('overview');
  switchTab('overview');
  renderOverview();
  loadProjects();
}

// ── Tab Switching ─────────────────────────────────────────────────────────────
async function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById(`panel-${tab}`).classList.add('active');

  if (tab === 'files') renderFileTree();
  if (tab === 'strings') renderStrings();
  if (tab === 'security') renderSecurity();
}

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview() {
  if (!state.report) return;
  const r = state.report;
  const type = r.type.toUpperCase();
  const container = document.getElementById('overview-content');

  let html = `<div class="overview-grid">
    <div class="card">
      <h3>📦 Info</h3>
      <div class="meta-row"><span class="meta-key">Type</span><span class="meta-val">${type}</span></div>
      <div class="meta-row"><span class="meta-key">File</span><span class="meta-val">${esc(r.file)}</span></div>
      <div class="meta-row"><span class="meta-key">Size</span><span class="meta-val">${esc(r.size)}</span></div>
      <div class="meta-row"><span class="meta-key">Analyzed</span><span class="meta-val">${esc((r.analyzed||'').split('T')[0])}</span></div>
    </div>`;

  if (r.type === 'apk' && r.manifest) {
    const m = r.manifest;
    html += `<div class="card">
      <h3>🤖 Manifest</h3>
      <div class="meta-row"><span class="meta-key">Package</span><span class="meta-val">${esc(m.package)}</span></div>
      <div class="meta-row"><span class="meta-key">Version</span><span class="meta-val">${esc(m.version_name)}</span></div>
      <div class="meta-row"><span class="meta-key">Min SDK</span><span class="meta-val">${esc(m.min_sdk)}</span></div>
      <div class="meta-row"><span class="meta-key">Permissions</span><span class="meta-val">${m.permissions ? m.permissions.length : 0}</span></div>
      ${m.permissions && m.permissions.length ? `<div class="perm-list">${m.permissions.slice(0, 5).map(p => `<span class="perm-tag ${p.dangerous?'perm-dangerous':'perm-normal'}">${p.name.split('.').pop()}</span>`).join('')}</div>` : ''}
    </div>`;
  } else if (r.type === 'ipa' && r.info_plist) {
    const i = r.info_plist;
    html += `<div class="card">
      <h3>🍎 Info.plist</h3>
      <div class="meta-row"><span class="meta-key">Bundle ID</span><span class="meta-val">${esc(i.bundle_id)}</span></div>
      <div class="meta-row"><span class="meta-key">Name</span><span class="meta-val">${esc(i.bundle_name)}</span></div>
      <div class="meta-row"><span class="meta-key">Version</span><span class="meta-val">${esc(i.version)}</span></div>
      <div class="meta-row"><span class="meta-key">Min OS</span><span class="meta-val">${esc(i.min_os)}</span></div>
    </div>`;
  }

  html += `</div>`;
  container.innerHTML = html;
}

// ── Security ──────────────────────────────────────────────────────────────────
function renderSecurity() {
  const r = state.report;
  if (!r) return;
  const findings = (r.security || {}).findings || [];
  const container = document.getElementById('security-content');

  if (!findings.length) {
    container.innerHTML = '<div class="empty-state">No security findings.</div>';
    return;
  }

  container.innerHTML = `<div style="margin-bottom:20px">
    <span style="margin-right:16px">🔴 High: ${findings.filter(f=>f.severity==='high').length}</span>
    <span style="margin-right:16px">🟠 Medium: ${findings.filter(f=>f.severity==='medium').length}</span>
    <span>🔵 Info: ${findings.filter(f=>f.severity==='info').length}</span>
  </div>` + findings.map(f => `
    <div class="finding ${f.severity}">
      <div class="finding-badge">${f.severity.toUpperCase()}</div>
      <div style="flex:1">
        <div class="finding-title">${esc(f.title)}</div>
        <div class="finding-detail">${esc(f.description)}</div>
      </div>
    </div>`).join('');
}

// ── Files ─────────────────────────────────────────────────────────────────────
async function renderFileTree() {
  const res = await fetch(`/api/project/${state.currentProject}/tree`);
  const tree = await res.json();
  const panel = document.getElementById('file-tree-panel');

  if (!tree.length) {
    panel.innerHTML = '<div class="empty-state">No files extracted</div>';
    return;
  }

  let html = '';
  let currentDepth = 0;

  for (const node of tree.slice(0, 2000)) {
    const indent = `margin-left:${node.depth * 12}px`;
    if (node.type === 'dir') {
      html += `<div class="tree-node dir" style="${indent}">📁 ${esc(node.name)}</div>`;
    } else {
      const path = node.path;
      html += `<div class="tree-node file" style="${indent}" onclick="loadFile(event, '${esc(path)}')">📄 ${esc(node.name)} <span style="font-size:10px;color:var(--text-dim)">${node.size}</span></div>`;
    }
  }

  panel.innerHTML = html;
}

async function loadFile(event, path) {
  document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('selected'));
  event.currentTarget.classList.add('selected');

  const viewer = document.getElementById('file-viewer');
  viewer.innerHTML = '<div class="loading-overlay" style="position:relative;height:200px"><div class="spinner"></div><div class="loading-text">Loading…</div></div>';

  const res = await fetch(`/api/project/${state.currentProject}/file?path=${encodeURIComponent(path)}`);
  const data = await res.json();

  if (data.error) { 
    viewer.innerHTML = `<div class="empty-state">${esc(data.error)}</div>`; 
    if (data.available_sample) {
      viewer.innerHTML += `<br><br><small style="color:var(--text-dim)">Available files:<br>${data.available_sample.map(p => esc(p)).join('<br>')}</small>`;
    }
    return; 
  }

  const ext = path.split('.').pop().toLowerCase();
  const content = data.content || '';
  const highlighted = syntaxHighlight(content, ext);

  viewer.innerHTML = `
    <div class="code-viewer">
      <div class="code-header">
        <span>📄 ${esc(path.split('/').pop())}</span>
        <span style="color:var(--text-dim)">·</span>
        <span>${esc(data.size)}</span>
        <span style="color:var(--text-dim)">·</span>
        <span style="color:var(--text-dim)">${esc(path)}</span>
      </div>
      <div class="code-content"><pre class="code">${highlighted}</pre></div>
    </div>`;

  // Update right panel
  document.getElementById('right-panel').style.display = 'flex';
  document.getElementById('right-content').innerHTML = `
    <div class="info-section"><h4>File</h4>
      <div class="info-pill"><span class="k">Name</span><span class="v">${esc(path.split('/').pop())}</span></div>
      <div class="info-pill"><span class="k">Size</span><span class="v">${esc(data.size)}</span></div>
      <div class="info-pill"><span class="k">Type</span><span class="v">${esc(ext||'unknown')}</span></div>
    </div>
    <div class="info-section"><h4>Path</h4>
      <div style="font-size:10px;color:var(--text-muted);word-break:break-all;padding:8px">${esc(path)}</div>
    </div>`;
}

function syntaxHighlight(text, ext) {
  const safe = esc(text);
  if (['xml','html','plist'].includes(ext)) {
    return safe
      .replace(/(&lt;\/?[a-zA-Z][^&gt;]*&gt;)/g, '<span style="color:#81a1c1">$1</span>')
      .replace(/(&quot;[^&quot;]*&quot;)/g, '<span style="color:#a3be8c">$1</span>');
  }
  if (['java','kt','swift','m','h'].includes(ext)) {
    const kws = /\b(public|private|protected|class|interface|import|package|return|void|static|final|new|if|else|for|while|try|catch|throws|extends|implements|override|func|var|let|const|null|true|false|this|super)\b/g;
    return safe
      .replace(kws, '<span style="color:#81a1c1">$1</span>')
      .replace(/(\/\/[^\n]*)/g, '<span style="color:#616e88;font-style:italic">$1</span>')
      .replace(/(&quot;[^&quot;\n]*&quot;)/g, '<span style="color:#a3be8c">$1</span>');
  }
  return safe;
}

// ── Strings ───────────────────────────────────────────────────────────────────
function renderStrings() {
  const r = state.report;
  if (!r) return;
  const container = document.getElementById('strings-content');

  let rows = [];
  const addStrings = (arr, tag) => arr.forEach(s => rows.push({s, tag}));

  if (r.type === 'apk') {
    const interesting = (r.dex||{}).interesting_strings || {};
    addStrings(interesting.urls||[], 'url');
    addStrings(interesting.api_keys_patterns||[], 'key');
    addStrings(interesting.network_hosts||[], 'host');
    addStrings(interesting.file_paths||[], 'path');
    addStrings(interesting.crypto_mentions||[], 'crypto');
  } else {
    const strs = (r.macho||{}).strings_sample || [];
    strs.forEach(s => {
      let tag = 'host';
      if (s.startsWith('http')) tag = 'url';
      else if (/key|pass|token|secret/i.test(s)) tag = 'key';
      else if (/aes|rsa|sha|md5|crypto/i.test(s)) tag = 'crypto';
      rows.push({s, tag});
    });
  }

  if (!rows.length) { container.innerHTML = '<div class="empty-state">No interesting strings found.</div>'; return; }

  container.innerHTML = `
    <div class="section-title">Interesting Strings (${rows.length})</div>
    <table class="string-table">
      <thead><tr><th>Type</th><th>Value</th></tr></thead>
      <tbody>${rows.map(({s,tag})=>`
        <tr><td><span class="tag tag-${tag}">${tag.toUpperCase()}</span></td>
        <td>${esc(String(s).slice(0,300))}</td></tr>`).join('')}
      </tbody>
    </table>`;
}

// ── Search ────────────────────────────────────────────────────────────────────
function handleSearchKey(e) {
  if (e.key === 'Enter') performSearch();
}

async function performSearch() {
  const q = document.getElementById('search-input').value.trim();
  if (!q || !state.currentProject) return;

  switchTab('search-results');
  document.getElementById('search-results-content').innerHTML = '<div style="text-align:center;padding:40px"><div class="spinner"></div></div>';

  const res = await fetch(`/api/project/${state.currentProject}/search?q=${encodeURIComponent(q)}`);
  const data = await res.json();

  if (!data.results.length) {
    document.getElementById('search-results-content').innerHTML = `<div class="empty-state">No results for "<b>${esc(q)}</b>"</div>`;
    return;
  }

  const re = new RegExp(escapeRegex(q), 'gi');
  document.getElementById('search-results-content').innerHTML = `
    <div class="section-title">${data.results.length} file(s) matched "${esc(q)}"</div>
    ${data.results.map(r => `
      <div class="search-result">
        <div class="search-file">📄 ${esc(r.file)}</div>
        ${r.matches.map(m => `
          <div class="search-match">
            <span class="line-num">L${m.line}</span>
            <span class="match-text">${esc(m.text).replace(re, s=>`<span class="search-hl">${esc(s)}</span>`)}</span>
          </div>`).join('')}
      </div>`).join('')}`;
}

function setupSearch() {
  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'f') {
      e.preventDefault();
      document.getElementById('search-input').focus();
    }
  });
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportReport(fmt) {
  if (!state.currentProject) return;
  window.location = `/api/project/${state.currentProject}/export?format=${fmt}`;
}

async function deleteProject() {
  if (!state.currentProject) return;
  if (!confirm('Delete this project? This cannot be undone.')) return;
  await fetch(`/api/project/${state.currentProject}/delete`, {method:'DELETE'});
  state.currentProject = null;
  state.report = null;
  document.getElementById('tab-bar').style.display = 'none';
  document.getElementById('btn-export-json').style.display = 'none';
  document.getElementById('btn-export-html').style.display = 'none';
  document.getElementById('btn-delete').style.display = 'none';
  document.getElementById('right-panel').style.display = 'none';
  showPanel('welcome');
  loadProjects();
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }

function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  const p = document.getElementById(`panel-${name}`);
  if (p) p.classList.add('active');
}

function showToast(msg, type='info') {
  const t = document.createElement('div');
  t.className = 'toast';
  t.style.borderColor = type==='error'?'var(--red)':type==='success'?'var(--green)':'var(--border)';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 3000);
}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def open_browser(port: int):
    """Open the browser after a short delay."""
    time.sleep(1.2)
    url = f"http://127.0.0.1:{port}"
    log.info(f"Opening browser at {url}")
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    PORT = 7432
    log.info("=" * 60)
    log.info("Mobile App Analyzer starting…")
    log.info(f"Projects dir : {PROJECTS}")
    log.info(f"Logs dir     : {LOG_DIR}")
    log.info(f"URL          : http://127.0.0.1:{PORT}")
    log.info("=" * 60)

    threading.Thread(target=open_browser, args=(PORT,), daemon=True).start()
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
