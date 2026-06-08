## --- --- --- ---
# Q(uarantine)Helper.py v2
# author: <shift000> Markus Schätzle
# date  : 08-06-2026
#
# v2 changes:
#   - No graphical TUI selection, only numbers 0->x or enter for all
#   - No pre-analysis phase
#   - File type detection via extension, magic bytes, or content
#   - Content-based rating
#   - Filename from eml or fallback
#   - Executables → defused/ folder with _defused suffix
#   - Post-extraction overview with rating + delete/keep prompt

import os
import sys
import re
import json
import base64
import quopri
import hashlib
import mimetypes
import logging
import datetime
import shutil
import struct
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

try:
    import msvcrt
    _IS_WINDOWS = True
except ImportError:
    _IS_WINDOWS = False
    import tty
    import termios
    import select as _select

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False
    import zipfile

################################################################################
# ANSI / TUI STYLING
################################################################################

RESET     = "\033[0m"
BOLD      = "\033[1m"
DIM       = "\033[2m"

C_CYAN    = "\033[96m"
C_YELLOW  = "\033[93m"
C_GREEN   = "\033[92m"
C_RED     = "\033[91m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_WHITE   = "\033[97m"
C_GRAY    = "\033[90m"
C_ORANGE  = "\033[33m"

def clr(text, *codes):
    return "".join(codes) + str(text) + RESET

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def hr(char="─", width=60, color=C_GRAY):
    print(clr(char * width, color))

def banner():
    clear_screen()
    print()
    print(clr("      .-')     ('-. .-.   ('-.             _ (`-.    ('-.  _  .-')   ", C_CYAN, BOLD))
    print(clr("     (  OO)   ( OO )  / _(  OO)           ( (OO  ) _(  OO)( \( -O )  ", C_CYAN, BOLD))
    print(clr("    (_)---\_)  ,--. ,--.(,------.,--.     _.`     \(,------.,------.  ", C_CYAN, BOLD))
    print(clr("    '  .-.  '  |  | |  | |  .---'|  |.-')(__...--'' |  .---'|   /`. ' ", C_CYAN, BOLD))
    print(clr("   ,|  | |  |  |   .|  | |  |    |  | OO )|  /  | | |  |    |  /  | | ", C_CYAN, BOLD))
    print(clr("  (_|  | |  |  |       |(|  '--. |  |`-' ||  |_.' |(|  '--. |  |_.' | ", C_CYAN, BOLD))
    print(clr("    |  | |  |  |  .-.  | |  .--'(|  '---.'|  .___.' |  .--' |  .  '.' ", C_CYAN, BOLD))
    print(clr("    '  '-'  '-.|  | |  | |  `---.|      | |  |      |  `---'|  |\  \  ", C_CYAN, BOLD))
    print(clr("     `-----'--'`--' `--' `------'`------' `--'      `------'`--' '--' ", C_CYAN, BOLD))
    print()
    print(clr("       Quarantine Helper v2.0", C_YELLOW, BOLD))
    print(clr("              Simplified Extraction & Analysis", C_GRAY))
    print()
    hr()

def section(title):
    print()
    print(clr(f"  ▶  {title}", C_YELLOW, BOLD))
    hr("─", 60, C_GRAY)

def ok(msg):    print(clr(f"  [✓] {msg}", C_GREEN))
def warn(msg):  print(clr(f"  [!] {msg}", C_YELLOW))
def err(msg):   print(clr(f"  [✗] {msg}", C_RED))
def info(msg):  print(clr(f"  [i] {msg}", C_CYAN))
def dim(msg):   print(clr(f"      {msg}", C_GRAY))

def prompt(msg):
    return input(clr(f"\n  {msg} ", C_WHITE, BOLD))

def press_enter():
    input(clr("\n  Press Enter to continue...", C_GRAY))

################################################################################
# GLOBALS
################################################################################

DEFAULT_PASS = b"infected"
_logger = None

################################################################################
# LOGGER
################################################################################

def setup_logger(log_path: str):
    global _logger
    _logger = logging.getLogger("qhelper_v2")
    _logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s",
                            datefmt="%H:%M:%S")
    fh.setFormatter(fmt)
    _logger.handlers.clear()
    _logger.addHandler(fh)
    _logger.info("=== QHelper v2 session started ===")

def log(level: str, msg: str):
    if _logger:
        getattr(_logger, level, _logger.info)(msg)

################################################################################
# MAGIC BYTES DETECTION
################################################################################

# Magic bytes signatures for common file types
MAGIC_SIGNATURES = {
    b"%PDF":                          "pdf",
    b"\x89PNG\r\n\x1a\n":            "png",
    b"\xff\xd8\xff":                 "jpg",
    b"GIF87a":                        "gif",
    b"GIF89a":                        "gif",
    b"RIFF":                          "wav",  # will be refined
    b"\x00\x00\x01\x00":             "ico",
    b"\x00\x00\x02\x00":             "bmp",
    b"BM":                            "bmp",
    b"\x1f\x8b":                      "gz",
    b"PK\x03\x04":                    "zip",
    b"PK\x05\x06":                    "zip",
    b"PK\x07\x08":                    "zip",
    b"\x50\x4b\x03\x04":              "zip",
    b"\x7fELF":                       "elf",
    b"MZ":                            "exe",
    b"\x4d\x5a":                      "exe",
    b"\xca\xfe\xba\xbe":              "macho",
    b"\xfe\xed\xfa\xce":              "macho",
    b"\xfe\xed\xfa\xcf":              "macho",
    b"\xce\xfa\xed\xfe":              "macho",
    b"\xcf\xfa\xed\xfe":              "macho",
    b"SQLite format 3":              "sqlite",
    b"\x00\x00\x01\x00":             "woff",
    b"wOFF":                         "woff",
    b"wOF2":                         "woff2",
    b"\x1f\x9d":                      "tar_z",
    b"\x1f\xa0":                      "tar_z",
    b"Rar!":                          "rar",
    b"7z\xbc\xaf\x27\x1c":           "7z",
    b"\x00\x00\x00\x18\x66\x74\x79\x70": "mp4",
    b"\x00\x00\x00\x1c\x66\x74\x79\x70": "mp4",
    b"\x00\x00\x00\x20\x66\x74\x79\x70": "mp4",
    b"\x00\x00\x00\x1f\x66\x74\x79\x70": "mp4",
    # Office documents (OOXML - ZIP based)
    b"PK\x03\x04":                   "docx",  # same as zip, but will be refined by content
    # Rich Text Format
    b"{\\rtf":                        "rtf",
    # Java class files
    b"\xca\xfe\xba\xbe":             "class",
    # Windows shortcut / lnk
    b"\x4c\x00\x00\x00":             "lnk",  # needs more validation
    # HTML / text markers
    b"<!DOCTYPE":                    "html",
    b"<html":                        "html",
    b"<head":                        "html",
    b"<body":                        "html",
    b"<script":                      "html",
}

# Extended magic for RIFF (could be WAV, AVI, or other RIFF forms)
def _detect_riff_type(data: bytes) -> str:
    if len(data) >= 12:
        riff_type = data[8:12]
        if riff_type == b"WAVE":
            return "wav"
        elif riff_type == b"AVI ":
            return "avi"
        elif riff_type == b"WEBP":
            return "webp"
    return "riff"

def _detect_lnk(data: bytes) -> str:
    """Validate if this is likely a Windows Shortcut (.lnk) file."""
    if len(data) >= 4:
        if data[0] == 0x4C and data[1] == 0x00 and data[2] == 0x00 and data[3] == 0x00:
            return "lnk"
    return "bin"

def detect_by_magic(data: bytes) -> str:
    """Detect file type by magic bytes."""
    if not data:
        return "bin"

    # Check each magic signature
    for magic, file_type in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            if file_type == "riff":
                return _detect_riff_type(data)
            if file_type == "lnk":
                return _detect_lnk(data)
            if file_type == "zip":
                # Could be docx/xlsx/pptx - check content type
                return _check_ooxml_type(data)
            return file_type

    # Check for UTF-8 text files
    try:
        text = data.decode("utf-8", errors="strict")
        if text.startswith("<?xml") or text.startswith("<?"):
            return "xml"
        if text.startswith("{") and "}" in text:
            return "json"
        if text.startswith("-----BEGIN"):
            return "pem"
        return "txt"
    except (UnicodeDecodeError, ValueError):
        pass

    return "bin"

def _check_ooxml_type(data: bytes) -> str:
    """Check ZIP contents for OOXML type."""
    try:
        import zipfile
        from io import BytesIO
        z = zipfile.ZipFile(BytesIO(data))
        names = [n.lower() for n in z.namelist()]
        z.close()
        if any("word/" in n for n in names):
            return "docx"
        if any("ppt/" in n for n in names):
            return "pptx"
        if any("xl/" in n for n in names):
            return "xlsx"
        return "zip"
    except Exception:
        return "zip"

################################################################################
# CONTENT-BASED RATING
################################################################################

RATING_KEYWORDS = {
    "html": {
        "base": -20,
        "keywords": [
            ("<script",           -5), ("</script>",          -5),
            ("unescape",          -10), ("document.write",    -5),
            ("eval(",             -8), ("innerHTML",          -5),
            ("outerHTML",         -5), ("innerText",          -3),
            ("powershell",        -12), ("cmd.exe",            -10),
            ("wscript",           -8), ("shell",              -5),
            ("hidden",            -8), ("display:none",       -5),
            ("onerror=",          -8), ("onload=",            -5),
            ("onclick=",          -3), ("onmouseover=",       -3),
            ("createElement",    -5), ("appendChild",         -3),
            ("atob(",            -8), ("fromCharCode",        -5),
            ("base64",           -3), ("crypto",              -3),
            ("location.href",    -8), ("window.open",         -5),
            ("setTimeout",       -3), ("setInterval",         -3),
            ("XMLHttpRequest",   -5), ("fetch(",              -3),
            ("activeElement",    -5), ("parentNode",          -3),
            ("iframe",           -3), ("x-frame-options",     +3),
            ("google-analytics",  +5), ("jquery",              +3),
            ("bootstrap",         +3), ("<!-- legitimate",    +10),
            ("polyfill",          +3), ("cdnjs",               +3),
        ]
    },
    "js": {
        "base": -15,
        "keywords": [
            ("eval(",                -10), ("Function(",            -8),
            ("setTimeout(",          -3), ("setInterval(",          -3),
            ("WScript",              -10), ("Shell",                -8),
            ("ActiveXObject",        -10), ("GetObject",            -8),
            ("powershell",           -12), ("cmd",                  -8),
            ("bash",                 -5), ("/bin/sh",               -5),
            ("exec(",                -10), ("spawn(",                -8),
            ("child_process",        -10), ("require('child_process')", -15),
            ("http",                 -3), ("https",                  -2),
            ("document.cookie",      -8), ("localStorage",          -3),
            ("sessionStorage",       -3), ("crypto",                -5),
            ("SubtleCrypto",         -8), ("encrypt",                -5),
            ("fetch(",               -3), ("XMLHttpRequest",         -5),
            ("WebSocket",            -3), ("navigator.clipboard",    -5),
            ("navigator.geolocation",-8), ("permissions.query",     -5),
            ("fetch('https://",      -8), ("xhr.open(",              -5),
            ("console.log",          +5), ("// @license",            +5),
            ("sourceMappingURL",     +3), ("debugger",               +3),
        ]
    },
    "ps1": {
        "base": -30,
        "keywords": [
            ("Invoke-Expression",  -12), ("IEX",               -12),
            ("Invoke-WebRequest",   -8), ("iwr",                -8),
            ("Invoke-RestMethod",   -5), ("irm",                -5),
            ("Start-Process",       -8), ("spawn",              -8),
            ("powershell -enc",    -15), ("-EncodedCommand",    -15),
            ("-nop",               -10), ("-w hidden",          -10),
            ("-windowstyle hidden", -10), ("bypass",             -8),
            ("NoProfile",           -8), ("Remote32",            -10),
            ("DownloadString",     -12), ("DownloadFile",       -10),
            ("WebClient",           -10), ("Net.WebClient",      -10),
            ("Set-ItemProperty",    -5), ("New-Object",          -3),
            ("Add-Type",            -5), ("[Reflection.Assembly]", -5),
            ("Get-Credential",      -8), ("Securestring",        -5),
            ("Start-Job",           -5), ("Runspace",            -5),
            ("#Requires",            +5), ("Get-Help",            +3),
            ("Get-Command",         +3), ("param(",              +3),
        ]
    },
    "bat": {
        "base": -30,
        "keywords": [
            ("del ",                -5), ("deltree",           -8),
            ("shutdown",           -10), ("format",            -10),
            ("Attrib +H",          -8), ("Attrib +S",          -8),
            ("echo off",           -5), ("@echo off",          -5),
            ("powershell",        -12), ("cmd /c",             -8),
            ("reg add",            -5), ("reg delete",          -8),
            ("net user",           -8), ("net localgroup",      -8),
            ("vssadmin delete",  -10), ("bcdedit",            -8),
            ("taskkill",           -5), ("wmic os",             -5),
            ("certutil",          -10), ("bitsadmin",          -10),
            ("echo.",              +3), ("REM ",               +3),
        ]
    },
    "cmd": {
        "base": -30,
        "keywords": [
            ("del ",                -5), ("deltree",           -8),
            ("shutdown",           -10), ("format",            -10),
            ("Attrib +H",          -8), ("Attrib +S",          -8),
            ("powershell",        -12), ("cmd /c",             -8),
            ("reg add",            -5), ("reg delete",          -8),
            ("net user",           -8), ("net localgroup",      -8),
            ("vssadmin delete",  -10), ("bcdedit",            -8),
            ("certutil",          -10), ("mshta",              -10),
            ("echo.",              +3), ("REM ",               +3),
        ]
    },
    "vbs": {
        "base": -25,
        "keywords": [
            ("Shell",           -10), ("Run",              -8),
            ("Wscript",          -8), ("CreateObject",     -8),
            ("GetObject",        -8), ("Exec",             -10),
            ("powershell",      -12), ("cmd.exe",          -10),
            ("Hidden",          -8), ("Setlocale",         -3),
            ("SendKeys",        -10), ("Send",             -5),
        ]
    },
    "pdf": {
        "base": -10,
        "keywords": [
            ("/JavaScript",        -15), ("/Launch",           -15),
            ("/AA",                -12), ("/OpenAction",       -12),
            ("/Names",             -8), ("/JAAgent",          -10),
            ("/RichMedia",        -10), ("/XFA",              -12),
            ("autoexec",          -10), ("/S",                 -3),
            ("/Type /Action",     -8), ("/S /JavaScript",    -15),
            ("/S /Launch",        -15), ("/S /GoToR",          -5),
            ("/URI",               -5), ("/S /Submit",         -8),
            ("/S /ImportData",    -10), ("/EmbeddedFiles",     -8),
            ("/Type /Catalog",     +5), ("/Pages",             +3),
            ("/Producer",           +2), ("/Creator",            +2),
        ]
    },
    "doc": {
        "base": -15,
        "keywords": [
            ("VBA",               -10), ("Project.",           -8),
            (" macro",             -8), ("Cmnd",               -8),
            ("References",         -5), ("Sub AutoOpen",      -10),
            ("Sub Document_Open", -10), ("Document_Open",     -10),
            ("Application.Run",    -8), ("Shell",              -10),
            ("powershell",        -12), ("cmd.exe",            -10),
            ("Normal.dotm",        +5), ("Built-in",           +3),
        ]
    },
    "url": {
        "base": -8,
        "keywords": [
            ("powershell",    -12), ("-nop",          -10),
            ("-w hidden",     -10), ("-EncodedCommand",-15),
            ("cmd /c",        -8), ("bitsadmin",     -10),
            ("certutil",     -10), ("curl",           -5),
        ]
    },
    "xml": {
        "base": -3,
        "keywords": [
            ("<script",      -10), ("&lt;script",    -10),
            ("eval(",        -8), ("document.",      -5),
            ("powershell",   -12), ("http://",        -3),
        ]
    },
    "json": {
        "base": -3,
        "keywords": [
            ("eval(",        -8), ("document.",      -5),
            ("location",     -5), ("window",         -5),
            ("function",     -2), ("constructor",    -5),
        ]
    },
    "txt": {
        "base": 0,
        "keywords": [
            ("powershell",   -10), ("curl",            -5),
            ("wget",         -5), ("base64 -d",       -8),
            ("bash -i",      -8), ("/dev/tcp",        -10),
            ("nc -e",       -10), ("ncat",             -8),
            ("sh -i",        -8), ("2>&1",             -3),
        ]
    },
    "eml": {
        "base": 0,
        "keywords": [
            ("Content-Type: text/html",     -5),
            ("<script",                     -8),
            ("unescape",                   -10),
            ("powershell",                 -12),
            ("cmd.exe",                    -10),
            ("Content-Disposition: inline", -3),
            ("X-Mailer:",                  -2),
        ]
    },
    "exe": {
        "base": -35,
        "keywords": [
            ("UPX",           -5), ("ASPack",          -5),
            ("ASPack",          -5), ("Petite",          -5),
            ("WinLicense",      -5), ("Themida",         -5),
            ("VMProtect",      -5),
        ]
    },
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".com", ".scr", ".pif", ".msi", ".msp", ".mst",
    ".bat", ".cmd", ".btm",
    ".ps1", ".ps2", ".psm1", ".psd1", ".ps1xml",
    ".vbs", ".vbe", ".wsf", ".wsh", ".wsc", ".hta",
    ".js", ".jse", ".ws",
    ".reg", ".lnk", ".inf", ".cpl",
    ".dll", ".sys", ".drv",
    ".sh", ".bash", ".zsh", ".ksh", ".csh",
    ".run", ".elf",
    ".xlsm", ".xltm", ".xlam",
    ".docm", ".dotm",
    ".pptm", ".potm", ".ppam",
    ".jar", ".jnlp", ".gadget",
    ".py", ".rb", ".pl", ".php",
}

TRUST_EXTENSIONS = {
    ".txt", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".webp", ".tiff", ".tif", ".pdf", ".mp4", ".avi", ".mp3",
    ".wav", ".flac", ".zip", ".rar", ".7z",
}

DANGEROUS_MIME_PREFIXES = (
    "application/x-msdownload", "application/x-executable",
    "application/x-dosexec",    "application/x-sh",
    "application/x-bat",        "application/x-msi",
    "application/x-msdos-program",
)

def _tag_from_extension(name: str) -> str:
    """Get file type tag from extension."""
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    tag_map = {
        "": "???",
        "jse": "js", "mjs": "js",
        "vbe": "vbs",
        "ps2": "ps1",
        "htm": "html",
        "jpeg": "jpg",
        "tiff": "tif",
        "py": "py", "pl": "pl", "rb": "rb",
        "zip": "zip", "7z": "zip", "rar": "zip",
        "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    }
    return tag_map.get(ext, ext)

def _scan_content(content: str, type_key: str) -> tuple[int, list[str]]:
    """Scan content for keywords and return (score_delta, [reason_str])."""
    reasons = []
    cfg = RATING_KEYWORDS.get(type_key, {})
    base = cfg.get("base", 0)
    total = base

    for pattern, delta in cfg.get("keywords", []):
        if pattern.lower() in content.lower():
            total += delta
            reasons.append(pattern)

    return total, reasons

def determine_file_type(data: bytes, filename: str) -> str:
    """Determine file type using magic bytes, extension, or content."""
    ext = os.path.splitext(filename)[1].lower()

    # Try magic bytes first (most reliable)
    magic_type = detect_by_magic(data[:2048])
    if magic_type not in ("bin", "txt"):
        return magic_type

    # Try content-based detection for text-like files
    try:
        text = data.decode("utf-8", errors="replace")
        prefix = text[:10].lower().strip()
        text_lower = text.lower()

        if prefix.startswith("%pdf"):
            return "pdf"
        if prefix.startswith("<?xml") or prefix.startswith("<?"):
            return "xml"
        if prefix.startswith("{") and "}" in text:
            return "json"
        if prefix.startswith("<!doctype") or prefix.startswith("<html") or prefix.startswith("<head") or prefix.startswith("<body") or prefix.startswith("<script"):
            return "html"
        # Check for JavaScript patterns in content
        if "function" in text_lower[:500] or "javascript" in text_lower[:1000]:
            return "js"
        # Check for PowerShell patterns
        if "invoke-" in text_lower or "iex" in text_lower or "-encodedcommand" in text_lower:
            return "ps1"
        # Check for batch/cmd patterns
        if "@echo off" in text_lower or "echo off" in text_lower[:200]:
            return "bat"
    except Exception:
        pass

    # Fall back to extension-based detection
    tag = _tag_from_extension(filename)
    if tag != "???":
        return tag

    return "bin"

def rate_file_content(data: bytes, filename: str, detected_type: str) -> tuple[int, list[str], bool]:
    """Rate file content for suspicious indicators.
    Returns (rating 0-100, [reasons], is_executable)."""
    ext = os.path.splitext(filename)[1].lower()
    score_delta = 0
    reasons = []
    is_executable = False

    # Check if it's a dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        is_executable = True
        score_delta += _get_ext_score(ext)

    # Check magic bytes for executables
    magic_type = detect_by_magic(data[:2048])
    if magic_type in ("exe", "elf", "dll", "macho"):
        is_executable = True
        score_delta += -35

    # Content-based scanning
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    if text:
        # Scan based on detected type
        if detected_type in RATING_KEYWORDS:
            delta, found_reasons = _scan_content(text, detected_type)
            score_delta += delta
            reasons.extend(found_reasons)
        elif is_executable:
            # Scan executables for suspicious patterns
            delta, found_reasons = _scan_content(text, "exe")
            score_delta += delta
            reasons.extend(found_reasons)
        else:
            # Generic scan for text files
            for scan_type in ("html", "js", "txt"):
                delta, found_reasons = _scan_content(text, scan_type)
                if delta < -5:
                    score_delta += delta
                    reasons.extend(f"[generic:{scan_type}] {r}" for r in found_reasons)

    rating = max(0, min(100, 100 + score_delta))
    return rating, reasons, is_executable

def _get_ext_score(ext: str) -> int:
    """Get score delta for extension."""
    dangerous_scores = {
        ".exe": -35, ".com": -30, ".scr": -30, ".pif": -25,
        ".msi": -25, ".msp": -20, ".mst": -20,
        ".bat": -30, ".cmd": -30, ".btm": -30,
        ".ps1": -30, ".ps2": -30, ".psm1": -30, ".psd1": -30,
        ".vbs": -25, ".vbe": -25, ".wsf": -25, ".wsh": -25,
        ".hta": -25,
        ".js": -15, ".jse": -15, ".ws": -15,
        ".dll": -20, ".sys": -25, ".drv": -20,
        ".reg": -15, ".lnk": -25, ".inf": -15, ".cpl": -20,
        ".xlsm": -15, ".xltm": -15, ".xlam": -15,
        ".docm": -15, ".dotm": -15,
        ".pptm": -15, ".potm": -15, ".ppam": -15,
        ".jar": -25, ".jnlp": -25, ".gadget": -25,
        ".sh": -20, ".bash": -20, ".zsh": -20,
        ".run": -25, ".elf": -20,
        ".py": -20, ".rb": -20, ".pl": -20, ".php": -25,
    }
    return dangerous_scores.get(ext, 0)

# Executable/dangerous content types
EXECUTABLE_TYPES = {"js", "ps1", "vbs", "bat", "cmd", "exe", "elf", "dll", "macho", "html", "hta", "wsf", "wsh", "jse", "vbe", "scr", "pif", "com", "msi", "msp", "mst"}

# Safe content types (not dangerous even with lower ratings)
SAFE_TYPES = {"txt", "csv", "png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "tif",
              "pdf", "mp4", "avi", "mp3", "wav", "flac", "zip", "rar", "7z",
              "docx", "xlsx", "pptx", "odt", "ods", "odp"}

def _is_dangerous_content(data: bytes, filename: str, detected_type: str) -> bool:
    """Check if content is dangerous based on type and content."""
    ext = os.path.splitext(filename)[1].lower()

    # Extension-based check
    if ext in DANGEROUS_EXTENSIONS:
        return True

    # Magic bytes check for executables
    magic_type = detect_by_magic(data[:2048])
    is_executable_magic = magic_type in ("exe", "elf", "dll", "macho", "bat", "ps1", "vbs", "js")

    # Content-based check
    rating, _, _ = rate_file_content(data, filename, detected_type)

    # Safe type check
    is_safe_type = detected_type in SAFE_TYPES or ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".pdf", ".mp4", ".avi", ".mp3", ".wav", ".flac", ".zip", ".rar", ".7z")

    # Defused if:
    # 1. executable by magic bytes AND rating < 60
    # 2. dangerous extension (already caught above)
    # 3. detected type is executable content AND rating < 60
    # 4. rating < 40 (very suspicious regardless of type)
    if is_executable_magic and rating < 60:
        return True

    if not is_safe_type and rating < 60:
        return True

    if rating < 40:
        return True

    return False

################################################################################
# EXTRACTION
################################################################################

def _determine_top_dir(names: list, archive_path: str) -> str:
    """Determine root extraction directory based on ZIP contents."""
    if not names:
        return os.path.splitext(os.path.basename(archive_path))[0]

    top_levels = set()
    for name in names:
        if name.endswith("/"):
            top_levels.add(name.rstrip("/"))
        elif "/" in name:
            top_levels.add(name.split("/")[0])
        else:
            top_levels.add(name)

    if len(top_levels) == 1:
        candidate = list(top_levels)[0]
        if "." in os.path.splitext(candidate)[1]:
            return os.path.splitext(os.path.basename(archive_path))[0]
        return candidate
    return os.path.splitext(os.path.basename(archive_path))[0]

def extract_archive(archive_path: str, password: bytes) -> str:
    if HAS_PYZIPPER:
        with pyzipper.AESZipFile(archive_path) as z:
            z.pwd = password
            names = z.namelist()
            top_dir = _determine_top_dir(names, archive_path)
            os.makedirs(top_dir, exist_ok=True)
            for name in names:
                if name.endswith("/"):
                    continue
                if "/" in name:
                    rel = os.path.relpath(name, top_dir)
                else:
                    rel = name
                dest = os.path.join(top_dir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with z.open(name) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
            return top_dir
    else:
        with zipfile.ZipFile(archive_path) as z:
            names = z.namelist()
            top_dir = _determine_top_dir(names, archive_path)
            os.makedirs(top_dir, exist_ok=True)
            for name in names:
                if name.endswith("/"):
                    continue
                if "/" in name:
                    rel = os.path.relpath(name, top_dir)
                else:
                    rel = name
                dest = os.path.join(top_dir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with z.open(name) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
            return top_dir

################################################################################
# MIME PART MODEL
################################################################################

class ContentPart:
    def __init__(self):
        self.properties = {
            "name": None, "encoding": None, "type": None,
            "charset": None, "disposition": None,
        }
        self.data = []

    def set_property(self, key, value):
        if key is None:
            return -1
        k = key.strip().lower()
        if k in self.properties:
            v = value.strip() if isinstance(value, str) else value
            if isinstance(v, str):
                if ";" in v:
                    parts = v.split(";")
                    v = parts[0].strip()
                    for param in parts[1:]:
                        param = param.strip()
                        if "=" in param:
                            pk, pv = param.split("=", 1)
                            pk = pk.strip().lower()
                            pv = pv.strip().strip('"')
                            if pk in self.properties and not self.properties[pk]:
                                self.properties[pk] = pv
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
            self.properties[k] = v
            return 0
        return -1

    def get(self, key, default=None):
        return self.properties.get(key) or default

    def add_data(self, line):
        self.data.append(line)

    def get_data(self):
        return self.data

    def __repr__(self):
        return (f"<Part type={self.get('type')} name={self.get('name')} "
                f"enc={self.get('encoding')} lines={len(self.data)}>")

################################################################################
# EML BOUNDARY / MIME PARSING
################################################################################

def _is_boundary_line(line: str) -> bool:
    if not line:
        return False
    if line.startswith("--") and len(line) > 2 and not line.startswith("-- "):
        return True
    sptr = ['-', '=', '_']
    ptr = 0
    if line[0] not in sptr:
        return False
    for c in line:
        if c == sptr[ptr]:
            continue
        elif ptr < len(sptr) - 1 and c == sptr[ptr + 1]:
            ptr += 1
            continue
        else:
            if c.isdigit():
                return True
    return False

def extract_mime_parts(file_path: str, result_list: list):
    current = None
    in_part = False
    in_headers = True

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\r\n")

            if _is_boundary_line(line):
                if in_part and current and current.data:
                    result_list.append(current)
                current = ContentPart()
                in_part = True
                in_headers = True
                continue

            if not in_part:
                continue

            if not line.strip():
                if in_headers:
                    in_headers = False
                else:
                    current.add_data(raw_line)
                continue

            if in_headers:
                if line.lower().startswith("content-"):
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    v = v.strip()
                    parts_v = [p.strip() for p in v.split(";")]
                    primary = parts_v[0]
                    for prop in current.properties:
                        if prop in k.lower():
                            current.set_property(prop, primary)
                    for param in parts_v[1:]:
                        if "=" in param:
                            pk, pv = param.split("=", 1)
                            pk = pk.strip().lower()
                            pv = pv.strip().strip('"')
                            for prop in current.properties:
                                if prop == pk:
                                    current.set_property(prop, pv)
                    continue

                if line.startswith(("\t", " ")):
                    kv = line.strip()
                    if "=" in kv:
                        pk, pv = kv.split("=", 1)
                        pk = pk.strip().lower().strip(";").strip()
                        pv = pv.strip().strip('"').rstrip(";").strip()
                        for prop in current.properties:
                            if prop == pk:
                                current.set_property(prop, pv)
                    continue
                continue

            current.add_data(raw_line)

    if in_part and current and current.data:
        result_list.append(current)

def extract_mail_headers(file_path: str) -> dict:
    headers = {}
    current_key = None
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.rstrip("\r\n")
            if not stripped:
                break
            if stripped[0] in (" ", "\t") and current_key:
                headers[current_key] = headers[current_key] + " " + stripped.strip()
            elif ":" in stripped:
                k, v = stripped.split(":", 1)
                current_key = k.strip().lower()
                headers[current_key] = v.strip()
    return headers

################################################################################
# URL EXTRACTION & SCORING
################################################################################

_URL_RE = re.compile(
    r'(?:href=["\']?|src=["\']?|url\(["\']?|(?<!["\'\w]))'
    r'((?:https?|ftp)://[^\s"\'<>\]\)]{4,})',
    re.IGNORECASE
)

_SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                     ".top", ".work", ".click", ".pw", ".cc"}
_SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "password", "bank", "paypal", "microsoft", "apple", "invoice",
    "docusign", "sharepoint", "onedrive", "signin", "credential",
]

def _score_url(url: str) -> tuple[int, list[str]]:
    """Score a URL for suspicious indicators. Returns (score, reasons)."""
    score = 0
    reasons = []
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            score += 4
            reasons.append("IP address host")

        tld = "." + host.split(".")[-1] if "." in host else ""
        if tld in _SUSPICIOUS_TLDS:
            score += 3
            reasons.append(f"suspicious TLD ({tld})")

        hits = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in url.lower()]
        if hits:
            score += min(len(hits) * 2, 4)
            reasons.append(f"keywords: {', '.join(hits)}")

        if len(host.split(".")) > 4:
            score += 1
            reasons.append("many subdomains")

        if parsed.port and parsed.port not in (80, 443):
            score += 2
            reasons.append(f"non-standard port ({parsed.port})")

        if len(url) > 200:
            score += 1
            reasons.append("very long URL")

    except Exception:
        pass
    return min(score, 10), reasons

def extract_urls_from_decoded(decoded_dir: str) -> list:
    """Extract URLs from all text files in decoded directory."""
    results = []
    seen = set()

    if not os.path.isdir(decoded_dir):
        return results

    for fname in os.listdir(decoded_dir):
        fpath = os.path.join(decoded_dir, fname)
        if not os.path.isfile(fpath):
            continue
        # Also scan defused subfolder
        if fname == "defused" and os.path.isdir(fpath):
            for dfname in os.listdir(fpath):
                dfpath = os.path.join(fpath, dfname)
                if os.path.isfile(dfpath):
                    _scan_file_for_urls(dfpath, results, seen)
            continue
        _scan_file_for_urls(fpath, results, seen)

    results.sort(key=lambda x: -x["score"])
    return results

def _scan_file_for_urls(fpath: str, results: list, seen: set):
    """Scan a single file for URLs. Also scans .bin files with text content."""
    _, ext = os.path.splitext(fpath.lower())
    text_exts = {".html", ".htm", ".txt", ".xml", ".csv", ".json", ".eml", ".js", ".bin"}
    if ext not in text_exts:
        return
    try:
        with open(fpath, "rb") as fh:
            raw_data = fh.read()
        # Try to decode as text
        try:
            content = raw_data.decode("utf-8", errors="replace")
        except Exception:
            return
        for m in _URL_RE.finditer(content):
            url = m.group(1).rstrip(".,;)")
            if url in seen:
                continue
            seen.add(url)
            score, reasons = _score_url(url)
            results.append({
                "url": url,
                "source_file": os.path.basename(fpath),
                "score": score,
                "reasons": reasons,
            })
    except Exception as e:
        log("warning", f"URL scan failed for {fpath}: {e}")

def display_urls(urls: list):
    """Display extracted URLs with scores."""
    if not urls:
        print()
        warn("No URLs found in decoded files.")
        return

    high = [u for u in urls if u["score"] >= 6]
    med = [u for u in urls if 3 <= u["score"] < 6]
    low = [u for u in urls if u["score"] < 3]

    print()
    print(f"  {clr(f'{len(urls)} unique URL(s) found', C_WHITE, BOLD)}"
          f" - {len(high)} HIGH  {len(med)} MED  {len(low)} LOW")
    print()

    for i, entry in enumerate(urls):
        score = entry["score"]
        if score >= 6:
            color = C_RED
            label = "HIGH  "
        elif score >= 3:
            color = C_YELLOW
            label = "MED   "
        else:
            color = C_GREEN
            label = "LOW   "
        reasons = "  (" + ", ".join(entry["reasons"]) + ")" if entry["reasons"] else ""

        print(f"  {clr(f'[{i+1:02d}]', C_GRAY)} {clr(f'[{label}]', color, BOLD)}"
              f" {clr(f'score={score}/10', color)}")
        print(f"       {entry['url'][:100]}")
        print(f"       {clr(f'from: {entry["source_file"]}', C_GRAY)}{clr(reasons, C_GRAY)}")
        print()

################################################################################
# HASH REPORT
################################################################################

def display_hash_report(stats: dict):
    """Display MD5 and SHA256 hashes for all extracted files."""
    section("File Hash Report")

    all_entries = []
    for key, entries in stats.items():
        if key.startswith("__errors__"):
            continue
        for e in entries:
            if isinstance(e, dict):
                if key == "__defused__":
                    e["dangerous"] = True
                all_entries.append(e)

    if not all_entries:
        warn("No hash data available.")
        return

    # Table header
    print(clr(f"  {'Filename':<50} {'Type':<10} {'Dangerous':<10} {'Size':>12}", C_CYAN, BOLD))
    print(clr("  " + "-" * 85, C_GRAY))

    for e in all_entries:
        dangerous = e.get("dangerous", False)
        detected_type = e.get("detected_type", e.get("extension", "bin").lstrip("."))
        color = C_RED if dangerous else C_GREEN
        danger_label = "YES" if dangerous else "no"
        fname_str = e["filename"][:50]
        type_str = f"{detected_type:<10}"
        size_fmt = f"{e.get('size', 0):>12,}"

        print(f"  {clr(fname_str, color):<50} {clr(type_str, C_MAGENTA)} {clr(danger_label, C_RED if dangerous else C_GREEN, BOLD):<10} {size_fmt} B")

    print()
    print(clr("  " + "-" * 85, C_GRAY))
    print(f"  {clr('Hashes:', C_CYAN, BOLD)}")
    for e in all_entries:
        dangerous = e.get("dangerous", False)
        color = C_RED if dangerous else C_GREEN
        print(f"    {clr(e['filename'], color)}")
        print(f"      MD5    : {e.get('md5', 'N/A')}")
        print(f"      SHA256 : {e.get('sha256', 'N/A')}")
        print()

################################################################################
# EML HEADER SUMMARY
################################################################################

_INTERESTING_HEADERS = [
    "from", "to", "cc", "reply-to", "subject", "date",
    "received-spf", "x-originating-ip", "x-mailer",
    "authentication-results",
]

def display_mail_summary(eml_files: list):
    """Display mail header summary for all EML files."""
    section("Mail Header Summary")

    if not eml_files:
        warn("No EML files found.")
        return

    for eml in eml_files:
        headers = extract_mail_headers(eml)
        print(f"  {clr(os.path.basename(eml), C_MAGENTA, BOLD)}")
        hr("·", 58, C_GRAY)

        for key in _INTERESTING_HEADERS:
            val = headers.get(key)
            if val:
                display = val if len(val) < 90 else val[:87] + "..."
                print(f"    {clr(f'{key:<22}', C_CYAN)}{display}")

        print()

        # SPF verdict
        spf = headers.get("received-spf", "").lower()
        if "pass" in spf:
            ok("SPF: pass")
        elif "fail" in spf:
            err("SPF: FAIL  <- potential spoofing indicator")
        elif spf:
            warn(f"SPF: {spf[:60]}")

        # DKIM
        if headers.get("dkim-signature"):
            info("DKIM signature present")
        else:
            warn("No DKIM signature found")

        # Reply-To mismatch
        from_val = headers.get("from", "")
        reply_to = headers.get("reply-to", "")
        if reply_to and reply_to not in from_val:
            warn(f"Reply-To differs from From  <- social engineering indicator")
            dim(f"  From:     {from_val}")
            dim(f"  Reply-To: {reply_to}")

        print()

################################################################################
# MAIN MENU
################################################################################

_MIME_TO_EXT = {
    "text/html": ".html",      "text/plain": ".txt",
    "text/xml":  ".xml",       "text/csv":   ".csv",
    "application/pdf":   ".pdf",  "application/json": ".json",
    "application/xml":   ".xml",  "application/zip":  ".zip",
    "image/jpeg": ".jpg",  "image/png":  ".png",
    "image/gif":  ".gif",  "image/webp": ".webp",
    "image/bmp":  ".bmp",  "image/tiff": ".tiff",
}

################################################################################
# DECODE AND WRITE
################################################################################

_B64_VALID_BYTES = set(
    list(range(65, 91))  +  # A-Z
    list(range(97, 123)) +  # a-z
    list(range(48, 58))  +  # 0-9
    [43, 47, 61]            # + / =
)

def _clean_base64_bytes(raw: str) -> str:
    out = []
    stripped = 0
    for ch in raw:
        if ord(ch) in _B64_VALID_BYTES:
            out.append(ch)
        else:
            stripped += 1
    return "".join(out)

def _decode_base64_data(lines: list) -> bytes:
    raw = "".join(l.strip() for l in lines)
    raw = _clean_base64_bytes(raw)
    missing = len(raw) % 4
    if missing:
        raw += "=" * (4 - missing)
    return base64.b64decode(raw)

def decode_and_write_part(cp: ContentPart, out_dir: str, idx: int, stats: dict):
    """Decode a MIME part and write to disk, handling dangerous file detection."""
    ctype = cp.get("type", "application/octet-stream")
    name = cp.get("name", "") or ""
    encoding = cp.get("encoding", "") or ""
    charset = cp.get("charset", "utf-8") or "utf-8"
    data_lines = cp.get_data()

    log("info", f"Part[{idx:02d}] type={ctype!r} name={name!r} enc={encoding!r} data_lines={len(data_lines)}")

    # Skip empty parts
    if not data_lines:
        log("warning", f"Part[{idx:02d}] has no data, skipping")
        stats.setdefault("__errors__", [])
        stats["__errors__"].append(f"part_{idx:02d}: empty part (no data)")
        return

    # Build safe filename from eml name or fallback
    safe_name = _build_filename(name, ctype, idx)

    try:
        enc_lower = encoding.lower()
        if "base64" in enc_lower:
            raw_bytes = _decode_base64_data(data_lines)
            log("info", f"Part[{idx:02d}] decoded {len(raw_bytes)} bytes from base64")
        elif "quoted-printable" in enc_lower:
            raw_text = "".join(data_lines)
            raw_bytes = quopri.decodestring(raw_text.encode("latin-1"))
            log("info", f"Part[{idx:02d}] decoded {len(raw_bytes)} bytes from QP")
        else:
            raw_text = "".join(data_lines)
            raw_bytes = raw_text.encode(charset, errors="replace")
            log("info", f"Part[{idx:02d}] encoded {len(raw_bytes)} bytes as {charset}")

        # Determine file type
        detected_type = determine_file_type(raw_bytes, safe_name)

        # Rate content
        rating, reasons, is_executable = rate_file_content(raw_bytes, safe_name, detected_type)

        # Check if dangerous
        dangerous = _is_dangerous_content(raw_bytes, safe_name, detected_type)

        log("info", f"Part[{idx:02d}] detected={detected_type} rating={rating} dangerous={dangerous}")

        # Determine target directory and final filename
        if dangerous:
            target_dir = os.path.join(out_dir, "defused")
            os.makedirs(target_dir, exist_ok=True)
            # Add _defused suffix to extension
            base, ext = os.path.splitext(safe_name)
            final_name = f"{base}_defused{ext}"
            stat_key = "__defused__"
        else:
            target_dir = out_dir
            final_name = safe_name
            stat_key = ctype

        out_path = os.path.join(target_dir, final_name)
        log("info", f"Part[{idx:02d}] -> {out_path}")

        # Write file
        with open(out_path, "wb") as fh:
            fh.write(raw_bytes)

        # Calculate hashes
        md5 = hashlib.md5(raw_bytes).hexdigest()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        log("info", f"Part[{idx:02d}] MD5={md5} SHA256={sha256}")

        # Get file extension for display
        _, file_ext = os.path.splitext(final_name)

        stats.setdefault(stat_key, [])
        stats[stat_key].append({
            "filename": final_name,
            "path": out_path,
            "size": len(raw_bytes),
            "md5": md5,
            "sha256": sha256,
            "dangerous": dangerous,
            "ctype": ctype,
            "rating": rating,
            "extension": file_ext,
            "detected_type": detected_type,
            "reasons": reasons,
        })

    except Exception as e:
        import traceback
        log("error", f"Part[{idx:02d}] FAILED: {e}")
        log("error", traceback.format_exc())
        stats.setdefault("__errors__", [])
        stats["__errors__"].append(f"part_{idx:02d}: {e}")

def _decode_rfc2047(encoded_text: str) -> str:
    """Decode RFC 2047 encoded word (e.g. =?UTF-8?B?QmFkTmFtZQ==?= -> BadName)."""
    import re
    # Pattern: =?charset?encoding?encoded_text?=
    pattern = r"=\?([^?]+)\?([BQbq])\?([^?]+)\?="
    decoded_parts = []

    for match in re.finditer(pattern, encoded_text):
        try:
            charset = match.group(1)
            encoding = match.group(2).upper()
            text = match.group(3)
            if encoding == "B":
                # Base64
                decoded = base64.b64decode(text).decode(charset, errors="replace")
            elif encoding == "Q":
                # Quoted-printable
                decoded = quopri.decodestring(text.encode(charset)).decode(charset, errors="replace")
            else:
                decoded = match.group(0)
            decoded_parts.append(decoded)
        except Exception:
            decoded_parts.append(match.group(0))

    if not decoded_parts:
        return encoded_text
    return "".join(decoded_parts)

def _build_filename(name: str, ctype: str, idx: int) -> str:
    """Build safe filename from eml name or generate fallback."""
    ctype_base = ctype.split(";")[0].strip().lower()

    if name:
        name = os.path.basename(name.replace("\\", "/"))
        # Decode RFC 2047 encoded filenames
        if name.startswith("=?"):
            decoded_name = _decode_rfc2047(name)
            if decoded_name != name:
                name = decoded_name
        base, ext = os.path.splitext(name)
        if not ext:
            ext = _MIME_TO_EXT.get(ctype_base) or mimetypes.guess_extension(ctype_base) or ".bin"
        return f"{base}{ext}"

    ext = _MIME_TO_EXT.get(ctype_base) or mimetypes.guess_extension(ctype_base) or ".bin"
    type_slug = ctype_base.replace("/", "_").replace(" ", "")
    return f"part_{idx:02d}_{type_slug}{ext}"

################################################################################
# SESSION
################################################################################

class Session:
    def __init__(self, archive_path: str, password: bytes):
        self.archive_path = archive_path
        self.password = password
        self.extract_dir = ""
        self.eml_files = []
        self.parts = []
        self.stats = {}

    def load(self):
        info(f"Extracting archive: {os.path.basename(self.archive_path)}")
        self.extract_dir = extract_archive(self.archive_path, self.password)
        ok(f"Extracted to: {self.extract_dir}/")
        log_path = os.path.join(self.extract_dir, "qhelper_v2.log")
        setup_logger(log_path)
        log("info", f"Archive: {self.archive_path}")
        info(f"Log file: {log_path}")

        # Find EML files
        self.eml_files = [
            os.path.join(self.extract_dir, f)
            for f in os.listdir(self.extract_dir)
            if f.lower().endswith(".eml")
        ]
        ok(f"Found {len(self.eml_files)} EML file(s)")

    def extract_parts(self):
        for eml in self.eml_files:
            info(f"Parsing: {os.path.basename(eml)}")
            log("info", f"--- EML: {eml} ---")
            before = len(self.parts)
            extract_mime_parts(eml, self.parts)
            found = len(self.parts) - before
            dim(f"-> {found} part(s) found")
            log("info", f"Found {found} parts in {os.path.basename(eml)}")
        ok(f"Total parts extracted: {len(self.parts)}")

    def decode_parts(self, threads: int = 8):
        section("Decoding & Analyzing")
        out_dir = os.path.join(self.extract_dir, "decoded")
        os.makedirs(out_dir, exist_ok=True)
        log("info", f"Output dir: {out_dir}")
        log("info", f"Parts to decode: {len(self.parts)}")
        info(f"Safe files -> {out_dir}/")
        info(f"Defused    -> {out_dir}/defused/")

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [
                ex.submit(decode_and_write_part, cp, out_dir, i, self.stats)
                for i, cp in enumerate(self.parts)
            ]
            for f in futures:
                f.result()

        ok("Decoding complete.")

################################################################################
# OVERVIEW DISPLAY
################################################################################

def _rating_color(rating: int) -> str:
    if rating < 30:
        return C_RED
    if rating < 60:
        return C_YELLOW
    return C_GREEN

def _rating_label(rating: int) -> str:
    if rating < 30:
        return "HIGH RISK"
    if rating < 60:
        return "MEDIUM"
    return "LOW RISK"

def display_overview(stats: dict, extract_dir: str):
    """Display overview of all extracted files with ratings."""
    section("Extraction Overview")

    all_files = []
    for key, entries in stats.items():
        if key.startswith("__errors__"):
            continue
        for e in entries:
            if isinstance(e, dict):
                # __defused__ entries need dangerous=True set explicitly
                if key == "__defused__":
                    e["dangerous"] = True
                all_files.append(e)

    if not all_files:
        warn("No files were extracted.")
        return

    # Group by safe/defused
    safe_files = [f for f in all_files if not f.get("dangerous")]
    defused_files = [f for f in all_files if f.get("dangerous")]

    print(f"\n  Found {len(all_files)} file(s):")
    print(f"    {clr(f'{len(safe_files)} safe', C_GREEN)}  |  {clr(f'{len(defused_files)} defused', C_RED)}\n")

    # Table header
    print(clr(f"  {'#':<3} {'Filename':<45} {'Ext':<8} {'Rating':<12} {'Size':>10}", C_CYAN, BOLD))
    print(clr("  " + "-" * 80, C_GRAY))

    # Display safe files
    for i, f in enumerate(safe_files):
        rating = f.get("rating", 50)
        ext = f.get("extension", ".bin")
        size = f.get("size", 0)
        reasons = f.get("reasons", [])
        rating_clr = _rating_color(rating)
        rating_str = f"{rating}/100"
        idx_str = f"{i+1:<3}"
        ext_str = f"{ext:<8}"
        rating_fmt = f"{rating_str:<12}"
        fname_str = f["filename"][:45]
        print(f"  {clr(idx_str, C_GRAY)} {fname_str:<45} {clr(ext_str, C_MAGENTA)} {clr(rating_fmt, rating_clr)} {size:>10,} B")
        if reasons:
            reasons_str = ", ".join(reasons[:5])
            if len(reasons) > 5:
                reasons_str += f" ... (+{len(reasons)-5} more)"
            print(clr(f"       -> {reasons_str}", C_YELLOW))

    # Display defused files
    for i, f in enumerate(defused_files):
        rating = f.get("rating", 50)
        ext = f.get("extension", ".bin")
        size = f.get("size", 0)
        reasons = f.get("reasons", [])
        rating_clr = _rating_color(rating)
        rating_str = f"{rating}/100"
        idx = len(safe_files) + i + 1
        idx_str = f"{idx:<3}"
        ext_str = f"{ext:<8}"
        rating_fmt = f"{rating_str:<12}"
        fname_str = f["filename"][:45]
        print(f"  {clr(idx_str, C_GRAY)} {clr(fname_str, C_RED):<45} {clr(ext_str, C_MAGENTA)} {clr(rating_fmt, rating_clr)} {size:>10,} B")
        if reasons:
            reasons_str = ", ".join(reasons[:5])
            if len(reasons) > 5:
                reasons_str += f" ... (+{len(reasons)-5} more)"
            print(clr(f"       -> {reasons_str}", C_YELLOW))

    # Display errors if any
    errors = stats.get("__errors__", [])
    if errors:
        print()
        print(clr("  ERRORS:", C_RED, BOLD))
        for err_msg in errors:
            print(clr(f"    ! {err_msg}", C_RED))

    # Rating legend
    print()
    print(f"  {clr('Rating:', C_CYAN)}", end=" ")
    print(f"{clr('HIGH RISK', C_RED)} <30  ", end="")
    print(f"{clr('MEDIUM', C_YELLOW)} 30-59  ", end="")
    print(f"{clr('LOW RISK', C_GREEN)} 60-100")

    # Show defused folder info
    defused_dir = os.path.join(extract_dir, "decoded", "defused")
    if defused_files:
        print()
        info(f"Defused files are in: {defused_dir}/")

def prompt_cleanup(extract_dir: str, stats: dict) -> bool:
    """Prompt user to delete or keep extracted files. Returns True if deleted."""
    print()
    print(clr("  What would you like to do?", C_WHITE, BOLD))
    print(clr("  [0]", C_CYAN, BOLD) + " Keep all files (leave as is)")
    print(clr("  [1]", C_RED, BOLD) + " Delete entire extraction folder (including archive contents)")
    print()

    choice = prompt("Choice >").strip()

    if choice == "1":
        # Delete entire extraction directory
        if os.path.exists(extract_dir):
            try:
                shutil.rmtree(extract_dir)
                ok(f"Deleted: {os.path.basename(extract_dir)}/")
                log("info", f"Deleted entire extraction folder: {extract_dir}")
                return True
            except Exception as e:
                err(f"Failed to delete: {e}")
                log("error", f"Failed to delete {extract_dir}: {e}")
                return False
        else:
            warn("Extraction directory not found.")
            return False
    else:
        info("Files kept at current location.")
        return False

################################################################################
# ARCHIVE SELECTION
################################################################################

def select_archives() -> list:
    """Simple numbered archive selection, or enter for all."""
    section("Available ZIP Archives")
    files = sorted(f for f in os.listdir(".") if f.lower().endswith(".zip"))

    if not files:
        warn("No .zip files found in current directory.")
        return []

    for i, f in enumerate(files):
        size_kb = os.path.getsize(f) // 1024
        print(clr(f"  [{i}]", C_CYAN, BOLD) + f"  {f}" + clr(f"  ({size_kb} KB)", C_GRAY))

    print()
    print(clr("  Examples:", C_GRAY))
    print(clr("    0,2,5", C_CYAN) + clr("  -> process archives 0, 2 and 5", C_GRAY))
    print(clr("    1-3", C_CYAN)   + clr("  -> process archives 1 through 3", C_GRAY))
    print(clr("    all", C_CYAN)   + clr("  -> process all", C_GRAY))
    print(clr("    (press Enter for all)", C_GRAY))
    print()

    raw = prompt("Select >").strip()

    if raw == "":
        return files

    # Parse selection
    selected = []
    parts = raw.replace(" ", "").split(",")
    try:
        for p in parts:
            if "-" in p:
                s, e = p.split("-", 1)
                selected.extend(range(int(s), int(e) + 1))
            else:
                selected.append(int(p))
    except ValueError:
        err("Invalid selection syntax.")
        return []

    # Map to filenames
    result = []
    for idx in selected:
        if 0 <= idx < len(files):
            result.append(files[idx])

    return result

################################################################################
# PASSWORD UI
################################################################################

def get_password() -> bytes:
    print()
    print(clr(f"  Default password: {DEFAULT_PASS.decode()}", C_GRAY))
    raw = prompt("Password (press Enter for default) >").strip()
    if not raw:
        ok(f"Using default password: {DEFAULT_PASS.decode()}")
        return DEFAULT_PASS
    ok("Using custom password.")
    return raw.encode("utf-8")

################################################################################
# MAIN
################################################################################

def main():
    global _logger

    while True:
        banner()
        print(clr("  [0]", C_CYAN, BOLD) + " Extract attachments from archive")
        print(clr("  [Q]", C_RED,  BOLD) + " Quit")
        print()
        hr()

        sel = prompt("Choice >").strip().lower()

        if sel == "q":
            banner()
            print(clr("  Goodbye.\n", C_CYAN, BOLD))
            sys.exit(0)

        if sel == "0":
            archives = select_archives()
            if not archives:
                press_enter()
                continue

            password = get_password()

            raw = prompt("Worker threads (press Enter for 8) >").strip()
            threads = int(raw) if raw.isdigit() else 8
            info(f"Using {threads} threads.")

            for archive in archives:
                banner()
                print(clr(f"  Processing: {archive}", C_YELLOW, BOLD))
                hr()

                sess = Session(archive, password)
                try:
                    sess.load()
                except Exception as e:
                    err(f"Failed to extract archive: {e}")
                    press_enter()
                    continue

                sess.extract_parts()

                if not sess.parts:
                    warn("No MIME parts found.")
                    # Clean up empty extraction directory
                    if os.path.exists(sess.extract_dir):
                        try:
                            shutil.rmtree(sess.extract_dir)
                            info(f"Cleaned up: {os.path.basename(sess.extract_dir)}/")
                        except Exception as e:
                            dim(f"  Cleanup failed: {e}")
                    press_enter()
                    continue

                sess.decode_parts(threads=threads)

                # Post-extraction menu
                while True:
                    banner()
                    print(clr(f"  Archive: {archive}", C_WHITE, BOLD))
                    section("Post-Extraction")
                    display_overview(sess.stats, sess.extract_dir)

                    print()
                    print(clr("  [1]", C_CYAN, BOLD) + " Show URLs found")
                    print(clr("  [2]", C_CYAN, BOLD) + " Show Hash Report")
                    print(clr("  [3]", C_CYAN, BOLD) + " Show Mail Header Summary")
                    print(clr("  [0]", C_GRAY, BOLD) + " Continue to cleanup")
                    print()

                    choice = prompt("Choice >").strip()

                    if choice == "1":
                        banner()
                        section("Extracted URLs")
                        decoded_dir = os.path.join(sess.extract_dir, "decoded")
                        urls = extract_urls_from_decoded(decoded_dir)
                        display_urls(urls)
                        press_enter()
                    elif choice == "2":
                        banner()
                        display_hash_report(sess.stats)
                        press_enter()
                    elif choice == "3":
                        banner()
                        display_mail_summary(sess.eml_files)
                        press_enter()
                    elif choice == "0":
                        break
                    else:
                        warn("Invalid choice.")

                # Ask to clean up
                prompt_cleanup(sess.extract_dir, sess.stats)

                print()
                info(f"Output directory: {sess.extract_dir}/decoded/")
                press_enter()

        else:
            warn("Unknown option.")

if __name__ == "__main__":
    main()
