#!/usr/bin/env python3
"""Static metadata and indicator analysis for the official Dropew Android APK.

No app source code, raw DEX strings, credentials, or original assets are copied
to the repository. The APK and any optional JADX output remain on the runner.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import logging
import re
import sys
import tempfile
import urllib.parse
import zipfile
from pathlib import Path

logging.getLogger("androguard").setLevel(logging.ERROR)

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
TOKENISH_RE = re.compile(r"(?i)(bearer\s+|access[_-]?token|refresh[_-]?token|authorization\s*:|password\s*=)")
FRAMEWORK_MARKERS = {
    "Kotlin": [r"kotlin/"],
    "Jetpack Compose": [r"androidx/compose", r"Composable"],
    "OkHttp": [r"okhttp3/", r"okhttp/"],
    "Retrofit": [r"retrofit2/"],
    "Firebase": [r"com/google/firebase/", r"firebase"],
    "Room": [r"androidx/room/"],
    "WorkManager": [r"androidx/work/"],
    "Flutter": [r"io/flutter/", r"flutter_assets"],
    "React Native": [r"com/facebook/react/", r"reactnative"],
    "Capacitor": [r"com/getcapacitor/"],
    "Cordova": [r"org/apache/cordova/"],
    "Compose Multiplatform": [r"org/jetbrains/compose"],
    "WebView": [r"android/webkit/WebView"],
    "SQLCipher": [r"net/sqlcipher/"],
}
FEATURE_MARKERS = {
    "authentication": [r"login", r"logout", r"token", r"oauth", r"qr.?code", r"qrcode", r"refresh"],
    "file_transfer": [r"upload", r"download", r"multipart", r"content.?range", r"fileprovider", r"documentfile"],
    "resumable_transfer": [r"resume", r"chunk", r"upload.?id", r"part.?number", r"range"],
    "device_linking": [r"device.?id", r"device.?link", r"drop.?id", r"pair", r"qr.?scan"],
    "realtime_sync": [r"websocket", r"socket\.io", r"stomp", r"eventsource", r"mqtt"],
    "persistent_storage": [r"sqlite", r"roomdatabase", r"datastore", r"sharedpreferences", r"indexeddb"],
}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def normalize_url(raw: str):
    candidate = raw.rstrip(".,;:!?)]}")
    try:
        parsed = urllib.parse.urlsplit(candidate)
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        path_parts = [p for p in (parsed.path or "/").split("/") if p]
        sanitized = []
        for part in path_parts[:4]:
            if re.fullmatch(r"[0-9a-fA-F-]{24,}", part) or re.fullmatch(r"[A-Za-z0-9_-]{40,}", part):
                sanitized.append("{id}")
            else:
                sanitized.append(part[:80])
        return {
            "scheme": parsed.scheme.lower(),
            "host": host,
            "path_prefix": "/" + "/".join(sanitized) if sanitized else "/",
        }
    except Exception:
        return None

def xml_attribute(node, name: str):
    if node is None:
        return None
    return node.attrib.get("{http://schemas.android.com/apk/res/android}" + name)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True)
    parser.add_argument("--output", default="analysis/android")
    parser.add_argument("--expected-package", default="com.ztech.dropew")
    args = parser.parse_args()
    original_path = Path(args.apk)
    if not original_path.is_file():
        raise FileNotFoundError(original_path)
    apk_path = original_path
    split_apk_entries = []
    with zipfile.ZipFile(original_path) as outer_archive:
        outer_names = outer_archive.namelist()
        is_plain_apk = "AndroidManifest.xml" in outer_names and any(re.fullmatch(r"classes\d*\.dex", Path(n).name) for n in outer_names)
        embedded_apks = [n for n in outer_names if n.lower().endswith(".apk") and not n.startswith("../") and not n.startswith("/")]
        if not is_plain_apk and embedded_apks:
            split_apk_entries = embedded_apks
            base_candidates = [n for n in embedded_apks if Path(n).name.lower() in ("base.apk", "base-master.apk")]
            chosen = base_candidates[0] if base_candidates else sorted(embedded_apks)[0]
            temp_dir = Path(tempfile.mkdtemp(prefix="redrop-xapk-"))
            apk_path = temp_dir / "base.apk"
            apk_path.write_bytes(outer_archive.read(chosen))

    try:
        from androguard.core.apk import APK
        from androguard.misc import AnalyzeAPK
    except ImportError as exc:
        raise RuntimeError("Install androguard before running this analyzer: pip install androguard") from exc

    apk = APK(str(apk_path))
    package = apk.get_package()
    if package != args.expected_package:
        raise ValueError("Package mismatch: expected %s, received %s" % (args.expected_package, package))
    if not apk.is_valid_APK():
        raise ValueError("Androguard did not recognize a valid APK.")

    root = apk.get_android_manifest_xml()
    application = root.find("application") if root is not None else None
    app_attrs = {
        "debuggable": xml_attribute(application, "debuggable"),
        "allowBackup": xml_attribute(application, "allowBackup"),
        "usesCleartextTraffic": xml_attribute(application, "usesCleartextTraffic"),
        "networkSecurityConfig": xml_attribute(application, "networkSecurityConfig"),
        "fullBackupContent": xml_attribute(application, "fullBackupContent"),
    }
    app_attrs = {k: v for k, v in app_attrs.items() if v is not None}

    analysis_apk, dexes, _ = AnalyzeAPK(str(apk_path))
    strings = []
    class_count = 0
    method_count = 0
    top_packages = collections.Counter()
    for dex in dexes if isinstance(dexes, (list, tuple)) else [dexes]:
        try:
            strings.extend(s for s in dex.get_strings() if isinstance(s, str))
        except Exception:
            pass
        try:
            for cls in dex.get_classes():
                class_count += 1
                name = cls.get_name()
                if name.startswith("L") and "/" in name:
                    top_packages["/".join(name[1:].split("/")[:3])] += 1
                try:
                    method_count += sum(1 for _ in cls.get_methods())
                except Exception:
                    pass
        except Exception:
            pass

    string_blob = "\n".join(strings)
    framework_hits = {}
    for name, patterns in FRAMEWORK_MARKERS.items():
        found = sum(len(re.findall(p, string_blob, re.I)) for p in patterns)
        if found:
            framework_hits[name] = found

    feature_hits = {}
    for name, patterns in FEATURE_MARKERS.items():
        found = sum(len(re.findall(p, string_blob, re.I)) for p in patterns)
        if found:
            feature_hits[name] = found

    endpoints = collections.Counter()
    for value in strings:
        if TOKENISH_RE.search(value):
            continue
        for raw in URL_RE.findall(value):
            endpoint = normalize_url(raw)
            if endpoint:
                endpoints[(endpoint["scheme"], endpoint["host"], endpoint["path_prefix"])] += 1

    with zipfile.ZipFile(apk_path) as archive:
        entries = []
        dex_entries = []
        native_libs = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith("../") or name.startswith("/"):
                continue
            entries.append({"path": name, "size_bytes": info.file_size})
            if re.fullmatch(r"classes\d*\.dex", Path(name).name):
                dex_entries.append({"path": name, "size_bytes": info.file_size})
            if name.startswith("lib/") and name.endswith(".so"):
                native_libs.append(name)

    try:
        min_sdk = apk.get_min_sdk_version()
    except Exception:
        min_sdk = None
    try:
        target_sdk = apk.get_target_sdk_version()
    except Exception:
        target_sdk = None
    try:
        version_name = apk.get_androidversion_name()
        version_code = apk.get_androidversion_code()
    except Exception:
        version_name, version_code = None, None

    components = {
        "activities": sorted(apk.get_activities() or []),
        "services": sorted(apk.get_services() or []),
        "receivers": sorted(apk.get_receivers() or []),
        "providers": sorted(apk.get_providers() or []),
    }
    try:
        components["main_activity"] = apk.get_main_activity()
    except Exception:
        components["main_activity"] = None

    summary = {
        "source": "APKPure URL supplied for this research run",
        "expected_package": args.expected_package,
        "actual_package": package,
        "app_name": apk.get_app_name(),
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "apk_size_bytes": apk_path.stat().st_size,
        "apk_sha256": sha256_file(apk_path),
        "downloaded_container_sha256": sha256_file(original_path),
        "split_apk_entry_count": len(split_apk_entries),
        "permissions": sorted(apk.get_permissions() or []),
        "application_manifest_flags": app_attrs,
        "components": components,
        "dex": {
            "files": dex_entries,
            "class_count": class_count,
            "method_count": method_count,
            "top_package_prefixes": dict(top_packages.most_common(40)),
        },
        "native_libraries": sorted(native_libs),
        "framework_indicators": framework_hits,
        "feature_indicators": feature_hits,
        "unique_dex_string_count": len(set(strings)),
        "network_endpoint_indicators": [
            {"scheme": k[0], "host": k[1], "path_prefix": k[2], "occurrences": v}
            for k, v in sorted(endpoints.items())
        ],
        "archive_entry_count": len(entries),
        "archive_inventory": entries,
        "notes": [
            "Static analysis only; indicator counts do not prove runtime behavior.",
            "No decompiled source, raw DEX strings, tokens, cookies, or user data are committed.",
            "The private server implementation and server-side account/storage logic are not recoverable from this APK alone.",
            "Validate network behavior only with a test account and test data that you control.",
        ],
    }

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "apk-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Dropew Android APK static analysis",
        "",
        "- Package: " + package,
        "- App name: " + str(summary["app_name"]),
        "- Version: " + str(version_name) + " (" + str(version_code) + ")",
        "- Minimum SDK: " + str(min_sdk),
        "- Target SDK: " + str(target_sdk),
        "- APK size: " + str(summary["apk_size_bytes"]) + " bytes",
        "- APK SHA-256: " + summary["apk_sha256"],
        "- Downloaded container SHA-256: " + summary["downloaded_container_sha256"],
        "- Embedded split APKs: " + str(len(split_apk_entries)),
        "",
        "## Manifest and components",
        "",
        "- Activities: " + str(len(components["activities"])),
        "- Services: " + str(len(components["services"])),
        "- Receivers: " + str(len(components["receivers"])),
        "- Providers: " + str(len(components["providers"])),
        "- Main activity: " + str(components["main_activity"]),
        "- Permissions: " + ", ".join(summary["permissions"]),
        "- Application flags: " + json.dumps(app_attrs, ensure_ascii=False),
        "",
        "## DEX and libraries",
        "",
        "- DEX files: " + str(len(dex_entries)),
        "- Classes: " + str(class_count),
        "- Methods: " + str(method_count),
        "- Unique DEX strings: " + str(summary["unique_dex_string_count"]),
        "- Native libraries: " + ", ".join(Path(x).name for x in sorted(native_libs)),
        "",
        "## Framework indicators",
        "",
    ]
    lines.extend("- " + k + ": " + str(v) for k, v in framework_hits.items())
    if not framework_hits:
        lines.append("No common framework marker detected.")
    lines.extend(["", "## Feature indicators", ""])
    lines.extend("- " + k + ": " + str(v) for k, v in feature_hits.items())
    if not feature_hits:
        lines.append("No common feature marker detected.")
    lines.extend(["", "## Network endpoint indicators", ""])
    lines.extend(["| Scheme | Host | Path prefix | Occurrences |", "|---|---|---|---:|"])
    for k, count in sorted(endpoints.items()):
        lines.append("| " + k[0] + " | " + k[1] + " | " + k[2] + " | " + str(count) + " |")
    if not endpoints:
        lines.append("| - | No endpoint indicators found | - | 0 |")
    lines.extend(["", "## Limitations", ""])
    lines.extend("- " + note for note in summary["notes"])
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Android APK analysis written to " + str(output))
    print("The APK itself and extracted code remain outside the repository.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("APK ANALYSIS FAILED: " + str(exc), file=sys.stderr)
        raise
