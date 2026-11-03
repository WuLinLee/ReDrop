#!/usr/bin/env python3
"""Summarize JADX output without publishing proprietary decompiled source."""
from __future__ import annotations
import argparse
import collections
import json
import re
from pathlib import Path
import urllib.parse

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
CLASS_RE = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")
METHOD_RE = re.compile(r"(?m)^\s*(?:(?:public|protected|private|static|final|synchronized|native|abstract|override)\s+)+[\w.$<>?,\[\] ]+\s+([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws [^{]+)?\{")
FEATURES = {
    "network_clients": [r"OkHttpClient", r"Retrofit", r"HttpURLConnection", r"WebSocket"],
    "authentication": [r"access.?token", r"refresh.?token", r"Authorization", r"login", r"QRCode"],
    "file_transfer": [r"upload", r"download", r"MultipartBody", r"Content-Range", r"FileProvider"],
    "resumable_transfer": [r"chunk", r"resume", r"part.?number", r"upload.?id"],
    "persistence": [r"RoomDatabase", r"SharedPreferences", r"SQLiteDatabase", r"DataStore"],
    "device_pairing": [r"Drop.?ID", r"device.?id", r"pair", r"qr.?scan"],
}

def endpoint(raw):
    try:
        u = urllib.parse.urlsplit(raw.rstrip(".,;:!?)]}"))
        host = (u.hostname or "").lower()
        if not host:
            return None
        parts = []
        for part in [x for x in (u.path or "/").split("/") if x][:4]:
            if re.fullmatch(r"[0-9a-fA-F-]{24,}|[A-Za-z0-9_-]{40,}", part):
                part = "{id}"
            parts.append(part[:80])
        return (u.scheme.lower(), host, "/" + "/".join(parts) if parts else "/")
    except Exception:
        return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sources", required=True)
    p.add_argument("--output", default="analysis/android/decompiled-structure.json")
    args = p.parse_args()
    root = Path(args.sources)
    if not root.is_dir():
        raise FileNotFoundError("JADX sources folder not found: " + str(root))

    files = list(root.rglob("*.java"))
    classes = collections.Counter()
    method_count = 0
    feature_counts = collections.Counter()
    endpoints = collections.Counter()
    total_bytes = 0
    samples = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total_bytes += path.stat().st_size
        package = "unknown"
        match = re.search(r"(?m)^\s*package\s+([\w.]+)\s*;", text)
        if match:
            package = match.group(1)
        classes[package] += len(CLASS_RE.findall(text))
        names = METHOD_RE.findall(text)
        method_count += len(names)
        if len(samples) < 100:
            samples.extend(names[: max(0, 100 - len(samples))])
        for category, patterns in FEATURES.items():
            for pattern in patterns:
                feature_counts[category] += len(re.findall(pattern, text, re.I))
        for raw in URL_RE.findall(text):
            ep = endpoint(raw)
            if ep:
                endpoints[ep] += 1

    result = {
        "decompiler": "JADX",
        "source_files": len(files),
        "approximate_class_count": sum(classes.values()),
        "approximate_method_declarations": method_count,
        "decompiled_text_bytes_in_ephemeral_runner": total_bytes,
        "package_class_counts": dict(classes.most_common(60)),
        "feature_code_indicators": dict(sorted(feature_counts.items())),
        "network_endpoint_indicators": [
            {"scheme": k[0], "host": k[1], "path_prefix": k[2], "occurrences": v}
            for k, v in sorted(endpoints.items())
        ],
        "method_name_samples": sorted(set(samples))[:100],
        "notice": "Decompiled Java files are used only inside the temporary Actions runner. This committed JSON contains structural summaries and sanitized endpoint indicators, not copied source code.",
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("JADX structure summary written to " + str(out))

if __name__ == "__main__":
    main()
