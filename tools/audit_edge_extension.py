#!/usr/bin/env python3
"""Sanitized static inspection of a publicly distributed Edge extension CRX."""
from __future__ import annotations
import argparse, csv, hashlib, io, json, os, re, shutil, struct, tempfile, urllib.parse, urllib.request, zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

DEFAULT_ID = "glglacjhoenjihpamfmokhkocpibpdkh"
UPDATE_URL = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
MARKERS = {
    "network": [r"\bfetch\s*\(", r"XMLHttpRequest", r"\baxios\b", r"\bWebSocket\b", r"\bEventSource\b"],
    "browser_storage": [r"chrome\.storage", r"browser\.storage", r"storage\.local", r"storage\.sync"],
    "web_storage": [r"\blocalStorage\b", r"\bsessionStorage\b", r"\bindexedDB\b"],
    "messaging": [r"runtime\.sendMessage", r"runtime\.onMessage", r"tabs\.sendMessage", r"\bpostMessage\b"],
    "file_transfer": [r"\bFormData\b", r"\bBlob\b", r"\bFileReader\b", r"\bArrayBuffer\b", r"\bReadableStream\b"],
    "resumable_transfer": [r"\bchunk\b", r"\bresume\b", r"\buploadId\b", r"\bpartNumber\b", r"Content-Range"],
    "authentication": [r"\blogin\b", r"\blogout\b", r"\btoken\b", r"\bQRCode\b", r"\bqrcode\b", r"\brefreshToken\b"],
}

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def unwrap_crx(data: bytes) -> tuple[bytes, str]:
    if data.startswith(b"PK\x03\x04"):
        return data, "zip"
    if not data.startswith(b"Cr24") or len(data) < 12:
        raise ValueError("Response is not a recognized CRX or ZIP package.")
    version = struct.unpack("<I", data[4:8])[0]
    if version == 3:
        offset = 12 + struct.unpack("<I", data[8:12])[0]
    elif version == 2:
        if len(data) < 16:
            raise ValueError("CRX2 header is truncated.")
        key_len, sig_len = struct.unpack("<II", data[8:16])
        offset = 16 + key_len + sig_len
    else:
        raise ValueError("Unsupported CRX version: %s" % version)
    payload = data[offset:]
    if not payload.startswith(b"PK\x03\x04"):
        raise ValueError("CRX ZIP payload was not found.")
    return payload, "crx%s" % version

def download_crx(extension_id: str, out_path: Path):
    params = urllib.parse.urlencode({"response": "redirect", "x": "id=%s&installsource=ondemand&uc" % extension_id})
    request = urllib.request.Request(
        UPDATE_URL + "?" + params,
        headers={"User-Agent": "Mozilla/5.0 Edg/130.0", "Accept": "application/octet-stream, */*"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        data, final_url = response.read(), response.geturl()
        content_type = response.headers.get("Content-Type", "")
    if len(data) < 1024:
        raise ValueError("Downloaded package is unexpectedly small: %d bytes" % len(data))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return data, final_url, content_type

def extract_safely(zf: zipfile.ZipFile, root: Path):
    records = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        rel = PurePosixPath(info.filename)
        if rel.is_absolute() or any(part in ("", "..") for part in rel.parts):
            continue
        raw = zf.read(info.filename)
        dest = root.joinpath(*rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        records.append({"path": rel.as_posix(), "size_bytes": len(raw), "sha256": digest(raw), "extension": Path(rel.name).suffix.lower()})
    return records

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension-id", default=os.getenv("EXTENSION_ID", DEFAULT_ID))
    parser.add_argument("--output", default="analysis/edge")
    parser.add_argument("--scratch", default=os.getenv("RUNNER_TEMP", tempfile.gettempdir()) + "/redrop-dropew")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-p]{32}", args.extension_id):
        parser.error("Extension ID must be 32 characters from the Chromium a-p alphabet.")

    scratch = Path(args.scratch)
    if scratch.exists():
        shutil.rmtree(scratch)
    unpacked = scratch / "unpacked"
    unpacked.mkdir(parents=True, exist_ok=True)
    package, final_url, content_type = download_crx(args.extension_id, scratch / "extension.crx")
    payload, package_format = unwrap_crx(package)
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        if "manifest.json" not in zf.namelist():
            raise ValueError("manifest.json is missing from CRX.")
        manifest = json.loads(zf.read("manifest.json").decode("utf-8-sig"))
        inventory = extract_safely(zf, unpacked)

    js_files = [row for row in inventory if row["extension"] in (".js", ".mjs", ".cjs")]
    counts, hosts, source_maps, js_metrics = Counter(), Counter(), [], []
    for row in js_files:
        source = (unpacked / row["path"]).read_text(encoding="utf-8", errors="replace")
        if "sourceMappingURL=" in source:
            source_maps.append(row["path"])
        for category, patterns in MARKERS.items():
            for pattern in patterns:
                counts[category] += len(re.findall(pattern, source, re.I))
        for found in URL_RE.findall(source):
            try:
                host = (urllib.parse.urlsplit(found.rstrip(".,;:!?)]}")).hostname or "").lower()
                if host:
                    hosts[host] += 1
            except ValueError:
                pass
        js_metrics.append({"path": row["path"], "bytes": row["size_bytes"], "line_count": source.count("\n") + 1, "looks_minified": row["size_bytes"] / max(1, source.count("\n") + 1) > 1200})

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    keys = ["name", "short_name", "version", "version_name", "manifest_version", "description", "permissions", "host_permissions", "optional_permissions", "optional_host_permissions", "background", "action", "browser_action", "side_panel", "options_page", "options_ui", "content_scripts", "web_accessible_resources", "commands", "storage", "externally_connectable"]
    manifest_summary = {key: manifest[key] for key in keys if key in manifest}
    (output / "manifest-summary.json").write_text(json.dumps(manifest_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "code-indicators.json").write_text(json.dumps({
        "note": "Static text indicators, not proof of runtime behavior.",
        "marker_counts": dict(sorted(counts.items())),
        "javascript_files": js_metrics,
        "source_map_references": source_maps,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "network-hosts.json").write_text(json.dumps({
        "note": "Only hostname counts are retained. URLs, paths, query strings, and request contents are not committed.",
        "host_occurrences": dict(sorted(hosts.items())),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (output / "file-inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "size_bytes", "sha256", "extension"])
        writer.writeheader()
        writer.writerows(sorted(inventory, key=lambda row: row["path"]))

    report = [
        "# Dropew Edge extension static analysis", "",
        "- Extension ID: " + args.extension_id,
        "- Package name: " + str(manifest.get("name", "unknown")),
        "- Version: " + str(manifest.get("version", "unknown")),
        "- Manifest version: " + str(manifest.get("manifest_version", "unknown")),
        "- Package format: " + package_format,
        "- Downloaded bytes: " + str(len(package)),
        "- SHA-256: " + digest(package),
        "- Response content type: " + content_type,
        "- Download host: " + (urllib.parse.urlsplit(final_url).hostname or "unknown"),
        "", "## Inventory", "",
        "- Total files: " + str(len(inventory)),
        "- JavaScript files: " + str(len(js_files)),
        "- CSS files: " + str(sum(row["extension"] == ".css" for row in inventory)),
        "- Source-map references: " + str(len(source_maps)),
        "", "## Manifest capabilities", "",
        "- Permissions: " + ", ".join(manifest.get("permissions", [])),
        "- Host permissions: " + ", ".join(manifest.get("host_permissions", [])),
        "- Background: " + json.dumps(manifest.get("background", {}), ensure_ascii=False),
        "- Action: " + json.dumps(manifest.get("action", manifest.get("browser_action", {})), ensure_ascii=False),
        "- Side panel: " + json.dumps(manifest.get("side_panel", {}), ensure_ascii=False),
        "", "## Static code indicators", "",
        "| Category | Occurrences |", "|---|---:|",
    ]
    report.extend("| " + key + " | " + str(value) + " |" for key, value in sorted(counts.items()))
    report.extend(["", "## Embedded network host indicators", ""])
    if hosts:
        report.extend(["| Host | Occurrences |", "|---|---:|"])
        report.extend("| " + host + " | " + str(count) + " |" for host, count in sorted(hosts.items()))
    else:
        report.append("No literal network hostnames were detected.")
    report.extend([
        "", "## Interpretation", "",
        "This is static analysis of the publicly distributed extension package. Counts and hostnames are indicators only; validate behavior with controlled test traffic.",
        "",
        "The package does not contain private server implementation, database, account system, or cloud storage internals. No original source files, assets, credentials, tokens, cookies, request bodies, or query strings are committed.",
        "",
        "The downloaded CRX and unpacked files remain only in the ephemeral GitHub Actions runner workspace.",
    ])
    (output / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("Analysis written to " + str(output))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
