#!/usr/bin/env python3
"""Download an APK from an APKPure URL into the ephemeral CI workspace."""
from __future__ import annotations
import argparse, hashlib, os, sys, urllib.parse, urllib.request
from pathlib import Path

MAX_BYTES = 1_500_000_000
ALLOWED = ("apkpure.com",)

def trusted(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in ALLOWED)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()
    parsed = urllib.parse.urlsplit(args.url)
    if parsed.scheme != "https" or not trusted(parsed.hostname or ""):
        parser.error("Only HTTPS URLs on apkpure.com or its subdomains are accepted.")
    if args.package != "com.ztech.dropew":
        parser.error("The package name is pinned to com.ztech.dropew for this project.")

    download_url = args.url
    page_parts = [part for part in parsed.path.split("/") if part]
    if (parsed.hostname or "").lower() in ("apkpure.com", "www.apkpure.com") and len(page_parts) >= 2 and page_parts[0] == "p" and page_parts[1] == args.package:
        download_url = "https://d.apkpure.com/b/APK/" + args.package + "?version=latest"
    request = urllib.request.Request(download_url, headers={
        "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36",
        "Accept": "application/vnd.android.package-archive, application/octet-stream, */*",
    })
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=90) as response, output.open("wb") as handle:
            final_host = urllib.parse.urlsplit(response.geturl()).hostname or ""
            if not trusted(final_host):
                raise ValueError("Redirect left APKPure domain: " + final_host)
            content_type = response.headers.get("Content-Type", "")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError("APK exceeds configured 1.5 GB size limit.")
                digest.update(chunk)
                handle.write(chunk)
        with output.open("rb") as handle:
            magic = handle.read(8)
        if magic[:4] != b"PK\x03\x04":
            sample = output.read_bytes()[:200].decode("utf-8", "replace")
            raise ValueError("Download is not an APK ZIP archive. Content-Type=%s; body=%r" % (content_type, sample))
        print("Downloaded bytes: %d" % total)
        print("SHA-256: %s" % digest.hexdigest())
        print("Redirect host: %s" % final_host)
        print("Content-Type: %s" % content_type)
        print("Temporary file: %s" % output)
        return 0
    except Exception:
        if output.exists():
            output.unlink()
        raise

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("APK DOWNLOAD FAILED: " + str(exc), file=sys.stderr)
        raise
