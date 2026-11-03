#!/usr/bin/env python3
"""Inspect public Dropew website metadata for official mobile-app entry points."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

BASE = "https://dropew.com/"
USER_AGENT = "Mozilla/5.0 (compatible; ReDropResearch/0.1; +https://github.com/WuLinLee/ReDrop)"
INTERESTING = re.compile(r"(android|apk|google.?play|play\.google|appgallery|huawei|mobile|download|manifest|service.?worker)", re.I)

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.meta = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append({"kind": "anchor", "href": a["href"], "text": ""})
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.links.append({"kind": "link", "rel": a.get("rel", ""), "href": a["href"]})
        elif tag == "meta":
            self.meta.append({"name": a.get("name"), "property": a.get("property"), "content": a.get("content")})

def fetch(url: str, limit: int = 2_000_000):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*"})
    with urllib.request.urlopen(request, timeout=40) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Response exceeded size limit: " + url)
        return data, response.geturl(), response.headers.get("Content-Type", "")

def main():
    out = Path("analysis/website")
    out.mkdir(parents=True, exist_ok=True)
    result = {"source": BASE, "fetch_ok": False, "links": [], "scripts": [], "meta": [], "manifest": None, "assetlinks": None, "errors": []}
    try:
        raw, final_url, content_type = fetch(BASE)
        html = raw.decode("utf-8", "replace")
        parser = PageParser()
        parser.feed(html)
        result["fetch_ok"] = True
        result["final_url"] = final_url
        result["content_type"] = content_type
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        result["title"] = title_match.group(1).strip() if title_match else None
        result["meta"] = parser.meta
        result["scripts"] = [urllib.parse.urljoin(final_url, s) for s in parser.scripts]
        for item in parser.links:
            resolved = urllib.parse.urljoin(final_url, item["href"])
            if item.get("kind") == "anchor":
                result["links"].append({"kind": "anchor", "url": resolved, "text": item.get("text", "")})
            else:
                result["links"].append({"kind": "link", "rel": item.get("rel", ""), "url": resolved})
        result["links"] = [x for x in result["links"] if INTERESTING.search(x["url"] + " " + x.get("text", "") + " " + x.get("rel", ""))]
        manifests = [x["url"] for x in result["links"] if "manifest" in x.get("rel", "").lower() or "manifest" in x["url"].lower()]
        if manifests:
            try:
                body, resolved, _ = fetch(manifests[0], limit=500_000)
                result["manifest"] = {"url": resolved, "data": json.loads(body.decode("utf-8", "replace"))}
            except Exception as exc:
                result["errors"].append("manifest: " + str(exc))
    except Exception as exc:
        result["errors"].append("homepage: " + str(exc))

    try:
        body, final, _ = fetch("https://dropew.com/.well-known/assetlinks.json", limit=500_000)
        result["assetlinks"] = {"url": final, "data": json.loads(body.decode("utf-8", "replace"))}
    except urllib.error.HTTPError as exc:
        result["assetlinks"] = {"http_status": exc.code}
    except Exception as exc:
        result["errors"].append("assetlinks: " + str(exc))

    (out / "mobile-entrypoints.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# Dropew website / mobile entry-point audit", "", "- Website fetched: " + str(result["fetch_ok"]), "- Final URL: " + str(result.get("final_url", "unavailable")), "- Title: " + str(result.get("title", "unavailable")), "", "## Candidate links", ""]
    if result["links"]:
        lines += ["| Type | URL |", "|---|---|"]
        lines += ["| " + x.get("kind", "link") + " | " + x["url"] + " |" for x in result["links"]]
    else:
        lines.append("No Android or app-store related links were exposed in the parsed HTML.")
    lines += ["", "## Web App Manifest", "", "A manifest is present." if result["manifest"] else "No manifest link was identified in the parsed HTML.", "", "## Android App Links", "", "See mobile-entrypoints.json for the public assetlinks.json response.", "", "## Errors", ""]
    lines += ["- " + x for x in result["errors"]] if result["errors"] else ["None"]
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Website audit written to analysis/website")

if __name__ == "__main__":
    main()
