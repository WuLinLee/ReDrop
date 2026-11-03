# ReDrop

A clean-room, research-led reimplementation of the user-facing workflows of Dropew ("Drop everywhere").

## Scope

This repository is for interoperability research and an original implementation. It does **not** redistribute Dropew's proprietary source, bundled assets, credentials, tokens, or server-side code.

The first automation stage downloads the publicly distributed Microsoft Edge extension package, inspects its manifest and package structure, and generates a sanitized static-analysis report. Original extension files and beautified bundles stay inside the ephemeral GitHub Actions runner and are not committed.

## Current research target

- Product: Dropew - transfer file and text
- Microsoft Edge Add-ons extension ID: `glglacjhoenjihpamfmokhkocpibpdkh`
- Package source: Microsoft Edge Add-ons update service
- Analysis output: `analysis/`

## What the analysis can establish

- Manifest version, permissions, content scripts, background/service worker, extension pages, and entry points.
- Package inventory, source-map presence, bundled libraries, and hashes.
- Publicly embedded API host/path indicators and use of browser storage/network APIs.
- A basis for a clean-room client and protocol implementation.

## Important limitations

The extension package cannot reveal private server implementation, database schema, account data, or undocumented behavior that is only returned by the service. Static URL strings are clues, not proof that an endpoint is currently live. Dynamic traffic analysis requires a test account and an authorized test session; never commit cookies, bearer tokens, QR login payloads, or personal data.

## Run the audit

Use **Actions → Dropew package audit → Run workflow**. The workflow downloads the current package from Microsoft's public extension update endpoint, analyzes it, and commits sanitized reports to `main`.

## Legal and security notes

This project aims to independently reimplement compatible behavior from observable interfaces and protocol metadata. Do not publish copied proprietary source or assets. Do not use this project to bypass authentication, access controls, quotas, or another user's data.