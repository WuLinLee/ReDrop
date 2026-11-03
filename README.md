# ReDrop

A clean-room, research-led reimplementation of the user-facing workflows of Dropew ("Drop everywhere").

## Scope

This repository is for interoperability research and an original implementation. It does **not** redistribute Dropew's proprietary source, bundled assets, credentials, tokens, or server-side code.

The research pipeline downloads the publicly distributed Microsoft Edge extension and the Android package, inspects their structure, runs static analysis and performs Android DEX decompilation in an ephemeral GitHub Actions runner. Sanitized reports and structural summaries are committed to `main`; the original CRX/APK and decompiled source trees are not.

## Research targets

- Product: Dropew - transfer file and text
- Microsoft Edge Add-ons extension ID: `glglacjhoenjihpamfmokhkocpibpdkh`
- Android package: `com.ztech.dropew`
- Android APK source used: [APKPure package page](https://apkpure.com/p/com.ztech.dropew)
- Official Android App Links: [assetlinks.json](https://dropew.com/.well-known/assetlinks.json)
- Analysis output: `analysis/`

## Current findings

### Edge extension

- Version: 4.3.1; Manifest V3.
- Package inventory: 58 files, including 30 JavaScript files and 5 CSS files.
- Permissions: `storage`, `sidePanel`.
- Background service worker: `background.js`.
- Declared hosts: `https://*.dropew.com/*` and `wss://*.dropew.com/*`.

See [Edge analysis report](analysis/edge/report.md), [manifest summary](analysis/edge/manifest-summary.json), and [static code indicators](analysis/edge/code-indicators.json).

### Android app

The downloaded package was verified to declare `com.ztech.dropew`, matching the official website's Android App Links declaration.

- APK version: 1.0, version code 2.
- Minimum SDK 29; target SDK 35.
- APK size: 5,296,915 bytes.
- SHA-256: `6a6570c9de893f02a6ce6c7ddf8cb3113856b075489526d0b498dbbd26f6609a`.
- DEX inventory: 1 file, 1,628 classes and 7,925 methods.
- Main activity: `com.ztech.dropew.MainActivity`.
- QR scan activity: `com.ztech.dropew.QrScanActivity`.
- Transfer service: `com.ztech.dropew.transfer.TransferService`.
- WebView, CameraX and ZXing-related components are present.
- Static URL indicators include `dropew.com/drop` and `dropew.com/server/android/update`.

The Android package appears to have a small native Android shell around a larger WebView-oriented flow, with QR scanning and a native transfer service. This is an initial static-analysis hypothesis, not a fully verified runtime architecture.

See [Android analysis report](analysis/android/report.md), [APK summary](analysis/android/apk-summary.json), and [JADX structure summary](analysis/android/decompiled-structure.json).

## Automation

Use **Actions → Dropew package audit → Run workflow**. The workflow:

1. Downloads the current public Edge extension package.
2. Audits the Dropew website and official Android App Links.
3. Downloads the Android APK from the configured APKPure page (package name is pinned to `com.ztech.dropew`).
4. Parses the Android Manifest/DEX with Androguard.
5. Runs JADX in the temporary runner workspace and records a sanitized code-structure summary.
6. Commits sanitized analysis outputs to `main`.

A push touching the audit scripts or workflow also runs the audit. The Android job uses the APKPure URL shown above by default.

## What static analysis can establish

- Manifest capabilities, permissions, activities, services, receivers and providers.
- Package structure, DEX class/method counts, native libraries and framework indicators.
- Embedded host/path indicators and references to authentication, transfer, resume, pairing and storage code.
- A basis for a clean-room client and protocol implementation.

Static indicators are clues, not proof of runtime behavior. URL literals may be unused or obsolete. A package cannot reveal private server implementation, database schema, account data, or behavior returned only by the service.

## Next engineering phase

1. Map user-visible flows (QR sign-in, text send, file upload/download, history and device pairing).
2. Observe network behavior only with a test account and test data you control.
3. Document request/response shapes and persistence semantics without collecting private user data.
4. Implement an independent Edge extension, Android client and backend compatibility layer.

## Legal and security notes

Do not publish copied proprietary source or assets. Do not commit cookies, bearer tokens, QR login payloads, personal data, or test-account credentials. Do not use this project to bypass authentication, access controls, quotas, or another user's data.
