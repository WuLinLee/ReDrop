# Dropew Edge extension static analysis

- Extension ID: glglacjhoenjihpamfmokhkocpibpdkh
- Package name: __MSG_extName__
- Version: 4.3.1
- Manifest version: 3
- Package format: crx3
- Downloaded bytes: 424583
- SHA-256: abe7b3fdfcd74b0a182dc9f18ed385ff5cf7dac1da3eb296153ae857f1ad975e
- Response content type: application/x-chrome-extension
- Download host: msedgeextensions.f.tlu.dl.delivery.mp.microsoft.com

## Inventory

- Total files: 58
- JavaScript files: 30
- CSS files: 5
- Source-map references: 0

## Manifest capabilities

- Permissions: storage, sidePanel
- Host permissions: https://*.dropew.com/*, wss://*.dropew.com/*
- Background: {"service_worker": "background.js"}
- Action: {"default_icon": "drop.png"}
- Side panel: {}

## Static code indicators

| Category | Occurrences |
|---|---:|
| authentication | 33 |
| browser_storage | 5 |
| file_transfer | 51 |
| messaging | 6 |
| network | 13 |
| resumable_transfer | 26 |
| web_storage | 72 |

## Embedded network host indicators

| Host | Occurrences |
|---|---:|
| $ | 10 |
| apkpure.com | 1 |
| apps.apple.com | 1 |
| chromewebstore.google.com | 1 |
| dev.dropew.com | 2 |
| dropew.com | 2 |
| intl-tel-input.com | 1 |
| metrics.dropew.com | 1 |
| www.w3.org | 26 |

## Interpretation

This is static analysis of the publicly distributed extension package. Counts and hostnames are indicators only; validate behavior with controlled test traffic.

The package does not contain private server implementation, database, account system, or cloud storage internals. No original source files, assets, credentials, tokens, cookies, request bodies, or query strings are committed.

The downloaded CRX and unpacked files remain only in the ephemeral GitHub Actions runner workspace.
