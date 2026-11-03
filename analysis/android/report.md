# Dropew Android APK static analysis

- Package: com.ztech.dropew
- App name: Dropew
- Version: 1.0 (2)
- Minimum SDK: 29
- Target SDK: 35
- APK size: 5296915 bytes
- APK SHA-256: 6a6570c9de893f02a6ce6c7ddf8cb3113856b075489526d0b498dbbd26f6609a
- Downloaded container SHA-256: 6a6570c9de893f02a6ce6c7ddf8cb3113856b075489526d0b498dbbd26f6609a
- Embedded split APKs: 0

## Manifest and components

- Activities: 5
- Services: 4
- Receivers: 1
- Providers: 2
- Main activity: com.ztech.dropew.MainActivity
- Permissions: android.permission.ACCESS_NETWORK_STATE, android.permission.CAMERA, android.permission.FOREGROUND_SERVICE, android.permission.FOREGROUND_SERVICE_DATA_SYNC, android.permission.INTERNET, android.permission.POST_NOTIFICATIONS, android.permission.REQUEST_INSTALL_PACKAGES, com.ztech.dropew.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
- Application flags: {"allowBackup": "false"}

## DEX and libraries

- DEX files: 1
- Classes: 1628
- Methods: 7925
- Unique DEX strings: 9822
- Native libraries: libimage_processing_util_jni.so, libsurface_util_jni.so, libzxingcpp_android.so, libimage_processing_util_jni.so, libsurface_util_jni.so, libzxingcpp_android.so

## Framework indicators

- WebView: 2

## Feature indicators

- authentication: 46
- file_transfer: 25
- resumable_transfer: 100
- device_linking: 10
- persistent_storage: 3

## Network endpoint indicators

| Scheme | Host | Path prefix | Occurrences |
|---|---|---|---:|
| https | accounts.google.com | /o/oauth2/revoke | 1 |
| https | dropew.com | / | 1 |
| https | dropew.com | /drop | 1 |
| https | dropew.com | /server/android/update | 1 |
| https | issuetracker.google.com | /issues/new | 1 |
| https | www.googleapis.com | /auth/games | 1 |
| https | www.googleapis.com | /auth/games_lite | 1 |

## Limitations

- Static analysis only; indicator counts do not prove runtime behavior.
- No decompiled source, raw DEX strings, tokens, cookies, or user data are committed.
- The private server implementation and server-side account/storage logic are not recoverable from this APK alone.
- Validate network behavior only with a test account and test data that you control.
