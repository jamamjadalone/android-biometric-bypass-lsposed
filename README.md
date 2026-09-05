# Universal Biometric Redirection Core (LSPosed)

[![Build & Release](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/actions/workflows/build_apk.yml/badge.svg)](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/actions/workflows/build_apk.yml)
[![Android Support](https://img.shields.io/badge/Android-8.0%20to%2016%20(API%2026--36)-06B6D4.svg)](https://developer.android.com)
[![Framework](https://img.shields.io/badge/LSPosed-Zygisk%20%2F%20Rikka-blueviolet.svg)](https://github.com/LSPosed/LSPosed)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight, system-level LSPosed module engineered to resolve credential detection bottlenecks on custom Android distributions (LineageOS, Pixel Experience, GSI, AOSP) where hardware biometric sensors or calibration blocks prevent authentication handshakes.

---

## Features & System Overrides

- **Target SDK 36 Compliant**: Compatible with Android 16 QPR2 / LineageOS 23.2.
- **FingerprintManager Fallback**:
  - Intercepts `isHardwareDetected()` -> Returns `true`
  - Intercepts `hasEnrolledFingerprints()` & `hasEnrolledFingerprints(int userId)` -> Returns `true`
- **BiometricManager Interface**:
  - Dynamically forces `canAuthenticate()` and `canAuthenticate(int authenticators)` to `BiometricManager.BIOMETRIC_SUCCESS` (`0`).
- **Clean Material 3 UI**: Provides real-time module status inspection and architecture details.

---

## Installation & Configuration

1. **Prerequisites**:
   - Magisk / KernelSU / APatch with Zygisk enabled.
   - [LSPosed Framework](https://github.com/LSPosed/LSPosed) (Zygisk release).
2. **Setup**:
   - Download the latest `UniversalBiometricBypass-vX.X.X.apk` from the [Releases](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/releases) section.
   - Install the APK on your target device.
   - Open LSPosed Manager, enable the **Biometric Redirection Core** module.
   - Ensure the module scope is set to `System Framework (android)` and any target apps requiring hardware checks.
   - Soft reboot or restart the system server.

---

## Privacy & Security Notice

> **Notice:** This utility executes purely local in-memory method modifications within system service boundaries. It does **NOT** log, store, exfiltrate, or transmit user credentials, biometric templates, PINs, or device telemetry. All operations are isolated to your local device runtime environment.

---

## Building from Source

```bash
# Clone the repository
git clone https://github.com/jamamjadalone/android-biometric-bypass-lsposed.git
cd android-biometric-bypass-lsposed

# Build Debug APK
./gradlew assembleDebug
```

The compiled package will be available under:
`app/build/outputs/apk/debug/app-debug.apk`
