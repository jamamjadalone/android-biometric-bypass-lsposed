# Universal Biometric Redirection Core

<div align="center">

[![Latest Release](https://img.shields.io/github/v/release/jamamjadalone/android-biometric-bypass-lsposed?color=06B6D4&label=release&logo=github&style=for-the-badge)](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/jamamjadalone/android-biometric-bypass-lsposed/build_apk.yml?branch=main&label=CI%2FCD&logo=githubactions&style=for-the-badge)](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge&logo=apache)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B%20(API%2026--36)-3DDC84.svg?style=for-the-badge&logo=android)](https://developer.android.com)
[![Framework](https://img.shields.io/badge/Framework-LSPosed%20%2F%20API%2093%2B-8B5CF6.svg?style=for-the-badge&logo=android)](https://github.com/LSPosed/LSPosed)
[![Language](https://img.shields.io/badge/Language-Java%2017-E76F51.svg?style=for-the-badge&logo=openjdk)](https://www.oracle.com/java/)

<p align="center">
  <b>High-performance, non-blocking biometric framework interceptor for custom ROMs, GSI builds, and AOSP devices.</b>
</p>

</div>

---

## 📖 Overview

**Universal Biometric Redirection Core** is a hardened system-level [LSPosed](https://github.com/LSPosed/LSPosed) module engineered to resolve credential discovery bottlenecks on custom Android distributions (LineageOS, Pixel Experience, crDroid, GSI). When devices feature uncalibrated, unconfigured, or faulty biometric hardware, target client apps often refuse to open or present authentication fallback workflows.

This module intercepts framework and Jetpack compatibility queries at runtime, short-circuiting hardware HAL dependency checks and reporting healthy, enrolled sensor availability to client applications.

---

## ⚡ Key Features

- 🛡️ **Zero Native HAL Crashes**: Employs short-circuiting `beforeHookedMethod` execution, eliminating `NullPointerException` and `DeadObjectException` caused by broken hardware binders.
- 🚀 **Zero-GC Object Reusability**: Utilizes static singleton hook callbacks (`RETURN_TRUE`, `RETURN_BIOMETRIC_SUCCESS`) to prevent heap allocation overhead and eliminate runtime GC churn.
- 📦 **Modern AndroidX Biometrics Layer**: Complete coverage for both legacy framework APIs (`FingerprintManager`, `BiometricManager`) and modern Jetpack libraries (`androidx.biometric.BiometricManager`, `FingerprintManagerCompat`).
- 📱 **Target SDK 36 Compliant**: Fully compatible with Android 8.0 (Oreo / API 26) through Android 16 QPR2 (Baklava / API 36).
- 🎨 **Material 3 Interface**: Minimal, battery-friendly status dashboard built according to Material You design principles.

---

## 🏗️ Architecture & Execution Flow

```text
┌────────────────────────────────────────────────────────┐
│               Target Android Application               │
│          (Banking / Enterprise / Authenticator)        │
└───────────────────────────┬────────────────────────────┘
                            │ Queries Biometric State
                            ▼
┌────────────────────────────────────────────────────────┐
│            Android Framework / Jetpack API             │
│   • BiometricManager.canAuthenticate(...)              │
│   • FingerprintManager.isHardwareDetected()            │
│   • FingerprintManager.hasEnrolledFingerprints(...)    │
│   • androidx.biometric.BiometricManager                │
└───────────────────────────┬────────────────────────────┘
                            │ Intercepted via LSPosed
                            ▼
┌────────────────────────────────────────────────────────┐
│           UniversalBiometricHook (LSPosed)             │
│  [beforeHookedMethod Short-Circuiting Engine]          │
│                                                        │
│  ⚡ Halts call before reaching broken Vendor HAL / TEE  │
│  ⚡ Injects BiometricManager.BIOMETRIC_SUCCESS (0)     │
│  ⚡ Injects enrolled state: TRUE                       │
└───────────────────────────┬────────────────────────────┘
                            │ Returns Spoofed Health State
                            ▼
┌────────────────────────────────────────────────────────┐
│            Application Receives Success Result         │
│          Enables User Passcode / Fallback Path         │
└────────────────────────────────────────────────────────┘
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Device running Android 8.0 - 16 with Root access (Magisk, KernelSU, or APatch).
- [Zygisk](https://github.com/topjohnwu/Magisk) enabled in your root manager.
- [LSPosed Framework](https://github.com/LSPosed/LSPosed) (Zygisk release v1.9.2+ recommended).

### Step-by-Step Configuration
1. **Download & Install**: Grab the latest `UniversalBiometricBypass-vX.X.X.apk` from the [Releases](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/releases) page.
2. **Open LSPosed Manager**: A notification will prompt that a new module is detected.
3. **Enable Module**: Navigate to **Modules** ➔ Select **Biometric Redirection Core** ➔ Toggle **Enable**.
4. **Scope Selection**:
   - Ensure **System Framework (`android`)** is ticked (default).
   - *(Optional)* Check any specific financial, banking, or enterprise apps requiring explicit availability overrides.
5. **Reboot**: Soft reboot your device or restart the Android system server.

---

## 📦 Building from Source

This project compiles with standard Gradle and JDK 17:

```bash
# 1. Clone the repository
git clone https://github.com/jamamjadalone/android-biometric-bypass-lsposed.git
cd android-biometric-bypass-lsposed

# 2. Grant wrapper execution rights (Linux/macOS)
chmod +x gradlew

# 3. Build Debug APK
./gradlew assembleDebug --stacktrace --info
```

The output APK will be generated at:
```text
app/build/outputs/apk/debug/app-debug.apk
```

---

## 🔒 Security & Privacy Notice

> [!IMPORTANT]
> **Privacy Notice**: This module performs local, non-persistent method return adjustments inside your device's memory. It **does NOT** store, record, capture, or transmit user credentials, biometric templates, passwords, PINs, or device identifiers. All operations strictly execute on-device within isolated process sandboxes.

---

## 📄 License

```text
Copyright 2026 Jam Amjad

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
