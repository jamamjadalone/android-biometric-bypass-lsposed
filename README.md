# Biometric Bypass for LSPosed (PIN-Fallback)

<div align="center">

[![Latest Release](https://img.shields.io/github/v/release/jamamjadalone/android-biometric-bypass-lsposed?color=06B6D4&label=release&logo=github&style=for-the-badge)](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/jamamjadalone/android-biometric-bypass-lsposed/build_apk.yml?branch=main&label=CI%2FCD&logo=githubactions&style=for-the-badge)](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge&logo=apache)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B%20(API%2026--36)-3DDC84.svg?style=for-the-badge&logo=android)](https://developer.android.com)
[![Framework](https://img.shields.io/badge/Framework-LSPosed%20%2F%20API%2093%2B-8B5CF6.svg?style=for-the-badge&logo=android)](https://github.com/LSPosed/LSPosed)

<p align="center">
  <b>App-process-only LSPosed module that turns your device PIN into a biometric fallback.</b><br/>
  <i>For devices with non-functional or zero-enrolled biometric hardware.</i>
</p>

</div>

---

## ⚠️ Disclaimer — Read Before Using

> [!WARNING]
> **This is a dual-use tool. Use it only on devices and accounts that you own.**
>
> - This module lets an app authenticate with a **PIN / device credential** when
>   it formally requires a **biometric** (fingerprint / face).
> - **Not every app will work.** Banks and financial apps frequently use
>   obfuscated, device-attestation-gated, or server-validated biometric paths
>   that an app-process hook simply cannot satisfy. **Expect partial
>   compatibility.**
> - If an app rejects the fallback, **the app is doing what it was designed to
>   do** — this is not a bug in the module. Do not use it to defeat the
>   authentication security of an app you do not own.
> - Use at **your own risk**. The author assumes no responsibility for app
>   lockouts, account bans, or device issues that may result from use.
> - Removing the module restores default behavior immediately (no system
>   files are ever modified).

---

## 📖 What This Is

**Biometric Bypass for LSPosed** is an [LSPosed](https://github.com/LSPosed/LSPosed)
framework module that intercepts the biometric APIs inside a target app's
process and rewrites its requests so that Android's **device credential**
(PIN / pattern / password) is accepted where a fingerprint would normally be
required.

It targets a specific, common situation:

> A device has **no enrolled fingerprints** (`hasEnrollments == false`), but the
> user has a **PIN** set. Apps that gate access behind "biometric only" see
> "no biometric enrolled" and refuse to show the fallback that stock Android
> provides (e.g., Google Pay's "use PIN on failure" flow).

The module recreates that stock PIN-fallback UX at the app-process level.

- ✅ **No system modifications** — no `/system`, `/vendor`, or `/boot` changes.
- ✅ **`system_server` is never touched** — the module explicitly skips the
  `android` package, so ADB and system services stay functional.
- ✅ **Inert by default** — nothing is hooked until you explicitly enable an
  app from the in-app UI.
- ✅ **No bootloop possible** — a failed hook is a no-op, never a crash.

---

## 🧱 How It Works

Inside the **selected app's own process** (never system_server), the module:

1. **Rewrites `BiometricPrompt` / AndroidX `PromptInfo`** so the allowed
   authenticators include `DEVICE_CREDENTIAL` (`0x8000`). The system
   `BiometricService` then shows the PIN screen (the same behavior stock
   Android uses when biometrics fail).
2. **Spoofs availability gates** (`BiometricManager.canAuthenticate()`,
   `FingerprintManager.isHardwareDetected()`, enrolled-fingerprint lists) to a
   "healthy" state, so apps that refuse to *open* a fallback flow when nothing
   is enrolled will proceed.
3. **Makes the PIN result a real credential** — when the user correctly enters
   the PIN, Android mints a genuine credential token, and the app's own
   `onAuthenticationSucceeded` fires. No fake crypto is injected.

> Because this happens per-app and at the API boundary, compatibility depends
> entirely on what that specific app uses internally.

---

## ⚡ Key Features

- 🛡️ **App-process only** — the system is never hooked or modified.
- 🔒 **Inert-by-default per-app config** — a JSON file lists exactly which apps
  get hooks and which features (`biometric`, `devOptions`, `usbDebug`).
- 🔄 **PIN fallback** — `BiometricPrompt` requests are rewritten to allow
  `DEVICE_CREDENTIAL`; system `BiometricService` shows the real PIN screen.
- 📦 **Broad API coverage**:
  - Framework: `BiometricManager`, `FingerprintManager`, `IBiometricService`
  - Jetpack/AndroidX: `androidx.biometric.BiometricManager`, `BiometricPrompt`,
    `FingerprintManagerCompat`
  - Obfuscated AndroidX (R8-renamed) — hooked **by method signature**, so
    renamed `a()`/`b()` methods are caught as well.
  - OFSS Digix (Meezan Bank family) `ResourceMapper` + keystore enable-flow fix.
- 📱 **API 26 – 36** (Android 8.0 through Android 16).
- 🧹 **Diagnostic logging** behind tag `BioDiag` for troubleshooting.

---

## 📁 Compatibility

> [!NOTE]
> **This module is best-effort, not guaranteed.** Results vary by app.

| Category | Typical result |
| :- | :- |
| Apps using **stock `BiometricPrompt`** or **unobfuscated AndroidX prompt** | **Likely works** — PIN fallback is inserted cleanly. |
| Apps using **obfuscated AndroidX** or **custom auth SDKs** (banks, fintech) | **May partially work** — gates are spoofed, but prompt behavior depends on the app's internal flow. |
| Apps with **server-side / attestation-based** biometric checks | **Unlikely to work** — the check isn't local, so no in-app hook can satisfy it. |

**Known real-world results (community testing):**
- ✅ Works on some apps using the framework `BiometricPrompt`.
- ⚠️ Meezan Bank, Skrill, and several other fintech apps may not display the
  PIN prompt even with the module enabled — the enable/verify flow differs per
  app and may use unattestable or obfuscated paths.
- ❓ App behavior can change with every app update.

**Always test on a per-app basis.** If it doesn't work for an app, that is
expected behaviour, not a module defect.

---

## ⚙️ Installation & Setup

### Prerequisites

- Android 8.0 – 16 device with **root** (Magisk, KernelSU, or APatch) and
  [Zygisk](https://github.com/topjohnwu/Magisk) enabled.
- [LSPosed](https://github.com/LSPosed/LSPosed) (Zygisk build) installed.

### Steps

1. **Install the module APK** from the
   [Releases](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/releases)
   page.
2. **Enable the module** in your LSPosed Manager:
   - Modules → **Biometric Bypass** → toggle **Enable**.
3. **Set an app scope** for the module so it can load into the target app's
   process. The module loads universally, but stays **inert** until you enable
   it per-app:
   - In LSPosed, set the module scope to the apps you want to try, **or** to
     all apps (`*`) if you prefer to decide from the in-app UI; the module
     never touches `system_server` either way.
4. **Enable the app in the module's in-app UI**:
   - Open the **Biometric Bypass** app.
   - Pick an app and turn on **Biometric** (`biometric: true`).
   - The config is written to `/data/local/tmp/biobypass_config.json`.
5. **Force-stop the target app** (so its next launch loads the hooks), then
   open it and try the biometric flow.

> Scope and config can be managed either from the LSPosed manager or via the
> module CLI (`su -c '/data/adb/lspd/cli ...'`). Config schema:
> `{"version":2, "apps": {"com.example.app": {"biometric": true, "devOptions": false, "usbDebug": false}}}`

---

## 🔍 Troubleshooting

- **PIN prompt still doesn't appear?** Check the app actually uses a local
  `BiometricPrompt` path (see Compatibility above). Some apps gate behind
  attestation that no app-process hook can satisfy.
- **Grab diagnostics:** enable debug logging in the module, then
  `adb logcat -s BioDiag:*` while you reproduce the flow in the target app.
  `INSTALL_OK` lines show which hooks actually installed for that app.
- **Nothing happens at all?** Verify (1) the module is enabled in LSPosed,
  (2) the app is in the LSPosed scope, (3) `bio=true` is present for that
  package in the config file, and (4) the app was force-stopped after the
  config change.

---

## 🏗️ Building from Source

> [!IMPORTANT]
> This repository uses **GitHub Actions** as its official build pipeline.
> A new release is produced automatically when a version tag (matching
> `versionName` in `app/build.gradle`) is pushed. Local Gradle builds are
> discouraged for release distribution.

To build locally for development (JDK 17 required):

```bash
git clone https://github.com/jamamjadalone/android-biometric-bypass-lsposed.git
cd android-biometric-bypass-lsposed
./gradlew assembleDebug
```

Output APK: `app/build/outputs/apk/debug/app-debug.apk`

---

## 🔒 Privacy & Security

- All hooks run **inside the target app's own process** — nothing is persisted
  except the small local config file at `/data/local/tmp/biobypass_config.json`.
- **No credential is ever captured.** The PIN prompt is the genuine system
  dialog; the app receives a normal, authentic authentication result.
- No telemetry, no network access, no data transmission.

Please report vulnerabilities through GitHub's private vulnerability reporting
feature; see [SECURITY.md](SECURITY.md).

---

## 💬 Community & Support

- 📺 YouTube: [@jamamjadalone](https://www.youtube.com/@jamamjadalone)
- 🙏 Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE).