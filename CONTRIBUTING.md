# Contributing to Biometric Bypass for LSPosed

First off, thank you for considering contributing! Contributions help keep this module fast, stable, and compatible across a wide range of Android devices and app SDK configurations.

---

## 📜 Code of Conduct

By participating in this project, you agree to maintain a respectful, welcoming, and harassment-free environment for all contributors.

---

## 🛠️ How to Contribute

### 1. Reporting Bugs
- Search existing [Issues](https://github.com/jamamjadalone/android-biometric-bypass-lsposed/issues) to ensure the bug hasn't already been reported.
- If not found, open a new issue with a clear title and provide:
  - Android OS version, ROM build, and device model.
  - LSPosed logcat output (`adb logcat -s LSPosed-Bridge:V BiometricHook:V`).
  - Expected behavior vs. actual behavior.

### 2. Suggesting Features
- Open an issue categorized as a feature request describing the proposed hook extension or optimization.

### 3. Submitting Pull Requests (PRs)

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/android-biometric-bypass-lsposed.git
   cd android-biometric-bypass-lsposed
   ```
3. **Create a topic branch** from `main`:
   ```bash
   git checkout -b feature/support-oem-custom-biometrics
   ```
4. **Make your changes**:
   - Ensure you follow existing conventions (short-circuiting `beforeHookedMethod`, zero-allocation static callbacks, defensive null checks).
   - Verify code compiles cleanly with `./gradlew assembleDebug`.
5. **Commit your changes**:
   - Follow [Conventional Commits](https://www.conventionalcommits.org/):
     - `feat: add hook support for Samsung SemBiometricManager`
     - `fix: prevent potential NPE on Android 8.0 FingerprintManager`
     - `docs: update troubleshooting guide for HyperOS`
6. **Push to your fork and submit a PR**:
   - Open a pull request against the `main` branch with a clear summary of your changes.

---

## 🧪 Development Guidelines

- **Java 17 / SDK 36**: Ensure code conforms to modern Android Java standards.
- **No Heavy Allocations in Hook Paths**: Do not instantiate new objects or run heavy loops inside high-frequency method hooks.
- **Preserve Stability**: Always catch exceptions defensively (`XposedHelpers.findClassIfExists`, guarded calls) so a failed hook will never trigger a System UI crash or bootloop.
- **Per-app config model**: Hooks must be gated behind `Config.forPackage(...)`.
  Do not add hooks that fire for every app unconditionally — the module is
  **inert by default** and only acts for apps explicitly enabled in the config
  file.
- **`system_server` safety**: never hook the `android` package. Applications
  only.
