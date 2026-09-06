# Agent Rules (MUST READ FIRST)

## ABSOLUTE BUILD RULE — BUILD VIA GITHUB ACTIONS ONLY

NEVER run a local/build-system Gradle build for this project.

- FORBIDDEN on the local PC: `./gradlew assembleDebug`, `gradle build`,
  `./gradlew build`, or any other local Gradle/system build step.
- The ONLY build pipeline is GitHub Actions (`.github/workflows/build_apk.yml`).

After ANY source change, do ONLY this:

1. `git add -A`
2. `git commit -m "..."`        (read versionCode/versionName in app/build.gradle first)
3. `git tag v2.2.0`            (version MUST match app/build.gradle versionName)
4. `git push origin main`
5. `git push origin v2.2.0`    (this triggers the GitHub Actions build + release)
6. Monitor the Actions run:
   https://github.com/jamamjadalone/android-biometric-bypass-lsposed/actions
7. Download the APK from the created release.

Do NOT attempt to build/test locally. Do NOT change the workflow unless strictly
necessary, and if you do, make the smallest possible change (see important.txt).

## Project context

- LSPosed/Xposed module: `com.jamamjad.biometricbypass`
- Entry hook: `com.jamamjad.biometricbypass.UniversalBiometricHook`
- Target scope (arrays.xml): `*` (universal - loads into EVERY app process;
  system_server "android" is SKIPPED in handleLoadPackage() to keep ADB/
  system services safe. v1.1.6+)
- **SAFE UNIVERSAL DESIGN (v2.2)**: Module loads into every app process
  automatically, but is INERT by default — Config.forPackage() returns
  AppConfig.NONE (biometric=false, devOptions=false, usbDebug=false) for
  any app not listed in /data/local/tmp/biobypass_config.json. Users must
  manually enable each app via the in-app UI (MainActivity) before any
  hook fires. Zero pre-enabled auto-start. Full app coverage, per-app
  control.
- Config file: `/data/local/tmp/biobypass_config.json` (root-written, world-readable)
  JSON schema: `{"version":2,"apps":{"pkg":{"biometric":bool,"devOptions":bool,"usbDebug":bool}}}`
- Install/update flow (each GitHub Actions build signs with a NEW debug key,
  so `adb install -r` fails with signature mismatch):
  1. `adb uninstall com.jamamjad.biometricbypass`
  2. `adb install UniversalBiometricBypass-v<VER>.apk`
  3. `adb shell "su -c '/data/adb/lspd/cli modules enable com.jamamjad.biometricbypass'"`
  4. `adb shell "su -c '/data/adb/lspd/cli scope set com.jamamjad.biometricbypass *'"`
     (universal scope via `*`; system_server auto-excluded in code)
- **Safety guarantees**:
  - system_server ("android") is ALWAYS skipped — never hooked
  - No `/system`, `/vendor`, `/boot` partition modifications
  - No Magisk module needed — pure LSPosed/Xposed APK
  - Uninstall = instant return to normal
  - Zero system-level modifications, no bootloop possible
