# Agent Rules (MUST READ FIRST)

## ABSOLUTE BUILD RULE — BUILD VIA GITHUB ACTIONS ONLY

NEVER run a local/build-system Gradle build for this project.

- FORBIDDEN on the local PC: `./gradlew assembleDebug`, `gradle build`,
  `./gradlew build`, or any other local Gradle/system build step.
- The ONLY build pipeline is GitHub Actions (`.github/workflows/build_apk.yml`).

After ANY source change, do ONLY this:

1. `git add -A`
2. `git commit -m "..."`        (read versionCode/versionName in app/build.gradle first)
3. `git tag v1.1.3`             (version MUST match app/build.gradle versionName)
4. `git push origin main`
5. `git push origin v1.1.3`     (this triggers the GitHub Actions build + release)
6. Monitor the Actions run:
   https://github.com/jamamjadalone/android-biometric-bypass-lsposed/actions
7. Download the APK from the created release.

Do NOT attempt to build/test locally. Do NOT change the workflow unless strictly
necessary, and if you do, make the smallest possible change (see important.txt).

## Project context

- LSPosed/Xposed module: `com.jamamjad.biometricbypass`
- Entry hook: `com.jamamjad.biometricbypass.UniversalBiometricHook`
- Target scope (arrays.xml): `*` (universal - loads into EVERY app process;
  system_server "android" is skipped in code to keep ADB/system services safe.
  v1.1.6+)
- Install/update flow (each GitHub Actions build signs with a NEW debug key,
  so `adb install -r` fails with signature mismatch):
  1. `adb uninstall com.jamamjad.biometricbypass`
  2. `adb install UniversalBiometricBypass-v<VER>.apk`
  3. `adb shell "su -c '/data/adb/lspd/cli modules enable com.jamamjad.biometricbypass'"`
  4. `adb shell "su -c '/data/adb/lspd/cli scope set com.jamamjad.biometricbypass system com.avanza.ambitwizfbl pk.upaisa.com'"`