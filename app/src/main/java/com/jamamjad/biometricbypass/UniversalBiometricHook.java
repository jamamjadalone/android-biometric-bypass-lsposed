package com.jamamjad.biometricbypass;

import android.content.ContentResolver;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;

import java.util.ArrayList;
import java.util.Collections;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * Hardened Biometric State Interceptor
 * - Uses short-circuiting beforeHookedMethod to prevent native HAL null-pointer crashes.
 * - Reuses static hook instances to minimize heap allocations and GC pressure.
 * - Supports AOSP, AndroidX, and legacy hardware compatibility APIs.
 *
 * ============================================================================
 * FIX BUILD (v1.1.1+) - closes the "No fingerprint enrolled" gaps found on the
 * target device (Samsung Galaxy A52, Android 16 / SDK 36, Vector/LSPosed).
 *
 * v1.1.2 adds developer-option/USB-debugging spoofing: Faysal Bank refuses to
 * start while USB debugging or Developer options are enabled, and reads that
 * state from the Settings provider in its own process. The module returns the
 * "off" value for adb_enabled / adb_wifi_enabled / development_settings_enabled
 * so the banking app starts normally while real adb keeps working.
 *
 * Verified during Step 6 on-device diagnostics:
 *   - Module loads into com.avanza.ambitwizfbl (bank app) - confirmed by
 *     INSTALL_SUMMARY in that process.
 *   - androidx.biometric.BiometricManager.canAuthenticate(15) was already
 *     intercepted and spoofed to 0 (BIOMETRIC_SUCCESS).
 *   - Remaining coverage gaps on SDK 36:
 *       * hidden BiometricManager.canAuthenticate(int,int,String) and
 *         canAuthenticate(int,int,int,String) overloads
 *       * hidden BiometricManager.hasEnrolledBiometrics()
 *       * hidden FingerprintManager.getEnrolledFingerprints(int)
 *     each guarded so an absent method on a given OEM build is a no-op.
 * Diagnostic logging retained (tag "BioDiag"); disable at runtime with:
 *   adb shell setprop persist.biometric.diag 0
 * ============================================================================
 */
public class UniversalBiometricHook implements IXposedHookLoadPackage {

    private static final String TAG = "BiometricHook";
    private static final boolean DEBUG = true; // Diagnostic build: log all hook activity

    // Reusable singers to prevent excessive object allocation
    private static final XC_MethodHook RETURN_TRUE = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            DiagnosticLogger.callSpoofed(
                    param.method.getDeclaringClass().getName(),
                    param.method.getName(),
                    param.args,
                    true);
            param.setResult(true);
        }
    };

    private static final XC_MethodHook RETURN_BIOMETRIC_SUCCESS = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            // BiometricManager.BIOMETRIC_SUCCESS = 0
            DiagnosticLogger.callSpoofed(
                    param.method.getDeclaringClass().getName(),
                    param.method.getName(),
                    param.args,
                    BiometricManager.BIOMETRIC_SUCCESS);
            param.setResult(BiometricManager.BIOMETRIC_SUCCESS);
        }
    };

    // Spoofs a hidden API that reports the enrolled fingerprint LIST (SDK <=28
    // style / internal apps). Returns a single synthetic enrollment so callers
    // that trust this list see "fingerprint enrolled". Built once, safely.
    private static final XC_MethodHook RETURN_ENROLLED_LIST = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            DiagnosticLogger.callSpoofed(
                    param.method.getDeclaringClass().getName(),
                    param.method.getName(),
                    param.args,
                    "non-empty");
            param.setResult(SyntheticEnrollment.INSTANCE);
        }
    };

    private static final class SyntheticEnrollment {
        private static final Object INSTANCE = build();

        private static Object build() {
            try {
                Class<?> fpc = Class.forName("android.hardware.fingerprint.Fingerprint");
                java.lang.reflect.Constructor<?> ctor = fpc.getDeclaredConstructor(
                        byte[].class, int.class, int.class, CharSequence.class, int.class);
                ctor.setAccessible(true);
                Object fp = ctor.newInstance(new byte[1], 0, 1, "fp", 0);
                ArrayList<Object> list = new ArrayList<>(1);
                list.add(fp);
                return Collections.unmodifiableList(list);
            } catch (Throwable t) {
                return Collections.EMPTY_LIST;
            }
        }
    };

    // Observation-only: logs the ORIGINAL result, never modifies it.
    private static final XC_MethodHook OBSERVE_RESULT = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            DiagnosticLogger.callObserved(
                    param.method.getDeclaringClass().getName(),
                    param.method.getName(),
                    param.args,
                    param.getResult());
        }
    };

    // --- Developer-option / USB-debugging spoofing -------------------------
    // Faysal Bank (and similar apps) refuses to start while USB debugging or
    // Developer options are ON. These are read from the Settings provider in
    // the app's own process. We return the "off" value for the specific keys,
    // so the app cannot tell that developer mode is active. The DEVICE's real
    // settings are untouched - adb keeps working normally.
    private static final XC_MethodHook RETURN_DEV_OPTIONS_OFF = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            if (isDeveloperOptionKey(param.args[1])) {
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args, 0);
                param.setResult(0);
            }
        }
    };

    private static final XC_MethodHook RETURN_DEV_OPTIONS_OFF_DEFAULT = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            if (isDeveloperOptionKey(param.args[1])) {
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args, 0);
                param.setResult(0);
            }
        }
    };

    private static final XC_MethodHook RETURN_DEV_OPTIONS_NULL = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            if (isDeveloperOptionKey(param.args[1])) {
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args, "null");
                param.setResult(null);
            }
        }
    };

    private static boolean isDeveloperOptionKey(Object arg) {
        if (!(arg instanceof String)) {
            return false;
        }
        String key = (String) arg;
        return key.equalsIgnoreCase("adb_enabled")
                || key.equalsIgnoreCase("adb_wifi_enabled")
                || key.equalsIgnoreCase("development_settings_enabled");
    }

    private int hooksInstalled;
    private int hooksFailed;

    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (lpparam.classLoader == null) {
            return;
        }

        // Diagnostic context + runtime switch (Phase 12 support).
        DiagnosticLogger.setProcessContext(lpparam.packageName, lpparam.processName);
        DiagnosticLogger.applyRuntimeSwitch();
        DiagnosticLogger.log("LOADED package=" + lpparam.packageName
                + " process=" + lpparam.processName
                + " isFirstApplication=" + lpparam.isFirstApplication
                + " sdk=" + Build.VERSION.SDK_INT);

        hookFingerprintManager(lpparam.classLoader);
        hookBiometricManager(lpparam.classLoader);
        hookAndroidXBiometrics(lpparam.classLoader);
        hookObserversOnly(lpparam.classLoader);
        hookDeveloperOptionDetectors(lpparam.classLoader);

        // Install summary, per process, for the diagnostic report.
        DiagnosticLogger.log("INSTALL_SUMMARY installed=" + hooksInstalled
                + " failed=" + hooksFailed
                + " package=" + lpparam.packageName
                + " process=" + lpparam.processName);
    }

    private void hookFingerprintManager(ClassLoader classLoader) {
        try {
            Class<?> fpClass = XposedHelpers.findClassIfExists(
                    "android.hardware.fingerprint.FingerprintManager", classLoader);
            if (fpClass != null) {
                hookSafely(fpClass, "isHardwareDetected", RETURN_TRUE);
                hookSafely(fpClass, "hasEnrolledFingerprints", RETURN_TRUE);
                hookSafely(fpClass, "hasEnrolledFingerprints", int.class, RETURN_TRUE);
                // Hidden: returns the raw enrolled-fingerprint list (some apps /
                // internal APIs consult it directly instead of the boolean).
                hookSafely(fpClass, "getEnrolledFingerprints", int.class, RETURN_ENROLLED_LIST);
            }
        } catch (Throwable t) {
            logError("FingerprintManager hook failure", t);
        }
    }

    private void hookBiometricManager(ClassLoader classLoader) {
        try {
            Class<?> bioClass = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricManager", classLoader);
            if (bioClass != null) {
                hookSafely(bioClass, "canAuthenticate", RETURN_BIOMETRIC_SUCCESS);
                hookSafely(bioClass, "canAuthenticate", int.class, RETURN_BIOMETRIC_SUCCESS);
                // Hook canAuthenticate(int, int) found on specific OEM/API versions
                hookSafely(bioClass, "canAuthenticate", int.class, int.class, RETURN_BIOMETRIC_SUCCESS);
                // Hidden overloads present on newer SDK levels (sensor-scoped).
                hookSafely(bioClass, "canAuthenticate", int.class, int.class, String.class, RETURN_BIOMETRIC_SUCCESS);
                hookSafely(bioClass, "canAuthenticate", int.class, int.class, int.class, String.class, RETURN_BIOMETRIC_SUCCESS);
                // Hidden boolean check that some code paths use as the gate for
                // "is a print enrolled at all" before offering biometrics.
                hookSafely(bioClass, "hasEnrolledBiometrics", RETURN_TRUE);
            }
        } catch (Throwable t) {
            logError("BiometricManager hook failure", t);
        }
    }

    private void hookAndroidXBiometrics(ClassLoader classLoader) {
        try {
            // AndroidX BiometricManager hook
            Class<?> androidxBio = XposedHelpers.findClassIfExists(
                    "androidx.biometric.BiometricManager", classLoader);
            if (androidxBio != null) {
                hookSafely(androidxBio, "canAuthenticate", RETURN_BIOMETRIC_SUCCESS);
                hookSafely(androidxBio, "canAuthenticate", int.class, RETURN_BIOMETRIC_SUCCESS);
            }

            // AndroidX FingerprintManagerCompat hook
            Class<?> compatFp = XposedHelpers.findClassIfExists(
                    "androidx.core.hardware.fingerprint.FingerprintManagerCompat", classLoader);
            if (compatFp != null) {
                hookSafely(compatFp, "isHardwareDetected", RETURN_TRUE);
                hookSafely(compatFp, "hasEnrolledFingerprints", RETURN_TRUE);
            }
        } catch (Throwable t) {
            logError("AndroidX Biometric hook failure", t);
        }
    }

    /**
     * Observation-only hooks. These do NOT modify any return value - they exist
     * purely to capture the ORIGINAL result of biometric-adjacent queries so we
     * can identify the real failing path without changing behavior.
     */
    private void hookObserversOnly(ClassLoader classLoader) {
        // KeyguardManager.isKeyguardSecure - commonly consulted for device-credential
        // / fallback availability decisions.
        try {
            Class<?> kgClass = XposedHelpers.findClassIfExists("android.app.KeyguardManager", classLoader);
            if (kgClass != null) {
                hookObserveSafely(kgClass, "isKeyguardSecure");
            }
        } catch (Throwable t) {
            logError("KeyguardManager observer failure", t);
        }

        // BiometricManager.getEnrolledBiometrics(int, String) (API 30+) - returns
        // the enrolled biometric info list; empty list means NOT_ENROLLED.
        try {
            Class<?> bioClass = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricManager", classLoader);
            if (bioClass != null) {
                hookSafely(bioClass, "getEnrolledBiometrics", int.class, String.class, OBSERVE_RESULT);
            }
        } catch (Throwable t) {
            logError("BiometricManager observer failure", t);
        }
    }

    /**
     * Spoofs "developer options / USB debugging are OFF" when the target app
     * reads the Settings provider, without touching the real device settings.
     * Covered: Settings.Global, Settings.Secure, Settings.System.
     */
    private void hookDeveloperOptionDetectors(ClassLoader classLoader) {
        String[] settingsClasses = {
                "android.provider.Settings$Global",
                "android.provider.Settings$Secure",
                "android.provider.Settings$System"
        };
        for (String className : settingsClasses) {
            try {
                Class<?> settings = XposedHelpers.findClassIfExists(className, classLoader);
                if (settings != null) {
                    hookSafely(settings, "getInt",
                            ContentResolver.class, String.class, RETURN_DEV_OPTIONS_OFF);
                    hookSafely(settings, "getInt",
                            ContentResolver.class, String.class, int.class, RETURN_DEV_OPTIONS_OFF_DEFAULT);
                    hookSafely(settings, "getString",
                            ContentResolver.class, String.class, RETURN_DEV_OPTIONS_NULL);
                }
            } catch (Throwable t) {
                logError("Settings hook failure for " + className, t);
            }
        }
    }

    private void hookSafely(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
        try {
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
            hooksInstalled++;
            DiagnosticLogger.hookInstalled(clazz.getName(), methodName);
        } catch (NoSuchMethodError ignored) {
            // Normal across different Android SDK levels / OEM variants
            hooksFailed++;
            DiagnosticLogger.hookFailed(clazz.getName(), methodName, "NoSuchMethod");
        } catch (Throwable t) {
            hooksFailed++;
            DiagnosticLogger.hookFailed(clazz.getName(), methodName, t.getMessage());
            logError("Error hooking " + clazz.getSimpleName() + "#" + methodName, t);
        }
    }

    private void hookObserveSafely(Class<?> clazz, String methodName, Object... parameterTypes) {
        Object[] argsWithCallback = java.util.Arrays.copyOf(parameterTypes, parameterTypes.length + 1);
        argsWithCallback[parameterTypes.length] = OBSERVE_RESULT;
        hookSafely(clazz, methodName, argsWithCallback);
    }

    private static void logError(String message, Throwable t) {
        if (DEBUG) {
            DiagnosticLogger.logError(message, t);
        }
    }
}