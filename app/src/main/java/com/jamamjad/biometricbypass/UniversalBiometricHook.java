package com.jamamjad.biometricbypass;

import android.hardware.biometrics.BiometricManager;
import android.os.Build;
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
 * DIAGNOSTIC BUILD (Step 5) - NO CHANGE TO RETURN BEHAVIOR.
 *
 * This build only adds structured instrumentation. Every spoof hook logs the
 * call and the override it applies; additional observation-only hooks log the
 * ORIGINAL results of biometric-adjacent queries WITHOUT modifying them.
 * It also logs which package/process the module actually loaded into, so we can
 * verify the LSPosed scope covers the app process (currently arrays.xml scopes
 * ["android"] only, which is a prime suspect for the post-reboot false negative).
 *
 * Logs are written to logcat under tag "BioDiag" and can be read with:
 *   adb logcat -s BioDiag
 * Disable logging at runtime without a rebuild:
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