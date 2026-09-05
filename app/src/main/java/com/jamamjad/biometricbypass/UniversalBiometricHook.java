package com.jamamjad.biometricbypass;

import android.hardware.biometrics.BiometricManager;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * Hardened Biometric State Interceptor
 * - Uses short-circuiting beforeHookedMethod to prevent native HAL null-pointer crashes.
 * - Reuses static hook instances to minimize heap allocations and GC pressure.
 * - Supports AOSP, AndroidX, and legacy hardware compatibility APIs.
 */
public class UniversalBiometricHook implements IXposedHookLoadPackage {

    private static final String TAG = "BiometricHook";
    private static final boolean DEBUG = false; // Disable in production to eliminate log overhead

    // Reusable singletons to prevent excessive object allocation
    private static final XC_MethodHook RETURN_TRUE = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            param.setResult(true);
        }
    };

    private static final XC_MethodHook RETURN_BIOMETRIC_SUCCESS = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            // BiometricManager.BIOMETRIC_SUCCESS = 0
            param.setResult(BiometricManager.BIOMETRIC_SUCCESS);
        }
    };

    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (lpparam.classLoader == null) {
            return;
        }

        hookFingerprintManager(lpparam.classLoader);
        hookBiometricManager(lpparam.classLoader);
        hookAndroidXBiometrics(lpparam.classLoader);
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

    private void hookSafely(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
        try {
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
        } catch (NoSuchMethodError ignored) {
            // Normal across different Android SDK levels / OEM variants
        } catch (Throwable t) {
            logError("Error hooking " + clazz.getSimpleName() + "#" + methodName, t);
        }
    }

    private static void logError(String message, Throwable t) {
        if (DEBUG) {
            XposedBridge.log(TAG + ": " + message + " -> " + t.getMessage());
        }
    }
}
