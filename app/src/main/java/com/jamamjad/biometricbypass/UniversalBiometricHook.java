package com.jamamjad.biometricbypass;

import android.hardware.biometrics.BiometricManager;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

/**
 * Hook engine that safely adjusts biometric framework availability queries
 * for system services and client applications on custom ROM environments.
 */
public class UniversalBiometricHook implements IXposedHookLoadPackage {

    private static final String TAG = "UniversalBiometricHook: ";

    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        hookFingerprintManager(lpparam.classLoader);
        hookBiometricManager(lpparam.classLoader);
    }

    private void hookFingerprintManager(ClassLoader classLoader) {
        try {
            Class<?> fpManagerClass = XposedHelpers.findClassIfExists(
                    "android.hardware.fingerprint.FingerprintManager", classLoader);
            if (fpManagerClass == null) {
                return;
            }

            // Hook isHardwareDetected() -> true
            XposedHelpers.findAndHookMethod(fpManagerClass, "isHardwareDetected", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(true);
                }
            });

            // Hook hasEnrolledFingerprints() -> true
            XposedHelpers.findAndHookMethod(fpManagerClass, "hasEnrolledFingerprints", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(true);
                }
            });

            // Hook hasEnrolledFingerprints(int userId) -> true
            try {
                XposedHelpers.findAndHookMethod(fpManagerClass, "hasEnrolledFingerprints", int.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(true);
                    }
                });
            } catch (Throwable ignored) {
                // Some Android variations might not expose the overload
            }

            XposedBridge.log(TAG + "FingerprintManager methods successfully hooked.");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Failed to hook FingerprintManager: " + t.getMessage());
        }
    }

    private void hookBiometricManager(ClassLoader classLoader) {
        try {
            Class<?> bioManagerClass = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricManager", classLoader);
            if (bioManagerClass == null) {
                return;
            }

            // Hook canAuthenticate() -> BIOMETRIC_SUCCESS (0)
            try {
                XposedHelpers.findAndHookMethod(bioManagerClass, "canAuthenticate", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(BiometricManager.BIOMETRIC_SUCCESS);
                    }
                });
            } catch (Throwable ignored) {}

            // Hook canAuthenticate(int authenticators) -> BIOMETRIC_SUCCESS (0)
            try {
                XposedHelpers.findAndHookMethod(bioManagerClass, "canAuthenticate", int.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        param.setResult(BiometricManager.BIOMETRIC_SUCCESS);
                    }
                });
            } catch (Throwable ignored) {}

            XposedBridge.log(TAG + "BiometricManager methods successfully hooked.");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "Failed to hook BiometricManager: " + t.getMessage());
        }
    }
}
