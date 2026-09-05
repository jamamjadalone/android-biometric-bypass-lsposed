package com.jamamjad.biometricbypass;

import android.hardware.biometrics.BiometricManager;
import android.os.Build;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
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
 *
 * ============================================================================
 * v1.1.3 - DEVICE-CREDENTIAL (PIN) FALLBACK (the real bypass), removes the
 * v1.1.2 developer-option/USB-debugging spoof.
 *
 * The device has REAL enrolled fingerprints = 0, so system BiometricService
 * answers ERROR_NO_BIOMETRICS (11) before any prompt can appear. The app-side
 * canAuthenticate spoof cannot change that server-side check. Solution:
 * intercept the biometric request in the app process BEFORE it reaches
 * BiometricService, and force `BiometricManager.Authenticators.DEVICE_CREDENTIAL`
 * (0x8000) into the allowed authenticators. BiometricService then shows the
 * real device PIN screen; on correct PIN entry it mints a genuine auth token
 * and delivers onAuthenticationSucceeded - so the app believes the "fingerprint"
 * authentication really worked (identical to Google's own PIN-fallback UX).
 *
 * Three defense-in-depth interception layers (all app-process only):
 *   1) BiometricPrompt$Params$Builder#build()   - rewrites the freshly built
 *      Params so EVERY downstream path (framework + AndroidX alike) carries
 *      DEVICE_CREDENTIAL.
 *   2) BiometricPrompt#authenticate(Params)     - catches callers that supply
 *      a pre-built Params without going through the Builder hook.
 *   3) IBiometricService$Stub$Proxy#authenticate - the AIDL proxy used inside
 *      this process to talk to system BiometricService; the last net before
 *      the system server sees the request.
 *
 * v1.1.4 - PromptInfo-aware rewrite. On modern AOSP the object that actually
 * crosses the binder into BiometricService is `android.hardware.biometrics.
 * PromptInfo` (the framework base class - BiometricPrompt$Params extends it),
 * and the authenticator mask lives on it. The rewrite layer now recognises
 * PromptInfo (and its subclasses) and uses the public setAllowedAuthenticators()
 * first, field write second, so the service-level call is rewritten whether it
 * is a BiometricPrompt$Params or a raw PromptInfo. DEVICE_CREDENTIAL is OR-ed
 * into the existing mask (keeps keystore-bound requests valid) rather than
 * replacing it.
 *
 * No system files are modified. This is 100% LSPosed-level.
 * ============================================================================
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

    /** BiometricManager.Authenticators.DEVICE_CREDENTIAL = (1 << 15) = 0x8000 */
    private static final int AUTHENTICATOR_DEVICE_CREDENTIAL = 0x8000;

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

    // --- DEVICE-CREDENTIAL (PIN) FALLBACK -----------------------------------
    // Rewrites the authenticators of any BiometricPrompt request to DEVICE_CREDENTIAL
    // (0x8000), so system BiometricService shows the PIN screen instead of failing
    // with ERROR_NO_BIOMETRICS when zero fingerprints are enrolled. The token minted
    // for the PIN is a genuine credential token, so onAuthenticationSucceeded fires.
    private static final XC_MethodHook REWRITE_AUTH_PARAMS = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            if (param.args == null || param.args.length == 0) {
                return;
            }
            for (int i = 0; i < param.args.length; i++) {
                Object a = param.args[i];
                if (isPromptParams(a)) {
                    Object forced = forceDeviceCredential(a);
                    if (forced != null && forced != a) {
                        DiagnosticLogger.callSpoofed(
                                param.method.getDeclaringClass().getName(),
                                param.method.getName(),
                                param.args,
                                "AUTHENTICATORS->DEVICE_CREDENTIAL(0x8000)");
                        param.args[i] = forced;
                    }
                }
            }
        }
    };

    // Rewrites the RESULT of BiometricPrompt$Params$Builder#build().
    private static final XC_MethodHook REWRITE_BUILT_PARAMS = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            Object built = param.getResult();
            if (isPromptParams(built)) {
                Object forced = forceDeviceCredential(built);
                if (forced != null && forced != built) {
                    DiagnosticLogger.callSpoofed(
                            param.method.getDeclaringClass().getName(),
                            param.method.getName(),
                            param.args,
                            "AUTHENTICATORS->DEVICE_CREDENTIAL(0x8000)");
                    param.setResult(forced);
                }
            }
        }
    };

    private static boolean isPromptParams(Object o) {
        if (o == null) {
            return false;
        }
        Class<?> c = o.getClass();
        String n = c.getName();
        // The authenticator mask ultimately lives inside PromptInfo (or a
        // subclass of it). On API 28+ the app-level carrier is
        // BiometricPrompt$Params (= AuthenticationParams), while the object
        // that reaches IBiometricService.authenticate() is a PromptInfo (the
        // framework base class) or a Params subclass. We rewrite either.
        if (n.equals("android.hardware.biometrics.PromptInfo")
                || n.startsWith("android.hardware.biometrics.PromptInfo$")) {
            return true;
        }
        if (n.equals("android.hardware.biometrics.BiometricPrompt$Params")
                || n.equals("android.hardware.biometrics.BiometricPrompt$AuthenticationParams")
                || n.startsWith("android.hardware.biometrics.BiometricPrompt$")) {
            return true;
        }
        // Subclasses of PromptInfo from the open-source framework / vendors.
        while (c != null) {
            Class<?> sup = c.getSuperclass();
            if (sup != null
                    && sup.getName().equals("android.hardware.biometrics.PromptInfo")) {
                return true;
            }
            c = sup;
        }
        return false;
    }

    private static int getAllowedAuthenticators(Object params) {
        try {
            Method m = params.getClass().getMethod("getAllowedAuthenticators");
            Object r = m.invoke(params);
            if (r instanceof Integer) {
                return (Integer) r;
            }
        } catch (Throwable ignored) {
        }
        return -1;
    }

    private static boolean readBoolMethod(Object params, String name) {
        try {
            Method m = params.getClass().getMethod(name);
            Object r = m.invoke(params);
            if (r instanceof Boolean) {
                return (Boolean) r;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Forces a BiometricPrompt Params object to use DEVICE_CREDENTIAL.
     * Strategy: (1) overwrite the private final mAllowedAuthenticators field in
     * place (preserves the entire object, including title/opPackageName/flags);
     * (2) if the platform refuses field writes, rebuild the same AuthenticationParams
     * shape with the forced authenticator via its public constructor / Builder.
     */
    private static Object forceDeviceCredential(Object params) {
        if (params == null) {
            return null;
        }
        int current = getAllowedAuthenticators(params);
        if (current == -1) {
            // Unreadable - leave untouched rather than risk a broken Parcelable.
            return params;
        }
        // Already credential-guided (credential-only or biometric+credential):
        // BiometricService auto-falls back to PIN when nothing is enrolled.
        if ((current & AUTHENTICATOR_DEVICE_CREDENTIAL) != 0) {
            return params;
        }
        // OR in DEVICE_CREDENTIAL while KEEPING the original biometric bits.
        // BiometricService sees "no biometric enrolled, credential allowed" and
        // automatically falls back to the device PIN screen. Preserving the
        // original mask also keeps keystore-bound cryptographic requests valid.
        if (overwriteAllowedAuthenticators(params,
                current | AUTHENTICATOR_DEVICE_CREDENTIAL)) {
            return params;
        }
        Object rebuilt = rebuildAuthenticationParams(params);
        return rebuilt != null ? rebuilt : params;
    }

    private static boolean overwriteAllowedAuthenticators(Object params, int value) {
        // Preferred path: the public setter (present on PromptInfo and on
        // BiometricPrompt$Params on modern SDKs). It updates the backing field
        // and keeps the object fully usable for marshalling across the binder.
        try {
            Method setter = params.getClass().getMethod("setAllowedAuthenticators", int.class);
            setter.invoke(params, value);
            return getAllowedAuthenticators(params) == value;
        } catch (Throwable ignored) {
            // fall through to the field rewrite below
        }
        try {
            Class<?> c = params.getClass();
            Field f = null;
            while (c != null && f == null) {
                try {
                    f = c.getDeclaredField("mAllowedAuthenticators");
                } catch (NoSuchFieldException e) {
                    c = c.getSuperclass();
                }
            }
            if (f == null) {
                return false;
            }
            f.setAccessible(true);
            f.setInt(params, value);
            return getAllowedAuthenticators(params) == value;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Rebuilds a Params/AuthenticationParams object as AuthenticationParams with
     * the forced authenticator, preserving the boolean flags the caller set.
     */
    private static Object rebuildAuthenticationParams(Object original) {
        try {
            // Walk to the concrete AuthenticationParams class if we only see Params.
            Class<?> target = original.getClass();
            if (!target.getName().equals("android.hardware.biometrics.BiometricPrompt$AuthenticationParams")) {
                Class<?> loaded = XposedHelpers.findClassIfExists(
                        "android.hardware.biometrics.BiometricPrompt$AuthenticationParams",
                        original.getClass().getClassLoader());
                if (loaded != null) {
                    target = loaded;
                }
            }
            Constructor<?>[] ctors = target.getDeclaredConstructors();
            for (Constructor<?> c : ctors) {
                Class<?>[] types = c.getParameterTypes();
                if (types.length < 1 || types[0] != int.class) {
                    continue;
                }
                boolean allBoolean = true;
                for (int i = 1; i < types.length; i++) {
                    if (types[i] != boolean.class) {
                        allBoolean = false;
                        break;
                    }
                }
                if (!allBoolean) {
                    continue;
                }
                c.setAccessible(true);
                Object[] args = new Object[types.length];
                int originalAuths = getAllowedAuthenticators(original);
                args[0] = (originalAuths >= 0)
                        ? (originalAuths | AUTHENTICATOR_DEVICE_CREDENTIAL)
                        : AUTHENTICATOR_DEVICE_CREDENTIAL;
                boolean confirm = readBoolMethod(original, "isConfirmCredentialRequired");
                boolean promptEnabled = readBoolMethod(original, "isBiometricPromptEnabled");
                boolean ignoreEnrollment = readBoolMethod(original, "isIgnoreEnrollmentState");
                boolean disallowSkip = readBoolMethod(original, "isDisallowSkipPrompt");
                for (int i = 1; i < args.length; i++) {
                    switch (i - 1) {
                        case 0:
                            args[i] = confirm;
                            break;
                        case 1:
                            args[i] = promptEnabled;
                            break;
                        case 2:
                            args[i] = ignoreEnrollment;
                            break;
                        case 3:
                            args[i] = disallowSkip;
                            break;
                        default:
                            args[i] = false;
                            break;
                    }
                }
                return c.newInstance(args);
            }

            // Last resort: the public Builder API.
            Class<?> builderClass = XposedHelpers.findClassIfExists(
                    target.getName() + "$Builder", target.getClassLoader());
            if (builderClass != null) {
                Object builder = builderClass.getDeclaredConstructor().newInstance();
                XposedHelpers.callMethod(builder, "setAllowedAuthenticators",
                        AUTHENTICATOR_DEVICE_CREDENTIAL);
                return XposedHelpers.callMethod(builder, "build");
            }
        } catch (Throwable t) {
            logError("rebuildAuthenticationParams failed", t);
        }
        return null;
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
        hookDeviceCredentialFallback(lpparam.classLoader);

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
     * v1.1.3 core: forces every biometric request in this app process to use the
     * DEVICE-CREDENTIAL (PIN) path, replacing the removed v1.1.2 dev-option spoof.
     *
     * 1) BiometricPrompt$Params$Builder#build() - rewrites the built Params; both
     *    framework BiometricPrompt and AndroidX build their Params with this Builder.
     * 2) BiometricPrompt#authenticate(Params) - catches callers passing a pre-built
     *    Params object directly.
     * 3) IBiometricService$Stub$Proxy#authenticate(...) - the in-process AIDL proxy
     *    to system BiometricService; rewrites the Params argument right before it is
     *    marshalled across the binder.
     */
    private void hookDeviceCredentialFallback(ClassLoader classLoader) {
        try {
            Class<?> bioPrompt = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt", classLoader);
            Class<?> paramsClass = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt$Params", classLoader);
            if (bioPrompt != null && paramsClass != null) {
                hookSafely(bioPrompt, "authenticate", paramsClass, REWRITE_AUTH_PARAMS);
            }

            Class<?> builder = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt$Params$Builder", classLoader);
            if (builder != null) {
                hookAllSafely(builder, "build", REWRITE_BUILT_PARAMS);
            }

            Class<?> proxy = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.IBiometricService$Stub$Proxy", classLoader);
            if (proxy != null) {
                hookAllSafely(proxy, "authenticate", REWRITE_AUTH_PARAMS);
            }
        } catch (Throwable t) {
            logError("Device-credential fallback hook failure", t);
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

    private void hookAllSafely(Class<?> clazz, String methodName, XC_MethodHook hook) {
        try {
            Set<XC_MethodHook.Unhook> unhooks = XposedBridge.hookAllMethods(clazz, methodName, hook);
            hooksInstalled += unhooks.size();
            DiagnosticLogger.log("INSTALL_OK class=" + clazz.getName()
                    + " method=" + methodName
                    + " overloads=" + unhooks.size());
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