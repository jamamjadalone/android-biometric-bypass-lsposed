package com.jamamjad.biometricbypass;

import android.content.Context;
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
 * v1.1.5 - UNIVERSAL bank-app hardening (per understand-itttt plan):
 *   - Hook BiometricManager.getEnrolledBiometrics() to return a synthetic
 *     non-empty list (API 30+ apps gate fingerprint setup on it; empty == NOT
 *     ENROLLED and was blocking the "Enable Fingerprint" toggle).
 *   - Hook FingerprintManager.getEnrolledFingerprints() no-arg return as well.
 *   - Force the REAL builder classes to build a credential-allowed prompt:
 *       framework  BiometricPrompt$Builder / PromptInfo$Builder / Params$Builder
 *       AndroidX   BiometricPrompt$PromptInfo$Builder / BiometricPrompt$Builder
 *     by forcing setDeviceCredentialAllowed(true),
 *     setConfirmationRequired(false), and OR-ing 0x8000 into
 *     setAllowedAuthenticators(...) - so the prompt shows the PIN screen and
 *     the app's own onAuthenticationSucceeded fires with a REAL credential
 *     token (no forged crypto).
 *   - Retains the IBiometricService$Stub$Proxy.authenticate PromptInfo rewrite
 *     as the final in-process net before the binder.
 *
 * v1.1.6 - UNIVERSAL scope (per new-plan.txt):
 *   - arrays.xml scope = "*" (load into EVERY app process).
 *   - handleLoadPackage() SKIPS system_server ("android") so ADB and system
 *     services stay safe (the previous ADB breakage vector).
 *   - ADB/developer-option spoofs for EVERY app process (Settings.Global/
 *     Secure/System getInt/getString for adb_enabled, adb_wifi_enabled and
 *     development_settings_enabled -> 0/off, plus Debug.isDebuggerConnected()
 *     -> false). Harmless for normal apps, satisfies bank anti-debug checks.
 *
 * v1.1.7 - OBFUSCATION-PROOF ANDROIDX HOOKS. Some apps (Meezan Bank / OFSS
 *   Digix = a Cordova app) bundle an R8-obfuscated copy of androidx.biometric
 *   where every method is renamed: BiometricManager.from()->h();
 *   canAuthenticate()->a(); canAuthenticate(int)->b(int);
 *   PromptInfo$Builder.setAllowedAuthenticators()->b(int);
 *   PromptInfo$Builder.build()->a(); PromptInfo.getAllowedAuthenticators()->a().
 *   Canonical-name hooks (setAllowedAuthenticators / canAuthenticate / build)
 *   silently NoSuchMethod in such apps -> the availability gate reports real
 *   AndroidX state and the prompt is never credential-allowed.
 *   FIX: additionally hook AndroidX classes BY METHOD SIGNATURE, which cannot
 *   be obfuscated away:
 *     - androidx.biometric.BiometricManager: every non-static ()int and
 *       (int)int method IS canAuthenticate()/canAuthenticate(int) -> 0.
 *     - androidx.biometric.BiometricPrompt$PromptInfo$Builder /
 *       $BiometricPrompt$Builder: any (int)->Builder method IS
 *       setAllowedAuthenticators -> OR-in DEVICE_CREDENTIAL; any ()->PromptInfo
 *       method IS build() -> force DEVICE_CREDENTIAL on the built PromptInfo.
 *   The framework bridge in these apps still calls the canonical
 *   android.hardware.biometrics.* methods (never obfuscated), so the
 *   framework/service nets remain valid on top.
 *
 * v1.1.8 - MEEZAN ENABLE-FINGERPRINT FIX (keystore keygen + OFSS ResourceMapper).
 *   On-device finding: tapping "Enable Fingerprint" died in
 *   com.ofss.digx.mobile.android.plugins.fingerprintauth.FingerprintAuth.e()
 *   with "At least one biometric must be enrolled to create keys requiring
 *   user authentication for every use". The cause: the plugin branches on
 *   ResourceMapper.l(ctx) == R.bool.ALLOW_FACE_BIOMETRIC (hardcoded FALSE on
 *   this build); FALSE branch adds setUserAuthenticationRequired(true).set
 *   InvalidatedByBiometricEnrollment(true) to the KeyGenParameterSpec, and
 *   keystore2 rejects keygen while zero fingerprints are enrolled - before any
 *   BiometricPrompt is shown. The user's device has a PIN but 0 prints.
 *   FIX (app-process only, OFSS/meezan gated):
 *     - Force android.security.keystore.KeyGenParameterSpec$Builder
 *       setUserAuthenticationRequired(boolean) -> false, so the enable-flow
 *       key is created like Meezan's own "face/allowed" branch does. PIN
 *       prompt (v1.1.3..v1.1.7 layers) still gates access after enrolment.
 *     - Force every static (android.content.Context)->boolean accessor on
 *       com.ofss.digx.mobile.obdxcore.infra.util.ResourceMapper -> true.
 *       Bind lazily through a ClassLoader.loadClass hook because the class is
 *       app-sourced and not yet loaded when handleLoadPackage() runs; the
 *       (Context)->boolean methods are R8-renamed (k/l/m/n/o/p), so they are
 *       matched by signature, not by name. This makes the enable flow use the
 *       credential-allowed prompt and unblocks the later "decrypt" (login)
 *       branch which is itself gated on ResourceMapper.l().
 *
 * v2.0.0 - PER-APP SCOPE & FEATURE CONFIG (replaces universal * scope):
 *   User-selectable apps only. The in-app UI (MainActivity) writes a JSON
 *   config to /data/local/tmp/biobypass_config.json (root, world-readable)
 *   listing EACH selected app and its enabled features:
 *       { biometric, devOptions, usbDebug }
 *   handleLoadPackage() now reads Config.forPackage(packageName) in every
 *   process and:
 *     - biometric  -> installs the full PIN-fallback / prompt-rewrite stack
 *                     (AndroidX + framework + signature + OFSS Digix).
 *     - devOptions -> spoof development_settings_enabled read -> 0 (apps that
 *                     detect "Developer options" being ON).
 *     - usbDebug   -> spoof adb_enabled / adb_wifi_enabled reads -> 0 and
 *                     Debug.isTracing()/isDebuggerConnected() -> false (apps
 *                     that detect USB debugging specifically).
 *   Apps NOT in the config receive NO hooks at all (module inert). This model
 *   mirrors the HMA per-app idea (see HMA_Config in the project folder) but
 *   with our own JSON+flags implementation: you add YOUR banks/apps, not all.
 *   LSPosed scope is likewise written by the UI (su + lspd cli scope set) to
 *   ONLY the selected packages (+ optional "system"); universal * is removed.
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

    // BiometricManager.getEnrolledBiometrics() -> List<BiometricManager.BiometricInfo>.
    // Returns a synthetic single-entry list so API-30+ apps see "enrolled".
    private static final XC_MethodHook RETURN_ENROLLED_BIOMETRICS = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            DiagnosticLogger.callSpoofed(
                    param.method.getDeclaringClass().getName(),
                    param.method.getName(),
                    param.args,
                    "non-empty");
            param.setResult(SyntheticEnrollment.BIOMETRIC_INSTANCE);
        }
    };

    // --- v2.0 DEV-OPTION / USB-DEBUG SPOOF (per-app, gated by config) --------
    // Banks decide to run or refuse based on these Setting reads. v2.0 splits
    // them into two independent feature flags per app (Config.devOptions vs
    // Config.usbDebug). Only the KEY the app actually probes gets spoofed, and
    // only for apps the user selected in the UI.
    private static final String KEY_DEVELOPMENT_SETTINGS_ENABLED = "development_settings_enabled";
    private static final String KEY_ADB_ENABLED = "adb_enabled";
    private static final String KEY_ADB_WIFI_ENABLED = "adb_wifi_enabled";

    // Per-process flags set from Config in handleLoadPackage().
    private static volatile boolean cfgBiometric;
    private static volatile boolean cfgDevOptions;
    private static volatile boolean cfgUsbDebug;

    // 1 == developer-options key, 2 == usb-debug key, 0 == unrelated.
    private static int devOptionKeyType(Object[] args) {
        if (args == null || args.length < 2 || !(args[1] instanceof String)) {
            return 0;
        }
        String key = (String) args[1];
        if (KEY_DEVELOPMENT_SETTINGS_ENABLED.equals(key)) {
            return 1;
        }
        if (KEY_ADB_ENABLED.equals(key) || KEY_ADB_WIFI_ENABLED.equals(key)) {
            return 2;
        }
        return 0;
    }

    private static boolean devOptionKeyAllowed(int type) {
        return (type == 1 && cfgDevOptions) || (type == 2 && cfgUsbDebug);
    }

    // Settings.Global/Secure/System.getInt(ContentResolver, String, int) and
    // the (ContentResolver, String) legacy overload -> force 0 (disabled).
    private static final XC_MethodHook RETURN_DEV_OPTIONS_OFF = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            int type = devOptionKeyType(param.args);
            if (type != 0 && devOptionKeyAllowed(type)) {
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args,
                        "0 (disabled)");
                param.setResult(0);
            }
        }
    };

    // Settings.*.getString(ContentResolver, String) -> "0".
    private static final XC_MethodHook RETURN_DEV_OPTIONS_NULL = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            int type = devOptionKeyType(param.args);
            if (type != 0 && devOptionKeyAllowed(type)) {
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args,
                        "\"0\" (disabled)");
                param.setResult("0");
            }
        }
    };

    // Debug.isTracing() / isDebuggerConnected() -> false (usb-debug feature).
    private static final XC_MethodHook RETURN_NOT_TRACING = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            if (cfgUsbDebug) {
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args,
                        "false");
                param.setResult(false);
            }
        }
    };

    private static final class SyntheticEnrollment {
        private static final Object INSTANCE = build("android.hardware.fingerprint.Fingerprint");
        // BiometricManager.BiometricInfo list (API 28+). Apps that check
        // getEnrolledBiometrics() see "biometric enrolled" instead of empty.
        private static final Object BIOMETRIC_INSTANCE = build("android.hardware.biometrics.BiometricManager$BiometricInfo");

        private static Object build(String className) {
            try {
                Class<?> c = Class.forName(className);
                // Try every known signature across API levels until one works.
                java.lang.reflect.Constructor<?>[] ctors = c.getDeclaredConstructors();
                Object proto = null;
                for (java.lang.reflect.Constructor<?> cand : ctors) {
                    Class<?>[] pt = cand.getParameterTypes();
                    boolean allPrimitive = true;
                    for (Class<?> p : pt) {
                        if (!p.isPrimitive()) {
                            allPrimitive = false;
                            break;
                        }
                    }
                    try {
                        cand.setAccessible(true);
                        Object[] args = new Object[pt.length];
                        if (!allPrimitive) {
                            // Fingerprint-Family: first arg is the enrollment NAME
                            // (byte[] pre-26, CharSequence 26+). Only attempt these.
                            if (pt.length == 0) {
                                continue;
                            }
                            for (int i = 0; i < pt.length; i++) {
                                if (pt[i] == int.class) {
                                    args[i] = (i == 1) ? 1 : 2018;
                                } else if (pt[i] == long.class) {
                                    args[i] = 1L;
                                } else if (pt[i] == boolean.class) {
                                    args[i] = true;
                                } else if (pt[i] == CharSequence.class) {
                                    args[i] = "fp";
                                } else if (pt[i] == byte[].class) {
                                    args[i] = new byte[]{'f', 'p'};
                                } else {
                                    throw new Throwable("unhandled param type");
                                }
                            }
                        } else {
                            for (int i = 0; i < pt.length; i++) {
                                if (pt[i] == int.class) {
                                    args[i] = (i == 1) ? 1 : 2018;
                                } else if (pt[i] == long.class) {
                                    args[i] = 1L;
                                } else if (pt[i] == boolean.class) {
                                    args[i] = true;
                                } else if (pt[i] == char.class) {
                                    args[i] = '!';
                                } else {
                                    args[i] = (byte) 0;
                                }
                            }
                        }
                        proto = cand.newInstance(args);
                        break;
                    } catch (Throwable ignore) {
                        // try next ctor
                    }
                }
                if (proto == null) {
                    return Collections.emptyList();
                }
                ArrayList<Object> list = new ArrayList<>(1);
                list.add(proto);
                return Collections.unmodifiableList(list);
            } catch (Throwable t) {
                return Collections.emptyList();
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

    // Part 2.1 hooks from the UNIVERSAL-BY-PASS plan: force the builder itself
    // to ALLOW the device credential. This is the rosetta-stone hook for the
    // AndroidX & framework PromptInfo.Builder classes:
    //   - setDeviceCredentialAllowed(true)  -> system may use PIN
    //   - setConfirmationRequired(false)    -> PIN prompt appears immediately
    //   - setAllowedAuthenticators(...)     -> OR-in DEVICE_CREDENTIAL
    private static final XC_MethodHook FORCE_DEVICE_CREDENTIAL_BUILDER = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            String name = param.method.getName();
            try {
                if (name.equals("setDeviceCredentialAllowed")) {
                    param.args[0] = Boolean.TRUE;
                    DiagnosticLogger.callSpoofed(
                            param.method.getDeclaringClass().getName(), name, param.args, "true");
                } else if (name.equals("setConfirmationRequired")) {
                    param.args[0] = Boolean.FALSE;
                    DiagnosticLogger.callSpoofed(
                            param.method.getDeclaringClass().getName(), name, param.args, "false");
                } else if (name.equals("setAllowedAuthenticators")
                        && param.args != null && param.args.length > 0
                        && param.args[0] instanceof Integer) {
                    int orig = (Integer) param.args[0];
                    // OR-in DEVICE_CREDENTIAL while preserving the original flags.
                    param.args[0] = orig | AUTHENTICATOR_DEVICE_CREDENTIAL;
                    DiagnosticLogger.callSpoofed(
                            param.method.getDeclaringClass().getName(), name, param.args,
                            "AUTHENTICATORS|0x8000");
                }
            } catch (Throwable t) {
                // no-op: never let a logging failure break the app
            }
        }
    };

    // v1.1.7: signature-based builder spoof - ORs DEVICE_CREDENTIAL into the
    // authenticator int of ANY (int)->Builder method on the AndroidX builders,
    // regardless of its obfuscated name (setAllowedAuthenticators may be
    // renamed to b()/etc. by R8 inside the app's bundled androidx.biometric).
    private static final XC_MethodHook FORCE_INT_AUTHENTICATORS = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            try {
                if (param.args != null && param.args.length == 1 && param.args[0] instanceof Integer) {
                    int orig = (Integer) param.args[0];
                    if ((orig & AUTHENTICATOR_DEVICE_CREDENTIAL) == 0) {
                        param.args[0] = orig | AUTHENTICATOR_DEVICE_CREDENTIAL;
                        DiagnosticLogger.callSpoofed(
                                param.method.getDeclaringClass().getName(),
                                param.method.getName(),
                                param.args,
                                "AUTHENTICATORS|0x8000");
                    }
                }
            } catch (Throwable ignored) {
            }
        }
    };

    // v1.1.8: allow OFSS keystore keygen when zero real prints are enrolled.
    // The app only sets this when R.bool.ALLOW_FACE_BIOMETRIC is false; removing the
    // user-auth requirement mirrors Meezan's own "secure" branch and the PIN
    // fallback prompt (v1.1.3+) still gates access at the UI level.
    private static final XC_MethodHook FORCE_NO_USER_AUTH = new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            try {
                if (param.args != null && param.args.length == 1
                        && param.args[0] instanceof Boolean) {
                    param.args[0] = Boolean.FALSE;
                    DiagnosticLogger.callSpoofed(
                            param.method.getDeclaringClass().getName(),
                            param.method.getName(),
                            param.args,
                            "false (no user-auth required)");
                }
            } catch (Throwable ignored) {
            }
        }
    };

    // v1.1.7: rewrites a freshly built androidx.biometric.BiometricPrompt
    // PromptInfo so its authenticator mask carries DEVICE_CREDENTIAL, even
    // when the app bundles an R8-obfuscated AndroidX (field + getter names
    // renamed). Only the (single) int field holding the mask is updated.
    private static final XC_MethodHook REWRITE_ANDROIDX_PROMPTINFO = new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) {
            try {
                Object built = param.getResult();
                if (built == null || !built.getClass().getName()
                        .equals("androidx.biometric.BiometricPrompt$PromptInfo")) {
                    return;
                }
                Class<?> c = built.getClass();
                Method getter = null;
                for (Method m : c.getDeclaredMethods()) {
                    if (m.getParameterCount() == 0 && m.getReturnType() == int.class) {
                        getter = m;
                        break;
                    }
                }
                if (getter == null) {
                    return;
                }
                getter.setAccessible(true);
                Object r = getter.invoke(built);
                if (!(r instanceof Integer)) {
                    return;
                }
                int current = (Integer) r;
                if ((current & AUTHENTICATOR_DEVICE_CREDENTIAL) != 0) {
                    return;
                }
                Field maskField = null;
                Class<?> walk = c;
                outer:
                while (walk != null) {
                    for (Field f : walk.getDeclaredFields()) {
                        if (f.getType() == int.class) {
                            f.setAccessible(true);
                            if (((Integer) f.get(built)).intValue() == current) {
                                maskField = f;
                                break outer;
                            }
                        }
                    }
                    walk = walk.getSuperclass();
                }
                if (maskField == null) {
                    return;
                }
                maskField.setInt(built, current | AUTHENTICATOR_DEVICE_CREDENTIAL);
                DiagnosticLogger.callSpoofed(
                        param.method.getDeclaringClass().getName(),
                        param.method.getName(),
                        param.args,
                        "androidx PromptInfo AUTHENTICATORS->0x"
                                + Integer.toHexString(current | AUTHENTICATOR_DEVICE_CREDENTIAL));
            } catch (Throwable ignored) {
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
        // v2.0: NOTHING is injected into system_server under any condition -
        // the previous universal ADB breakage vector. The UI may still add
        // "system" to the LSPosed scope list, but this guard keeps ADB and
        // system services fully functional.
        if ("android".equals(lpparam.packageName)) {
            DiagnosticLogger.setProcessContext(lpparam.packageName, lpparam.processName);
            DiagnosticLogger.log("Skipping system_server (prevents ADB breakage)");
            return;
        }

        if (lpparam.classLoader == null) {
            return;
        }

        // v2.0: per-app feature configuration. Apps NOT listed in the config
        // get zero hooks ("I add MY apps, not ALL apps").
        Config.AppConfig app = Config.forPackage(lpparam.packageName);
        cfgBiometric = app.biometric;
        cfgDevOptions = app.devOptions;
        cfgUsbDebug = app.usbDebug;

        // Diagnostic context + runtime switch (Phase 12 support).
        DiagnosticLogger.setProcessContext(lpparam.packageName, lpparam.processName);
        DiagnosticLogger.applyRuntimeSwitch();
        DiagnosticLogger.log("LOADED package=" + lpparam.packageName
                + " process=" + lpparam.processName
                + " isFirstApplication=" + lpparam.isFirstApplication
                + " sdk=" + Build.VERSION.SDK_INT
                + " cfg={bio=" + cfgBiometric + ",dev=" + cfgDevOptions
                + ",usb=" + cfgUsbDebug + "}");

        if (cfgBiometric) {
            hookFingerprintManager(lpparam.classLoader);
            hookBiometricManager(lpparam.classLoader);
            hookAndroidXBiometrics(lpparam.classLoader);
            // v1.1.7: obfuscation-proof AndroidX hooks (R8-renamed androidx.biometric
            // in bank apps like Meezan), matched by signature not by method name.
            hookAndroidxBySignature(lpparam.classLoader);
            hookObserversOnly(lpparam.classLoader);
            hookDeviceCredentialFallback(lpparam.classLoader);
            // v1.1.8: OFSS Digix (Meezan Bank family) enable-fingerprint fix -
            // keystore keygen without an enrolled biometric + ResourceMapper bools.
            hookOfssDigix(lpparam.classLoader, lpparam.packageName);
        }
        if (cfgDevOptions || cfgUsbDebug) {
            // v2.0: dev-option / usb-debug spoof; internal key filter decides
            // which keys may be spoofed for THIS app based on the config.
            hookDeveloperOptionsSpoof(lpparam.classLoader);
        }

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
                hookAllSafely(fpClass, "getEnrolledFingerprints", RETURN_ENROLLED_LIST);
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
     * v1.1.7: signature-based AndroidX hooks (obfuscation-proof). Apps such as
     * Meezan Bank (OFSS Digix, Cordova) bundle an R8-obfuscated copy of
     * androidx.biometric where canAuthenticate()=a(), canAuthenticate(int)=b(int),
     * setAllowedAuthenticators(int)=b(int), build()=a() - so canonical-name hooks
     * NoSuchMethod and the app's availability gate + prompt rewrite silently fail.
     * Matching BY SIGNATURE is immune to renaming:
     *   - BiometricManager: every non-static ()int and (int)int instance method
     *     is a canAuthenticate(...) overload -> return BIOMETRIC_SUCCESS.
     *   - PromptInfo$Builder / BiometricPrompt$Builder: (int)->Builder ==
     *     setAllowedAuthenticators -> OR-in DEVICE_CREDENTIAL; ()->PromptInfo ==
     *     build() -> force DEVICE_CREDENTIAL on the built object.
     * Works for BOTH obfuscated and clean AndroidX (double coverage is harmless).
     */
    private void hookAndroidxBySignature(ClassLoader classLoader) {
        try {
            Class<?> bm = XposedHelpers.findClassIfExists(
                    "androidx.biometric.BiometricManager", classLoader);
            if (bm != null) {
                for (Method m : bm.getDeclaredMethods()) {
                    if (m.getReturnType() != int.class
                            || java.lang.reflect.Modifier.isStatic(m.getModifiers())) {
                        continue;
                    }
                    Class<?>[] pt = m.getParameterTypes();
                    if (pt.length == 0 || (pt.length == 1 && pt[0] == int.class)) {
                        try {
                            XposedBridge.hookMethod(m, RETURN_BIOMETRIC_SUCCESS);
                            hooksInstalled++;
                            DiagnosticLogger.log("INSTALL_OK class=" + bm.getName()
                                    + " method=" + m.getName() + " (sig canAuthenticate) -> 0");
                        } catch (Throwable t) {
                            hooksFailed++;
                            DiagnosticLogger.hookFailed(bm.getName(), m.getName(),
                                    "sig-hook: " + t.getMessage());
                        }
                    }
                }
            }
        } catch (Throwable t) {
            logError("AndroidX sig hook (BiometricManager) failure", t);
        }

        String[] builders = new String[]{
                "androidx.biometric.BiometricPrompt$PromptInfo$Builder",
                "androidx.biometric.BiometricPrompt$Builder"
        };
        for (String bn : builders) {
            try {
                Class<?> bc = XposedHelpers.findClassIfExists(bn, classLoader);
                if (bc == null) {
                    continue;
                }
                Class<?> promptInfoCls = XposedHelpers.findClassIfExists(
                        "androidx.biometric.BiometricPrompt$PromptInfo", classLoader);
                for (Method m : bc.getDeclaredMethods()) {
                    Class<?>[] pt = m.getParameterTypes();
                    boolean isBuilderReturn = m.getReturnType() == bc;
                    if (isBuilderReturn && pt.length == 1 && pt[0] == int.class) {
                        try {
                            XposedBridge.hookMethod(m, FORCE_INT_AUTHENTICATORS);
                            hooksInstalled++;
                            DiagnosticLogger.log("INSTALL_OK class=" + bc.getName()
                                    + " method=" + m.getName()
                                    + " (sig setAllowedAuthenticators) |0x8000");
                        } catch (Throwable t) {
                            hooksFailed++;
                            DiagnosticLogger.hookFailed(bc.getName(), m.getName(),
                                    "sig-hook: " + t.getMessage());
                        }
                    } else if (pt.length == 0
                            && promptInfoCls != null && m.getReturnType() == promptInfoCls) {
                        try {
                            XposedBridge.hookMethod(m, REWRITE_ANDROIDX_PROMPTINFO);
                            hooksInstalled++;
                            DiagnosticLogger.log("INSTALL_OK class=" + bc.getName()
                                    + " method=" + m.getName()
                                    + " (sig build) force credential");
                        } catch (Throwable t) {
                            hooksFailed++;
                            DiagnosticLogger.hookFailed(bc.getName(), m.getName(),
                                    "sig-hook: " + t.getMessage());
                        }
                    }
                }
            } catch (Throwable t) {
                logError("AndroidX sig hook (builder) failure: " + bn, t);
            }
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
        // the enrolled biometric info list; empty list means NOT_ENROLLED. On real
        // devices with zero prints this returns empty, which gates out fingerprint
        // setup. We return a synthetic non-empty BiometricInfo list instead.
        try {
            Class<?> bioClass = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricManager", classLoader);
            if (bioClass != null) {
                hookAllSafely(bioClass, "getEnrolledBiometrics", RETURN_ENROLLED_BIOMETRICS);
            }
        } catch (Throwable t) {
            logError("BiometricManager getEnrolledBiometrics hook failure", t);
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
            // Framework layer 1: BiometricPrompt.authenticate(params) +
            // Builder.build() rewrite (API 28-29 PromptInfo.Builder / API 30+
            // BiometricPrompt.Builder -> all funnel into Params/PromptInfo).
            Class<?> bioPrompt = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt", classLoader);
            Class<?> paramsClass = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt$Params", classLoader);
            if (bioPrompt != null && paramsClass != null) {
                hookSafely(bioPrompt, "authenticate", paramsClass, REWRITE_AUTH_PARAMS);
            }

            // API 28-31: BiometricPrompt$Params$Builder#build()
            Class<?> builder = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt$Params$Builder", classLoader);
            if (builder != null) {
                hookAllSafely(builder, "build", REWRITE_BUILT_PARAMS);
            }

            // API 30+: BiometricPrompt$Builder#build() returns PromptInfo.
            Class<?> modernBuilder = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.BiometricPrompt$Builder", classLoader);
            if (modernBuilder != null) {
                hookAllSafely(modernBuilder, "build", REWRITE_BUILT_PARAMS);
            }

            // SDK 30+ PromptInfo.Builder (the object that carries the mask to
            // IBiometricService).
            Class<?> promptInfoBuilder = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.PromptInfo$Builder", classLoader);
            if (promptInfoBuilder != null) {
                hookAllSafely(promptInfoBuilder, "build", REWRITE_BUILT_PARAMS);
            }

            // Part 2.1: force the builder setters so the app itself builds a
            // credential-allowed prompt (covers framework on all API >= 28).
            String[] builderNames = new String[]{
                    "android.hardware.biometrics.BiometricPrompt$Builder",
                    "android.hardware.biometrics.BiometricPrompt$Params$Builder",
                    "android.hardware.biometrics.PromptInfo$Builder"
            };
            for (String b : builderNames) {
                Class<?> bc = XposedHelpers.findClassIfExists(b, classLoader);
                if (bc != null) {
                    hookAllSafely(bc, "setDeviceCredentialAllowed",
                            FORCE_DEVICE_CREDENTIAL_BUILDER);
                    hookAllSafely(bc, "setConfirmationRequired",
                            FORCE_DEVICE_CREDENTIAL_BUILDER);
                    hookAllSafely(bc, "setAllowedAuthenticators",
                            FORCE_DEVICE_CREDENTIAL_BUILDER);
                }
            }

            // AndroidX equivalent builders.
            String[] androidxBuilders = new String[]{
                    "androidx.biometric.BiometricPrompt$PromptInfo$Builder",
                    "androidx.biometric.BiometricPrompt$Builder"
            };
            for (String b : androidxBuilders) {
                Class<?> bc = XposedHelpers.findClassIfExists(b, classLoader);
                if (bc != null) {
                    hookAllSafely(bc, "setDeviceCredentialAllowed",
                            FORCE_DEVICE_CREDENTIAL_BUILDER);
                    hookAllSafely(bc, "setConfirmationRequired",
                            FORCE_DEVICE_CREDENTIAL_BUILDER);
                    hookAllSafely(bc, "setAllowedAuthenticators",
                            FORCE_DEVICE_CREDENTIAL_BUILDER);
                }
            }

            // Framework layer 3: IBiometricService$Stub$Proxy#authenticate - the
            // in-process AIDL proxy to system BiometricService; rewrites the
            // Params/PromptInfo argument right before it is marshalled across the
            // binder. This is the LAST net and works even if the app path avoids
            // every builder above.
            Class<?> proxy = XposedHelpers.findClassIfExists(
                    "android.hardware.biometrics.IBiometricService$Stub$Proxy", classLoader);
            if (proxy != null) {
                hookAllSafely(proxy, "authenticate", REWRITE_AUTH_PARAMS);
            }
        } catch (Throwable t) {
            logError("Device-credential fallback hook failure", t);
        }
    }

    /**
     * v1.1.6: spoofs Developer Options / USB debugging / hierarchy state as OFF
     * inside every app process (banks refuse to run with them enabled). This is a
     * pure read-spoof - the real system settings are never written, so ADB on the
     * PC keeps working. Applied to ALL apps; system_server is skipped (see
     * handleLoadPackage) so system services read the true values.
     */
    private void hookDeveloperOptionsSpoof(ClassLoader classLoader) {
        String[] settingsClasses = new String[]{
                "android.provider.Settings$Global",
                "android.provider.Settings$Secure",
                "android.provider.Settings$System"
        };
        for (String settingsClass : settingsClasses) {
            Class<?> sc = XposedHelpers.findClassIfExists(settingsClass, classLoader);
            if (sc == null) {
                continue;
            }
            // getInt(ContentResolver, String)              -> int
            // getInt(ContentResolver, String, int)         -> int (default)
            // getInt(ContentResolver, String, int, int)    -> int (legacy)
            hookAllSafely(sc, "getInt", RETURN_DEV_OPTIONS_OFF);
            // getString(ContentResolver, String)           -> String
            hookAllSafely(sc, "getString", RETURN_DEV_OPTIONS_NULL);
        }

        // Runtime tracing/debugger probes (some banks check isTracing() last).
        Class<?> debug = XposedHelpers.findClassIfExists("android.os.Debug", classLoader);
        if (debug != null) {
            hookAllSafely(debug, "isTracing", RETURN_NOT_TRACING);
            hookAllSafely(debug, "isDebuggerConnected", RETURN_NOT_TRACING);
        }
    }

    /**
     * v1.1.8: Meezan/OFSS Digix enable-fingerprint fix. The Digix
     * fingerprintauth plugin (Cordova) generates an RSA key with
     * setUserAuthenticationRequired(true) whenever R.bool.ALLOW_FACE_BIOMETRIC
     * is false; keystore2 rejects that keygen while zero fingerprints are
     * enrolled, killing the enable flow before the prompt is shown. We
     * (1) force setUserAuthenticationRequired(false) and (2) force every
     * static (Context)->boolean accessor on com.ofss...ResourceMapper to true,
     * so the app behaves like its own ALLOW_FACE_BIOMETRIC=true branch.
     * Gated to OFSS Digix package names so non-OFSS apps are untouched.
     */
    private static final String OFSS_RESOURCE_MAPPER_CLASS =
            "com.ofss.digx.mobile.obdxcore.infra.util.ResourceMapper";
    private static final String OFSS_ALIAS_PROMOTE = "invo8.";

    private void hookOfssDigix(ClassLoader classLoader, String packageName) {
        if (packageName == null
                || !(packageName.startsWith(OFSS_ALIAS_PROMOTE)
                || packageName.contains("ofss")
                || packageName.contains("digx"))) {
            return;
        }
        DiagnosticLogger.log("OFSS_DIGIX detected package=" + packageName);

        // (1) Force the keystore key to need NO user authentication - the exact
        // gate that fails with 0 enrolled prints.
        try {
            Class<?> spec = XposedHelpers.findClassIfExists(
                    "android.security.keystore.KeyGenParameterSpec$Builder", classLoader);
            if (spec != null) {
                hookSafely(spec, "setUserAuthenticationRequired", boolean.class, FORCE_NO_USER_AUTH);
            }
        } catch (Throwable t) {
            logError("OFSS keystore hook failure", t);
        }

        // (2) Force every static (Context)->boolean ResourceMapper accessor to
        // true (R8-renamed k/l/m/n/o/p; matched by signature). The class is
        // app-sourced, so install eagerly if already loaded, else bind lazily
        // through a ClassLoader.loadClass hook.
        Class<?> rm = XposedHelpers.findClassIfExists(OFSS_RESOURCE_MAPPER_CLASS, classLoader);
        if (rm != null) {
            bindOfssResourceMapper(rm);
        } else {
            try {
                XposedBridge.hookAllMethods(java.lang.ClassLoader.class, "loadClass",
                        new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                if (ofssResourceMapperBound) {
                                    return;
                                }
                                try {
                                    Object loaded = param.getResult();
                                    if (loaded instanceof Class
                                            && OFSS_RESOURCE_MAPPER_CLASS.equals(
                                            ((Class<?>) loaded).getName())) {
                                        bindOfssResourceMapper((Class<?>) loaded);
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        });
            } catch (Throwable t) {
                logError("OFSS ResourceMapper loadClass hook failure", t);
            }
        }
    }

    private boolean ofssResourceMapperBound;

    private void bindOfssResourceMapper(Class<?> rm) {
        if (ofssResourceMapperBound) {
            return;
        }
        ofssResourceMapperBound = true;
        for (Method m : rm.getDeclaredMethods()) {
            if (!java.lang.reflect.Modifier.isStatic(m.getModifiers())
                    || m.getReturnType() != boolean.class) {
                continue;
            }
            Class<?>[] pt = m.getParameterTypes();
            if (pt.length == 1 && pt[0] == Context.class) {
                try {
                    XposedBridge.hookMethod(m, RETURN_TRUE);
                    hooksInstalled++;
                    DiagnosticLogger.log("INSTALL_OK class=" + rm.getName()
                            + " method=" + m.getName()
                            + " (OFSS ResourceMapper bool) -> true");
                } catch (Throwable t) {
                    hooksFailed++;
                    DiagnosticLogger.hookFailed(rm.getName(), m.getName(), t.getMessage());
                }
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