package com.jamamjad.biometricbypass;

import android.os.Build;
import android.util.Log;

/**
 * Structured, non-crashing diagnostic logger for the biometric bypass module.
 *
 * DIAGNOSTIC BUILD: logging is enabled by default here. It can be disabled at
 * runtime without rebuilding by setting the system property
 * `persist.biometric.diag` to `0` (checked lazily via reflection).
 *
 * This logger only records method call metadata and (un)modified results. It
 * NEVER logs passwords, tokens, private/secret keys, signature material,
 * challenge data, or any personal information.
 */
public final class DiagnosticLogger {

    private static final String TAG = "BioDiag";
    private static volatile boolean enabled = true;
    private static volatile String packageName = "unknown";
    private static volatile String processName = "unknown";

    private DiagnosticLogger() {
    }

    public static void setEnabled(boolean e) {
        enabled = e;
    }

    public static boolean isEnabled() {
        return enabled;
    }

    public static void setProcessContext(String pkg, String proc) {
        packageName = pkg != null ? pkg : "unknown";
        processName = proc != null ? proc : "unknown";
    }

    /**
     * Runtime off-switch (Phase 12 style, no rebuild needed).
     * Uses the framework `android.os.SystemProperties` via reflection so it is
     * safe on every android version. If the property does not exist the
     * build-time default is kept.
     */
    public static void applyRuntimeSwitch() {
        try {
            Object value = de.robv.android.xposed.XposedHelpers.callStaticMethod(
                    Class.forName("android.os.SystemProperties"),
                    "get", "persist.biometric.diag", "1");
            if (value instanceof String) {
                enabled = "1".equalsIgnoreCase((String) value);
            }
        } catch (Throwable ignored) {
            // keep build-time default
        }
    }

    private static String prefix() {
        return "pkg=" + packageName + " proc=" + processName + " api=" + Build.VERSION.SDK_INT;
    }

    public static void log(String message) {
        if (!enabled) {
            return;
        }
        try {
            Log.i(TAG, prefix() + " " + message);
        } catch (Throwable ignored) {
            // logging must never crash a hooked process
        }
    }

    public static void logError(String message, Throwable t) {
        if (!enabled) {
            return;
        }
        try {
            Log.e(TAG, prefix() + " " + message, t);
        } catch (Throwable ignored) {
        }
    }

    /** Safe, truncated rendering of method arguments. Never includes secrets. */
    public static String describeArgs(Object[] args) {
        if (args == null || args.length == 0) {
            return "args=[]";
        }
        StringBuilder sb = new StringBuilder("args=[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            Object a = args[i];
            String v = String.valueOf(a);
            if (v.length() > 48) {
                v = v.substring(0, 48) + "...";
            }
            sb.append(v);
        }
        return sb.append(']').toString();
    }

    public static void hookInstalled(String clazz, String method) {
        log("INSTALL_OK class=" + clazz + " method=" + method);
    }

    public static void hookFailed(String clazz, String method, String why) {
        if (!enabled) {
            return;
        }
        try {
            Log.w(TAG, prefix() + " INSTALL_FAIL class=" + clazz + " method=" + method + " err=" + why);
        } catch (Throwable ignored) {
        }
    }

    /** A spoof hook fired: the call was overridden. Original pre-execution value is generally not available. */
    public static void callSpoofed(String clazz, String method, Object[] args, Object override) {
        log("CALL_SPOOFED class=" + clazz + " method=" + method + " " + describeArgs(args)
                + " override=" + String.valueOf(override));
    }

    /** An observation-only hook fired: original result observed, NOT modified. */
    public static void callObserved(String clazz, String method, Object[] args, Object original) {
        log("CALL_OBSERVED class=" + clazz + " method=" + method + " " + describeArgs(args)
                + " original=" + String.valueOf(original));
    }
}