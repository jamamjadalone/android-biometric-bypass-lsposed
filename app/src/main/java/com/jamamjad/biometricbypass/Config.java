package com.jamamjad.biometricbypass;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * v2.0: per-app configuration model (inspired by the HMA-Config idea: per-app
 * granular control, own implementation - simple JSON on disk read by the hook
 * inside every hooked process).
 *
 * The UI (MainActivity) writes /data/local/tmp/biobypass_config.json (world
 * readable, root-written, chmod 644). UniversalBiometricHook reads it once per
 * process and applies ONLY the enabled features for that specific package.
 * Apps that are NOT listed in the JSON get an AppConfig with all flags FALSE,
 * i.e. the module stays entirely inert for them (this is what "I want to add
 * MY apps, not ALL apps" means at runtime).
 *
 * JSON schema:
 * {
 *   "version": 2,
 *   "apps": {
 *     "invo8.meezan.mb": { "biometric": true, "devOptions": true, "usbDebug": false },
 *     ...
 *   }
 * }
 */
public final class Config {

    private static final String TAG = "BiometricHook";
    private static final String CONFIG_PATH = "/data/local/tmp/biobypass_config.json";
    private static final int CONFIG_VERSION = 2;

    /** Per-package feature flags with sensible defaults (all OFF). */
    public static final class AppConfig {
        public static final AppConfig NONE = new AppConfig(false, false, false);

        public final boolean biometric;   // PIN-fallback / biometric prompt rewrite
        public final boolean devOptions;  // spoof Settings development_settings_enabled -> 0
        public final boolean usbDebug;    // spoof adb_enabled / adb_wifi_enabled / Debug probes

        AppConfig(boolean biometric, boolean devOptions, boolean usbDebug) {
            this.biometric = biometric;
            this.devOptions = devOptions;
            this.usbDebug = usbDebug;
        }

        public boolean any() {
            return biometric || devOptions || usbDebug;
        }
    }

    private static volatile Config instance;
    private static volatile long lastModified = -1;

    private final Map<String, AppConfig> apps;

    private Config(Map<String, AppConfig> apps) {
        this.apps = apps;
    }

    /** Returns the config for a package, defaulting to NONE if unknown. */
    public static AppConfig forPackage(String pkg) {
        Config c = load();
        if (c == null || pkg == null) {
            return AppConfig.NONE;
        }
        AppConfig a = c.apps.get(pkg);
        return a != null ? a : AppConfig.NONE;
    }

    /** Everything currently configured (pkg -> flags). Empty when no file. */
    public static Map<String, AppConfig> all() {
        Config c = load();
        if (c == null) {
            return new HashMap<>();
        }
        return c.apps;
    }

    /** Loads (cached, mtime-checked) the on-disk config file. Never throws. */
    public static Config load() {
        File f = new File(CONFIG_PATH);
        if (!f.exists()) {
            instance = null;
            lastModified = -1;
            return null;
        }
        long mt = f.lastModified();
        if (instance != null && mt == lastModified) {
            return instance;
        }
        Config parsed = parse(new File(CONFIG_PATH));
        instance = parsed;
        lastModified = mt;
        return parsed;
    }

    /** Re-reads the file unconditionally (used by writes to refresh the cache). */
    public static void refresh() {
        instance = parse(new File(CONFIG_PATH));
        lastModified = new File(CONFIG_PATH).lastModified();
    }

    private static Config parse(File f) {
        Map<String, AppConfig> map = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                new FileInputStream(f), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JSONObject root = new JSONObject(sb.toString());
            JSONObject appsObj = root.optJSONObject("apps");
            if (appsObj != null) {
                Iterator<String> keys = appsObj.keys();
                while (keys.hasNext()) {
                    String pkg = keys.next();
                    JSONObject cfg = appsObj.optJSONObject(pkg);
                    if (cfg == null) {
                        continue;
                    }
                    map.put(pkg, new AppConfig(
                            cfg.optBoolean("biometric", false),
                            cfg.optBoolean("devOptions", false),
                            cfg.optBoolean("usbDebug", false)));
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "Config parse failed: " + t.getMessage(), t);
        }
        return new Config(map);
    }

    /**
     * Writes the config JSON to /data/local/tmp and makes it world-readable so
     * every hooked app process can read it. Requires root (su) since the file
     * lives outside the app sandbox. Returns a short status message.
     */
    public static String write(String json) {
        String esc = json.replace("'", "'\\''");
        String cmd = "mkdir -p /data/local/tmp && echo '" + esc
                + "' > " + CONFIG_PATH + " && chmod 644 " + CONFIG_PATH
                + " && echo WRITE_OK";
        String out = runSu(cmd);
        refresh();
        return out != null && out.contains("WRITE_OK") ? "Config saved" : out;
    }

    public static String getConfigPath() {
        return CONFIG_PATH;
    }

    public static String runSu(String command) {
        try {
            Process p = new ProcessBuilder("su", "-c", command)
                    .redirectErrorStream(true)
                    .start();
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    p.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
            p.waitFor();
            return sb.toString().trim();
        } catch (Throwable t) {
            return "su-error: " + t.getMessage();
        }
    }

    public static int getConfigVersionValue() {
        return CONFIG_VERSION;
    }
}