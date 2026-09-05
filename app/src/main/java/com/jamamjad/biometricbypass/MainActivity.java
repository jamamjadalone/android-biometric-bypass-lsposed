package com.jamamjad.biometricbypass;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * v2.0: per-app configuration UI. Pick the apps YOU want (banks, telcos...)
 * and enable only the features they need:
 *   - Biometric  : PIN-fallback / prompt-rewrite stack (the main bypass).
 *   - Dev Optns  : hide "Developer options" being ON (spoofs the setting read).
 *   - USB DBG    : hide USB debugging (adb_enabled / Debug probes).
 * The Apply button (1) writes /data/local/tmp/biobypass_config.json via root
 * and (2) overwrites the LSPosed scope with ONLY the selected apps (+ optional
 * "system"). Nothing is applied at the system level or to unselected apps.
 */
public class MainActivity extends AppCompatActivity {

    private static final int BIO = 0;
    private static final int DEV = 1;
    private static final int USB = 2;

    private static class AppEntry {
        String pkg;
        String label;
        Drawable icon;
    }

    private List<AppEntry> allApps = new ArrayList<>();
    private List<AppEntry> shownApps = new ArrayList<>();
    private final Map<String, boolean[]> state = new HashMap<>(); // [bio,dev,usb]

    private EditText etSearch;
    private ListView listView;
    private TextView tvStatus;
    private Switch swSystemScope;
    private AppAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etSearch = findViewById(R.id.et_search);
        listView = findViewById(R.id.lv_apps);
        tvStatus = findViewById(R.id.tv_apply_status);
        swSystemScope = findViewById(R.id.sw_system_scope);

        adapter = new AppAdapter();
        listView.setAdapter(adapter);

        loadInstalledApps();
        loadConfigIntoState();

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void afterTextChanged(Editable s) {
                applyFilter(s.toString().toLowerCase());
            }

            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {
            }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int c) {
            }
        });

        findViewById(R.id.btn_apply).setOnClickListener(v -> applyConfig());

        updateStatus("Select apps below, then Apply. Apps not listed here get no hooks.");
    }

    private void loadInstalledApps() {
        allApps.clear();
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> pkgs = pm.getInstalledApplications(PackageManager.GET_META_DATA);
        for (ApplicationInfo ai : pkgs) {
            if (getPackageName().equals(ai.packageName)) {
                continue;
            }
            AppEntry e = new AppEntry();
            e.pkg = ai.packageName;
            try {
                e.label = pm.getApplicationLabel(ai).toString();
            } catch (Throwable t) {
                e.label = ai.packageName;
            }
            try {
                e.icon = pm.getApplicationIcon(ai.packageName);
            } catch (Throwable t) {
                e.icon = null;
            }
            allApps.add(e);
        }
        Collections.sort(allApps, new Comparator<AppEntry>() {
            @Override
            public int compare(AppEntry a, AppEntry b) {
                return a.label.toLowerCase().compareTo(b.label.toLowerCase());
            }
        });
        applyFilter("");
    }

    private void loadConfigIntoState() {
        Map<String, Config.AppConfig> cfg = Config.all();
        for (String pkg : cfg.keySet()) {
            Config.AppConfig ac = cfg.get(pkg);
            state.put(pkg, new boolean[]{ac.biometric, ac.devOptions, ac.usbDebug});
        }
        // default: suggest the bank/telco list from R.array
        String[] defaults = getResources().getStringArray(R.array.xposed_scope);
        if (defaults != null) {
            for (String d : defaults) {
                if (d != null && !d.startsWith("*") && !state.containsKey(d)) {
                    state.put(d, new boolean[]{true, true, true});
                }
            }
        }
        adapter.notifyDataSetChanged();
    }

    private void applyFilter(String needle) {
        shownApps.clear();
        for (AppEntry e : allApps) {
            if (needle.isEmpty()
                    || e.label.toLowerCase().contains(needle)
                    || e.pkg.toLowerCase().contains(needle)) {
                shownApps.add(e);
            }
        }
        adapter.notifyDataSetChanged();
    }

    private void applyConfig() {
        try {
            JSONObject root = new JSONObject();
            root.put("version", Config.getConfigVersionValue());
            JSONObject apps = new JSONObject();
            List<String> scopePkgs = new ArrayList<>();
            boolean anyEnabled = false;
            for (Map.Entry<String, boolean[]> e : state.entrySet()) {
                boolean[] f = e.getValue();
                if (!f[BIO] && !f[DEV] && !f[USB]) {
                    continue;
                }
                anyEnabled = true;
                JSONObject cfg = new JSONObject();
                cfg.put("biometric", f[BIO]);
                cfg.put("devOptions", f[DEV]);
                cfg.put("usbDebug", f[USB]);
                apps.put(e.getKey(), cfg);
                scopePkgs.add(e.getKey());
            }
            root.put("apps", apps);

            String writeRes = Config.write(root.toString());
            // Overwrite LSPosed scope with ONLY the selected apps (+ optional system).
            StringBuilder sb = new StringBuilder("/data/adb/lspd/cli scope set com.jamamjad.biometricbypass");
            for (String p : scopePkgs) {
                sb.append(' ').append(p);
            }
            if (swSystemScope.isChecked()) {
                sb.append(" system");
            }
            String scopeRes = Config.runSu(sb.toString());

            String msg = "Config: " + (writeRes == null ? "null" : writeRes)
                    + " | Scope(" + scopePkgs.size() + "): "
                    + (scopeRes == null ? "null" : scopeRes.replace('\n', ' '));
            if (!anyEnabled && !swSystemScope.isChecked()) {
                msg = "No apps enabled. Select at least one app, then Apply.";
            }
            updateStatus(msg);
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
        } catch (Throwable t) {
            updateStatus("Apply failed: " + t.getMessage());
            Toast.makeText(this, "Apply failed: " + t.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void updateStatus(String s) {
        if (tvStatus != null) {
            tvStatus.setText(s);
        }
    }

    // ---------------------------------------------------------------------

    class AppAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return shownApps.size();
        }

        @Override
        public AppEntry getItem(int position) {
            return shownApps.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(MainActivity.this)
                        .inflate(R.layout.item_app, parent, false);
            }
            AppEntry e = getItem(position);
            boolean[] f = state.get(e.pkg);
            if (f == null) {
                f = new boolean[]{false, false, false};
                state.put(e.pkg, f);
            }
            final boolean[] flags = f;

            ImageView ivIcon = convertView.findViewById(R.id.iv_icon);
            TextView tvName = convertView.findViewById(R.id.tv_app_name);
            TextView tvPkg = convertView.findViewById(R.id.tv_app_pkg);
            Switch swBio = convertView.findViewById(R.id.sw_bio);
            Switch swDev = convertView.findViewById(R.id.sw_dev);
            Switch swUsb = convertView.findViewById(R.id.sw_usb);

            if (e.icon != null) {
                ivIcon.setImageDrawable(e.icon);
            }
            tvName.setText(e.label);
            tvPkg.setText(e.pkg);

            swBio.setChecked(flags[BIO]);
            swDev.setChecked(flags[DEV]);
            swUsb.setChecked(flags[USB]);

            swBio.setOnCheckedChangeListener((v, is) -> flags[BIO] = is);
            swDev.setOnCheckedChangeListener((v, is) -> flags[DEV] = is);
            swUsb.setOnCheckedChangeListener((v, is) -> flags[USB] = is);

            return convertView;
        }
    }
}