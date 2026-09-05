package com.jamamjad.biometricbypass;

import android.os.Bundle;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tvStatus = findViewById(R.id.tv_hook_status);
        if (tvStatus != null) {
            tvStatus.setText(getString(R.string.module_active));
        }
    }
}
