package ru.evgeniy.dpitunnel;

import android.app.ActivityManager;
import android.app.FragmentManager;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class MainActivity extends AppCompatActivity {

    private Button mainButton;
    private ImageButton settingsButton;
    private ImageButton browserButton;
    private Button updateHostlistButton;
    private TextView asciiLogo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        if (!prefs.getBoolean("firstTimeFlag", false)) {
            // do one time tasks
            new updateHostlistTask().execute();

            // mark first time has ran.
            SharedPreferences.Editor editor = prefs.edit();
            editor.putBoolean("firstTimeFlag", true);
            editor.commit();
        }

        // Set gefault settings values
        PreferenceManager.setDefaultValues(this, R.xml.settings, false);

        // Find layout elements
        mainButton = findViewById(R.id.main_button);
        settingsButton = findViewById(R.id.settings_button);
        browserButton = findViewById(R.id.browser_button);
        updateHostlistButton = findViewById(R.id.update_hostlist_button);
        asciiLogo = findViewById(R.id.ascii_logo);

        // Set logo state
        if(isServiceRunning(NativeService.class)) {
            asciiLogo.setText(R.string.app_ascii_logo_unlock);
            asciiLogo.setTextColor(Color.GREEN);
            mainButton.setText(R.string.on);
        }
        else {
            asciiLogo.setText(R.string.app_ascii_logo_lock);
            asciiLogo.setTextColor(Color.RED);
            mainButton.setText(R.string.off);
        }

        // Initialize buttons
        mainButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(isServiceRunning(NativeService.class)) {
                    stopService(new Intent(MainActivity.this, NativeService.class));

                    asciiLogo.setText(R.string.app_ascii_logo_lock);
                    asciiLogo.setTextColor(Color.RED);
                    mainButton.setText(R.string.off);
                }
                else {
                    startService(new Intent(MainActivity.this, NativeService.class));

                    asciiLogo.setText(R.string.app_ascii_logo_unlock);
                    asciiLogo.setTextColor(Color.GREEN);
                    mainButton.setText(R.string.on);
                }
            }
        });
        settingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MainActivity.this.startActivity(new Intent(MainActivity.this, SettingsActivity.class));
            }
        });
        browserButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MainActivity.this.startActivity(new Intent(MainActivity.this, BrowserActivity.class));
            }
        });
        updateHostlistButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new updateHostlistTask().execute();
            }
        });
    }

    private boolean isServiceRunning(Class<?> serviceClass) {
        ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (serviceClass.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

    private class updateHostlistTask extends AsyncTask<Void, Void, Void> {
        private ProgressBar updateHostlistBar = findViewById(R.id.update_hostlist_bar);
        private boolean isOK = true;

        @Override
        protected void onPreExecute() {
            // Show ProgressBar
            updateHostlistBar.setVisibility(View.VISIBLE);
        }

        @Override
        protected Void doInBackground(Void... values) {
            try {

                FileOutputStream f = new FileOutputStream(MainActivity.this.getPackageManager().getPackageInfo(MainActivity.this.getPackageName(), 0).applicationInfo.dataDir + "/hostlist.txt");
                URL u = new URL("https://reestr.rublacklist.net/api/v2/domains/json");
                HttpsURLConnection c = (HttpsURLConnection) u.openConnection();

                // Create the SSL connection
                SSLContext sc;
                sc = SSLContext.getInstance("TLS");
                sc.init(null, null, new java.security.SecureRandom());
                c.setSSLSocketFactory(sc.getSocketFactory());

                // Set options and connect
                c.setReadTimeout(700);
                c.setConnectTimeout(700);
                c.setRequestMethod("GET");
                c.setDoInput(true);

                // Save to file
                InputStream in = c.getInputStream();

                byte[] buffer = new byte[1024];
                int len1 = 0;
                while ((len1 = in.read(buffer)) > 0) {
                    f.write(buffer, 0, len1);
                }

                f.close();
            } catch (Exception e) {
                e.printStackTrace();
                isOK = false;
            }

            return null;
        }

        @Override
        protected void onPostExecute(Void result) {
            // Hide ProgressBar
            updateHostlistBar.setVisibility(View.INVISIBLE);

            // Show updateHostlistStatus
            if(isOK)
            {
                Toast.makeText(MainActivity.this, getString(R.string.update_hostlist_ok), Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, getString(R.string.update_hostlist_bad), Toast.LENGTH_SHORT).show();
            }
        }
    }
}
