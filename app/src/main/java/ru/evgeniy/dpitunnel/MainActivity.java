package ru.evgeniy.dpitunnel;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.graphics.Color;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class MainActivity extends AppCompatActivity {

    private Button mainButton;
    private TextView asciiLogo;
    private CustomEditText bindPort;
    private boolean isPortChanged = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        if (!prefs.getBoolean("firstTimeFlag", false)) {
            // do one time tasks
            extractAssetsFile("cacert.pem");
            new updateHostlistTask().execute();

            // mark first time has ran.
            SharedPreferences.Editor editor = prefs.edit();
            editor.putBoolean("firstTimeFlag", true);
            editor.commit();
        }

        asciiLogo = findViewById(R.id.ascii_logo);
        bindPort = findViewById(R.id.bind_port);
        mainButton = findViewById(R.id.main_button);

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

        bindPort.setText(Integer.toString(prefs.getInt("bind_port", 8080)));

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

        bindPort.addTextChangedListener(new TextWatcher() {
            // the user's changes are saved here
            public void onTextChanged(CharSequence c, int start, int before, int count) {
                isPortChanged = true;
            }

            public void beforeTextChanged(CharSequence c, int start, int count, int after) {
                // this space intentionally left blank
            }

            public void afterTextChanged(Editable c) {
                // this one too
            }
        });

        bindPort.setOnFocusChangeListener(new View.OnFocusChangeListener() {

            public void onFocusChange(View v, boolean hasFocus) {
                if(!hasFocus && isPortChanged) {
                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                    SharedPreferences.Editor editor = prefs.edit();
                    editor.putInt("bind_port", Integer.parseInt(bindPort.getText().toString()));
                    editor.commit();

                    isPortChanged = false;
                }
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
                c.setReadTimeout(7000);
                c.setConnectTimeout(7000);
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
            }

            return null;
        }
    }

    private void extractAssetsFile(String filename) {
        AssetManager assetManager = this.getAssets();

        InputStream in = null;
        OutputStream out = null;
        try {
            in = assetManager.open(filename);
            String newFileName = this.getPackageManager().getPackageInfo(this.getPackageName(), 0).applicationInfo.dataDir + "/" + filename;
            out = new FileOutputStream(newFileName);

            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
            in = null;
            out.flush();
            out.close();
            out = null;
        } catch (Exception e) {
            Log.e("Java/extractAssetsFile", e.getMessage());
        }

    }
}
