package ru.evgeniy.dpitunnel;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.DataOutputStream;

public class NativeService extends Service {

    static {
        System.loadLibrary("dpi-bypass");
    }

    private SharedPreferences prefs;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    thread nativeThread = new thread();
    @Override
    public void onCreate() {
        try {
            setApplicationDirectory(this.getPackageManager().getPackageInfo(this.getPackageName(), 0).applicationInfo.dataDir + "/");
        } catch (PackageManager.NameNotFoundException e) {
            Log.e("Java/NativeService/onCreate", "Package name not found");
            return;
        }

        // Start native code
        nativeThread.start();

        // Set http_proxy settings if need
        prefs = PreferenceManager.getDefaultSharedPreferences(this);

        if(prefs.getBoolean("other_proxy_setting", false)) {
            try {
                Process su = Runtime.getRuntime().exec("su");
                DataOutputStream outputStream = new DataOutputStream(su.getOutputStream());

                outputStream.writeBytes("settings put global http_proxy 127.0.0.1:" + prefs.getString("other_bind_port", "8080") + "\n");
                outputStream.flush();

                outputStream.writeBytes("exit\n");
                outputStream.flush();

                su.waitFor();
            } catch (Exception e) {
                Log.e("Java/NativeService/onCreate", "Failed to set http_proxy global settings");
            }
        }
    }

    private class thread extends Thread{
        volatile boolean isRunning = true;
        @Override
        public void run() {
            if(init(PreferenceManager.getDefaultSharedPreferences(NativeService.this)) == -1)
            {
                Log.e("Java/NativeService/nativeThread", "Init failure");
                NativeService.this.stopSelf();
                return;
            }

            while(isRunning)
            {
                acceptClient();
            }
        }

        public void quit() {
            isRunning = false;
            deInit();
        }
    }

    @Override
    public void onDestroy() {

        // Unset http_proxy settings if need
        if(prefs.getBoolean("other_proxy_setting", false)) {
            try {
                Process su = Runtime.getRuntime().exec("su");
                DataOutputStream outputStream = new DataOutputStream(su.getOutputStream());

                outputStream.writeBytes("settings put global http_proxy :0\n");
                outputStream.flush();

                outputStream.writeBytes("exit\n");
                outputStream.flush();

                su.waitFor();
            } catch (Exception e) {
                Log.e("Java/NativeService/onCreate", "Failed to unset http_proxy global settings");
            }
        }

        nativeThread.quit();
    }

    public native int init(SharedPreferences prefs);
    public native void acceptClient();
    public native void deInit();
    public native void setApplicationDirectory(String ApplicationDirectory);
}
