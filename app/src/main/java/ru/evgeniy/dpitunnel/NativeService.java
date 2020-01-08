package ru.evgeniy.dpitunnel;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.preference.PreferenceManager;
import android.util.Log;

public class NativeService extends Service {

    static {
        System.loadLibrary("dpi-bypass");
    }

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

        nativeThread.start();
    }

    @Override
    public void onDestroy() {
        nativeThread.quit();
    }

    private class thread extends Thread{
        volatile boolean isRunning = true;
        @Override
        public void run() {
            if(init(PreferenceManager.getDefaultSharedPreferences(NativeService.this)) == -1)
            {
                Log.e("Java/NativeService/nativeThread", "Init failure");
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

    public native int init(SharedPreferences prefs);
    public native void acceptClient();
    public native void deInit();
    public native void setApplicationDirectory(String ApplicationDirectory);
}
