package com.test.ipce2e;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class MyTestService extends Service {

    private static final String TAG = "IPC_E2E";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "MyTestService started with intent: " + intent);
        // Service will be stopped explicitly by MainActivity
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}