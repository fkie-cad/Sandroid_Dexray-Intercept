package com.test.securitye2e;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public final class FridaWorkerService extends Service {

    private static final String TAG = "BYPASS_E2E";
    private static final String READY_FILE_NAME = "frida_worker.ready";

    @Override
    public void onCreate() {
        super.onCreate();
        writeReadyMarker();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        File readyFile = getFileStreamPath(READY_FILE_NAME);

        if (readyFile.exists() && !readyFile.delete()) {
            Log.w(TAG, "Unable to remove Frida worker readiness marker");
        }

        super.onDestroy();
    }

    private void writeReadyMarker() {
        try (FileOutputStream output = openFileOutput(
                READY_FILE_NAME,
                MODE_PRIVATE
        )) {
            output.write("ready".getBytes());
            output.getFD().sync();

            Log.i(TAG, "Frida worker service ready");
        } catch (IOException error) {
            Log.e(TAG, "Unable to write Frida worker readiness marker", error);
        }
    }
}