package com.test.ipce2e;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class MyTestService extends Service {

    private static final String TAG = "IPC_E2E";
    private static final String CHANNEL_ID = "ipc_e2e_fg_channel";
    // extra key used by startForegroundService trigger to request startForeground()
    static final String EXTRA_START_FOREGROUND = "start_foreground";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "MyTestService started with intent: " + intent);
        boolean isForeground = intent != null
                && intent.getBooleanExtra(EXTRA_START_FOREGROUND, false);

        if (isForeground) {
            // Foreground service path: startForeground() exempts this service from
            // Background Activity Launch (BAL) restrictions (API 29+).
            // startActivity here reliably dispatches through ContextWrapper.startActivity,
            // which is the hook target in broadcast.ts BC-4/BC-5.
            startForegroundWithMinimalNotification();
            try {
                Intent fromFgService = new Intent(this, SecondActivity.class);
                fromFgService.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                fromFgService.putExtra("from", "ForegroundService");
                startActivity(fromFgService);
                Log.i(TAG, "MyTestService: startActivity from foreground Service OK");
            } catch (Throwable t) {
                Log.w(TAG, "MyTestService: startActivity from foreground Service failed: "
                        + t.getMessage());
            }

            // startActivity(Intent, Bundle) from foreground Service ->
            // broadcast.ts: ContextWrapper.startActivity[Intent,Bundle] (BC-5)
            // requires FLAG_ACTIVITY_NEW_TASK from non-Activity context
            try {
                Intent fromFgServiceBundle = new Intent(this, SecondActivity.class);
                fromFgServiceBundle.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                fromFgServiceBundle.putExtra("from", "ForegroundServiceBundle");
                android.os.Bundle activityOptions = new android.os.Bundle();
                activityOptions.putString("opt_key", "opt_value");
                startActivity(fromFgServiceBundle, activityOptions);
                Log.i(TAG, "MyTestService: startActivity(Intent,Bundle) from foreground Service OK");
            } catch (Throwable t) {
                Log.w(TAG, "MyTestService: startActivity(Intent,Bundle) from foreground Service failed: "
                        + t.getMessage());
            }
            stopForeground(true);
        } else {
            // Background service path: startActivity is expected to be silently blocked
            // by BAL restrictions on API 29+. Trigger kept to document the call site
            // and to serve as a test if BAL restrictions are relaxed or if this service
            // is started in a context that grants activity launch permission.
            try {
                Intent fromBgService = new Intent(this, SecondActivity.class);
                fromBgService.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                fromBgService.putExtra("from", "BackgroundService");
                startActivity(fromBgService);
                Log.i(TAG, "MyTestService: startActivity from background Service OK");
            } catch (Throwable t) {
                Log.w(TAG, "MyTestService: startActivity from background Service blocked "
                        + "(expected on API 29+): " + t.getMessage());
            }
        }
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void startForegroundWithMinimalNotification() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null && nm.getNotificationChannel(CHANNEL_ID) == null) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "IPC E2E Test",
                    NotificationManager.IMPORTANCE_MIN);
            nm.createNotificationChannel(channel);
        }
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("IPC E2E foreground test")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build();
        startForeground(1, notification);
    }
}