package com.test.ipce2e;

import android.app.Activity;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.util.Log;

public class MainActivity extends Activity {

    private static final String TAG = "IPC_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "IpcE2E started");

        try {
            try {
                runBinderTests();
            } catch (Throwable t) {
                Log.e(TAG, "runBinderTests failed", t);
            }

            try {
                runBroadcastTests();
            } catch (Throwable t) {
                Log.e(TAG, "runBroadcastTests failed", t);
            }

            try {
                runIntentTests();
            } catch (Throwable t) {
                Log.e(TAG, "runIntentTests failed", t);
            }

            try {
                runSharedPrefsTests();
            } catch (Throwable t) {
                Log.e(TAG, "runSharedPrefsTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in IpcE2E", t);
        } finally {
            Log.i(TAG, "IpcE2E finished");
            finish();
        }
    }

    // ------------------------------------------------------------
    // 1) Binder tests (BinderE2E)
    // ------------------------------------------------------------

    private void runBinderTests() {
        Log.i(TAG, "runBinderTests started");

        try {
            // 1) Settings.Secure.getString(...) -> binder.ts: handle_write(...) via libbinder.so ioctl
            //    -> PROFILE_HOOKING_TYPE="IPC_BINDER", event_type="binder.transaction"
            String androidId = Settings.Secure.getString(
                    getContentResolver(),
                    Settings.Secure.ANDROID_ID
            );
            Log.i(TAG, "ANDROID_ID: " + androidId);

            // 2) Settings.Global.getString(...) -> binder.ts: handle_write(...) via libbinder.so ioctl
            //    -> PROFILE_HOOKING_TYPE="IPC_BINDER", event_type="binder.transaction"
            String deviceName = Settings.Global.getString(
                    getContentResolver(),
                    Settings.Global.DEVICE_NAME
            );
            Log.i(TAG, "DEVICE_NAME: " + deviceName);

            Log.i(TAG, "runBinderTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "Error in runBinderTests", t);
        }
    }

    // ------------------------------------------------------------
    // 2) Broadcast / Activity / Service tests (BroadcastsE2E)
    // ------------------------------------------------------------

    private void runBroadcastTests() {
        Log.i(TAG, "runBroadcastTests started");

        try {
            // 1) sendBroadcast(Intent) ->
            //    broadcast.ts: ContextWrapper.sendBroadcast[Intent]
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="broadcast.sent"
            Intent simpleBroadcast = new Intent("com.test.ipce2e.ACTION_SIMPLE");
            simpleBroadcast.putExtra("key", "value");
            sendBroadcast(simpleBroadcast);

            // 2) sendBroadcast(Intent, String) ->
            //    broadcast.ts: ContextWrapper.sendBroadcast[Intent,String]
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="broadcast.sent"
            Intent permBroadcast = new Intent("com.test.ipce2e.ACTION_PERMISSION");
            permBroadcast.putExtra("flag", true);
            sendBroadcast(permBroadcast, "com.test.ipce2e.PERMISSION_TEST");

            // 3) startActivity(Intent) ->
            //    broadcast.ts: ContextWrapper.startActivity[Intent]
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="activity.started"
            Intent activityIntent = new Intent(this, SecondActivity.class);
            activityIntent.putExtra("from", "MainActivity");
            startActivity(activityIntent);

            // 4) startActivity(Intent, Bundle) ->
            //    broadcast.ts: ContextWrapper.startActivity[Intent,Bundle]
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="activity.started"
            Intent activityWithBundle = new Intent(this, SecondActivity.class);
            Bundle options = new Bundle();
            options.putString("opt_key", "opt_value");
            activityWithBundle.putExtra("extra", "with_bundle");
            startActivity(activityWithBundle, options);

            // 5) startService(Intent) ->
            //    broadcast.ts: ContextWrapper.startService
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="service.started"
            Intent serviceIntent = new Intent(this, MyTestService.class);
            serviceIntent.putExtra("service_key", "service_value");
            startService(serviceIntent);

            // 6) stopService(Intent) ->
            //    broadcast.ts: ContextWrapper.stopService
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="service.stopped"
            stopService(serviceIntent);

            // 7) registerReceiver(BroadcastReceiver, IntentFilter) ->
            //    broadcast.ts: ContextWrapper.registerReceiver[BroadcastReceiver,IntentFilter]
            //    (hooked but no event emitted; used to verify hook safety)
            TestReceiver receiver1 = new TestReceiver();
            IntentFilter filter = new IntentFilter("com.test.ipce2e.ACTION_SIMPLE");
            registerReceiver(receiver1, filter);

            // 8) registerReceiver(BroadcastReceiver, IntentFilter, String, Handler) ->
            //    broadcast.ts: ContextWrapper.registerReceiver[BroadcastReceiver,IntentFilter,String,Handler]
            //    (hooked but no event emitted; used to verify hook safety)
            TestReceiver receiver2 = new TestReceiver();
            Handler handler = new Handler(getMainLooper());
            registerReceiver(receiver2, filter, "com.test.ipce2e.PERMISSION_TEST", handler);

            // 9) sendStickyBroadcast(Intent) ->
            //    broadcast.ts: ContextWrapper.sendStickyBroadcast[Intent]
            //    -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="broadcast.sticky_sent"
            //    requires android.permission.BROADCAST_STICKY in manifest
            try {
                Intent sticky = new Intent("com.test.ipce2e.ACTION_STICKY");
                sendStickyBroadcast(sticky);
                Log.i(TAG, "sendStickyBroadcast OK");
            } catch (SecurityException se) {
                Log.w(TAG, "sendStickyBroadcast permission denied: " + se.getMessage());
            }

            Log.i(TAG, "runBroadcastTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runBroadcastTests", t);
        }
    }

    // ------------------------------------------------------------
    // 3) Intent tests (IntentsE2E)
    // ------------------------------------------------------------

    private void runIntentTests() {
        Log.i(TAG, "runIntentTests started");

        try {
            // 1) Activity.getIntent() in MainActivity ->
            //    intents.ts: Activity.getIntent
            //    -> PROFILE_HOOKING_TYPE="IPC_INTENT", event_type="intent.accessed"
            Intent launchIntent = getIntent();
            if (launchIntent != null) {
                Log.i(TAG, "Launch intent action (MainActivity): " + launchIntent.getAction());

                // Optional data, may be null
                Uri launchData = launchIntent.getData();
                if (launchData != null) {
                    Log.i(TAG, "Launch intent data (MainActivity): " + launchData);
                }
            }

            // 2) Intent ACTION_VIEW with data + extras, getData() ->
            //    intents.ts: Intent.getData
            //    -> PROFILE_HOOKING_TYPE="IPC_INTENT", event_type="intent.data_accessed"
            Intent viewIntent = new Intent(Intent.ACTION_VIEW);
            viewIntent.setData(Uri.parse("https://example.com/path?x=1"));
            viewIntent.putExtra("extra_string", "hello");
            viewIntent.putExtra("extra_int", 123);
            viewIntent.putExtra("extra_bool", true);

            Uri data1 = viewIntent.getData();
            Log.i(TAG, "Intent1 data: " + data1);

            // 3) Explicit custom Intent with data + MIME type + extras, getData() ->
            //    intents.ts: Intent.getData
            //    -> PROFILE_HOOKING_TYPE="IPC_INTENT", event_type="intent.data_accessed"
            Intent customIntent = new Intent();
            customIntent.setAction("com.test.ipce2e.CUSTOM_ACTION");
            customIntent.setDataAndType(
                    Uri.parse("content://com.test.ipce2e/item/42"),
                    "text/plain"
            );
            customIntent.putExtra("extra_array", new String[]{"a", "b", "c"});

            Uri data2 = customIntent.getData();
            Log.i(TAG, "Intent2 data: " + data2);

            Log.i(TAG, "runIntentTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runIntentTests", t);
        }
    }

    // ------------------------------------------------------------
    // 4) SharedPreferences + DataStore tests (SharedPrefsE2E)
    // ------------------------------------------------------------

    private void runSharedPrefsTests() {
        Log.i(TAG, "runSharedPrefsTests started");

        try {
            // 1) getSharedPreferences(...) ->
            //    shared_prefs.ts: SharedPreferencesImpl.$init(File,int)
            //    -> PROFILE_HOOKING_TYPE="IPC_SHARED-PREF", event_type="shared_prefs.init"
            SharedPreferences prefs = getSharedPreferences("ipc_e2e_prefs", MODE_PRIVATE);

            SharedPreferences.Editor editor = prefs.edit();

            // 2) editor.putString(...) ->
            //    shared_prefs.ts: SharedPreferencesImpl$EditorImpl.putString(String,String)
            //    -> event_type="shared_prefs.put_string"
            editor.putString("sp_string", "hello");

            // 3) editor.putInt(...) ->
            //    shared_prefs.ts: SharedPreferencesImpl$EditorImpl.putInt(String,int)
            //    -> event_type="shared_prefs.putint"
            editor.putInt("sp_int", 123);

            // 4) editor.putLong(...) ->
            //    shared_prefs.ts: SharedPreferencesImpl$EditorImpl.putLong(String,long)
            //    -> event_type="shared_prefs.putlong"
            editor.putLong("sp_long", 987654321L);

            // 5) editor.putFloat(...) ->
            //    shared_prefs.ts: SharedPreferencesImpl$EditorImpl.putFloat(String,float)
            //    -> event_type="shared_prefs.putfloat"
            editor.putFloat("sp_float", 3.14f);

            // 6) editor.putBoolean(...) ->
            //    shared_prefs.ts: SharedPreferencesImpl$EditorImpl.putBoolean(String,boolean)
            //    -> event_type="shared_prefs.putboolean"
            editor.putBoolean("sp_bool", true);

            editor.apply();

            // Read-back (no hooks, just to verify values)
            String s = prefs.getString("sp_string", null);
            int i = prefs.getInt("sp_int", -1);
            long l = prefs.getLong("sp_long", -1L);
            float f = prefs.getFloat("sp_float", -1.0f);
            boolean b = prefs.getBoolean("sp_bool", false);

            Log.i(TAG, "SharedPreferences E2E: " +
                    "sp_string=" + s +
                    ", sp_int=" + i +
                    ", sp_long=" + l +
                    ", sp_float=" + f +
                    ", sp_bool=" + b);

            // 7) DataStore tests (Kotlin helper) ->
            //    shared_prefs.ts: hook_datastore()
            //    - DataStore.updateData[...] -> event_type="datastore.update"
            //    - DataStore.getData -> event_type="datastore.get"
            //    - Preferences$Key.$init(String) -> event_type="datastore_prefs.key_init"
            //    - Preferences.get(Key)/MutablePreferences.get(Key) -> event_type="datastore_prefs.get"
            SharedPrefsDataStoreHelper.runDataStoreTests(getApplicationContext());

            Log.i(TAG, "runSharedPrefsTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runSharedPrefsTests", t);
        }
    }
}