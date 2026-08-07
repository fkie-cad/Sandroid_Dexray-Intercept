package com.test.ipce2e;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

import java.util.ArrayList;


public class MainActivity extends Activity {

    private static final String TAG = "IPC_E2E";

    private ServiceConnection mTestServiceConn;
    private boolean mTestServiceBound = false;

    private final ArrayList<BroadcastReceiver> mRegisteredReceivers = new ArrayList<>();

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

    @Override
    protected void onDestroy() {
        unbindTestServiceIfNeeded();
        unregisterDynamicReceivers();
        super.onDestroy();
    }

    private void trackRegisteredReceiver(BroadcastReceiver receiver) {
        if (receiver != null && !mRegisteredReceivers.contains(receiver)) {
            mRegisteredReceivers.add(receiver);
        }
    }

    private void unregisterDynamicReceivers() {
        if (mRegisteredReceivers.isEmpty()) {
            return;
        }

        ArrayList<BroadcastReceiver> receivers = new ArrayList<>(mRegisteredReceivers);
        mRegisteredReceivers.clear();

        for (BroadcastReceiver receiver : receivers) {
            try {
                unregisterReceiver(receiver);
                Log.i(TAG, "unregisterReceiver OK: " + receiver.getClass().getName());
                Log.i(TAG, "unregisterDynamicReceivers count: " + mRegisteredReceivers.size());
            } catch (Throwable t) {
                Log.w(TAG, "unregisterReceiver failed: " + t.getMessage());
            }
        }
    }

    private void unbindTestServiceIfNeeded() {
        if (mTestServiceConn == null) {
            mTestServiceBound = false;
            return;
        }

        ServiceConnection conn = mTestServiceConn;
        mTestServiceConn = null;

        if (!mTestServiceBound) {
            return;
        }

        mTestServiceBound = false;

        try {
            unbindService(conn);
            Log.i(TAG, "onDestroy unbindService OK");
        } catch (Throwable t) {
            Log.w(TAG, "onDestroy unbindService failed: " + t.getMessage());
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

            // 7) registerReceiver - API 33+ requires explicit exported/not-exported flag.
            //    On API 33+, use registerReceiver(BroadcastReceiver,IntentFilter,int).
            //    On older APIs, use the legacy 2-arg overload.
            try {
                TestReceiver receiver1 = new TestReceiver();
                IntentFilter filter = new IntentFilter("com.test.ipce2e.ACTION_SIMPLE");

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    registerReceiver(receiver1, filter, Context.RECEIVER_NOT_EXPORTED);
                } else {
                    registerReceiver(receiver1, filter);
                }

                trackRegisteredReceiver(receiver1);
                Log.i(TAG, "registerReceiver(simple dynamic receiver) OK");
            } catch (Throwable t) {
                Log.w(TAG, "registerReceiver(simple dynamic receiver) failed: " + t.getMessage());
            }

            // 8) registerReceiver with permission.
            //    API 33+ requires explicit exported/not-exported flag.
            try {
                TestReceiver receiver2 = new TestReceiver();
                IntentFilter filter2 = new IntentFilter("com.test.ipce2e.ACTION_PERMISSION");
                Handler handler = new Handler(getMainLooper());

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    registerReceiver(
                            receiver2,
                            filter2,
                            "com.test.ipce2e.PERMISSION_TEST",
                            handler,
                            Context.RECEIVER_NOT_EXPORTED
                    );
                } else {
                    registerReceiver(
                            receiver2,
                            filter2,
                            "com.test.ipce2e.PERMISSION_TEST",
                            handler
                    );
                }

                trackRegisteredReceiver(receiver2);
                Log.i(TAG, "registerReceiver(permission dynamic receiver) OK");
            } catch (Throwable t) {
                Log.w(TAG, "registerReceiver(permission dynamic receiver) failed: " + t.getMessage());
            }

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

            // 10) startForegroundService(Intent) ->
            //     broadcast.ts: ContextWrapper.startForegroundService
            //     -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type may depend on current hooks.
            //     MyTestService should promote itself to foreground when EXTRA_START_FOREGROUND is true.
            try {
                Intent fgServiceIntent = new Intent(this, MyTestService.class);
                fgServiceIntent.putExtra("fg_service_key", "fg_service_value");
                fgServiceIntent.putExtra(MyTestService.EXTRA_START_FOREGROUND, true);

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(fgServiceIntent);
                    Log.i(TAG, "startForegroundService OK");
                } else {
                    startService(fgServiceIntent);
                    Log.i(TAG, "startService fallback for foreground service test OK");
                }
            } catch (Throwable t) {
                Log.w(TAG, "startForegroundService failed: " + t.getMessage());
            }

            // 11) sendOrderedBroadcast(Intent, String) - 2-arg
            //     broadcast.ts: ContextWrapper.sendOrderedBroadcast[Intent,String]
            //     -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="broadcast.ordered_sent"
            Intent orderedSimple = new Intent("com.test.ipce2e.ACTION_ORDERED_2ARG");
            orderedSimple.putExtra("ordered_key", "ordered_simple_value");
            sendOrderedBroadcast(orderedSimple, null);
            Log.i(TAG, "sendOrderedBroadcast(2-arg) OK");

            // 12) sendOrderedBroadcast(Intent,String,BroadcastReceiver,Handler,int,String,Bundle) - 7-arg
            //     broadcast.ts: ContextWrapper.sendOrderedBroadcast[Intent,String,BroadcastReceiver,Handler,int,String,Bundle]
            //     -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="broadcast.ordered_sent"
            Intent orderedFull = new Intent("com.test.ipce2e.ACTION_ORDERED_7ARG");
            orderedFull.putExtra("ordered_key", "ordered_full_value");
            sendOrderedBroadcast(
                    orderedFull,
                    null,
                    new BroadcastReceiver() {
                        @Override
                        public void onReceive(Context context, Intent intent) {
                            Log.i(TAG, "sendOrderedBroadcast(7-arg) final result receiver fired");
                        }
                    },
                    null,
                    RESULT_OK,
                    "initial_data",
                    null
            );
            Log.i(TAG, "sendOrderedBroadcast(7-arg) OK");

            // 13) bindService(Intent, ServiceConnection, int)
            //     broadcast.ts: ContextWrapper.bindService[Intent,ServiceConnection,int]
            //     -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="service.bound"
            //     unbindService called from onServiceConnected async, or onDestroy fallback.
            ServiceConnection conn = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    Log.i(TAG, "bindService onServiceConnected: " + name);

                    try {
                        unbindService(this);
                        Log.i(TAG, "unbindService OK");
                    } catch (Throwable t) {
                        Log.w(TAG, "unbindService failed: " + t.getMessage());
                    } finally {
                        if (mTestServiceConn == this) {
                            mTestServiceConn = null;
                        }
                        mTestServiceBound = false;
                    }
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    Log.i(TAG, "bindService onServiceDisconnected: " + name);

                    if (mTestServiceConn == this) {
                        mTestServiceConn = null;
                    }
                    mTestServiceBound = false;
                }
            };

            mTestServiceConn = conn;
            mTestServiceBound = false;

            boolean boundOk = bindService(
                    new Intent(this, MyTestService.class),
                    conn,
                    Context.BIND_AUTO_CREATE
            );

            mTestServiceBound = boundOk;
            if (!boundOk) {
                mTestServiceConn = null;
            }

            Log.i(TAG, "bindService result: " + boundOk);

            // 14) registerReceiver - 2-arg and 4-arg: only safe without flags on API < 33.
            //     On API 33+ these can throw SecurityException because exported flag is mandatory.
            //     Complements the existing flag-bearing test cases above.
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                try {
                    TestReceiver recv2arg = new TestReceiver();
                    registerReceiver(
                            recv2arg,
                            new IntentFilter("com.test.ipce2e.ACTION_TEST_2ARG")
                    );
                    trackRegisteredReceiver(recv2arg);
                    Log.i(TAG, "registerReceiver(2-arg) OK");
                } catch (Throwable t) {
                    Log.w(TAG, "registerReceiver(2-arg) failed: " + t.getMessage());
                }

                try {
                    TestReceiver recv4arg = new TestReceiver();
                    registerReceiver(
                            recv4arg,
                            new IntentFilter("com.test.ipce2e.ACTION_TEST_4ARG"),
                            null,
                            null
                    );
                    trackRegisteredReceiver(recv4arg);
                    Log.i(TAG, "registerReceiver(4-arg) OK");
                } catch (Throwable t) {
                    Log.w(TAG, "registerReceiver(4-arg) failed: " + t.getMessage());
                }
            }

            // 15) startActivityForResult(Intent, int) - 2-arg
            //     broadcast.ts: Activity.startActivityForResult[Intent,int]
            //     -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="activity.started_for_result"
            //     Note: hook fires synchronously; onActivityResult may not fire because MainActivity finishes.
            Intent forResult2arg = new Intent(this, SecondActivity.class);
            forResult2arg.putExtra("launched_by", "startActivityForResult_2arg");
            startActivityForResult(forResult2arg, 9001);
            Log.i(TAG, "startActivityForResult(2-arg) OK");

            // 16) startActivityForResult(Intent, int, Bundle) - 3-arg
            //     broadcast.ts: Activity.startActivityForResult[Intent,int,Bundle]
            //     -> PROFILE_HOOKING_TYPE="IPC_BROADCAST", event_type="activity.started_for_result"
            Intent forResult3arg = new Intent(this, SecondActivity.class);
            forResult3arg.putExtra("launched_by", "startActivityForResult_3arg");
            startActivityForResult(forResult3arg, 9002, null);
            Log.i(TAG, "startActivityForResult(3-arg) OK");

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
            //    - Also exercises both direct runBlocking calls and dispatched GlobalScope coroutine calls
            SharedPrefsDataStoreHelper.runDataStoreTests(getApplicationContext());

            Log.i(TAG, "runSharedPrefsTests completed");

        } catch (Throwable t) {
            Log.e(TAG, "Error in runSharedPrefsTests", t);
        }
    }
}