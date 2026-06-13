package com.test.ipce2e;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class SecondActivity extends Activity {

    private static final String TAG = "IPC_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "SecondActivity started");

        try {
            // 1) Activity.getIntent() in SecondActivity ->
            //    intents.ts: Activity.getIntent
            //    -> PROFILE_HOOKING_TYPE="IPC_INTENT", event_type="intent.accessed"
            Intent intent = getIntent();
            if (intent != null) {
                Log.i(TAG, "SecondActivity intent: " + intent);

                // 2) Intent.getData() in SecondActivity (may be null) ->
                //    intents.ts: Intent.getData
                //    -> PROFILE_HOOKING_TYPE="IPC_INTENT", event_type="intent.data_accessed"
                Uri data = intent.getData();
                if (data != null) {
                    Log.i(TAG, "SecondActivity intent data: " + data);
                }
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in SecondActivity", t);
        }

        finish();
    }
}