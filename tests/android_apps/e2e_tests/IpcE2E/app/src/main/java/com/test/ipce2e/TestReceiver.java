package com.test.ipce2e;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class TestReceiver extends BroadcastReceiver {

    private static final String TAG = "IPC_E2E";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "TestReceiver received: " + intent);
    }
}