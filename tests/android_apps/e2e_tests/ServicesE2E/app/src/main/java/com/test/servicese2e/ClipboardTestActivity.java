package com.test.servicese2e;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

public class ClipboardTestActivity extends Activity {

    private static final String TAG = "SERVICES_CLIPBOARD";

    // write does not require focus; read requires focus - split across lifecycle methods
    private boolean writeCompleted = false;
    private boolean focusTestRan = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "ClipboardTestActivity started");

        // setPrimaryClip does not require window focus - safe in onCreate
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) {
            Log.w(TAG, "ClipboardManager not available");
            finish();
            return;
        }

        try {
            ClipData clip = ClipData.newPlainText("label", "services-e2e-clipboard");
            cm.setPrimaryClip(clip);
            Log.i(TAG, "ClipboardManager.setPrimaryClip completed");
            writeCompleted = true;
        } catch (Throwable t) {
            Log.e(TAG, "setPrimaryClip failed", t);
        }
        // getPrimaryClip deferred to onWindowFocusChanged - requires active window focus
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (!hasFocus || focusTestRan) return;
        focusTestRan = true;

        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        try {
            ClipData result = cm != null ? cm.getPrimaryClip() : null;
            Log.i(TAG, "ClipboardManager.getPrimaryClip item count: "
                    + (result != null ? result.getItemCount() : "null"));
        } catch (Throwable t) {
            Log.e(TAG, "getPrimaryClip failed", t);
        } finally {
            Log.i(TAG, "ClipboardTestActivity finished");
            finish();
        }
    }
}