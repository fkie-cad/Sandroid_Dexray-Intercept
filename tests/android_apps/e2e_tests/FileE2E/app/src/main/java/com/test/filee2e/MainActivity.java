package com.test.filee2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {

    private static final String TAG = "FS_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "FileE2E started");

        // All test modules run synchronously on the main thread before onCreate()
        // returns. This satisfies the Theme.NoDisplay contract on Android 11+:
        // finish() must be called before onResume() completes.
        try {

            // 1) File.$init overloads: (String), (File,String), (String,String), (URI)
            try {
                new FileConstructorTests(this).runTests();
                Log.i(TAG, "FileConstructorTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "FileConstructorTests failed", t);
            }

            // 2) FileInputStream.$init and read overloads
            try {
                new FileInputStreamTests(this).runTests();
                Log.i(TAG, "FileInputStreamTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "FileInputStreamTests failed", t);
            }

            // 3) FileOutputStream.$init and write overloads
            try {
                new FileOutputStreamTests(this).runTests();
                Log.i(TAG, "FileOutputStreamTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "FileOutputStreamTests failed", t);
            }

            // 4) File.delete() (Java, .dex and .jar) and native unlink()
            try {
                new FileDeleteTests(this).runTests();
                Log.i(TAG, "FileDeleteTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "FileDeleteTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Unexpected error in FileE2E", t);
        } finally {
            Log.i(TAG, "FileE2E finished");
            finish();
        }
    }
}