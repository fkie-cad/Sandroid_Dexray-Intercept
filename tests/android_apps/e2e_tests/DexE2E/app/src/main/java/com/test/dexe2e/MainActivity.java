package com.test.dexe2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {

    private static final String TAG = "DEX_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "DexE2E started");

        // All test modules run synchronously on the main thread before onCreate()
        // returns. This satisfies the Theme.NoDisplay contract on Android 11+:
        // finish() must be called before onResume() completes. A background thread
        // would return from onCreate() before finish() is called, which triggers
        // "did not call finish() prior to onResume() completing".
        try {
            // 1) DexClassLoader.$init(String, String, String, ClassLoader)
            try {
                new DexClassLoaderTests(this).runTests();
                Log.i(TAG, "DexClassLoaderTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "DexClassLoaderTests failed", t);
            }

            // 2) PathClassLoader.$init - both 2-arg and 3-arg overloads
            try {
                new PathClassLoaderTests(this).runTests();
                Log.i(TAG, "PathClassLoaderTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "PathClassLoaderTests failed", t);
            }

            // 3) DelegateLastClassLoader.$init - 2-arg, 3-arg, and 4-arg (API 29+)
            try {
                new DelegateLastClassLoaderTests(this).runTests();
                Log.i(TAG, "DelegateLastClassLoaderTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "DelegateLastClassLoaderTests failed", t);
            }

            // 4) InMemoryDexClassLoader.$init(ByteBuffer, ClassLoader) - API 26+
            try {
                new InMemoryDexClassLoaderTests(this).runTests();
                Log.i(TAG, "InMemoryDexClassLoaderTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "InMemoryDexClassLoaderTests failed", t);
            }

            // 5) System.load(String) and System.loadLibrary(String)
            try {
                new SystemLoadLibraryTests(this).runTests();
                Log.i(TAG, "SystemLoadLibraryTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "SystemLoadLibraryTests failed", t);
            }

            // 6) Runtime.load(String) and Runtime.loadLibrary(String)
            try {
                new RuntimeLoadLibraryTests(this).runTests();
                Log.i(TAG, "RuntimeLoadLibraryTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "RuntimeLoadLibraryTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Unexpected error in DexE2E", t);
        } finally {
            Log.i(TAG, "DexE2E finished");
            finish();
        }
    }
}