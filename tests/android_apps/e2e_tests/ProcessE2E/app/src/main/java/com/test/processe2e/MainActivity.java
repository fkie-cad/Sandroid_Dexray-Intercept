package com.test.processe2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {

    private static final String TAG = "PROCESS_RUNTIME_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "ProcessE2E started");

        // All test modules run synchronously on the main thread before onCreate()
        // returns. This satisfies the Theme.NoDisplay contract on Android 11+:
        // finish() must be called before onResume() completes.
        try {

            // 1) android.os.Process: sendSignal, killProcess
            //    Process.start: not triggerable from user app - documented in test class
            try {
                new ProcessJavaTests().runTests();
                Log.i(TAG, "ProcessJavaTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "ProcessJavaTests failed", t);
            }

            // 2) Runtime.exec: all 6 overloads
            try {
                new RuntimeExecTests(getFilesDir()).runTests();
                Log.i(TAG, "RuntimeExecTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "RuntimeExecTests failed", t);
            }

            // 3) Runtime.loadLibrary and Runtime.load
            try {
                new RuntimeLoadTests().runTests();
                Log.i(TAG, "RuntimeLoadTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "RuntimeLoadTests failed", t);
            }

            // 4) Native: fork, execve, system, dlopen via JNI
            try {
                new NativeProcessTests().runTests();
                Log.i(TAG, "NativeProcessTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "NativeProcessTests failed", t);
            }

            // 5) Reflection: Class.forName (3-arg hooked, 1-arg not hooked),
            //    getMethod, getDeclaredMethod, ClassLoader.loadClass, Method.invoke
            try {
                new ReflectionTests(getClassLoader()).runTests();
                Log.i(TAG, "ReflectionTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "ReflectionTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Unexpected error in ProcessE2E", t);
        } finally {
            Log.i(TAG, "ProcessE2E finished");
            finish();
        }
    }
}