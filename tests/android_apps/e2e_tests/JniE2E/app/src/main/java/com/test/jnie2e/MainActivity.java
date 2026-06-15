package com.test.jnie2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {

    private static final String TAG = "JNI_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "JniE2E started");

        try {
            // 1) Env core tests (GetVersion / FindClass / GetSuperclass /
            //    IsAssignableFrom / IsInstanceOf / FromReflectedMethod /
            //    FromReflectedField / ToReflectedMethod / ToReflectedField)
            //    -> jni_trace.ts: JNIInterceptor.attach("GetVersion", jniEnvCallback)
            //       JNIInterceptor.attach("FindClass", jniEnvCallback)
            //       JNIInterceptor.attach("GetSuperclass", jniEnvCallback)
            //       JNIInterceptor.attach("IsAssignableFrom", jniEnvCallback)
            //       JNIInterceptor.attach("IsInstanceOf", jniEnvCallback)
            //       JNIInterceptor.attach("FromReflectedMethod", jniEnvCallback)
            //       JNIInterceptor.attach("FromReflectedField", jniEnvCallback)
            //       JNIInterceptor.attach("ToReflectedMethod", jniEnvCallback)
            //       JNIInterceptor.attach("ToReflectedField", jniEnvCallback)
            try {
                EnvCoreTests.runTests();
                Log.i(TAG, "EnvCoreTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvCoreTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in JniE2E", t);
        } finally {
            finish();
        }
    }
}