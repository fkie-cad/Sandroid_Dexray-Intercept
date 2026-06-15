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
            // 1) Env core tests
            try {
                EnvCoreTests.runTests();
                Log.i(TAG, "EnvCoreTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvCoreTests failed", t);
            }

            // 2) Env methods/fields tests
            try {
                EnvMethodsFieldsTests.runTests();
                Log.i(TAG, "EnvMethodsFieldsTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvMethodsFieldsTests failed", t);
            }

            // 3) Env instance/static call tests
            try {
                EnvCallsTests.runTests();
                Log.i(TAG, "EnvCallsTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvCallsTests failed", t);
            }

            // 4) Env string API tests
            try {
                EnvStringTests.runTests();
                Log.i(TAG, "EnvStringTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvStringTests failed", t);
            }

            // 5) Env array tests (primitive + object)
            try {
                // -> GetArrayLength
                //    NewObjectArray / GetObjectArrayElement / SetObjectArrayElement
                //    New*Array / Get*ArrayElements / Release*ArrayElements
                //    Set*ArrayRegion / Get*ArrayRegion
                //    GetPrimitiveArrayCritical / ReleasePrimitiveArrayCritical
                EnvArrayTests.runTests();
                Log.i(TAG, "EnvArrayTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvArrayTests failed", t);
            }

            // 6) Env reference / frame tests
            try {
                // -> PushLocalFrame / PopLocalFrame
                //    EnsureLocalCapacity
                //    NewLocalRef / DeleteLocalRef
                //    NewGlobalRef / DeleteGlobalRef
                //    NewWeakGlobalRef / DeleteWeakGlobalRef
                //    IsSameObject / GetObjectRefType
                EnvRefTests.runTests();
                Log.i(TAG, "EnvRefTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvRefTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in JniE2E", t);
        } finally {
            finish();
        }
    }
}