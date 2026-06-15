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
                // -> NewString / GetStringLength
                //    GetStringChars / ReleaseStringChars
                //    NewStringUTF / GetStringUTFLength
                //    GetStringUTFChars / ReleaseStringUTFChars
                //    GetStringRegion / GetStringUTFRegion
                //    GetStringCritical / ReleaseStringCritical
                EnvStringTests.runTests();
                Log.i(TAG, "EnvStringTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvStringTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in JniE2E", t);
        } finally {
            finish();
        }
    }
}