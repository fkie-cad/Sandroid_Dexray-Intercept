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
                // -> GetVersion, FindClass, GetSuperclass, IsAssignableFrom, IsInstanceOf,
                //    FromReflectedMethod/Field, ToReflectedMethod/Field
                EnvCoreTests.runTests();
                Log.i(TAG, "EnvCoreTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvCoreTests failed", t);
            }

            // 2) Env methods/fields tests
            try {
                // -> GetObjectClass, GetFieldID, GetStaticFieldID,
                //    Get*/Set*Field (instance + static, all primitive types + object)
                EnvMethodsFieldsTests.runTests();
                Log.i(TAG, "EnvMethodsFieldsTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvMethodsFieldsTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in JniE2E", t);
        } finally {
            finish();
        }
    }
}