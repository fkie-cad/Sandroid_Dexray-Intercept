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
                // -> Call<Type>Method / Call<Type>MethodV / Call<Type>MethodA
                //    CallStatic<Type>Method / CallStatic<Type>MethodV / CallStatic<Type>MethodA
                //    NewObject / NewObjectA for MethodTarget(int,String) ctor
                EnvCallsTests.runTests();
                Log.i(TAG, "EnvCallsTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "EnvCallsTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in JniE2E", t);
        } finally {
            finish();
        }
    }
}