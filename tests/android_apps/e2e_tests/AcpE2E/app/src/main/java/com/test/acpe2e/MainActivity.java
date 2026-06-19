package com.test.acpe2e;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.os.StrictMode;

public class MainActivity extends Activity {

    private static final String TAG = "ACP_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Allow network operations on main thread for test purposes
        StrictMode.setThreadPolicy(
                new StrictMode.ThreadPolicy.Builder()
                        .permitAll()
                        .build()
        );

        Log.i(TAG, "AcpE2E started");

        try {
            // 1) Proxy configuration tests
            try {
                ProxyConfigTests.runTests(this);
                Log.i(TAG, "ProxyConfigTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "ProxyConfigTests failed", t);
            }

            // 2) HTTPS URL connection / SSLContext tests
            try {
                HttpsUrlConnectionTests.runTests();
                Log.i(TAG, "HttpsUrlConnectionTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "HttpsUrlConnectionTests failed", t);
            }

            // 3) Root detection bypass tests
            try {
                RootDetectionTests.runTests(this);
                Log.i(TAG, "RootDetectionTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "RootDetectionTests failed", t);
            }

            // 4) System certificate injection / Conscrypt tests
            try {
                SystemCertInjectionTests.runTests();
                Log.i(TAG, "SystemCertInjectionTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "SystemCertInjectionTests failed", t);
            }

            // 5) Native connect() redirection tests
            try {
                NativeConnectTests.runTests();
                Log.i(TAG, "NativeConnectTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "NativeConnectTests failed", t);
            }

            // 6) OkHttp certificate pinning tests (OkHttp2 + OkHttp3)
            try {
                OkHttpAndPinnedLibTests.runTests();
                Log.i(TAG, "OkHttpAndPinnedLibTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "OkHttpAndPinnedLibTests failed", t);
            }

            // 7) Other pinned libraries (Netty, Appmattus CT, TrustKit)
            try {
                PinnedLibsTests.runTests();
                Log.i(TAG, "PinnedLibsTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "PinnedLibsTests failed", t);
            }

            // 8) Native TLS tests (Cronet / BoringSSL)
            try {
                NativeTlsTests.runTests(this);
                Log.i(TAG, "NativeTlsTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "NativeTlsTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "Error in AcpE2E", t);
        } finally {
            Log.i(TAG, "AcpE2E finished, calling finish()");
            finish();
        }
    }
}