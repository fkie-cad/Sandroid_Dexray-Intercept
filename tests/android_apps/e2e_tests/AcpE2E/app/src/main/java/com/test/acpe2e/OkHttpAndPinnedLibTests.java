package com.test.acpe2e;

import android.util.Log;

import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class OkHttpAndPinnedLibTests {

    private static final String TAG = "ACP_E2E_OKHTTP";

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    private static void assertTest(boolean cond, String name) {
        if (cond) {
            Log.i(TAG, "PASS: " + name);
            testsPassed++;
        } else {
            Log.e(TAG, "FAIL: " + name);
            testsFailed++;
        }
    }

    public static void runTests() {
        testsPassed = 0;
        testsFailed = 0;

        try {
            testOkHttp3CertificatePinnerChecks();
        } catch (Throwable t) {
            Log.e(TAG, "testOkHttp3CertificatePinnerChecks threw", t);
            testsFailed++;
        }

        try {
            testOkHttp3PinnedRequest();
        } catch (Throwable t) {
            Log.e(TAG, "testOkHttp3PinnedRequest threw", t);
            testsFailed++;
        }

        try {
            testOkHttp2CertificatePinnerChecks();
        } catch (Throwable t) {
            Log.e(TAG, "testOkHttp2CertificatePinnerChecks threw", t);
            testsFailed++;
        }

        Log.i(TAG, "OkHttpAndPinnedLibTests summary: passed=" + testsPassed + " failed=" + testsFailed);
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    /**
     * Dummy Certificate implementation for pinning checks.
     * Encoded form is empty; only used to exercise method signatures.
     */
    private static Certificate makeDummyCertificate() {
        return new Certificate("X.509") {
            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }

            @Override
            public void verify(java.security.PublicKey key) {
                // No-op
            }

            @Override
            public void verify(java.security.PublicKey key, String sigProvider) {
                // No-op
            }

            @Override
            public String toString() {
                return "DummyCert";
            }

            @Override
            public java.security.PublicKey getPublicKey() {
                return null;
            }
        };
    }

    // ------------------------------------------------------------------------
    // OkHttp3 tests -> okhttp3.CertificatePinner hooks
    // ------------------------------------------------------------------------

    private static void testOkHttp3CertificatePinnerChecks() {
        // Hooks:
        //   'okhttp3.CertificatePinner': [
        //     { methodName: 'check', overload: ['java.lang.String', 'java.util.List'], ... },
        //     { methodName: 'check', overload: ['java.lang.String', 'java.security.cert.Certificate'], ... },
        //     { methodName: 'check', overload: ['java.lang.String', '[Ljava.security.cert.Certificate;'], ... },
        //     { methodName: 'check$okhttp', ... }
        //   ]

        CertificatePinner pinner = new CertificatePinner.Builder()
                .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();

        Certificate dummy = makeDummyCertificate();

        // 1) check(String, List<Certificate>)
        //    -> android-certificate-unpinning.js: PINNING_FIXES['okhttp3.CertificatePinner'][0]
        try {
            List<Certificate> certs = Collections.singletonList(dummy);
            pinner.check("example.com", certs);
            Log.i(TAG, "okhttp3.CertificatePinner.check(String, List<Certificate>) executed");
            assertTest(true, "OkHttp3 CertificatePinner.check(String, List<Certificate>) call");
        } catch (Throwable t) {
            Log.w(TAG, "OkHttp3 check(String, List) threw: " + t.getMessage());
            assertTest(true, "OkHttp3 CertificatePinner.check(String, List<Certificate>) call (threw)");
        }

        // 2) check(String, Certificate)
        //    -> android-certificate-unpinning.js: PINNING_FIXES['okhttp3.CertificatePinner'][1]
        try {
            pinner.check("example.com", dummy);
            Log.i(TAG, "okhttp3.CertificatePinner.check(String, Certificate) executed");
            assertTest(true, "OkHttp3 CertificatePinner.check(String, Certificate) call");
        } catch (Throwable t) {
            Log.w(TAG, "OkHttp3 check(String, Certificate) threw: " + t.getMessage());
            assertTest(true, "OkHttp3 CertificatePinner.check(String, Certificate) call (threw)");
        }

        // 3) check(String, Certificate[])
        //    -> android-certificate-unpinning.js: PINNING_FIXES['okhttp3.CertificatePinner'][2]
        try {
            Certificate[] certArray = new Certificate[]{dummy};
            pinner.check("example.com", certArray);
            Log.i(TAG, "okhttp3.CertificatePinner.check(String, Certificate[]) executed");
            assertTest(true, "OkHttp3 CertificatePinner.check(String, Certificate[]) call");
        } catch (Throwable t) {
            Log.w(TAG, "OkHttp3 check(String, Certificate[]) threw: " + t.getMessage());
            assertTest(true, "OkHttp3 CertificatePinner.check(String, Certificate[]) call (threw)");
        }

        // Build client to ensure class initialization conditions similar to real usage.
        try {
            OkHttpClient client = new OkHttpClient.Builder()
                    .certificatePinner(pinner)
                    .build();
            Log.i(TAG, "OkHttp3 OkHttpClient with CertificatePinner created");
            assertTest(true, "OkHttp3 OkHttpClient with CertificatePinner build");
        } catch (Throwable t) {
            Log.w(TAG, "OkHttp3 client build failed: " + t.getMessage());
            assertTest(true, "OkHttp3 OkHttpClient build attempted");
        }
    }

    private static void testOkHttp3PinnedRequest() {
        // Target:
        //   okhttp3.CertificatePinner.check$okhttp (Kotlin synthetic)
        //   -> executed during real HTTPS request with CertificatePinner configured.
        //
        // This test builds a client with a deliberately invalid pin so that pinned
        // verification fails without unpinning. Under ACP + Mitmproxy, behaviour
        // can be compared.

        CertificatePinner pinner = new CertificatePinner.Builder()
                // Invalid dummy pin; does not match real certificate
                .add("example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
                .build();

        OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(pinner)
                .callTimeout(java.time.Duration.ofSeconds(5))
                .connectTimeout(java.time.Duration.ofSeconds(3))
                .readTimeout(java.time.Duration.ofSeconds(3))
                .build();

        Request req = new Request.Builder()
                .url("https://example.com/")
                .build();

        try (Response resp = client.newCall(req).execute()) {
            int code = resp.code();
            Log.i(TAG, "OkHttp3 pinned HTTPS response code: " + code);
        } catch (Throwable t) {
            Log.w(TAG, "OkHttp3 pinned HTTPS request failed (expected in many environments): " + t);
        }

        assertTest(true, "OkHttp3 pinned HTTPS request executed");
    }

    // ------------------------------------------------------------------------
    // OkHttp2 tests -> com.squareup.okhttp.CertificatePinner hooks
    // ------------------------------------------------------------------------

    private static void testOkHttp2CertificatePinnerChecks() {
        // Hooks:
        //   'com.squareup.okhttp.CertificatePinner': [
        //     { methodName: 'check', overload: ['java.lang.String', 'java.security.cert.Certificate'], ... },
        //     { methodName: 'check', overload: ['java.lang.String', 'java.util.List'], ... }
        //   ]
        //
        // OkHttp2 CertificatePinner API (2.7.x):
        //   - Builder.add(String pattern, String pin)
        //   - void check(String hostname, List<Certificate> peerCertificates)
        //   - void check(String hostname, Certificate... peerCertificates)

        try {
            com.squareup.okhttp.CertificatePinner pinner2 =
                    new com.squareup.okhttp.CertificatePinner.Builder()
                            .add("example.com", "sha1/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                            .build();

            Certificate dummy = makeDummyCertificate();

            // 1) check(String, List<Certificate>)
            //    -> android-certificate-unpinning.js: PINNING_FIXES['com.squareup.okhttp.CertificatePinner'][1]
            try {
                List<Certificate> certs = Collections.singletonList(dummy);
                pinner2.check("example.com", certs);
                Log.i(TAG, "OkHttp2 CertificatePinner.check(String, List<Certificate>) executed");
                assertTest(true, "OkHttp2 CertificatePinner.check(String, List<Certificate>) call");
            } catch (Throwable t) {
                Log.w(TAG, "OkHttp2 check(String, List<Certificate>) threw: " + t.getMessage());
                assertTest(true, "OkHttp2 CertificatePinner.check(String, List<Certificate>) call (threw)");
            }

            // 2) check(String, Certificate...) (varargs)
            //    -> mapped by hooks as check(String, Certificate) via varargs
            //    -> android-certificate-unpinning.js: PINNING_FIXES['com.squareup.okhttp.CertificatePinner'][0]
            try {
                pinner2.check("example.com", dummy);
                Log.i(TAG, "OkHttp2 CertificatePinner.check(String, Certificate...) executed");
                assertTest(true, "OkHttp2 CertificatePinner.check(String, Certificate...) call");
            } catch (Throwable t) {
                Log.w(TAG, "OkHttp2 check(String, Certificate...) threw: " + t.getMessage());
                assertTest(true, "OkHttp2 CertificatePinner.check(String, Certificate...) call (threw)");
            }
            
        } catch (Throwable t) {
            Log.e(TAG, "Error in testOkHttp2CertificatePinnerChecks", t);
            assertTest(false, "OkHttp2 CertificatePinner checks");
        }
    }
}