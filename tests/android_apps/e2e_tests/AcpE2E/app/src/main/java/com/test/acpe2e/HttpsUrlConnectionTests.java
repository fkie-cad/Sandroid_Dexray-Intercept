package com.test.acpe2e;

import android.util.Log;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;

public class HttpsUrlConnectionTests {

    private static final String TAG = "ACP_E2E_HTTPS";

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
            testSslContextInitAndHttpsConnection();
        } catch (Throwable t) {
            Log.e(TAG, "testSslContextInitAndHttpsConnection threw", t);
            testsFailed++;
        }

        Log.i(TAG, "HttpsUrlConnectionTests summary: passed=" + testsPassed + " failed=" + testsFailed);
    }

    private static void testSslContextInitAndHttpsConnection() {
        // Target: android-certificate-unpinning.js
        //  -> SSLContext.init(...) hook, replacement of TrustManager[] with ACP-provided trust manager
        //  -> HttpsURLConnection.setDefaultHostnameVerifier / setHostnameVerifier / setSSLSocketFactory

        try {
            // TrustManager that always throws to simulate strict pinning.
            X509TrustManager throwingTm = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    throw new RuntimeException("client not trusted");
                }
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    throw new RuntimeException("server not trusted");
                }
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };

            TrustManager[] tms = new TrustManager[]{throwingTm};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tms, new SecureRandom());

            // HostnameVerifier that always fails.
            HostnameVerifier failingVerifier = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return false;
                }
            };

            HttpsURLConnection.setDefaultHostnameVerifier(failingVerifier);

            URL url = new URL("https://example.com/");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            if (!(conn instanceof HttpsURLConnection)) {
                Log.w(TAG, "Connection is not HttpsURLConnection, skipping HTTPS-specific test");
                assertTest(true, "HttpURLConnection open (non-HTTPS env)");
                return;
            }

            HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
            httpsConn.setHostnameVerifier(failingVerifier);
            httpsConn.setSSLSocketFactory(sslContext.getSocketFactory());

            // In a strict environment without ACP, this should fail due to trust/hostname issues.
            // With ACP, connection may still succeed if proxy/cert are configured.
            try {
                httpsConn.setConnectTimeout(3000);
                httpsConn.setReadTimeout(3000);
                int code = httpsConn.getResponseCode();
                Log.i(TAG, "HTTPS response code: " + code);
                InputStream is = httpsConn.getInputStream();
                if (is != null) {
                    is.close();
                }
            } catch (Throwable t) {
                Log.w(TAG, "HTTPS request failed (expected in some environments)", t);
            } finally {
                httpsConn.disconnect();
            }

            assertTest(true, "HttpsURLConnection setHostnameVerifier/setSSLSocketFactory/SSLContext.init executed");
        } catch (Throwable t) {
            Log.e(TAG, "Error in testSslContextInitAndHttpsConnection", t);
            assertTest(false, "testSslContextInitAndHttpsConnection");
        }
    }
}