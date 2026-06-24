package com.test.networke2e;

import android.app.Activity;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.android.volley.RequestQueue;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Retrofit;
import retrofit2.http.GET;

public class MainActivity extends Activity {

    private static final String TAG                 = "NETWORK_E2E";
    private static final String TEST_HTTP_URL       = "https://httpbin.org/get"; 
    private static final String TEST_HTTP_POST_URL  = "https://httpbin.org/post";
    private static final String TEST_WEBSOCKET_URL  = "wss://echo.websocket.org";

    // Ordered fallback endpoints for HTTP POST tests (external).
    // Tried in sequence after the local MiniHttpServer baseline.
    // httpbin.org kept last - intermittent availability observed.
    private static final String[] HTTP_POST_FALLBACK_URLS = {
        "https://postman-echo.com/post",
        "https://jsonplaceholder.typicode.com/posts",
        "https://httpbin.org/post"
    };

    // Ordered fallback endpoints for HTTPS GET tests.
    // Tried in sequence; first successful response stops iteration.
    // A local server could be used here, but requires additional SSL setup.
    // httpbin.org kept last - intermittent availability observed.
    private static final String[] HTTPS_FALLBACK_URLS = {
        "https://postman-echo.com/get",
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://www.google.com/",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://httpbin.org/get"
    };

    private static final int LOCAL_WS_PORT = 8081;

    // Ordered fallback endpoints for WebSocket tests.
    // Local in-app echo server is tried first (no external dependency).
    // External WSS endpoints follow for real-network and TLS path coverage.
    // wss://echo.websocket.events removed - CNAME resolves to no A/AAAA records.
    private static final String[] WEBSOCKET_FALLBACK_URLS = {
        "ws://127.0.0.1:" + LOCAL_WS_PORT,   // in-app echo server - loopback, no TLS needed
        "wss://echo.websocket.org",           // primary public echo
        "wss://ws.postman-echo.com/raw",      // secondary public echo
        "wss://echo.rapidtoolset.com/ws"      // tertiary public echo - rate-limited, fine for infrequent runs
    };

    // Ordered fallback endpoints for HTTP GET tests (OkHttp3, legacy, Volley).
    // httpbin.org kept last - intermittent availability observed.
    private static final String[] HTTP_GET_FALLBACK_URLS = {
        "https://postman-echo.com/get",
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://httpbin.org/get"
    };

    // Ordered fallback base URLs for Retrofit tests.
    // httpbin.org kept last - intermittent availability observed.
    private static final String[] RETROFIT_BASE_FALLBACK_URLS = {
        "https://postman-echo.com/",
        "https://jsonplaceholder.typicode.com/",
        "https://httpbin.org/"
    };


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "NetworkE2E started");

        // WebView construction and all loadUrl/loadData/postUrl calls require
        // the main thread; executed here before the network thread is started.
        try {
            runWebViewTests();
            Log.i(TAG, "runWebViewTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runWebViewTests failed", t);
        }

        // All remaining tests perform blocking network I/O and must run off
        // the main thread to satisfy Android's NetworkOnMainThreadException policy.
        Thread thread = new Thread(() -> {
            try {

                // 1) URL / URI construction + HttpURLConnection (POST)
                //    web.ts: url.creation, uri.creation, url.open_connection,
                //            okhttp.request_method, okhttp.request_property,
                //            http.connect, http.output_stream, http.input_stream
                try {
                    runUrlAndHttpUrlConnectionTests();
                    Log.i(TAG, "runUrlAndHttpUrlConnectionTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runUrlAndHttpUrlConnectionTests failed", t);
                }

                // 2) HttpsURLConnection (GET)
                //    web.ts: https.request_method, https.connect, https.input_stream
                try {
                    runHttpsUrlConnectionTests();
                    Log.i(TAG, "runHttpsUrlConnectionTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runHttpsUrlConnectionTests failed", t);
                }

                // 3) OkHttp3
                //    web.ts: okhttp.request (OkHttpClient.newCall)
                try {
                    runOkHttp3Tests();
                    Log.i(TAG, "runOkHttp3Tests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runOkHttp3Tests failed", t);
                }

                // 4) Legacy OkHttp (com.squareup.okhttp.*)
                //    web.ts: okhttp_old.request
                try {
                    runOkHttpLegacyTests();
                    Log.i(TAG, "runOkHttpLegacyTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runOkHttpLegacyTests failed", t);
                }

                // 5) Retrofit2 - synchronous and asynchronous
                //    web.ts: retrofit.request, retrofit.response, retrofit.async_request
                try {
                    runRetrofitTests();
                    Log.i(TAG, "runRetrofitTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runRetrofitTests failed", t);
                }

                // 6) Volley StringRequest + RequestQueue
                //    web.ts: volley.string_request, volley.queue_request
                try {
                    runVolleyTests();
                    Log.i(TAG, "runVolleyTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runVolleyTests failed", t);
                }

                // 7) Java-layer and native socket tests (TCP, Unix domain, UDP)
                //    sockets.ts: socket.java.server_accept, socket.java.init,
                //                socket.java.connect, socket.java.local_accept,
                //                socket.java.datagram_connect
                //                + native: socket, bind, connect, write, read,
                //                          sendto, recvfrom (via JVM socket internals)
                try {
                    runSocketTests();
                    Log.i(TAG, "runSocketTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runSocketTests failed", t);
                }

                // 8) OkHttp3 WebSocket
                //    web.ts: websocket.send_text, websocket.opened,
                //            websocket.message_received
                try {
                    runWebSocketTests();
                    Log.i(TAG, "runWebSocketTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "runWebSocketTests failed", t);
                }

                // 9) Native libc syscalls not reliably reached via Java sockets
                //    sockets.ts: Libc::send, Libc::recv,
                //                Libc::sendmsg, Libc::recvmsg, Libc::close
                try {
                    NativeSocketTests.runTests();
                    Log.i(TAG, "NativeSocketTests completed");
                } catch (Throwable t) {
                    Log.e(TAG, "NativeSocketTests failed", t);
                }

            } catch (Throwable t) {
                Log.e(TAG, "Error in NetworkE2E", t);
            } finally {
                Log.i(TAG, "NetworkE2E finished");
            }
        }, "networke2e-tests");
        thread.start();
        Log.i(TAG, "NetworkE2E calling finish()");
        finish();
    }

    // ------------------------------------------------------------
    // URL / HttpURLConnection / URI
    // web.ts: install_url_hooks, install_http_hooks
    //   -> url.creation, uri.creation, url.open_connection,
    //      okhttp.request_method, okhttp.request_property,
    //      http.connect, http.output_stream, http.input_stream
    //
    // Phase 1: local MiniHttpServer - guaranteed baseline, no
    //          external dependency.
    // Phase 2: external HTTP_POST_FALLBACK_URLS iterated in order;
    //          first success stops iteration. Exercises the same
    //          hooks against real external endpoints.
    // ------------------------------------------------------------
    private void runUrlAndHttpUrlConnectionTests() {
        Log.i(TAG, "runUrlAndHttpUrlConnectionTests started");

        // Phase 1 - local MiniHttpServer baseline
        MiniHttpServer server = null;
        HttpURLConnection conn = null;
        try {
            server = new MiniHttpServer();
            server.start();

            String localUrl = "http://127.0.0.1:" + server.getPort() + "/post";

            // url.creation, uri.creation
            URL url = new URL(localUrl);
            URI uri = new URI(localUrl);
            Log.i(TAG, "MiniHttpServer URI: " + uri.toString());

            // url.open_connection
            conn = (HttpURLConnection) url.openConnection();

            // okhttp.request_method, http.request_method
            conn.setRequestMethod("POST");
            // okhttp.request_property
            conn.setRequestProperty("X-NetworkE2E", "1");
            conn.setDoOutput(true);

            // http.connect
            conn.connect();

            // http.output_stream
            OutputStream os = conn.getOutputStream();
            os.write("field=value".getBytes("UTF-8"));
            os.flush();

            // http.input_stream
            int code = conn.getResponseCode();
            Log.i(TAG, "MiniHttpServer response code: " + code);
            readInputStream(conn.getInputStream());
            Log.i(TAG, "runUrlAndHttpUrlConnectionTests MiniHttpServer phase passed");

        } catch (Throwable t) {
            Log.e(TAG, "runUrlAndHttpUrlConnectionTests MiniHttpServer phase failed", t);
        } finally {
            if (conn != null) conn.disconnect();
            if (server != null) server.join();
        }

        // Phase 2 - external endpoints
        for (String testUrl : HTTP_POST_FALLBACK_URLS) {
            HttpURLConnection extConn = null;
            try {
                // url.creation, uri.creation
                URL url = new URL(testUrl);
                URI uri = new URI(testUrl);
                Log.i(TAG, "External URI: " + uri.toString());

                // url.open_connection
                extConn = (HttpURLConnection) url.openConnection();

                // okhttp.request_method, http.request_method
                extConn.setRequestMethod("POST");
                // okhttp.request_property
                extConn.setRequestProperty("X-NetworkE2E", "1");
                extConn.setDoOutput(true);
                extConn.setConnectTimeout(3000);
                extConn.setReadTimeout(5000);

                // http.connect
                extConn.connect();

                // http.output_stream
                OutputStream os = extConn.getOutputStream();
                os.write("field=value".getBytes("UTF-8"));
                os.flush();

                // http.input_stream
                int code = extConn.getResponseCode();
                Log.i(TAG, "runUrlAndHttpUrlConnectionTests [" + testUrl + "] code: " + code);
                InputStream is = (code >= 400) ? extConn.getErrorStream() : extConn.getInputStream();
                readInputStream(is);
                Log.i(TAG, "runUrlAndHttpUrlConnectionTests external phase succeeded with: " + testUrl);
                return; // success - no further fallback needed

            } catch (Throwable t) {
                Log.w(TAG, "runUrlAndHttpUrlConnectionTests [" + testUrl + "] failed: " + t.getMessage());
            } finally {
                if (extConn != null) extConn.disconnect();
            }
        }
        Log.w(TAG, "runUrlAndHttpUrlConnectionTests: all external endpoints failed (MiniHttpServer baseline passed)");
    }

    // ------------------------------------------------------------
    // HttpsURLConnection
    // web.ts: install_https_hooks
    //   -> https.request_method, https.connect, https.input_stream
    //
    // Tries HTTPS_FALLBACK_URLS in order; stops at first success.
    // A local server could be used here, but requires additional
    // SSL setup.
    // TODO: add short per-endpoint retry interval to handle
    //       transient failures without exhausting the full list.
    // ------------------------------------------------------------
    private void runHttpsUrlConnectionTests() {
        Log.i(TAG, "runHttpsUrlConnectionTests started");
        for (String testUrl : HTTPS_FALLBACK_URLS) {
            HttpsURLConnection conn = null;
            try {
                URL url = new URL(testUrl);
                conn = (HttpsURLConnection) url.openConnection();
                // https.request_method
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(5000);
                // https.connect
                conn.connect();
                int code = conn.getResponseCode();
                Log.i(TAG, "runHttpsUrlConnectionTests [" + testUrl + "] code: " + code);
                // https.input_stream
                InputStream is = (code >= 400) ? conn.getErrorStream() : conn.getInputStream();
                Log.i(TAG, "runHttpsUrlConnectionTests succeeded with: " + testUrl);
                return; // success - no further fallback needed
            } catch (Throwable t) {
                Log.w(TAG, "runHttpsUrlConnectionTests [" + testUrl + "] failed: " + t.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }
        Log.e(TAG, "runHttpsUrlConnectionTests: all endpoints failed");
    }

    private void readInputStream(InputStream is) {
        if (is == null) return;
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(is));
            int lines = 0;
            while (reader.readLine() != null && lines++ < 3) { /* drain */ }
        } catch (Throwable t) {
            Log.e(TAG, "Error reading InputStream", t);
        } finally {
            try { is.close(); } catch (Throwable ignored) {}
            if (reader != null) try { reader.close(); } catch (Throwable ignored) {}
        }
    }

    // ------------------------------------------------------------
    // WebView & WebViewClient
    // web.ts: install_webview_hooks
    // ------------------------------------------------------------

    private void runWebViewTests() {
        Log.i(TAG, "runWebViewTests started");

        WebView webView = new WebView(this);

        // Subclass overrides required so onPageStarted / onPageFinished are
        // invoked; hooks on the base class intercept the call chain.
        WebViewClient client = new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return super.shouldOverrideUrlLoading(view, url);
            }
        };
        webView.setWebViewClient(client);

        // webview.load_url
        Log.i(TAG, "WebView.loadUrl(String) - trigger");
        webView.loadUrl("https://example.com");;

        // webview.load_url_with_headers
        Log.i(TAG, "WebView.loadUrl(String,Map) - trigger");
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WebView-Header", "1");
        webView.loadUrl("https://example.com?with_headers=1", headers);

        // webview.load_data
        Log.i(TAG, "WebView.loadData - trigger");
        webView.loadData(
                "<html><body><h1>NetworkE2E</h1></body></html>",
                "text/html",
                "UTF-8"
        );

        // webview.post_url
        Log.i(TAG, "WebView.postUrl - trigger");
        byte[] postData;
        try {
            postData = "p=1".getBytes("UTF-8");
        } catch (Throwable e) {
            postData = new byte[0];
        }
        webView.postUrl(TEST_HTTP_POST_URL, postData);

        // webview.url_override - invoked directly to guarantee the hook fires
        // regardless of whether the WebView engine processes the navigation.
        // webview.url_override
        Log.i(TAG, "WebViewClient.shouldOverrideUrlLoading - trigger (direct call)");
        try {
            client.shouldOverrideUrlLoading(webView, "https://example.com/override");
        } catch (Throwable t) {
            Log.e(TAG, "Error calling shouldOverrideUrlLoading", t);
        }

        // webview.page_started - direct call reaches super.onPageStarted() which is the hooked method
        Log.i(TAG, "WebViewClient.onPageStarted - trigger (direct call)");
        try {
            client.onPageStarted(webView, "https://example.com/page_started", null);
        } catch (Throwable t) {
            Log.e(TAG, "Error calling onPageStarted", t);
        }

        // webview.page_finished - direct call reaches super.onPageFinished() which is the hooked method
        Log.i(TAG, "WebViewClient.onPageFinished - trigger (direct call)");
        try {
            client.onPageFinished(webView, "https://example.com/page_finished");
        } catch (Throwable t) {
            Log.e(TAG, "Error calling onPageFinished", t);
        }
    }

    // ------------------------------------------------------------
    // OkHttp3 (okhttp3.*)
    // web.ts: install_okhttp_hooks -> okhttp.request
    //
    // Tries HTTP_GET_FALLBACK_URLS in order; stops at first success.
    // ------------------------------------------------------------
    private void runOkHttp3Tests() {
        Log.i(TAG, "runOkHttp3Tests started");
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();

        for (String testUrl : HTTP_GET_FALLBACK_URLS) {
            try {
                Request request = new Request.Builder()
                        .url(testUrl + "?okhttp3=1")
                        .header("X-OkHttp3", "1")
                        .build();
                Response response = client.newCall(request).execute();
                Log.i(TAG, "runOkHttp3Tests [" + testUrl + "] code: " + response.code());
                ResponseBody body = response.body();
                if (body != null) body.string();
                Log.i(TAG, "runOkHttp3Tests succeeded with: " + testUrl);
                return; // success - no further fallback needed
            } catch (Throwable t) {
                Log.w(TAG, "runOkHttp3Tests [" + testUrl + "] failed: " + t.getMessage());
            }
        }
        Log.e(TAG, "runOkHttp3Tests: all endpoints failed");
    }

    // ------------------------------------------------------------
    // Legacy OkHttp (com.squareup.okhttp.*)
    // web.ts: install_okhttp_hooks -> okhttp_old.request
    //
    // Tries HTTP_GET_FALLBACK_URLS in order; stops at first success.
    // ------------------------------------------------------------
    private void runOkHttpLegacyTests() {
        Log.i(TAG, "runOkHttpLegacyTests started");
        com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
        client.setConnectTimeout(3, TimeUnit.SECONDS);
        client.setReadTimeout(5, TimeUnit.SECONDS);

        for (String testUrl : HTTP_GET_FALLBACK_URLS) {
            try {
                com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                        .url(testUrl + "?okhttp_legacy=1")
                        .build();
                com.squareup.okhttp.Response response = client.newCall(request).execute();
                Log.i(TAG, "runOkHttpLegacyTests [" + testUrl + "] code: " + response.code());
                if (response.body() != null) response.body().string();
                Log.i(TAG, "runOkHttpLegacyTests succeeded with: " + testUrl);
                return; // success - no further fallback needed
            } catch (Throwable t) {
                Log.w(TAG, "runOkHttpLegacyTests [" + testUrl + "] failed: " + t.getMessage());
            }
        }
        Log.e(TAG, "runOkHttpLegacyTests: all endpoints failed");
    }

    public interface HttpbinApi {
        @GET("get")
        Call<ResponseBody> get();
    }

    // ------------------------------------------------------------
    // Retrofit2 (retrofit2.OkHttpCall, retrofit2.Call)
    // web.ts: install_retrofit_hooks
    //   -> retrofit.request, retrofit.response, retrofit.async_request
    //
    // Tries RETROFIT_BASE_FALLBACK_URLS in order for the sync call;
    // async enqueue uses the first base URL that produced a Retrofit
    // instance, reusing the same api handle.
    // ------------------------------------------------------------
    private void runRetrofitTests() {
        Log.i(TAG, "runRetrofitTests started");

        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();

        HttpbinApi api = null;
        for (String baseUrl : RETROFIT_BASE_FALLBACK_URLS) {
            try {
                Retrofit retrofit = new Retrofit.Builder()
                        .baseUrl(baseUrl)
                        .client(okHttpClient)
                        .build();
                HttpbinApi candidate = retrofit.create(HttpbinApi.class);

                // retrofit.request + retrofit.response via OkHttpCall.execute()
                retrofit2.Response<ResponseBody> resp = candidate.get().execute();
                Log.i(TAG, "Retrofit sync [" + baseUrl + "] response code: " + resp.code());
                api = candidate; // reuse for async call below
                break; // success - no further fallback needed
            } catch (Throwable e) {
                Log.w(TAG, "Retrofit sync [" + baseUrl + "] failed: " + e.getMessage());
            }
        }

        if (api == null) {
            Log.e(TAG, "runRetrofitTests: all sync endpoints failed");
            return;
        }

        // retrofit.async_request via Call.enqueue()
        try {
            CountDownLatch latch = new CountDownLatch(1);
            api.get().enqueue(new Callback<ResponseBody>() {
                @Override
                public void onResponse(Call<ResponseBody> call,
                                    retrofit2.Response<ResponseBody> response) {
                    Log.i(TAG, "Retrofit async succeeded, response code: " + response.code());
                    latch.countDown();
                }
                @Override
                public void onFailure(Call<ResponseBody> call, Throwable t) {
                    Log.w(TAG, "Retrofit async failed: " + t.getMessage());
                    latch.countDown();
                }
            });
            latch.await(5, TimeUnit.SECONDS);
        } catch (Throwable t) {
            Log.e(TAG, "Retrofit async error", t);
        }
    }

    // ------------------------------------------------------------
    // Volley (StringRequest, RequestQueue.add)
    // web.ts: install_volley_hooks
    //   -> volley.string_request, volley.queue_request
    //
    // Tries HTTP_GET_FALLBACK_URLS in order; stops at first success.
    // Both hooks fire at construction/add time regardless of network
    // outcome, but a successful response confirms end-to-end health.
    // ------------------------------------------------------------
    private void runVolleyTests() {
        Log.i(TAG, "runVolleyTests started");
        try {
            RequestQueue queue = Volley.newRequestQueue(getApplicationContext());

            for (String testUrl : HTTP_GET_FALLBACK_URLS) {
                CountDownLatch latch = new CountDownLatch(1);
                final boolean[] succeeded = {false};

                // volley.string_request via StringRequest.$init
                StringRequest request = new StringRequest(
                        com.android.volley.Request.Method.GET,
                        testUrl + "?volley=1",
                        new com.android.volley.Response.Listener<String>() {
                            @Override public void onResponse(String response) {
                                succeeded[0] = true;
                                latch.countDown();
                            }
                        },
                        new com.android.volley.Response.ErrorListener() {
                            @Override public void onErrorResponse(VolleyError error) {
                                latch.countDown();
                            }
                        }
                );

                // volley.queue_request via RequestQueue.add
                queue.add(request);
                latch.await(5, TimeUnit.SECONDS);

                if (succeeded[0]) { // success - no further fallback needed
                    Log.i(TAG, "runVolleyTests succeeded with: " + testUrl);
                    return;
                }
                Log.w(TAG, "runVolleyTests [" + testUrl + "] did not succeed, trying next");
            }
            Log.e(TAG, "runVolleyTests: all endpoints failed");
        } catch (Throwable t) {
            Log.e(TAG, "Error in runVolleyTests", t);
        }
    }

    // ------------------------------------------------------------
    // Java and native sockets (TCP, Unix domain, UDP)
    // sockets.ts: hook_java_socket_communication,
    //             hook_bionic_socket_commuication
    // ------------------------------------------------------------

    private void runSocketTests() {
        Log.i(TAG, "runSocketTests started");
        try {
            runTcpSocketTests();
            Log.i(TAG, "runTcpSocketTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runTcpSocketTests failed", t);
        }
        try {
            runLocalSocketTests();
            Log.i(TAG, "runLocalSocketTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runLocalSocketTests failed", t);
        }
        try {
            runUdpSocketTests();
            Log.i(TAG, "runUdpSocketTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runUdpSocketTests failed", t);
        }
    }

    private void runTcpSocketTests() throws Exception {
        Log.i(TAG, "runTcpSocketTests started");

        // socket.java.server_accept (3 accepts)
        ServerSocket serverSocket = new ServerSocket(0, 3, InetAddress.getByName("127.0.0.1"));
        final int port = serverSocket.getLocalPort();
        CountDownLatch serverLatch = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                for (int i = 0; i < 3; i++) {
                    Socket client = serverSocket.accept();
                    Log.i(TAG, "ServerSocket.accept() - connection " + (i + 1));
                    InputStream  in  = client.getInputStream();
                    OutputStream out = client.getOutputStream();
                    byte[] buf = new byte[64];
                    int read = in.read(buf);
                    if (read > 0) { out.write("OK".getBytes()); out.flush(); }
                    client.close();
                }
            } catch (Throwable e) {
                Log.e(TAG, "TCP server error", e);
            } finally {
                try { serverSocket.close(); } catch (Throwable ignored) {}
                serverLatch.countDown();
            }
        }, "tcp-server");
        serverThread.start();

        // socket.java.init - Socket.$init(String, int)
        Log.i(TAG, "Socket.$init(String,int) - trigger");
        Socket s1 = new Socket("127.0.0.1", port);
        s1.getOutputStream().write("hello1".getBytes());
        s1.close();

        // socket.java.connect - Socket.connect(SocketAddress)
        Log.i(TAG, "Socket.connect(SocketAddress) - trigger");
        Socket s2 = new Socket();
        s2.connect(new InetSocketAddress("127.0.0.1", port));
        s2.getOutputStream().write("hello2".getBytes());
        s2.close();

        // socket.java.connect - Socket.connect(SocketAddress, int)
        Log.i(TAG, "Socket.connect(SocketAddress,int) - trigger");
        Socket s3 = new Socket();
        s3.connect(new InetSocketAddress("127.0.0.1", port), 2000);
        s3.getOutputStream().write("hello3".getBytes());
        s3.close();

        serverLatch.await(5, TimeUnit.SECONDS);
    }

    private void runLocalSocketTests() throws Exception {
        Log.i(TAG, "runLocalSocketTests started");

        // socket.java.local_accept - LocalServerSocket.accept
        final String SOCKET_NAME = "networke2e_local";
        LocalServerSocket serverSocket = new LocalServerSocket(SOCKET_NAME);
        CountDownLatch serverLatch = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                Log.i(TAG, "LocalServerSocket.accept() - waiting");
                LocalSocket incoming = serverSocket.accept();
                Log.i(TAG, "LocalServerSocket.accept() - connection received");
                byte[] buf = new byte[32];
                incoming.getInputStream().read(buf);
                incoming.close();
            } catch (Throwable e) {
                Log.e(TAG, "LocalServerSocket error", e);
            } finally {
                try { serverSocket.close(); } catch (Throwable ignored) {}
                serverLatch.countDown();
            }
        }, "local-server");
        serverThread.start();

        Log.i(TAG, "LocalSocket.connect - trigger");
        LocalSocket client = new LocalSocket();
        client.connect(new LocalSocketAddress(SOCKET_NAME));
        client.getOutputStream().write("local".getBytes());
        client.close();

        serverLatch.await(5, TimeUnit.SECONDS);
    }

    private void runUdpSocketTests() throws Exception {
        Log.i(TAG, "runUdpSocketTests started");

        DatagramSocket receiver = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        int port = receiver.getLocalPort();

        DatagramSocket sender = new DatagramSocket();

        // socket.java.datagram_connect - DatagramSocket.connect(InetAddress, int)
        Log.i(TAG, "DatagramSocket.connect(InetAddress,int) - trigger");
        sender.connect(InetAddress.getByName("127.0.0.1"), port);

        byte[] outBuf = "udp-test".getBytes("UTF-8");
        sender.send(new DatagramPacket(outBuf, outBuf.length));
        Log.i(TAG, "DatagramSocket.send - sent " + outBuf.length + " bytes");

        byte[] inBuf = new byte[64];
        receiver.receive(new DatagramPacket(inBuf, inBuf.length));
        Log.i(TAG, "DatagramSocket.receive - received packet");

        sender.close();
        receiver.close();
    }

    // ------------------------------------------------------------
    // WebSocket (okhttp3.WebSocket / WebSocketListener)
    // web.ts: install_websocket_hooks
    //   -> websocket.send_text, websocket.opened,
    //      websocket.message_received
    //
    // MiniWebSocketServer on loopback is started first as the
    // primary guaranteed path. External WSS endpoints follow as
    // fallbacks for real-network and TLS coverage.
    // Local URL is skipped if the server failed to start.
    // ------------------------------------------------------------
    private void runWebSocketTests() {
        Log.i(TAG, "runWebSocketTests started");

        MiniWebSocketServer localServer = null;
        try {
            localServer = new MiniWebSocketServer(LOCAL_WS_PORT);
            localServer.startAndWait();
            Log.i(TAG, "MiniWebSocketServer started on port " + LOCAL_WS_PORT);
        } catch (Throwable t) {
            Log.w(TAG, "MiniWebSocketServer failed to start: " + t.getMessage());
            localServer = null;
        }

        final MiniWebSocketServer serverRef = localServer;

        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();

        try {
            for (String wsUrl : WEBSOCKET_FALLBACK_URLS) {

                // skip local URL if server did not start
                if (wsUrl.startsWith("ws://127.0.0.1") && serverRef == null) {
                    Log.w(TAG, "Skipping local WebSocket URL - server not running: " + wsUrl);
                    continue;
                }

                CountDownLatch latch = new CountDownLatch(1);
                final boolean[] succeeded = {false};

                Request request = new Request.Builder().url(wsUrl).build();
                client.newWebSocket(request, new WebSocketListener() {
                    @Override
                    public void onOpen(WebSocket webSocket, Response response) {
                        Log.i(TAG, "WebSocket opened: " + wsUrl);
                        // websocket.send_text
                        webSocket.send("hello websocket from NetworkE2E");
                    }

                    @Override
                    public void onMessage(WebSocket webSocket, String text) {
                        Log.i(TAG, "WebSocket message: " + text);
                        succeeded[0] = true;
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(WebSocket webSocket, Throwable t,
                                        okhttp3.Response response) {
                        Log.w(TAG, "WebSocket [" + wsUrl + "] failure: " + t.getMessage());
                        latch.countDown();
                    }

                    @Override
                    public void onClosing(WebSocket webSocket, int code, String reason) {
                        webSocket.close(code, reason);
                    }
                });

                latch.await(6, TimeUnit.SECONDS);
                if (succeeded[0]) {
                    Log.i(TAG, "runWebSocketTests succeeded with: " + wsUrl);
                    return;
                }
                Log.w(TAG, "WebSocket [" + wsUrl + "] did not produce a message, trying next");
            }
            Log.e(TAG, "runWebSocketTests: all endpoints failed");
        } catch (Throwable t) {
            Log.e(TAG, "Error in runWebSocketTests", t);
        } finally {
            client.dispatcher().executorService().shutdown();
            if (serverRef != null) {
                try { serverRef.stop(); } catch (Throwable ignored) {}
            }
        }
    }

    // ------------------------------------------------------------
    // Local WebSocket echo server for self-contained WebSocket tests.
    // Bound to loopback only; echoes any received text message back
    // to the sender. Exercises the same OkHttp3 WebSocket hooks as
    // an external endpoint with no external dependency.
    // setReuseAddr(true) prevents bind failures on rapid re-runs.
    // ------------------------------------------------------------
    private static final class MiniWebSocketServer
            extends org.java_websocket.server.WebSocketServer {

        private final CountDownLatch startLatch = new CountDownLatch(1);

        MiniWebSocketServer(int port) throws java.net.UnknownHostException {
            super(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
            setReuseAddr(true);
        }

        @Override
        public void onOpen(org.java_websocket.WebSocket conn,
                        org.java_websocket.handshake.ClientHandshake handshake) {}

        @Override
        public void onClose(org.java_websocket.WebSocket conn, int code,
                            String reason, boolean remote) {}

        @Override
        public void onMessage(org.java_websocket.WebSocket conn, String message) {
            // echo back to trigger websocket.message_received hook on client side
            conn.send(message);
        }

        @Override
        public void onError(org.java_websocket.WebSocket conn, Exception ex) {}

        @Override
        public void onStart() {
            startLatch.countDown();
        }

        void startAndWait() throws InterruptedException {
            start();
            startLatch.await(3, TimeUnit.SECONDS);
        }
    }

    // ------------------------------------------------------------
    // Local HTTP server for self-contained URL/HTTP hook tests.
    // Accepts exactly one connection, responds 200 OK, then stops.
    // No external dependency - guarantees http.connect,
    // http.output_stream, http.input_stream hooks all fire.
    // ------------------------------------------------------------
    private static final class MiniHttpServer {
        private final ServerSocket serverSocket;
        private Thread thread;

        MiniHttpServer() throws java.io.IOException {
            serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        void start() {
            thread = new Thread(() -> {
                try {
                    Socket client = serverSocket.accept();
                    try {
                        // drain request headers + body
                        InputStream in = client.getInputStream();
                        byte[] buf = new byte[4096];
                        in.read(buf);

                        // respond 200 OK with a small JSON body
                        byte[] body = "{\"ok\":true}".getBytes("UTF-8");
                        String headers =
                                "HTTP/1.1 200 OK\r\n" +
                                "Content-Type: application/json\r\n" +
                                "Content-Length: " + body.length + "\r\n" +
                                "Connection: close\r\n\r\n";
                        OutputStream out = client.getOutputStream();
                        out.write(headers.getBytes("UTF-8"));
                        out.write(body);
                        out.flush();
                    } finally {
                        client.close();
                    }
                } catch (Throwable ignored) {
                } finally {
                    try { serverSocket.close(); } catch (Throwable ignored) {}
                }
            }, "mini-http-server");
            thread.start();
        }

        void join() {
            if (thread != null) {
                try { thread.join(3000); } catch (InterruptedException ignored) {}
            }
        }
    }
}