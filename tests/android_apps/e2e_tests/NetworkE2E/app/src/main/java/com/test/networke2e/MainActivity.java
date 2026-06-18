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

    private static final String TAG = "NETWORK_E2E";

    private static final String TEST_HTTP_URL     = "https://httpbin.org/get";
    private static final String TEST_HTTP_POST_URL = "https://httpbin.org/post";
    private static final String TEST_WEBSOCKET_URL = "wss://echo.websocket.events";

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
                Log.i(TAG, "NetworkE2E finished, calling finish()");
                finish();
            }
        }, "networke2e-tests");
        thread.start();
    }

    // ------------------------------------------------------------
    // URL / HttpURLConnection / URI
    // web.ts: install_url_hooks, install_http_hooks
    // ------------------------------------------------------------

    private void runUrlAndHttpUrlConnectionTests() {
        Log.i(TAG, "runUrlAndHttpUrlConnectionTests");
        HttpURLConnection conn = null;
        try {
            // url.creation, uri.creation
            URL url = new URL(TEST_HTTP_URL);
            URI uri = new URI(TEST_HTTP_URL);
            Log.i(TAG, "Created URI: " + uri.toString());

            // url.open_connection
            conn = (HttpURLConnection) url.openConnection();

            // okhttp.request_method, http.request_method
            conn.setRequestMethod("POST");
            // okhttp.request_property
            conn.setRequestProperty("X-NetworkE2E", "1");
            conn.setDoOutput(true);

            // http.connect (overwrites url.connection hook)
            conn.connect();

            // http.output_stream
            OutputStream os = conn.getOutputStream();
            os.write("field=value".getBytes("UTF-8"));
            os.flush();

            // http.input_stream
            readInputStream(conn.getInputStream());
        } catch (Throwable t) {
            Log.e(TAG, "Error in runUrlAndHttpUrlConnectionTests", t);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private void runHttpsUrlConnectionTests() {
        Log.i(TAG, "runHttpsUrlConnectionTests");
        HttpsURLConnection conn = null;
        try {
            // TEST_HTTP_URL already uses https://
            URL url = new URL(TEST_HTTP_URL.replace("http://", "https://"));

            conn = (HttpsURLConnection) url.openConnection();
            // https.request_method
            conn.setRequestMethod("GET");
            // https.connect
            conn.connect();
            // https.input_stream
            readInputStream(conn.getInputStream());
        } catch (Throwable t) {
            Log.e(TAG, "Error in runHttpsUrlConnectionTests", t);
        } finally {
            if (conn != null) conn.disconnect();
        }
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
        Log.i(TAG, "runWebViewTests");

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
        webView.loadUrl("https://example.com");

        // webview.load_url_with_headers
        Map<String, String> headers = new HashMap<>();
        headers.put("X-WebView-Header", "1");
        webView.loadUrl("https://example.com?with_headers=1", headers);

        // webview.load_data
        webView.loadData(
                "<html><body><h1>NetworkE2E</h1></body></html>",
                "text/html",
                "UTF-8"
        );

        // webview.post_url
        byte[] postData;
        try {
            postData = "p=1".getBytes("UTF-8");
        } catch (Throwable e) {
            postData = new byte[0];
        }
        webView.postUrl(TEST_HTTP_POST_URL, postData);

        // webview.url_override - invoked directly to guarantee the hook fires
        // regardless of whether the WebView engine processes the navigation.
        try {
            client.shouldOverrideUrlLoading(webView, "https://example.com/override");
        } catch (Throwable t) {
            Log.e(TAG, "Error calling shouldOverrideUrlLoading", t);
        }
    }

    // ------------------------------------------------------------
    // OkHttp3 (okhttp3.*)
    // web.ts: install_okhttp_hooks -> okhttp.request
    // ------------------------------------------------------------

    private void runOkHttp3Tests() {
        Log.i(TAG, "runOkHttp3Tests");
        OkHttpClient client = new OkHttpClient();
        try {
            Request request = new Request.Builder()
                    .url(TEST_HTTP_URL + "?okhttp3=1")
                    .header("X-OkHttp3", "1")
                    .build();
            Response response = client.newCall(request).execute();
            ResponseBody body = response.body();
            if (body != null) body.string();
        } catch (Throwable t) {
            Log.e(TAG, "Error in runOkHttp3Tests", t);
        }
    }

    // ------------------------------------------------------------
    // Legacy OkHttp (com.squareup.okhttp.*)
    // web.ts: install_okhttp_hooks -> okhttp_old.request
    // ------------------------------------------------------------

    private void runOkHttpLegacyTests() {
        Log.i(TAG, "runOkHttpLegacyTests");
        try {
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                    .url(TEST_HTTP_URL + "?okhttp_legacy=1")
                    .build();
            com.squareup.okhttp.Response response = client.newCall(request).execute();
            if (response.body() != null) response.body().string();
        } catch (Throwable t) {
            Log.e(TAG, "Error in runOkHttpLegacyTests", t);
        }
    }

    // ------------------------------------------------------------
    // Retrofit2 (retrofit2.OkHttpCall, retrofit2.Call)
    // web.ts: install_retrofit_hooks
    //   -> retrofit.request, retrofit.response, retrofit.async_request
    // ------------------------------------------------------------

    public interface HttpbinApi {
        @GET("get")
        Call<ResponseBody> get();
    }

    private void runRetrofitTests() {
        Log.i(TAG, "runRetrofitTests");
        try {
            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl("https://httpbin.org/")
                    .client(new OkHttpClient())
                    .build();
            HttpbinApi api = retrofit.create(HttpbinApi.class);

            // retrofit.request + retrofit.response via OkHttpCall.execute()
            try {
                retrofit2.Response<ResponseBody> resp = api.get().execute();
                Log.i(TAG, "Retrofit sync response code: " + resp.code());
            } catch (Throwable e) {
                Log.e(TAG, "Retrofit sync error", e);
            }

            // retrofit.async_request via Call.enqueue()
            CountDownLatch latch = new CountDownLatch(1);
            api.get().enqueue(new Callback<ResponseBody>() {
                @Override
                public void onResponse(Call<ResponseBody> call,
                                       retrofit2.Response<ResponseBody> response) {
                    latch.countDown();
                }
                @Override
                public void onFailure(Call<ResponseBody> call, Throwable t) {
                    latch.countDown();
                }
            });
            latch.await(5, TimeUnit.SECONDS);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runRetrofitTests", t);
        }
    }

    // ------------------------------------------------------------
    // Volley (StringRequest, RequestQueue.add)
    // web.ts: install_volley_hooks
    //   -> volley.string_request, volley.queue_request
    // ------------------------------------------------------------

    private void runVolleyTests() {
        Log.i(TAG, "runVolleyTests");
        try {
            RequestQueue queue = Volley.newRequestQueue(getApplicationContext());
            CountDownLatch latch = new CountDownLatch(1);

            // volley.string_request via StringRequest.$init
            StringRequest request = new StringRequest(
                    com.android.volley.Request.Method.GET,
                    TEST_HTTP_URL + "?volley=1",
                    new com.android.volley.Response.Listener<String>() {
                        @Override public void onResponse(String response) { latch.countDown(); }
                    },
                    new com.android.volley.Response.ErrorListener() {
                        @Override public void onErrorResponse(VolleyError error) { latch.countDown(); }
                    }
            );

            // volley.queue_request via RequestQueue.add
            queue.add(request);
            latch.await(5, TimeUnit.SECONDS);
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
        Log.i(TAG, "runSocketTests");
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
        Log.i(TAG, "runTcpSocketTests");

        // socket.java.server_accept (3 accepts)
        ServerSocket serverSocket = new ServerSocket(0, 3, InetAddress.getByName("127.0.0.1"));
        final int port = serverSocket.getLocalPort();
        CountDownLatch serverLatch = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                for (int i = 0; i < 3; i++) {
                    Socket client = serverSocket.accept();
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
        Socket s1 = new Socket("127.0.0.1", port);
        s1.getOutputStream().write("hello1".getBytes());
        s1.close();

        // socket.java.connect - Socket.connect(SocketAddress)
        Socket s2 = new Socket();
        s2.connect(new InetSocketAddress("127.0.0.1", port));
        s2.getOutputStream().write("hello2".getBytes());
        s2.close();

        // socket.java.connect - Socket.connect(SocketAddress, int)
        Socket s3 = new Socket();
        s3.connect(new InetSocketAddress("127.0.0.1", port), 2000);
        s3.getOutputStream().write("hello3".getBytes());
        s3.close();

        serverLatch.await(5, TimeUnit.SECONDS);
    }

    private void runLocalSocketTests() throws Exception {
        Log.i(TAG, "runLocalSocketTests");

        // socket.java.local_accept - LocalServerSocket.accept
        final String SOCKET_NAME = "networke2e_local";
        LocalServerSocket serverSocket = new LocalServerSocket(SOCKET_NAME);
        CountDownLatch serverLatch = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                LocalSocket incoming = serverSocket.accept();
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

        LocalSocket client = new LocalSocket();
        client.connect(new LocalSocketAddress(SOCKET_NAME));
        client.getOutputStream().write("local".getBytes());
        client.close();

        serverLatch.await(5, TimeUnit.SECONDS);
    }

    private void runUdpSocketTests() throws Exception {
        Log.i(TAG, "runUdpSocketTests");

        // socket.java.datagram_connect - DatagramSocket.connect(InetAddress, int)
        DatagramSocket receiver = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        int port = receiver.getLocalPort();

        DatagramSocket sender = new DatagramSocket();
        sender.connect(InetAddress.getByName("127.0.0.1"), port);

        byte[] outBuf = "udp-test".getBytes("UTF-8");
        sender.send(new DatagramPacket(outBuf, outBuf.length));

        byte[] inBuf = new byte[64];
        receiver.receive(new DatagramPacket(inBuf, inBuf.length));

        sender.close();
        receiver.close();
    }

    // ------------------------------------------------------------
    // WebSocket (okhttp3.WebSocket / WebSocketListener)
    // web.ts: install_websocket_hooks
    //   -> websocket.send_text, websocket.opened, websocket.message_received
    // ------------------------------------------------------------

    private void runWebSocketTests() {
        Log.i(TAG, "runWebSocketTests");
        OkHttpClient client = new OkHttpClient();
        CountDownLatch latch = new CountDownLatch(1);

        try {
            Request request = new Request.Builder().url(TEST_WEBSOCKET_URL).build();

            client.newWebSocket(request, new WebSocketListener() {
                @Override
                public void onOpen(WebSocket webSocket, Response response) {
                    Log.i(TAG, "WebSocket opened");
                    // websocket.send_text
                    webSocket.send("hello websocket from NetworkE2E");
                }

                @Override
                public void onMessage(WebSocket webSocket, String text) {
                    Log.i(TAG, "WebSocket message: " + text);
                    latch.countDown();
                }

                @Override
                public void onFailure(WebSocket webSocket, Throwable t, okhttp3.Response response) {
                    Log.e(TAG, "WebSocket failure", t);
                    latch.countDown();
                }

                @Override
                public void onClosing(WebSocket webSocket, int code, String reason) {
                    webSocket.close(code, reason);
                }
            });

            latch.await(5, TimeUnit.SECONDS);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runWebSocketTests", t);
        } finally {
            client.dispatcher().executorService().shutdown();
        }
    }
}