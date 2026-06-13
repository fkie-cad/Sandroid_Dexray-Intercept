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

    private static final String TEST_HTTP_URL = "https://httpbin.org/get";
    private static final String TEST_HTTP_POST_URL = "https://httpbin.org/post";
    private static final String TEST_WEBSOCKET_URL = "wss://echo.websocket.events";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "NetworkE2E started");

        try {
            runWebViewTests();

            Thread t = new Thread(() -> {
                try {
                    runUrlAndHttpUrlConnectionTests();
                    runHttpsUrlConnectionTests();
                    runOkHttp3Tests();
                    runOkHttpLegacyTests();
                    runRetrofitTests();
                    runVolleyTests();
                    runSocketTests();
                    runWebSocketTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "Error in network tests", t1);
                } finally {
                    runOnUiThread(this::finish);
                }
            });
            t.start();
        } catch (Throwable t) {
            Log.e(TAG, "Error in NetworkE2E", t);
            finish();
        }
    }

    // ------------------------------------------------------------
    // URL / HttpURLConnection / URI
    // ------------------------------------------------------------

    private void runUrlAndHttpUrlConnectionTests() {
        Log.i(TAG, "runUrlAndHttpUrlConnectionTests");
        HttpURLConnection conn = null;
        try {
            URL url = new URL(TEST_HTTP_URL);

            URI uri = new URI(TEST_HTTP_URL);
            Log.i(TAG, "Created URI: " + uri.toString());

            conn = (HttpURLConnection) url.openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("X-NetworkE2E", "1");
            conn.setDoOutput(true);

            conn.connect();

            OutputStream os = conn.getOutputStream();
            byte[] body = "field=value".getBytes("UTF-8");
            os.write(body);
            os.flush();

            InputStream is = conn.getInputStream();
            readInputStream(is);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runUrlAndHttpUrlConnectionTests", t);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private void runHttpsUrlConnectionTests() {
        Log.i(TAG, "runHttpsUrlConnectionTests");
        HttpsURLConnection conn = null;
        try {
            URL url = new URL(TEST_HTTP_URL.replace("http://", "https://"));

            conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.connect();

            InputStream is = conn.getInputStream();
            readInputStream(is);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runHttpsUrlConnectionTests", t);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private void readInputStream(InputStream is) {
        if (is == null) {
            return;
        }
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(is));
            String line;
            int lines = 0;
            while ((line = reader.readLine()) != null && lines < 3) {
                lines++;
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error reading InputStream", t);
        } finally {
            try {
                is.close();
            } catch (Throwable ignored) {
            }
            if (reader != null) {
                try {
                    reader.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    // ------------------------------------------------------------
    // WebView & WebViewClient
    // ------------------------------------------------------------

    private void runWebViewTests() {
        Log.i(TAG, "runWebViewTests");

        WebView webView = new WebView(this);

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

        webView.loadUrl("https://example.com");

        Map<String, String> headers = new HashMap<>();
        headers.put("X-WebView-Header", "1");
        webView.loadUrl("https://example.com?with_headers=1", headers);

        String html = "<html><body><h1>NetworkE2E</h1></body></html>";
        webView.loadData(html, "text/html", "UTF-8");

        byte[] postData;
        try {
            postData = "p=1".getBytes("UTF-8");
        } catch (Throwable e) {
            postData = new byte[0];
        }
        webView.postUrl(TEST_HTTP_POST_URL, postData);

        try {
            client.shouldOverrideUrlLoading(webView, "https://example.com/override");
        } catch (Throwable t) {
            Log.e(TAG, "Error calling shouldOverrideUrlLoading", t);
        }
    }

    // ------------------------------------------------------------
    // OkHttp3 (okhttp3.*)
    // ------------------------------------------------------------

    private void runOkHttp3Tests() {
        Log.i(TAG, "runOkHttp3Tests");
        OkHttpClient client = new OkHttpClient();
        try {
            Request request = new Request.Builder()
                    .url(TEST_HTTP_URL + "?okhttp3=1")
                    .header("X-OkHttp3", "1")
                    .build();

            okhttp3.Call call = client.newCall(request);

            Response response = call.execute();
            ResponseBody body = response.body();
            if (body != null) {
                body.string();
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runOkHttp3Tests", t);
        }
    }

    // ------------------------------------------------------------
    // Legacy OkHttp (com.squareup.okhttp.*)
    // ------------------------------------------------------------

    private void runOkHttpLegacyTests() {
        Log.i(TAG, "runOkHttpLegacyTests");
        try {
            com.squareup.okhttp.OkHttpClient client = new com.squareup.okhttp.OkHttpClient();
            com.squareup.okhttp.Request request = new com.squareup.okhttp.Request.Builder()
                    .url(TEST_HTTP_URL + "?okhttp_legacy=1")
                    .build();

            com.squareup.okhttp.Call call = client.newCall(request);
            com.squareup.okhttp.Response response = call.execute();
            if (response.body() != null) {
                response.body().string();
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runOkHttpLegacyTests", t);
        }
    }

    // ------------------------------------------------------------
    // Retrofit (retrofit2.OkHttpCall, retrofit2.Call)
    // ------------------------------------------------------------

    public interface HttpbinApi {
        @GET("get")
        Call<ResponseBody> get();
    }

    private void runRetrofitTests() {
        Log.i(TAG, "runRetrofitTests");
        try {
            OkHttpClient okHttpClient = new OkHttpClient();

            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl("https://httpbin.org/")
                    .client(okHttpClient)
                    .build();

            HttpbinApi api = retrofit.create(HttpbinApi.class);

            Call<ResponseBody> syncCall = api.get();
            try {
                retrofit2.Response<ResponseBody> resp = syncCall.execute();
                Log.i(TAG, "Retrofit sync response code: " + resp.code());
            } catch (Throwable e) {
                Log.e(TAG, "Retrofit sync error", e);
            }

            Call<ResponseBody> asyncCall = api.get();
            CountDownLatch latch = new CountDownLatch(1);
            asyncCall.enqueue(new Callback<ResponseBody>() {
                @Override
                public void onResponse(Call<ResponseBody> call, retrofit2.Response<ResponseBody> response) {
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
    // ------------------------------------------------------------

    private void runVolleyTests() {
        Log.i(TAG, "runVolleyTests");
        try {
            RequestQueue queue = Volley.newRequestQueue(getApplicationContext());

            String url = TEST_HTTP_URL + "?volley=1";
            CountDownLatch latch = new CountDownLatch(1);

            StringRequest request = new StringRequest(
                    com.android.volley.Request.Method.GET,
                    url,
                    new com.android.volley.Response.Listener<String>() {
                        @Override
                        public void onResponse(String response) {
                            latch.countDown();
                        }
                    },
                    new com.android.volley.Response.ErrorListener() {
                        @Override
                        public void onErrorResponse(VolleyError error) {
                            latch.countDown();
                        }
                    }
            );

            queue.add(request);

            latch.await(5, TimeUnit.SECONDS);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runVolleyTests", t);
        }
    }

    // ------------------------------------------------------------
    // Java and native sockets (TCP, local, UDP)
    // ------------------------------------------------------------

    private void runSocketTests() {
        Log.i(TAG, "runSocketTests");
        try {
            runTcpSocketTests();
            runLocalSocketTests();
            runUdpSocketTests();
        } catch (Throwable t) {
            Log.e(TAG, "Error in runSocketTests", t);
        }
    }

    private void runTcpSocketTests() throws Exception {
        Log.i(TAG, "runTcpSocketTests");

        ServerSocket serverSocket = new ServerSocket(0, 3, InetAddress.getByName("127.0.0.1"));
        final int port = serverSocket.getLocalPort();
        CountDownLatch serverLatch = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                for (int i = 0; i < 3; i++) {
                    Socket client = serverSocket.accept();
                    InputStream in = client.getInputStream();
                    OutputStream out = client.getOutputStream();
                    byte[] buf = new byte[64];
                    int read = in.read(buf);
                    if (read > 0) {
                        out.write("OK".getBytes());
                        out.flush();
                    }
                    client.close();
                }
            } catch (Throwable e) {
                Log.e(TAG, "TCP server error", e);
            } finally {
                try {
                    serverSocket.close();
                } catch (Throwable ignored) {
                }
                serverLatch.countDown();
            }
        });
        serverThread.start();

        Socket s1 = new Socket("127.0.0.1", port);
        s1.getOutputStream().write("hello1".getBytes());
        s1.close();

        Socket s2 = new Socket();
        s2.connect(new InetSocketAddress("127.0.0.1", port));
        s2.getOutputStream().write("hello2".getBytes());
        s2.close();

        Socket s3 = new Socket();
        s3.connect(new InetSocketAddress("127.0.0.1", port), 2000);
        s3.getOutputStream().write("hello3".getBytes());
        s3.close();

        serverLatch.await(5, TimeUnit.SECONDS);
    }

    private void runLocalSocketTests() throws Exception {
        Log.i(TAG, "runLocalSocketTests");

        final String SOCKET_NAME = "networke2e_local";

        LocalServerSocket serverSocket = new LocalServerSocket(SOCKET_NAME);
        CountDownLatch serverLatch = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try {
                LocalSocket incoming = serverSocket.accept();
                InputStream in = incoming.getInputStream();
                byte[] buf = new byte[32];
                in.read(buf);
                incoming.close();
            } catch (Throwable e) {
                Log.e(TAG, "LocalServerSocket server error", e);
            } finally {
                try {
                    serverSocket.close();
                } catch (Throwable ignored) {
                }
                serverLatch.countDown();
            }
        });
        serverThread.start();

        LocalSocket client = new LocalSocket();
        client.connect(new LocalSocketAddress(SOCKET_NAME));
        client.getOutputStream().write("local".getBytes());
        client.close();

        serverLatch.await(5, TimeUnit.SECONDS);
    }

    private void runUdpSocketTests() throws Exception {
        Log.i(TAG, "runUdpSocketTests");

        DatagramSocket receiver = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        int port = receiver.getLocalPort();

        DatagramSocket sender = new DatagramSocket();
        sender.connect(InetAddress.getByName("127.0.0.1"), port);

        byte[] outBuf = "udp-test".getBytes("UTF-8");
        DatagramPacket sendPacket = new DatagramPacket(outBuf, outBuf.length);
        sender.send(sendPacket);

        byte[] inBuf = new byte[64];
        DatagramPacket recvPacket = new DatagramPacket(inBuf, inBuf.length);
        receiver.receive(recvPacket);

        sender.close();
        receiver.close();
    }

    // ------------------------------------------------------------
    // WebSocket (okhttp3.WebSocket / WebSocketListener)
    // ------------------------------------------------------------

    private void runWebSocketTests() {
        Log.i(TAG, "runWebSocketTests");

        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
                .url(TEST_WEBSOCKET_URL)
                .build();

        CountDownLatch latch = new CountDownLatch(1);

        WebSocketListener listener = new WebSocketListener() {
            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                Log.i(TAG, "WebSocket opened");
                try {
                    webSocket.send("hello websocket from NetworkE2E");
                } catch (Throwable t) {
                    Log.e(TAG, "Error sending WebSocket message", t);
                }
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
        };

        try {
            client.newWebSocket(request, listener);
            latch.await(5, TimeUnit.SECONDS);
        } catch (Throwable t) {
            Log.e(TAG, "Error in runWebSocketTests", t);
        } finally {
            client.dispatcher().executorService().shutdown();
        }
    }
}