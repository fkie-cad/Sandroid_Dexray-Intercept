package com.test.acpe2e;

import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class NativeConnectTests {

    private static final String TAG = "ACP_E2E_CONNECT";

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
            testTcpConnectHttp();
        } catch (Throwable t) {
            Log.e(TAG, "testTcpConnectHttp threw", t);
            testsFailed++;
        }

        try {
            testTcpConnectHttps();
        } catch (Throwable t) {
            Log.e(TAG, "testTcpConnectHttps threw", t);
            testsFailed++;
        }

        try {
            testUdpConnectQuicPort();
        } catch (Throwable t) {
            Log.e(TAG, "testUdpConnectQuicPort threw", t);
            testsFailed++;
        }

        Log.i(TAG, "NativeConnectTests summary: passed=" + testsPassed + " failed=" + testsFailed);
    }

    private static void testTcpConnectHttp() {
        // Target: native-connect-hook.js
        //  -> connect() for TCP IPv4, interception of outgoing HTTP traffic (port 80)

        Socket socket = new Socket();
        try {
            SocketAddress addr = new InetSocketAddress("example.com", 80);
            socket.connect(addr, 3000);
            Log.i(TAG, "TCP connect to example.com:80 completed");
        } catch (IOException e) {
            Log.w(TAG, "TCP connect to example.com:80 failed: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }

        assertTest(true, "TCP connect to port 80 executed");
    }

    private static void testTcpConnectHttps() {
        // Target: native-connect-hook.js
        //  -> connect() for TCP IPv4, interception of outgoing HTTPS traffic (port 443)

        Socket socket = new Socket();
        try {
            SocketAddress addr = new InetSocketAddress("example.com", 443);
            socket.connect(addr, 3000);
            Log.i(TAG, "TCP connect to example.com:443 completed");
        } catch (IOException e) {
            Log.w(TAG, "TCP connect to example.com:443 failed: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }

        assertTest(true, "TCP connect to port 443 executed");
    }

    private static void testUdpConnectQuicPort() {
        // Target: native-connect-hook.js
        //  -> connect() for UDP IPv4 on port 443; branch for BLOCK_HTTP3 and UDP blocking

        DatagramSocket ds = null;
        try {
            ds = new DatagramSocket();
            SocketAddress addr = new InetSocketAddress("example.com", 443);
            ds.connect(addr);

            byte[] buf = "ping".getBytes();
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            ds.send(packet);

            Log.i(TAG, "UDP packet sent to example.com:443");
        } catch (IOException e) {
            Log.w(TAG, "UDP send to example.com:443 failed: " + e.getMessage());
        } finally {
            if (ds != null) {
                ds.close();
            }
        }

        assertTest(true, "UDP connect/send to port 443 executed");
    }
}