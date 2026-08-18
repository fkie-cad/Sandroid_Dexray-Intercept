package com.test.networke2e;

/**
 * Java wrapper for net_native_sockets.c.
 *
 * Exercises libc socket syscalls hooked in sockets.ts via safeAttachExport
 * that are not reliably reached by Java-level socket code:
 *   send()    -> "Libc::send"
 *   recv()    -> "Libc::recv"
 *   sendmsg() -> "Libc::sendmsg"
 *   recvmsg() -> "Libc::recvmsg"
 *   close()   -> "Libc::close"
 *   dlsym("send") / dlsym("recv")
 *       -> direct libc export validation for socket.native.send/recv
 *
 * Must be called from a background thread; POSIX socket syscalls are
 * performed directly on AF_INET loopback file descriptors.
 *
 * Self-validation: filter logcat with -s NET_NATIVE_SOCKETS:'*'
 */
public class NativeSocketTests {

    static {
        System.loadLibrary("net_native_sockets");
    }

    public static native void runTests();

    /**
     * Starts one AF_UNIX filesystem-namespace server in a native thread.
     * The Java test connects through LocalSocket using Namespace.FILESYSTEM.
     */
    public static native boolean startFilesystemLocalSocketServer(
            String socketPath
    );

    /**
     * Waits for the native filesystem local-socket server to accept and read
     * the deterministic Java LocalSocket client payload.
     */
    public static native boolean waitForFilesystemLocalSocketServer();
}