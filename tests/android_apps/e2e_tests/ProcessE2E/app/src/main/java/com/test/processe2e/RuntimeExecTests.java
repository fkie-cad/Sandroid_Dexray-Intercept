package com.test.processe2e;

import android.util.Log;

import java.io.File;
import java.io.InputStream;

// Triggers all Runtime.exec overloads in runtime.ts.
// runtime.ts hooks via .overloads.forEach so all 6 overloads are covered:
//   exec(String)
//   exec(String[])
//   exec(String, String[])
//   exec(String[], String[])
//   exec(String, String[], File)
//   exec(String[], String[], File)
// All commands produce minimal output; inline stream drain is safe on main thread.
public class RuntimeExecTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;
    private final File workDir;

    public RuntimeExecTests(File workDir) {
        this.workDir = workDir;
    }

    public void runTests() {
        testExec_String();
        testExec_StringArray();
        testExec_String_Envp();
        testExec_StringArray_Envp();
        testExec_String_Envp_Dir();
        testExec_StringArray_Envp_Dir();
        Log.i(TAG, "RuntimeExecTests summary: " + passed + " passed, " + failed + " failed");
    }

    // Runtime.exec(String) - overload 0
    private void testExec_String() {
        try {
            Process p = Runtime.getRuntime().exec("/system/bin/id");
            drainAndDestroy(p);
            Log.i(TAG, "Runtime.exec(String): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.exec(String) failed", t);
            failed++;
        }
    }

    // Runtime.exec(String[]) - overload 1
    private void testExec_StringArray() {
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"/system/bin/sh", "-c", "echo exec_array"});
            drainAndDestroy(p);
            Log.i(TAG, "Runtime.exec(String[]): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.exec(String[]) failed", t);
            failed++;
        }
    }

    // Runtime.exec(String, String[]) - overload 2
    private void testExec_String_Envp() {
        try {
            Process p = Runtime.getRuntime().exec(
                    "/system/bin/sh -c 'echo exec_envp'",
                    new String[]{"E2E_ENV=1"});
            drainAndDestroy(p);
            Log.i(TAG, "Runtime.exec(String, String[]): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.exec(String, String[]) failed", t);
            failed++;
        }
    }

    // Runtime.exec(String[], String[]) - overload 3
    private void testExec_StringArray_Envp() {
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"/system/bin/sh", "-c", "echo exec_array_envp"},
                    new String[]{"E2E_ENV=1"});
            drainAndDestroy(p);
            Log.i(TAG, "Runtime.exec(String[], String[]): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.exec(String[], String[]) failed", t);
            failed++;
        }
    }

    // Runtime.exec(String, String[], File) - overload 4
    private void testExec_String_Envp_Dir() {
        try {
            Process p = Runtime.getRuntime().exec(
                    "/system/bin/sh -c 'echo exec_dir'",
                    null,
                    workDir);
            drainAndDestroy(p);
            Log.i(TAG, "Runtime.exec(String, String[], File): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.exec(String, String[], File) failed", t);
            failed++;
        }
    }

    // Runtime.exec(String[], String[], File) - overload 5
    private void testExec_StringArray_Envp_Dir() {
        try {
            Process p = Runtime.getRuntime().exec(
                    new String[]{"/system/bin/sh", "-c", "echo exec_array_dir"},
                    null,
                    workDir);
            drainAndDestroy(p);
            Log.i(TAG, "Runtime.exec(String[], String[], File): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Runtime.exec(String[], String[], File) failed", t);
            failed++;
        }
    }

    // Drains stdout and stderr then destroys the process.
    // Sequential drain is safe here because all commands produce < 64 bytes of output.
    private void drainAndDestroy(Process p) throws Exception {
        byte[] buf = new byte[256];
        try (InputStream stdout = p.getInputStream()) {
            while (stdout.read(buf) != -1) { /* drain */ }
        }
        try (InputStream stderr = p.getErrorStream()) {
            while (stderr.read(buf) != -1) { /* drain */ }
        }
        p.destroy();
    }
}