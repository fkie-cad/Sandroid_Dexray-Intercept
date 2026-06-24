package com.test.processe2e;

import android.util.Log;

// Triggers android.os.Process hooks in process.ts.
//
// Hook status:
//   Process.sendSignal(int, int) -> process.signal - present
//   Process.killProcess(int)     -> process.kill   - present
//   Process.start(...)           -> process.creation - present but NOT triggerable
//                                   from a user app; Zygote-internal only;
//                                   requires rooted device with modified Zygote
//                                   or system-level instrumentation
public class ProcessJavaTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;

    public void runTests() {
        testSendSignal();
        testKillProcess();
        logProcessStartGap();
        Log.i(TAG, "ProcessJavaTests summary: " + passed + " passed, " + failed + " failed");
    }

    // hook: Process.sendSignal -> process.signal
    // Signal 0 to self: checks process existence, no actual signal delivered.
    private void testSendSignal() {
        try {
            int selfPid = android.os.Process.myPid();
            android.os.Process.sendSignal(selfPid, 0);
            Log.i(TAG, "Process.sendSignal(selfPid, 0): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.sendSignal failed", t);
            failed++;
        }
    }

    // hook: Process.killProcess -> process.kill
    // PID 99999 is outside any real process range; kernel rejects gracefully.
    // Hook fires before kernel rejection; no side effects.
    private void testKillProcess() {
        try {
            android.os.Process.killProcess(99999);
            Log.i(TAG, "Process.killProcess(99999): ok");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.killProcess failed", t);
            failed++;
        }
    }

    // hook: Process.start -> process.creation
    // Not triggerable from a user app. Process.start is called by the Android
    // system when forking a new app process from Zygote. Direct invocation from
    // user space is blocked by the security model. Requires a rooted device with
    // a modified Zygote or system-level instrumentation for hook testing.
    private void logProcessStartGap() {
        Log.i(TAG, "Process.start: not triggerable from user app - Zygote-internal only");
    }
}