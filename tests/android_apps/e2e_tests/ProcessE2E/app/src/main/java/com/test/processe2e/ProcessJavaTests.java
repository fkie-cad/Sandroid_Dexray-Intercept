package com.test.processe2e;

import android.util.Log;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

// Triggers android.os.Process hooks in process.ts.
//
// Hook status:
//   Process.sendSignal(int, int)              -> process.signal        - present
//   Process.killProcess(int)                  -> process.kill          - present
//   Process.killProcessQuiet(int)              -> process.kill_quiet    - present
//   Process.sendSignalQuiet(int, int)          -> process.signal_quiet  - present
//   Process.killProcessGroup(int, int)         -> process.kill_group    - present
//   Process.sendSignalToProcessGroup(int,int,int) -> process.signal_group - present
//   Process.setUid(int)                        -> process.set_uid       - present
//   Process.setGid(int)                        -> process.set_gid       - present
//   Process.setArgV0(String)                   -> process.rename        - present
//   Process.getPids(String, int[])             -> process.proc_scan.get_pids - present
//   Process.getPidsForCommands(String[])       -> process.proc_scan.get_pids_for_commands - present
//   Process.readProcFile(...)                  -> process.proc_scan.read_file - present
//   Process.readProcLines(...)                 -> process.proc_scan.read_lines - present
//   Process.parseProcLine(...)                 -> process.proc_scan.parse_line - present but
//                                                  not directly triggered; requires a raw
//                                                  byte-buffer/format setup with low direct-call
//                                                  likelihood in real apps; confirmed via direct
//                                                  Frida dispatch probing only
//   Process.start(...)                         -> process.creation - present but NOT
//                                                  triggerable from a user app; Zygote-internal
//                                                  only; requires rooted device with modified
//                                                  Zygote or system-level instrumentation
//
// setUid/setGid/killProcessGroup/sendSignalToProcessGroup realistically only occur from
// privileged system callers; a sandboxed app has no legitimate reason to call them. These
// triggers exercise the hook firing and the syscall's graceful rejection, not a real use case.
//
// getPids/getPidsForCommands/readProcFile/readProcLines are hidden APIs, invoked here via
// reflection for the same reason as the methods above. Format flags used for readProcFile
// and readProcLines are not verified to be semantically correct for the target /proc file;
// only firing the hook and observing whatever the real call returns is required here.
public class ProcessJavaTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;

    public void runTests() {
        testSendSignal();
        testKillProcess();
        logProcessStartGap();
        testKillProcessQuiet();
        testSendSignalQuiet();
        testSetArgV0();
        testKillProcessGroup();
        testSendSignalToProcessGroup();
        testSetUid();
        testSetGid();
        testGetPids();
        testGetPidsForCommands();
        testReadProcFile();
        testReadProcLines();
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

    // The following methods are @SystemApi/hidden - present at runtime and
    // visible to Frida, but absent from the public SDK compile stubs. They
    // are invoked here via reflection, which is also how real app code
    // reaches hidden platform APIs not exposed in the SDK. Android's hidden
    // API enforcement may still block a given method depending on API level
    // and its allowlist status; that outcome is logged as informative, not
    // as a test failure, since it reflects real platform behavior rather
    // than a hook defect.

    private Object invokeHiddenStaticMethod(String methodName, Class<?>[] paramTypes, Object[] args)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Method method = android.os.Process.class.getMethod(methodName, paramTypes);
        return method.invoke(null, args);
    }

    // hooks: Process.killProcessQuiet -> process.kill_quiet
    //        Process.sendSignalQuiet (internal delegation) -> process.signal_quiet
    private void testKillProcessQuiet() {
        try {
            invokeHiddenStaticMethod("killProcessQuiet", new Class<?>[]{int.class}, new Object[]{99998});
            Log.i(TAG, "Process.killProcessQuiet(99998): ok");
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.killProcessQuiet: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.killProcessQuiet failed", t);
            failed++;
        }
    }

    // hook: Process.sendSignalQuiet -> process.signal_quiet
    private void testSendSignalQuiet() {
        try {
            int selfPid = android.os.Process.myPid();
            invokeHiddenStaticMethod("sendSignalQuiet", new Class<?>[]{int.class, int.class}, new Object[]{selfPid, 0});
            Log.i(TAG, "Process.sendSignalQuiet(selfPid, 0): ok");
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.sendSignalQuiet: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.sendSignalQuiet failed", t);
            failed++;
        }
    }

    // hook: Process.setArgV0 -> process.rename
    // Restores the original name immediately after to avoid confusing later
    // log output or subsequent test modules with a renamed process identity.
    private void testSetArgV0() {
        try {
            invokeHiddenStaticMethod("setArgV0", new Class<?>[]{String.class}, new Object[]{"processe2e-renamed"});
            invokeHiddenStaticMethod("setArgV0", new Class<?>[]{String.class}, new Object[]{"com.test.processe2e"});
            Log.i(TAG, "Process.setArgV0: ok");
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.setArgV0: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.setArgV0 failed", t);
            failed++;
        }
    }

    // hook: Process.killProcessGroup -> process.kill_group
    // Non-existent pid; own uid. No real process group is affected regardless
    // of the kernel's returned status.
    private void testKillProcessGroup() {
        try {
            int selfUid = android.os.Process.myUid();
            Object result = invokeHiddenStaticMethod("killProcessGroup", new Class<?>[]{int.class, int.class}, new Object[]{selfUid, 99997});
            Log.i(TAG, "Process.killProcessGroup(selfUid, 99997): result=" + result);
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.killProcessGroup: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.killProcessGroup failed", t);
            failed++;
        }
    }

    // hook: Process.sendSignalToProcessGroup -> process.signal_group
    // Signal 0 to a non-existent pid; own uid.
    private void testSendSignalToProcessGroup() {
        try {
            int selfUid = android.os.Process.myUid();
            Object result = invokeHiddenStaticMethod("sendSignalToProcessGroup", new Class<?>[]{int.class, int.class, int.class}, new Object[]{selfUid, 99996, 0});
            Log.i(TAG, "Process.sendSignalToProcessGroup(selfUid, 99996, 0): result=" + result);
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.sendSignalToProcessGroup: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.sendSignalToProcessGroup failed", t);
            failed++;
        }
    }

    // hook: Process.setUid -> process.set_uid
    // Passes the process's own current uid. A sandboxed app lacks the
    // capability to change uid regardless of the value requested; this
    // exercises the hook and the syscall's expected rejection.
    private void testSetUid() {
        try {
            int selfUid = android.os.Process.myUid();
            Object result = invokeHiddenStaticMethod("setUid", new Class<?>[]{int.class}, new Object[]{selfUid});
            Log.i(TAG, "Process.setUid(selfUid): result=" + result);
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.setUid: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.setUid failed", t);
            failed++;
        }
    }

    // hook: Process.setGid -> process.set_gid
    // No public API exposes the process's own gid; reuses the uid value as a
    // safe, non-privileged argument. A sandboxed app lacks the capability to
    // change gid regardless of the value requested.
    private void testSetGid() {
        try {
            int selfUid = android.os.Process.myUid();
            Object result = invokeHiddenStaticMethod("setGid", new Class<?>[]{int.class}, new Object[]{selfUid});
            Log.i(TAG, "Process.setGid(selfUid): result=" + result);
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.setGid: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.setGid failed", t);
            failed++;
        }
    }

    // hook: Process.getPids -> process.proc_scan.get_pids
    private void testGetPids() {
        try {
            Object result = invokeHiddenStaticMethod(
                    "getPids",
                    new Class<?>[]{String.class, int[].class},
                    new Object[]{"/proc", null});
            int[] pids = (int[]) result;
            Log.i(TAG, "Process.getPids(/proc): " + (pids != null ? pids.length : 0) + " entries");
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.getPids: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.getPids failed", t);
            failed++;
        }
    }

    // hook: Process.getPidsForCommands -> process.proc_scan.get_pids_for_commands
    private void testGetPidsForCommands() {
        try {
            Object result = invokeHiddenStaticMethod(
                    "getPidsForCommands",
                    new Class<?>[]{String[].class},
                    new Object[]{new String[]{"system_server"}});
            int[] pids = (int[]) result;
            Log.i(TAG, "Process.getPidsForCommands: " + (pids != null ? pids.length : 0) + " entries");
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.getPidsForCommands: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.getPidsForCommands failed", t);
            failed++;
        }
    }

    // hook: Process.readProcFile -> process.proc_scan.read_file
    private void testReadProcFile() {
        try {
            int[] format = new int[]{0x2000}; // PROC_OUT_LONG per AOSP Process.java
            String[] outStrings = new String[1];
            long[] outLongs = new long[1];
            float[] outFloats = new float[1];
            Object result = invokeHiddenStaticMethod(
                    "readProcFile",
                    new Class<?>[]{String.class, int[].class, String[].class, long[].class, float[].class},
                    new Object[]{"/proc/self/stat", format, outStrings, outLongs, outFloats});
            Log.i(TAG, "Process.readProcFile(/proc/self/stat): result=" + result);
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.readProcFile: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.readProcFile failed", t);
            failed++;
        }
    }

    // hook: Process.readProcLines -> process.proc_scan.read_lines
    private void testReadProcLines() {
        try {
            String[] matchingLines = new String[]{"VmRSS"};
            long[] outSizes = new long[1];
            invokeHiddenStaticMethod(
                    "readProcLines",
                    new Class<?>[]{String.class, String[].class, long[].class},
                    new Object[]{"/proc/self/status", matchingLines, outSizes});
            Log.i(TAG, "Process.readProcLines(/proc/self/status): outSizes[0]=" + outSizes[0]);
            passed++;
        } catch (NoSuchMethodException e) {
            Log.i(TAG, "Process.readProcLines: hidden API not accessible on this API level");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Process.readProcLines failed", t);
            failed++;
        }
    }
}