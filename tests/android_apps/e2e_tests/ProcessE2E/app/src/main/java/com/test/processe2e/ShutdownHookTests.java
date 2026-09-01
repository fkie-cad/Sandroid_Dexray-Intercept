package com.test.processe2e;

import android.util.Log;

// Triggers Runtime.addShutdownHook/removeShutdownHook hooks in runtime.ts.
//
// Hook status:
//   Runtime.addShutdownHook(Thread)    -> runtime.add_shutdown_hook    - present
//   Runtime.removeShutdownHook(Thread) -> runtime.remove_shutdown_hook - present
//
// Runtime.exit(int) and Runtime.halt(int) are covered separately via an
// opt-in Intent trigger in MainActivity, since calling either terminates
// the process and cannot run as part of this default sequence.
public class ShutdownHookTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;

    public void runTests() {
        testAddAndRemoveShutdownHook();
        Log.i(TAG, "ShutdownHookTests summary: " + passed + " passed, " + failed + " failed");
    }

    // hooks: Runtime.addShutdownHook -> runtime.add_shutdown_hook
    //        Runtime.removeShutdownHook -> runtime.remove_shutdown_hook
    // The hook thread never actually runs, since it is removed immediately
    // after being added; this exercises both API calls without altering
    // process shutdown behavior.
    private void testAddAndRemoveShutdownHook() {
        try {
            Thread hook = new Thread(() -> Log.i(TAG, "shutdown hook ran"));
            Runtime.getRuntime().addShutdownHook(hook);
            Log.i(TAG, "Runtime.addShutdownHook: ok");

            boolean removed = Runtime.getRuntime().removeShutdownHook(hook);
            Log.i(TAG, "Runtime.removeShutdownHook: removed=" + removed);
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "addShutdownHook/removeShutdownHook failed", t);
            failed++;
        }
    }
}