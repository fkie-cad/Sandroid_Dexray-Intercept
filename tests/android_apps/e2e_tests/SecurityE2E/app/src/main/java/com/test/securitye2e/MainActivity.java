// tests/android_apps/e2e_tests/SecurityE2E/app/src/main/java/com/test/securitye2e/MainActivity.java
package com.test.securitye2e;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Debug;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends Activity {

    private static final String TAG = "BYPASS_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "SecurityE2E started");

        Thread t = new Thread(() -> {
            try {
                try {
                    runRootBypassTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "runRootBypassTests failed", t1);
                }

                try {
                    runFridaBypassTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "runFridaBypassTests failed", t1);
                }

                try {
                    runDebuggerBypassTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "runDebuggerBypassTests failed", t1);
                }

                try {
                    runEmulatorBypassTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "runEmulatorBypassTests failed", t1);
                }

                try {
                    runHookBypassTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "runHookBypassTests failed", t1);
                }

            } catch (Throwable t1) {
                Log.e(TAG, "Error in SecurityE2E", t1);
            } finally {
                Log.i(TAG, "SecurityE2E finished");
            }
        }, "securitye2e-tests");
        t.start();

        Log.i(TAG, "SecurityE2E calling finish()");
        finish();
    }

    // ------------------------------------------------------------
    // Root detection bypass tests
    // ------------------------------------------------------------

    private void runRootBypassTests() {
        Log.i(TAG, "runRootBypassTests started");
        try {
            List<String> rootPaths = Arrays.asList(
                    "/system/bin/su",
                    "/system/xbin/su",
                    "/sbin/su",
                    "/system/app/Superuser.apk",
                    "/system/app/SuperSU.apk",
                    "/data/data/com.noshufou.android.su",
                    "/data/data/com.koushikdutta.superuser",
                    "/data/data/eu.chainfire.supersu",
                    "/system/xbin/busybox",
                    "/system/bin/busybox",
                    "/system/app/RootCloak.apk",
                    "/dev/com.koushikdutta.superuser.daemon/"
            );
            // bypass.root.file_check - File.exists() root paths
            for (String path : rootPaths) {
                try {
                    Log.i(TAG, "File.exists(root path) - trigger: " + path);
                    boolean exists = new File(path).exists();
                    Log.i(TAG, "File.exists(root path) result: " + path + " -> " + exists);
                } catch (Throwable t) {
                    Log.e(TAG, "File.exists failed for " + path, t);
                }
            }

            try {
                Log.i(TAG, "File.exists(non-root path) - trigger");
                boolean exists = new File("/data/local/tmp/securitye2e_dummy").exists();
                Log.i(TAG, "File.exists(non-root path) -> " + exists);
            } catch (Throwable t) {
                Log.e(TAG, "File.exists failed for non-root path", t);
            }

            Runtime rt = Runtime.getRuntime();

            // bypass.root.command_execution - Runtime.exec(String)
            try {
                Log.i(TAG, "Runtime.exec(String) - trigger: su");
                rt.exec("su");
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec(\"su\") failed", t);
            }

            try {
                Log.i(TAG, "Runtime.exec(String) - trigger: which su");
                rt.exec("which su");
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec(\"which su\") failed", t);
            }

            // bypass.root.command_execution - Runtime.exec(String[])
            try {
                Log.i(TAG, "Runtime.exec(String[]) - trigger: su -c id");
                rt.exec(new String[]{"su", "-c", "id"});
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec([\"su\",\"-c\",\"id\"]) failed", t);
            }

            try {
                Log.i(TAG, "Runtime.exec(String[]) - trigger: busybox id");
                rt.exec(new String[]{"busybox", "id"});
            } catch (Throwable t) {
                Log.e(TAG, "Runtime.exec([\"busybox\",\"id\"]) failed", t);
            }

            // bypass.root.build_tags - Build.TAGS field read
            // Event fires at hook install time if Build.TAGS contains "test-keys",
            // not on this field read. Read included to confirm field is accessible.
            try {
                Log.i(TAG, "Build.TAGS read - trigger (event fires at hook install only)");
                String tags = android.os.Build.TAGS;
                Log.i(TAG, "Build.TAGS: " + tags);
            } catch (Throwable t) {
                Log.e(TAG, "Reading Build.TAGS failed", t);
            }

            // bypass.root.package_check - PackageManager.getInstalledPackages(int)
            try {
                Log.i(TAG, "PackageManager.getInstalledPackages(0) - trigger");
                PackageManager pm = getPackageManager();
                if (pm != null) {
                    pm.getInstalledPackages(0);
                }
            } catch (Throwable t) {
                Log.e(TAG, "getInstalledPackages failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runRootBypassTests", t);
        }
        Log.i(TAG, "runRootBypassTests completed");
    }

    // ------------------------------------------------------------
    // Frida detection bypass tests
    // ------------------------------------------------------------

    private void runFridaBypassTests() {
        Log.i(TAG, "runFridaBypassTests started");
        try {
            List<String> fridaPaths = Arrays.asList(
                    "/data/local/tmp/frida-server",
                    "/data/local/tmp/re.frida.server",
                    "/system/lib/libfrida-gadget.so",
                    "/system/lib64/libfrida-gadget.so"
            );
            // bypass.frida.file_check - File.exists() frida paths
            for (String path : fridaPaths) {
                try {
                    Log.i(TAG, "File.exists(frida path) - trigger: " + path);
                    boolean exists = new File(path).exists();
                    Log.i(TAG, "File.exists(frida path) result: " + path + " -> " + exists);
                } catch (Throwable t) {
                    Log.e(TAG, "File.exists failed for " + path, t);
                }
            }

            // bypass.frida.port_check - Socket.$init(String,int) port 27042
            try {
                Log.i(TAG, "Socket(127.0.0.1, 27042) - trigger");
                new Socket("127.0.0.1", 27042).close();
            } catch (Throwable t) {
                Log.i(TAG, "Socket(127.0.0.1, 27042) threw (expected): " + t.getClass().getSimpleName());
            }

            // bypass.frida.process_check - ActivityManager.getRunningAppProcesses()
            try {
                Log.i(TAG, "ActivityManager.getRunningAppProcesses() - trigger");
                ActivityManager am =
                        (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
                if (am != null) {
                    java.util.List<ActivityManager.RunningAppProcessInfo> list =
                            am.getRunningAppProcesses();
                    int count = list != null ? list.size() : 0;
                    Log.i(TAG, "Running app processes count: " + count);
                }
            } catch (Throwable t) {
                Log.e(TAG, "getRunningAppProcesses failed", t);
            }

            // bypass.frida.thread_check - Thread.getName() on thread named "frida-worker"
            try {
                Log.i(TAG, "Thread.getName() on frida-worker thread - trigger");
                Thread t = new Thread("frida-worker") {
                    @Override
                    public void run() {
                        try {
                            String name = getName();
                            Log.i(TAG, "Thread.getName() result (may be bypassed): " + name);
                        } catch (Throwable e) {
                            Log.e(TAG, "Thread name retrieval failed", e);
                        }
                    }
                };
                t.start();
                t.join();
            } catch (Throwable t) {
                Log.e(TAG, "Thread name test failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runFridaBypassTests", t);
        }
        Log.i(TAG, "runFridaBypassTests completed");
    }

    // ------------------------------------------------------------
    // Debugger detection bypass tests
    // ------------------------------------------------------------

    private void runDebuggerBypassTests() {
        Log.i(TAG, "runDebuggerBypassTests started");
        try {
            // bypass.debugger.connection_check - Debug.isDebuggerConnected()
            try {
                Log.i(TAG, "Debug.isDebuggerConnected() - trigger");
                boolean dbg = Debug.isDebuggerConnected();
                Log.i(TAG, "Debug.isDebuggerConnected() result (may be bypassed): " + dbg);
            } catch (Throwable t) {
                Log.e(TAG, "Debug.isDebuggerConnected failed", t);
            }

            // bypass.debugger.flag_check - PackageManager.getApplicationInfo(String,int)
            try {
                Log.i(TAG, "PackageManager.getApplicationInfo() - trigger");
                PackageManager pm = getPackageManager();
                if (pm != null) {
                    ApplicationInfo info =
                            pm.getApplicationInfo(getPackageName(), 0);
                    if (info != null) {
                        boolean debuggable =
                                (info.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
                        Log.i(TAG, "ApplicationInfo.FLAG_DEBUGGABLE (may be bypassed): " + debuggable);
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "getApplicationInfo failed", t);
            }

            // bypass.debugger.tracer_check - BufferedReader.readLine() on /proc/self/status
            // Event fires only when TracerPid is non-zero (Frida attached during hooked run).
            // During baseline run TracerPid is 0 so no bypass event fires; hook still installs.
            try {
                Log.i(TAG, "BufferedReader.readLine(/proc/self/status) - trigger");
                BufferedReader br = new BufferedReader(
                        new FileReader("/proc/self/status"));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        Log.i(TAG, "TracerPid line (may be bypassed): " + line);
                        break;
                    }
                }
                br.close();
            } catch (Throwable t) {
                Log.e(TAG, "Reading /proc/self/status failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runDebuggerBypassTests", t);
        }
        Log.i(TAG, "runDebuggerBypassTests completed");
    }

    // ------------------------------------------------------------
    // Emulator detection bypass tests
    // ------------------------------------------------------------

    private void runEmulatorBypassTests() {
        Log.i(TAG, "runEmulatorBypassTests started");
        try {
            // bypass.emulator.build_property - Build.* field reads
            // Events fire at hook install time only if field values match emulator indicators.
            // Field reads below confirm accessibility and log actual values.
            try {
                Log.i(TAG, "Build.* field reads - trigger (events fire at hook install only)");
                String brand = android.os.Build.BRAND;
                String device = android.os.Build.DEVICE;
                String model = android.os.Build.MODEL;
                String product = android.os.Build.PRODUCT;
                String manufacturer = android.os.Build.MANUFACTURER;
                String hardware = android.os.Build.HARDWARE;
                Log.i(TAG, "Build.BRAND=" + brand);
                Log.i(TAG, "Build.DEVICE=" + device);
                Log.i(TAG, "Build.MODEL=" + model);
                Log.i(TAG, "Build.PRODUCT=" + product);
                Log.i(TAG, "Build.MANUFACTURER=" + manufacturer);
                Log.i(TAG, "Build.HARDWARE=" + hardware);
            } catch (Throwable t) {
                Log.e(TAG, "Reading Build.* properties failed", t);
            }

            // bypass.emulator.system_property - SystemProperties.get(String)
            // Event fires only for ro.kernel.qemu=="1" or ro.product.model containing "google_sdk".
            try {
                Log.i(TAG, "SystemProperties.get(ro.kernel.qemu) - trigger");
                Class<?> spClass = Class.forName("android.os.SystemProperties");
                Method get = spClass.getMethod("get", String.class);
                Object qemu = get.invoke(null, "ro.kernel.qemu");
                Log.i(TAG, "SystemProperties.get(ro.kernel.qemu) = " + qemu);

                Log.i(TAG, "SystemProperties.get(ro.product.model) - trigger");
                Object modelProp = get.invoke(null, "ro.product.model");
                Log.i(TAG, "SystemProperties.get(ro.product.model) = " + modelProp);
            } catch (Throwable t) {
                Log.e(TAG, "SystemProperties.get emulator properties failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runEmulatorBypassTests", t);
        }
        Log.i(TAG, "runEmulatorBypassTests completed");
    }

    // ------------------------------------------------------------
    // Hook detection bypass tests
    // ------------------------------------------------------------

    private void runHookBypassTests() {
        Log.i(TAG, "runHookBypassTests started");
        try {
            // bypass.hook.stack_trace - Throwable.getStackTrace()
            try {
                Log.i(TAG, "Throwable.getStackTrace() - trigger");
                Throwable th = new Throwable("bypass-e2e");
                StackTraceElement[] stack = th.getStackTrace();
                Log.i(TAG, "Throwable.getStackTrace() length (may be filtered): " + stack.length);
                if (stack.length > 0) {
                    Log.i(TAG, "Stack[0]: " + stack[0].toString());
                }
            } catch (Throwable t) {
                Log.e(TAG, "Throwable.getStackTrace failed", t);
            }

            // bypass.hook.library_check - System.mapLibraryName()
            try {
                Log.i(TAG, "System.mapLibraryName(\"frida\") - trigger");
                String mapped = System.mapLibraryName("frida");
                Log.i(TAG, "System.mapLibraryName(\"frida\") = " + mapped);

                // Non-frida name to confirm hook passes through normally
                Log.i(TAG, "System.mapLibraryName(\"c\") - trigger (non-hooked path)");
                String mappedC = System.mapLibraryName("c");
                Log.i(TAG, "System.mapLibraryName(\"c\") = " + mappedC);
            } catch (Throwable t) {
                Log.e(TAG, "System.mapLibraryName failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runHookBypassTests", t);
        }
        Log.i(TAG, "runHookBypassTests completed");
    }
}