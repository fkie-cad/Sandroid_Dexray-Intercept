package com.test.processe2e;

import android.util.Log;

import java.lang.reflect.Method;

// Triggers reflection hooks in runtime.ts.
//
// Hook status per site:
//   Class.getMethod(String, Class[])              -> reflection.get_method         - present
//   Class.getDeclaredMethod(String, Class[])      -> reflection.get_declared_method - present
//   Class.forName(String, boolean, ClassLoader)   -> reflection.class_for_name     - present (3-arg only)
//   Class.forName(String)                         -> NOT hooked (1-arg overload missing from runtime.ts)
//   ClassLoader.loadClass(String, boolean)        -> reflection.load_class         - present
//                                                    internal class names filtered out by hook
//   Method.invoke(Object, Object[])               -> reflection.method_invoke      - present
public class ReflectionTests {

    private static final String TAG = "PROCESS_RUNTIME_E2E";
    private int passed = 0;
    private int failed = 0;
    private final ClassLoader classLoader;

    public ReflectionTests(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    public void runTests() {
        testClassForName_3arg();
        testClassForName_1arg();
        testGetMethod();
        testGetDeclaredMethod();
        testClassLoaderLoadClass();
        testMethodInvoke_static();
        testMethodInvoke_instance();
        Log.i(TAG, "ReflectionTests summary: " + passed + " passed, " + failed + " failed");
    }

    // hook: Class.forName(String, boolean, ClassLoader) -> reflection.class_for_name
    // 3-arg overload is the one hooked in runtime.ts.
    private void testClassForName_3arg() {
        try {
            Class<?> cls = Class.forName(
                    "com.test.processe2e.ReflectionTarget", true, classLoader);
            Log.i(TAG, "Class.forName(3-arg): " + cls.getName());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Class.forName(3-arg) failed", t);
            failed++;
        }
    }

    // Class.forName(String) 1-arg - NOT hooked in runtime.ts.
    // Trigger present to confirm no reflection.class_for_name event is emitted
    // for the 1-arg overload.
    private void testClassForName_1arg() {
        try {
            Class<?> cls = Class.forName("com.test.processe2e.ReflectionTarget");
            Log.i(TAG, "Class.forName(1-arg): " + cls.getName()
                    + " (1-arg overload not hooked in runtime.ts)");
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Class.forName(1-arg) failed", t);
            failed++;
        }
    }

    // hook: Class.getMethod(String, Class[]) -> reflection.get_method
    private void testGetMethod() {
        try {
            Class<?> cls = Class.forName("com.test.processe2e.ReflectionTarget");
            Method m = cls.getMethod("staticMethod", String.class, int.class);
            Log.i(TAG, "Class.getMethod: " + m.getName());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Class.getMethod failed", t);
            failed++;
        }
    }

    // hook: Class.getDeclaredMethod(String, Class[]) -> reflection.get_declared_method
    private void testGetDeclaredMethod() {
        try {
            Class<?> cls = Class.forName("com.test.processe2e.ReflectionTarget");
            Method m = cls.getDeclaredMethod("instanceMethod", String.class);
            Log.i(TAG, "Class.getDeclaredMethod: " + m.getName());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Class.getDeclaredMethod failed", t);
            failed++;
        }
    }

    // hook: ClassLoader.loadClass(String, boolean) -> reflection.load_class
    // The public 1-arg loadClass(String) internally calls the hooked 2-arg
    // protected overload loadClass(String, false).
    // Must use a non-internal class name; hook filters out names starting with
    // "android.", "com.android", "java.lang", "java.io".
    private void testClassLoaderLoadClass() {
        try {
            Class<?> cls = classLoader.loadClass("com.test.processe2e.ReflectionTarget");
            Log.i(TAG, "ClassLoader.loadClass: " + cls.getName());
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "ClassLoader.loadClass failed", t);
            failed++;
        }
    }

    // hook: Method.invoke(Object, Object[]) -> reflection.method_invoke
    // Static method: null instance.
    private void testMethodInvoke_static() {
        try {
            Class<?> cls = Class.forName("com.test.processe2e.ReflectionTarget");
            Method m = cls.getMethod("staticMethod", String.class, int.class);
            Object result = m.invoke(null, "prefix-", 42);
            Log.i(TAG, "Method.invoke(static): " + result);
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Method.invoke(static) failed", t);
            failed++;
        }
    }

    // hook: Method.invoke(Object, Object[]) -> reflection.method_invoke
    // Instance method: invoke on a constructed instance.
    private void testMethodInvoke_instance() {
        try {
            Class<?> cls = Class.forName("com.test.processe2e.ReflectionTarget");
            Object instance = cls.getConstructor(String.class).newInstance("base-");
            Method m = cls.getDeclaredMethod("instanceMethod", String.class);
            Object result = m.invoke(instance, "suffix");
            Log.i(TAG, "Method.invoke(instance): " + result);
            passed++;
        } catch (Throwable t) {
            Log.e(TAG, "Method.invoke(instance) failed", t);
            failed++;
        }
    }
}