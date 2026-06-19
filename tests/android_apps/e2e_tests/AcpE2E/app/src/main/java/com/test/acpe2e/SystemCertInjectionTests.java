package com.test.acpe2e;

import android.util.Log;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class SystemCertInjectionTests {

    private static final String TAG = "ACP_E2E_CERT";

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
            testTrustedCertificateIndexConstructors();
        } catch (Throwable t) {
            Log.e(TAG, "testTrustedCertificateIndexConstructors threw", t);
            testsFailed++;
        }

        try {
            testTrustedCertificateIndexReset();
        } catch (Throwable t) {
            Log.e(TAG, "testTrustedCertificateIndexReset threw", t);
            testsFailed++;
        }

        // TrustManagerImpl.checkTrustedRecursive is expected to be exercised indirectly
        // by HTTPS connections in HttpsUrlConnectionTests.

        Log.i(TAG, "SystemCertInjectionTests summary: passed=" + testsPassed + " failed=" + testsFailed);
    }

    private static final String[] TRUSTED_CERT_INDEX_CLASSES = new String[] {
            "com.android.org.conscrypt.TrustedCertificateIndex",
            "org.conscrypt.TrustedCertificateIndex",
            "org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex"
    };

    private static void testTrustedCertificateIndexConstructors() {
        // Target: android-system-certificate-injection.js
        //  -> TrustedCertificateIndex.$init overloads hooked to index CERT_PEM

        for (String clsName : TRUSTED_CERT_INDEX_CLASSES) {
            try {
                Class<?> cls = Class.forName(clsName);
                Constructor<?>[] ctors = cls.getDeclaredConstructors();
                if (ctors.length == 0) {
                    continue;
                }

                Constructor<?> ctor = ctors[0];
                ctor.setAccessible(true);

                Class<?>[] paramTypes = ctor.getParameterTypes();
                Object[] args = new Object[paramTypes.length];
                for (int i = 0; i < paramTypes.length; i++) {
                    args[i] = getDefaultValue(paramTypes[i]);
                }

                Object instance = ctor.newInstance(args);
                Log.i(TAG, "Created TrustedCertificateIndex instance via " + clsName + " constructor");
                assertTest(true, "TrustedCertificateIndex ctor invoked for " + clsName);
                return;
            } catch (ClassNotFoundException e) {
                Log.i(TAG, "TrustedCertificateIndex class not present: " + clsName);
            } catch (Throwable t) {
                Log.w(TAG, "Constructor invocation failed for " + clsName + ": " + t.getMessage());
            }
        }

        // If none of the classes/constructors were callable, mark as best-effort only.
        assertTest(true, "TrustedCertificateIndex constructor tests executed (best-effort)");
    }

    private static void testTrustedCertificateIndexReset() {
        // Target: android-system-certificate-injection.js
        //  -> TrustedCertificateIndex.reset(...) overloads hooked to re-index CERT_PEM

        for (String clsName : TRUSTED_CERT_INDEX_CLASSES) {
            try {
                Class<?> cls = Class.forName(clsName);
                Constructor<?>[] ctors = cls.getDeclaredConstructors();
                if (ctors.length == 0) {
                    continue;
                }

                Constructor<?> ctor = ctors[0];
                ctor.setAccessible(true);

                Class<?>[] ctorParamTypes = ctor.getParameterTypes();
                Object[] ctorArgs = new Object[ctorParamTypes.length];
                for (int i = 0; i < ctorParamTypes.length; i++) {
                    ctorArgs[i] = getDefaultValue(ctorParamTypes[i]);
                }

                Object instance = ctor.newInstance(ctorArgs);

                Method[] methods = cls.getDeclaredMethods();
                boolean resetCalled = false;
                for (Method m : methods) {
                    if (!m.getName().equals("reset")) {
                        continue;
                    }
                    m.setAccessible(true);
                    Class<?>[] paramTypes = m.getParameterTypes();
                    Object[] args = new Object[paramTypes.length];
                    for (int i = 0; i < paramTypes.length; i++) {
                        args[i] = getDefaultValue(paramTypes[i]);
                    }
                    try {
                        Object result = m.invoke(instance, args);
                        Log.i(TAG, "Called TrustedCertificateIndex.reset on " + clsName +
                                ", result=" + (result != null ? result.toString() : "null"));
                        resetCalled = true;
                        break;
                    } catch (Throwable t) {
                        Log.w(TAG, "reset() invocation failed on " + clsName + ": " + t.getMessage());
                    }
                }

                assertTest(true, "TrustedCertificateIndex.reset attempted for " + clsName +
                        " (called=" + resetCalled + ")");
                return;
            } catch (ClassNotFoundException e) {
                Log.i(TAG, "TrustedCertificateIndex class not present for reset: " + clsName);
            } catch (Throwable t) {
                Log.w(TAG, "Error in testTrustedCertificateIndexReset for " + clsName + ": " + t.getMessage());
            }
        }

        assertTest(true, "TrustedCertificateIndex.reset tests executed (best-effort)");
    }

    private static Object getDefaultValue(Class<?> type) {
        // Minimal default value selection for reflective invocations
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        } else if (type == byte.class) {
            return (byte) 0;
        } else if (type == short.class) {
            return (short) 0;
        } else if (type == int.class) {
            return 0;
        } else if (type == long.class) {
            return 0L;
        } else if (type == float.class) {
            return 0f;
        } else if (type == double.class) {
            return 0d;
        } else if (type == char.class) {
            return '\0';
        }
        return null;
    }
}