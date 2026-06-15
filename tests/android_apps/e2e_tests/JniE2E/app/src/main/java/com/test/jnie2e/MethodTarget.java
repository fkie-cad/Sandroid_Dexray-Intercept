package com.test.jnie2e;

/**
 * MethodTarget is used by JNI call tests to exercise:
 *  - Call<Type>Method / Call<Type>MethodV / Call<Type>MethodA
 *  - CallStatic<Type>Method / CallStatic<Type>MethodV / CallStatic<Type>MethodA
 *  - NewObject / NewObjectA with constructor arguments
 *  - Mixed parameter/return types (primitives + objects)
 */
public class MethodTarget {

    private int storedInt;
    private String storedString;

    public MethodTarget() {
        this.storedInt = 0;
        this.storedString = "";
    }

    // Constructor with args (for NewObject tests)
    public MethodTarget(int i, String s) {
        this.storedInt = i;
        this.storedString = s;
    }

    // 1) Simple int addition
    public int add(int a, int b) {
        return a + b;
    }

    // 2) Three long arguments
    public long sum3(long a, long b, long c) {
        return a + b + c;
    }

    // 3) String concatenation
    public String concat(String a, String b) {
        return a + b;
    }

    // 4) Mixed types (int, String, double)
    public String mixed(int i, String s, double d) {
        return i + "-" + s + "-" + d;
    }

    // 5) Many arguments with various types
    public long manyArgs(int i, long l, float f, double d, boolean b) {
        long result = i + l + (long) f + (long) d + (b ? 1 : 0);
        return result;
    }

    // 6) Static method
    public static long staticSum(long a, long b) {
        return a + b;
    }

    // 8) boolean and small primitive methods
    public boolean boolAnd(int a, boolean b) {
        return (a != 0) && b;
    }

    public byte addBytes(byte a, byte b) {
        return (byte) (a + b);
    }

    public short addShorts(short a, short b) {
        return (short) (a + b);
    }

    // 9) staticConcat3 for static object-call tests
    public static String staticConcat3(String a, String b, String c) {
        if (a == null) a = "null";
        if (b == null) b = "null";
        if (c == null) c = "null";
        return a + b + c;
    }

    // 10) float/double instance methods ---

    public float mulFloat(float a, float b) {
        return a * b;
    }

    public double mulDouble(double a, double b) {
        return a * b;
    }

    // 11) instance void method ---

    public void voidMethod(int v, String s) {
        this.storedInt = v;
        this.storedString = s;
    }

    // 12) static primitive methods for CallStatic*Method* ---

    public static boolean staticAnd(boolean a, boolean b) {
        return a && b;
    }

    public static byte staticAddBytes(byte a, byte b) {
        return (byte) (a + b);
    }

    public static char staticShiftChar(char c) {
        return (char) (c + 1);
    }

    public static short staticAddShorts(short a, short b) {
        return (short) (a + b);
    }

    public static int staticAddInts(int a, int b) {
        return a + b;
    }

    public static float staticMulFloats(float a, float b) {
        return a * b;
    }

    public static double staticMulDoubles(double a, double b) {
        return a * b;
    }

    public static void staticVoidLog(String s) {
        // no-op; used to exercise CallStaticVoidMethod* families
    }
}