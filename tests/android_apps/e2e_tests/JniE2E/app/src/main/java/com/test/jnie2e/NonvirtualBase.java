package com.test.jnie2e;

/**
 * Base class for testing CallNonvirtual*Method families.
 * Methods implement simple transformations; Derived overrides them
 * to different behavior so nonvirtual calls can be distinguished.
 */
public class NonvirtualBase {

    // Mixed-argument target for nonvirtual plain, V, and A boundary testing.
    public int boundaryMixedNonvirtual(
            int a, double b, int c, double d, int e, double f,
            int g, double h, int i, double j, int k, double l,
            double m, double n, double o) {
        return MethodTarget.boundaryMixed(
                a, b, c, d, e, f, g, h, i, j, k, l, m, n, o);
    }

    public int baseInt(int x) {
        return x * 10;
    }

    public boolean baseBool(boolean b) {
        return !b;
    }

    public byte baseByte(byte b) {
        return (byte) (b + 1);
    }

    public char baseChar(char c) {
        return (char) (c + 1);
    }

    public short baseShort(short s) {
        return (short) (s + 10);
    }

    public long baseLong(long l) {
        return l + 100L;
    }

    public float baseFloat(float f) {
        return f + 1.0f;
    }

    public double baseDouble(double d) {
        return d + 1.0;
    }

    public void baseVoid(String s) {
        // base behavior: no-op
    }

    public String baseConcat(String s) {
        return "base:" + s;
    }
}