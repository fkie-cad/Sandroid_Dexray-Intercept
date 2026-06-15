package com.test.jnie2e;

/**
 * Derived class that overrides NonvirtualBase methods with different behavior.
 * Using CallNonvirtual*Method with NonvirtualBase as the declaring class
 * should yield base-class semantics even when invoked on a NonvirtualDerived instance.
 */
public class NonvirtualDerived extends NonvirtualBase {

    @Override
    public int baseInt(int x) {
        return x * 100;
    }

    @Override
    public boolean baseBool(boolean b) {
        return b; // opposite of base
    }

    @Override
    public byte baseByte(byte b) {
        return (byte) (b + 2); // different increment
    }

    @Override
    public char baseChar(char c) {
        return (char) (c + 2);
    }

    @Override
    public short baseShort(short s) {
        return (short) (s + 20);
    }

    @Override
    public long baseLong(long l) {
        return l + 200L;
    }

    @Override
    public float baseFloat(float f) {
        return f + 2.0f;
    }

    @Override
    public double baseDouble(double d) {
        return d + 2.0;
    }

    @Override
    public void baseVoid(String s) {
        // derived behavior: still no-op for simplicity
    }
}