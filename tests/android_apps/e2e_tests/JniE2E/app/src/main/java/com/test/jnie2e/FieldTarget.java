package com.test.jnie2e;

/**
 * FieldTarget is used by JNI field tests to exercise:
 *  - GetObjectClass
 *  - GetFieldID / GetStaticFieldID
 *  - Get<Type>Field / Set<Type>Field
 *  - GetStatic<Type>Field / SetStatic<Type>Field
 */
public class FieldTarget {

    // Instance primitive fields
    public int intField;
    public long longField;
    public boolean boolField;
    public byte byteField;
    public short shortField;
    public char charField;
    public float floatField;
    public double doubleField;

    // Instance object field
    public String objectField;

    // Static primitive fields
    public static int staticIntField;
    public static long staticLongField;
    public static boolean staticBoolField;
    public static byte staticByteField;
    public static short staticShortField;
    public static char staticCharField;
    public static float staticFloatField;
    public static double staticDoubleField;

    // Static object field
    public static String staticObjectField;

    public FieldTarget() {
        // Default values, overwritten by JNI tests
    }
}