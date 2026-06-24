package com.test.processe2e;

public class ReflectionTarget {

    private String value;

    public ReflectionTarget(String value) {
        this.value = value;
    }

    public String instanceMethod(String suffix) {
        return value + suffix;
    }

    public static String staticMethod(String prefix, int number) {
        return prefix + number;
    }
}