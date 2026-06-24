const ARRAY_TYPE_INDEX = 1;
const TYPE_SIZE_64_BIT = 8;
const TYPE_SIZE_CHAR = 1;

/**
 * Utility helpers for converting between JVM descriptors (e.g. "I", "[I",
 * "Ljava/lang/String;"), JNI native types (e.g. jint, jstring, jintArray)
 * and Frida type strings ("int", "pointer", "double", ...), and for basic
 * size-of queries.
 *
 * Note: multi-dimensional array descriptors produced by JavaMethod
 * (e.g. "[[I") are collapsed to generic array/object pointers at the
 * JNI/Frida type level. If exact dimensionality is needed, use the
 * original JVM descriptor from JavaMethod.signature or JavaMethod.params.
 */
const Types = {
    isComplexObjectType (type: string): boolean {
        const JOBJECT = [
            "jobject",
            "jclass",
            "jweak"  
        ];

        return JOBJECT.includes(type);
    },
    sizeOf (type: string): number {
        if (type === "double" || type === "float" || type === "int64") {
            return TYPE_SIZE_64_BIT;
        } else if (type === "char") {
            return TYPE_SIZE_CHAR;
        } else {
            return Process.pointerSize;
        }
    },
    convertNativeJTypeToFridaType (jtype: string): string {
        if (jtype.endsWith("*")) {
            return "pointer";
        }
        if (jtype === "va_list") {
            return "pointer";
        }
        if (jtype === "jmethodID") {
            return "pointer";
        }
        if (jtype === "jfieldID") {
            return "pointer";
        }
        if (jtype === "va_list") {
            return "va_list";
        }
        if (jtype === "jweak") {
            jtype = "jobject";
        }
        if (jtype === "jthrowable") {
            jtype = "jobject";
        }
        if (jtype.includes("Array")) {
            jtype = "jarray";
        }
        if (jtype === "jarray") {
            jtype = "jobject";
        }
        if (jtype === "jstring") {
            jtype = "jobject";
        }
        if (jtype === "jclass") {
            jtype = "jobject";
        }
        if (jtype === "jobject") {
            return "pointer";
        }
        if (jtype === "jsize") {
            jtype = "jint";
        }
        if (jtype === "jobjectRefType") {
            // C enum (int-width); treat identically to jint
            jtype = "jint";
        }
        if (jtype === "jdouble") {
            return "double";
        }
        if (jtype === "jfloat") {
            return "float";
        }
        if (jtype === "jchar") {
            return "uint16";
        }
        if (jtype === "jboolean") {
            return "char";
        }
        if (jtype === "jlong") {
            return "int64";
        }
        if (jtype === "jint") {
            return "int";
        }
        if (jtype === "jshort") {
            return "int16";
        }
        if (jtype === "jbyte") {
            return "char";
        }

        return jtype;
    },
    convertJTypeToNativeJType (jtype: string): string {
        let result = "";
        let isArray = false;

        if (jtype.startsWith("[")) {
            isArray = true;
            jtype = jtype.substring(ARRAY_TYPE_INDEX);
        }

        if (jtype === "B") {
            result += "jbyte";
        } else if (jtype === "S") {
            result += "jshort";
        } else if (jtype === "I") {
            result += "jint";
        } else if (jtype === "J") {
            result += "jlong";
        } else if (jtype === "F") {
            result += "jfloat";
        } else if (jtype === "D") {
            result += "jdouble";
        } else if (jtype === "C") {
            result += "jchar";
        } else if (jtype === "Z") {
            result += "jboolean";
        } else if (jtype.startsWith("L")) {
            if (jtype === "Ljava/lang/String;") {
                result += "jstring";
            } else if (jtype === "Ljava/lang/Class;") {
                result += "jclass";
            } else {
                result += "jobject";
            }
        }

        if (isArray) {
            if (result === "jstring") {
                result = "jobject";
            }
            result += "Array";
        }

        return result;
    }
};

export { Types };
