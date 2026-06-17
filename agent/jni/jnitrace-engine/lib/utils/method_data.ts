import { JNIMethod } from "../jni/jni_method";

import { JavaMethod } from "./java_method";

/**
 * Container for a single JNI API invocation.
 *
 * Combines:
 *  - the JNI method definition (JNIMethod),
 *  - optional JavaMethod metadata (parsed Java signature),
 *  - the raw argument list as seen by the interceptor, and
 *  - the raw return value from the JNI call.
 *
 * Higher-level components (e.g. frontends, loggers) can use this to
 * format, filter or transport trace events without needing direct
 * access to the low-level interception logic.
 */
class MethodData {
    private readonly _method: JNIMethod;

    private readonly _jmethod: JavaMethod | undefined;

    private readonly _args: NativeArgumentValue[];

    private readonly _jparams: string[];

    private readonly _ret: NativeReturnValue;

    public constructor (
        method: JNIMethod,
        args: NativeArgumentValue[],
        ret: NativeReturnValue,
        jmethod?: JavaMethod
    ) {
        this._method = method;
        this._jmethod = jmethod;
        this._args = args;
        this._ret = ret;
        if (jmethod === undefined) {
            this._jparams = [];
        } else {
            this._jparams = jmethod.nativeParams;
        }
    }

    public get method (): JNIMethod {
        return this._method;
    }

    public get javaMethod (): JavaMethod | undefined {
        return this._jmethod;
    }

    public get args (): NativeArgumentValue[] {
        return this._args;
    }

    public getArgAsPtr (i: number): NativePointer {
        return this._args[i] as NativePointer;
    }

    public getArgAsNum (i: number): number {
        return this._args[i] as number;
    }

    public get jParams (): string[] {
        return this._jparams;
    }

    public get ret (): NativeReturnValue {
        return this._ret;
    }
}

export { MethodData };