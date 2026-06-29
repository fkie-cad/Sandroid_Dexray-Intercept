import { JNIInvocationCallback } from "..";
import { JNIInvocationListener } from "..";
import { JNIInvocationContext } from "..";
import { JNINativeReturnValue } from "..";


class JNICallbackManager {
    private readonly callbacks: Map<string, JNIInvocationCallback>;

    public constructor () {
        this.callbacks = new Map<string, JNIInvocationCallback>();
    }

    public addCallback (
        method: string,
        callback: JNIInvocationCallback
    ): JNIInvocationListener {
        if (!this.callbacks.has(method)) {
            this.callbacks.set(method, callback);
            return new JNIInvocationListener(this.callbacks, method);
        } else {
            throw new Error(
                "Callback already exists for "
                    + method + " please detach first."
            );
        }
    }

    // CHANGED: NativeArgumentValue[] -> NativeCallbackArgumentValue[]
    // NativeArgumentValue was a frida-gum v16 global that no longer exists in v19.
    // NativeCallbackArgumentValue is the v19 equivalent, defined in @types/frida-gum@19
    // as RecursiveValuesOf<NativeCallbackArgumentTypeMap>.
    public doBeforeCallback (
        method: string,
        ctx: JNIInvocationContext, 
        args: NativeCallbackArgumentValue[]
    ): void {
        if (this.callbacks.has(method)) {
            const cb = this.callbacks.get(method);
            if (cb?.onEnter !== undefined) {
                cb.onEnter.call(ctx, args);
            }
        }
    }

    // CHANGED: NativeReturnValue -> NativeCallbackReturnValue (both occurrences)
    // Same reason: NativeReturnValue was v16, NativeCallbackReturnValue is v19.
    public doAfterCallback (
        method: string,
        ctx: JNIInvocationContext,
        retval: NativeCallbackReturnValue
    ): NativeCallbackReturnValue {
        if (this.callbacks.has(method)) {
            const cb = this.callbacks.get(method);
            if (cb?.onLeave !== undefined) {
                const wrappedRet = new JNINativeReturnValue(retval);
                cb.onLeave.call(ctx, wrappedRet);
                if (wrappedRet.get() !== retval) {
                    retval = wrappedRet.get();
                }
            }
        }
        return retval;
    }

    public clear (): void {
        this.callbacks.clear();
    }
}

export { JNICallbackManager };