import { JNIThreadManager } from "./jni_thread_manager";
import { JNIEnvInterceptor } from "./jni_env_interceptor";
import { JavaVM } from "./java_vm";

import { Types } from "../utils/types";
import { ReferenceManager } from "../utils/reference_manager";
import { JNICallbackManager } from "../internal/jni_callback_manager";
import { JNIInvocationContext } from "../";
import { Config } from "../utils/config";

const JAVA_VM_INDEX = 0;
const JNI_OK = 0;
const JNI_ENV_INDEX = 1;

class JavaVMInterceptor {
    private readonly references: ReferenceManager;
    private readonly threads: JNIThreadManager;
    private readonly jniEnvInterceptor: JNIEnvInterceptor;
    private readonly callbackManager: JNICallbackManager;
    private shadowJavaVM: NativePointer;

    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        jniEnvInterceptor: JNIEnvInterceptor,
        callbackManager: JNICallbackManager
    ) {
        this.references = references;
        this.threads = threads;
        this.jniEnvInterceptor = jniEnvInterceptor;
        this.callbackManager = callbackManager;
        this.shadowJavaVM = NULL;
    }

    public isInitialised (): boolean {
        return !this.shadowJavaVM.isNull();
    }

    public get (): NativePointer {
        return this.shadowJavaVM;
    }

    public create (): NativePointer {
        const javaVMOffset = 3;
        const javaVMLength = 8;
        const javaVM = this.threads.getJavaVM();

        const newJavaVMStruct = Memory.alloc(Process.pointerSize * javaVMLength);
        this.references.add(newJavaVMStruct);

        const newJavaVM = Memory.alloc(Process.pointerSize);
        newJavaVM.writePointer(newJavaVMStruct);

        for (let i = javaVMOffset; i < javaVMLength; i++) {
            const offset = i * Process.pointerSize;
            const javaVMStruct = javaVM.readPointer();
            const methodAddr = javaVMStruct.add(offset).readPointer();

            const callback = this.createJavaVMIntercept(i, methodAddr);
            const trampoline = this.jniEnvInterceptor.createStubFunction();
            this.references.add(trampoline);
            // ensure the CpuContext will be populated
            Interceptor.replace(trampoline, callback);
            newJavaVMStruct.add(offset).writePointer(trampoline);
        }

        this.shadowJavaVM = newJavaVM;
        return newJavaVM;
    }

    private createJavaVMIntercept (
        id: number,
        methodAddr: NativePointer
    ): NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]> {
        const self = this;
        const method = JavaVM.getInstance().methods[id];
        const config = Config.getInstance();

        const fridaArgs = method.args.map(
            (a: string): string => Types.convertNativeJTypeToFridaType(a)
        );
        const fridaRet = Types.convertNativeJTypeToFridaType(method.ret);


        // CHANGED: cast type strings to v19 NativeFunction generic type parameters.
        // Same pattern as jni_env_interceptor.ts; types are computed dynamically
        // from JavaVM method definitions; cast asserts all strings are valid types.
        const nativeFunction = new NativeFunction(
            methodAddr,
            fridaRet as NativeFunctionReturnType,
            fridaArgs as NativeFunctionArgumentType[]
        ) as NativeFunction<NativeFunctionReturnValue, NativeFunctionArgumentValue[]>;

        const nativeCallback = new NativeCallback(
            // CHANGED: this: InvocationContext -> this: CallbackContext | InvocationContext
            // CHANGED: rest params replace [].slice.call(arguments)
            // CHANGED: this.threadId -> Process.getCurrentThreadId()
            function (
                this: CallbackContext | InvocationContext,
                ...callArgs: NativeCallbackArgumentValue[]
            ): NativeCallbackReturnValue {
                // CHANGED: Process.getCurrentThreadId() replaces this.threadId.
                // this.threadId is not available on CallbackContext; it only exists
                // on InvocationContext (Interceptor.attach callbacks). NativeCallback
                // bodies receive CallbackContext, so getCurrentThreadId() is correct.
                const threadId = Process.getCurrentThreadId();
                const javaVM = self.threads.getJavaVM();

                const localArgs: NativeCallbackArgumentValue[] = callArgs;
                localArgs[JAVA_VM_INDEX] = javaVM;

                const ctx: JNIInvocationContext = {
                    methodDef: method,
                    jniAddress: methodAddr,
                    threadId: threadId
                };
                
                if (config.backtrace === "accurate") {
                    ctx.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                } else if (config.backtrace === "fuzzy") {
                    ctx.backtrace = Thread.backtrace(this.context, Backtracer.FUZZY);
                }

                self.callbackManager.doBeforeCallback(method.name, ctx, localArgs);

                let ret = nativeFunction.apply(
                    null,
                    localArgs as NativeFunctionArgumentValue[]
                ) as NativeCallbackReturnValue;

                ret = self.callbackManager.doAfterCallback(method.name, ctx, ret);

                if (method.name === "GetEnv" ||
                        method.name === "AttachCurrentThread" ||
                        method.name === "AttachCurrentThreadAsDaemon"
                ) {

                    if (ret === JNI_OK) {
                        self.threads.setJNIEnv(
                            threadId, 
                            (localArgs[JNI_ENV_INDEX] as NativePointer).readPointer()
                        );
                    }

                    let jniEnv: NativePointer;
                    if (!self.jniEnvInterceptor.isInitialised()) {
                        jniEnv = self.jniEnvInterceptor.create();
                    } else {
                        jniEnv = self.jniEnvInterceptor.get();
                    }
                    // CHANGED: explicit cast; localArgs[1] is JNIEnv** (pointer)
                    (localArgs[JNI_ENV_INDEX] as NativePointer).writePointer(jniEnv);
                }

                return ret;
            } as NativeCallbackImplementation<NativeCallbackReturnValue, NativeCallbackArgumentValue[]>,
            fridaRet as NativeCallbackReturnType,
            fridaArgs as NativeCallbackArgumentType[]
        );

        this.references.add(nativeCallback);
        return nativeCallback;
    }
}

export { JavaVMInterceptor };
