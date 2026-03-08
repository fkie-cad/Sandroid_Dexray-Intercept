import JNI_ENV_METHODS from "../data/jni_env.json";

import { JNIThreadManager } from "./jni_thread_manager";
import { JavaVMInterceptor } from "./java_vm_interceptor";
import { JNIMethod } from "./jni_method";

import { ReferenceManager } from "../utils/reference_manager";
import { Types } from "../utils/types";
import { JavaMethod } from "../utils/java_method";
import { Config } from "../utils/config";

import { JNIInvocationContext } from "../";
import { JNICallbackManager } from "../internal/jni_callback_manager";

const TYPE_NAME_START = 0;
const TYPE_NAME_END = -1;
const COPY_ARRAY_INDEX = 0;
const JNI_ENV_INDEX = 0;

/**
 * Architecture-independent base class for JNIEnv interception.
 *
 * Responsibilities:
 *  - Create a shadow JNIEnv whose function table consists of
 *    per-method intercept stubs (normal and varargs).
 *  - Track per-thread JNIEnv and JavaVM pointers.
 *  - Map jmethodID → JavaMethod signatures (for decoding Java args).
 *  - Integrate JNI calls with JNICallbackManager (before/after hooks).
 *  - Delegate architecture-specific tasks to subclasses:
 *      * vararg shellcode trampoline (buildVaArgParserShellcode),
 *      * va_list decoding (setUpVaListArgExtract, extractVaListArgValue, resetVaListArgExtract).
 */
abstract class JNIEnvInterceptor {
    // Keeps allocated pages/callbacks alive for the lifetime of the script.
    protected references: ReferenceManager;

    // Tracks per-thread JNIEnv and JavaVM pointers
    protected threads: JNIThreadManager;

    // Manages user-defined “before” and “after” JNI callbacks
    protected callbackManager: JNICallbackManager;

    // Optional interceptor for JavaVM-level operations
    protected javaVMInterceptor: JavaVMInterceptor | null;

    // Pointer to the shadow JNIEnv (proxy function table)
    protected shadowJNIEnv: NativePointer;

    /**
     * Maps jmethodID (as string) → JavaMethod (parsed signature).
     * Populated when GetMethodID / GetStaticMethodID are intercepted.
     */
    protected methods: Map<string, JavaMethod>;

    /**
     * Per-method cache of main varargs callbacks:
     * methodId string -> NativeCallback for that JNI call.
     */
    protected fastMethodLookup: Map<string, NativeCallback>;

    /**
     * Per-thread backtrace captured just before a varargs JNI call is
     * handled by the shellcode trampoline.
     */
    protected vaArgsBacktraces: Map<number, NativePointer[]>;

    /**
     * Constructs a new base JNIEnv interceptor instance.
     *
     * @param references      Global reference manager.
     * @param threads         JNI thread manager.
     * @param callbackManager Manager for before/after JNI callbacks.
     */
    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        callbackManager: JNICallbackManager
    ) {
        this.references = references;
        this.threads = threads;
        this.callbackManager = callbackManager;

        this.javaVMInterceptor = null;

        this.shadowJNIEnv = NULL;
        this.methods = new Map<string, JavaMethod>();
        this.fastMethodLookup = new Map<string, NativeCallback>();
        this.vaArgsBacktraces = new Map<number, NativePointer[]>();
    }

    /**
     * Returns true if a shadow JNIEnv has already been created.
     */
    public isInitialised (): boolean {
        return !this.shadowJNIEnv.equals(NULL);
    }

    /**
     * Returns the pointer to the shadow JNIEnv (proxy function table).
     */
    public get (): NativePointer {
        return this.shadowJNIEnv;
    }

    /**
     * Creates the shadow JNIEnv for the current thread.
     *
     * - Clones the layout of the original JNIEnv vtable.
     * - For each slot, installs a small stub whose implementation is
     *   either a normal or varargs interceptor.
     * - The real JNI function pointers (methodPtr) are kept in the
     *   closures of those interceptors and invoked via NativeFunction;
     *   the shadow table itself only ever contains intercept stubs.
     * - Stores the new JNIEnv* pointer in shadowJNIEnv.
     *
     * @returns Pointer to the new JNIEnv* to be returned to native code.
     */
    public create (): NativePointer {
        const END_INDEX = 1;
        const threadId = Process.getCurrentThreadId();
        const jniEnv = this.threads.getJNIEnv(threadId);
        const jniEnvOffset = 4; // first methods to intercept
        const jniEnvLength = 232; // number of methods in table

        // Allocate space for new JNIEnv function table.
        const newJNIEnvStruct = Memory.alloc(Process.pointerSize * jniEnvLength);
        this.references.add(newJNIEnvStruct);

        // Allocate JNIEnv* that points to the table.
        const newJNIEnv = Memory.alloc(Process.pointerSize);
        newJNIEnv.writePointer(newJNIEnvStruct);
        this.references.add(newJNIEnv);

        // For each method slot, install a normal or varargs interceptor
        for (let i = jniEnvOffset; i < jniEnvLength; i++) {
            const method = JNI_ENV_METHODS[i];
            const offset = i * Process.pointerSize;
            const jniEnvStruct = jniEnv.readPointer();
            const methodAddr = jniEnvStruct.add(offset).readPointer();

            // Last argument type determines whether this is a varargs "..."
            if (method.args[method.args.length - END_INDEX] === "...") {
                const callback = this.createJNIVarArgIntercept(i, methodAddr);
                const trampoline = this.createStubFunction();
                this.references.add(trampoline);
                // Ensure CpuContext is populated for the callback
                Interceptor.replace(trampoline, callback);
                newJNIEnvStruct.add(offset).writePointer(trampoline);
            } else {
                const callback = this.createJNIIntercept(i, methodAddr);
                const trampoline = this.createStubFunction();
                this.references.add(trampoline);
                // Ensure CpuContext is populated for the callback
                Interceptor.replace(trampoline, callback);
                newJNIEnvStruct.add(offset).writePointer(trampoline);
            }
        }

        this.shadowJNIEnv = newJNIEnv;

        return newJNIEnv;
    }

    /**
     * Sets the JavaVM interceptor to be used when handling GetJavaVM
     * and JavaVM-related operations.
     */
    public setJavaVMInterceptor (javaVMInterceptor: JavaVMInterceptor): void {
        this.javaVMInterceptor = javaVMInterceptor;
    }

    /**
     * Creates a stub function used as an Interceptor target.
     *
     * The default implementation is a no-op NativeCallback that
     * immediately returns. Architecture-specific subclasses may override
     * this (e.g. to emit a minimal RET/POP PC stub in assembly).
     */
    public createStubFunction (): NativeCallback {
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        return new NativeCallback((): void => { }, "void", []);
    }

    /**
     * Creates the vararg interceptor for a JNI method with "..." in its
     * signature.
     *
     * - Allocates an executable page (`text`) and a data page (`data`).
     * - Creates the initial parser callback (see createJNIVarArgInitialCallback).
     * - Emits architecture-specific shellcode that:
     *     1. captures the original call context,
     *     2. calls the parser to get the main callback pointer,
     *     3. calls the main callback,
     *     4. returns to the original caller.
     * - Attaches an Interceptor to `text` to capture a backtrace before
     *   the shellcode modifies registers.
     *
     * @param id        Index into JNI_ENV_METHODS.
     * @param methodPtr Address of the real JNI function.
     * @returns Pointer to the shellcode entry (stored in shadowJNIEnv).
     */
    protected createJNIVarArgIntercept (
        id: number,
        methodPtr: NativePointer
    ): NativePointer {
        const self = this;
        const method = JNI_ENV_METHODS[id];

        const text = Memory.alloc(Process.pageSize);
        const data = Memory.alloc(Process.pageSize);

        this.references.add(text);
        this.references.add(data);

        // JS-level parser that will be called by the shellcode
        const vaArgsCallback = this.createJNIVarArgInitialCallback(
            method, methodPtr
        );

        this.references.add(vaArgsCallback);

        // Emit arch-specific trampoline shellcode
        self.buildVaArgParserShellcode(text, data, vaArgsCallback);

        const config = Config.getInstance();

        // Attach to the shellcode entry to capture a backtrace
        // before registers are clobbered
        Interceptor.attach(text, function (this: InvocationContext): void {
            let backtraceType = Backtracer.ACCURATE;
            if (config.backtrace === "fuzzy") {
                backtraceType = config.backtrace;
            }
            self.vaArgsBacktraces.set(
                this.threadId, Thread.backtrace(this.context, backtraceType)
            );
        });

        return text;
    }

    /**
     * Expands a trailing va_list / jvalue* argument into explicit Java
     * arguments, producing a cloned argument array with all Java args
     * appended.
     *
     * Used by non-vararg JNI functions that take va_list/jvalue* (e.g.
     * the "V" and "A" JNI variants).
     */
    private addJavaArgsForJNIIntercept (
        method: JNIMethod,
        args: NativeArgumentValue[]
    ): NativeArgumentValue[] {
        const LAST_INDEX = -1;
        const FIRST_INDEX = 0;
        const METHOD_ID_INDEX = 2;
        const NON_VIRTUAL_METHOD_ID_INDEX = 3;
        let methodIndex = METHOD_ID_INDEX;

        // Nonvirtual* JNI methods use a different index for jmethodID
        if (method.name.includes("Nonvirtual")) {
            methodIndex = NON_VIRTUAL_METHOD_ID_INDEX;
        }
        const lastParamType = method.args.slice(LAST_INDEX)[FIRST_INDEX];

        // If no va_list/jvalue* trailing argument, nothing to expand
        if (!["va_list", "jvalue*"].includes(lastParamType)) {
            return args.slice(COPY_ARRAY_INDEX);
        }

        const clonedArgs = args.slice(COPY_ARRAY_INDEX);
        const midPtr = args[methodIndex] as NativePointer;

        if (!this.methods.has(midPtr.toString())) {
            send({
                type: "error",
                message: "Failed to find corresponding method ID " +
                    "for method \"" + method.name + "\" call."
            });
            return args.slice(COPY_ARRAY_INDEX);
        }

        // JavaMethod contains the Java-side parameter types
        const javaMethod = this.methods.get(midPtr.toString()) as JavaMethod;
        const nativeJTypes = javaMethod.nativeParams;

        // Pointer to va_list or jvalue* (last argument)
        const readPtr = args.slice(LAST_INDEX)[FIRST_INDEX] as NativePointer;

        // For va_list, initialize architecture-specific extraction state
        if (lastParamType === "va_list") {
            this.setUpVaListArgExtract(readPtr);
        }

        // size of each jvalue entry
        const UNION_SIZE = 8;
        for (let i = 0; i < nativeJTypes.length; i++) {
            const type = Types.convertNativeJTypeToFridaType(nativeJTypes[i]);
            let val = undefined;
            if (lastParamType === "va_list") {
                // For va_list, delegate to arch-specific extractor
                const currentPtr = this.extractVaListArgValue(javaMethod, i);
                val = this.readValue(currentPtr, type, true);
            } else {
                // For jvalue*, read from the jvalue array
                val = this.readValue(readPtr.add(UNION_SIZE * i), type);
            }

            clonedArgs.push(val);
        }

        if (lastParamType === "va_list") {
            this.resetVaListArgExtract();
        }

        return clonedArgs;
    }

    /**
     * Handles the result of GetMethodID/GetStaticMethodID by storing
     * the mapping from returned jmethodID to its JavaMethod signature.
     */
    private handleGetMethodResult (
        args: NativeArgumentValue[],
        ret: NativeReturnValue
    ): void {
        const SIG_INDEX = 3;
        const signature = (args[SIG_INDEX] as NativePointer).readCString();

        if (signature !== null) {
            const methodSig = new JavaMethod(signature);
            this.methods.set((ret as NativePointer).toString(), methodSig);
        }
    }

    /**
     * Handles the result of GetJavaVM by installing or returning an
     * intercepted JavaVM pointer via JavaVMInterceptor.
     */
    private handleGetJavaVM (
        args: NativeArgumentValue[],
        ret: NativeReturnValue
    ): void {
        if (this.javaVMInterceptor !== null) {
            const JNI_OK = 0;
            const JAVA_VM_INDEX = 1;

            if (ret === JNI_OK) {
                const javaVMPtr = args[JAVA_VM_INDEX] as NativePointer;
                this.threads.setJavaVM(javaVMPtr.readPointer());

                let javaVM = undefined;
                if (!this.javaVMInterceptor.isInitialised()) {
                    javaVM = this.javaVMInterceptor.create();
                } else {
                    javaVM = this.javaVMInterceptor.get();
                }

                // Replace the JavaVM* out-param with the shadow JavaVM
                javaVMPtr.writePointer(javaVM);
            }
        }
    }

    /**
     * Handles RegisterNatives by:
     *  - iterating over the JNI method array;
     *  - attaching interceptors to each native method;
     *  - on entry of a native method, swapping the real JNIEnv* for
     *    the shadow JNIEnv*, so subsequent JNI calls go through us.
     */
    private handleRegisterNatives (args: NativeArgumentValue[]): void {
        const METHOD_INDEX = 2;
        const SIZE_INDEX = 3;
        const JNI_METHOD_SIZE = 3;

        const self = this;

        const methods = args[METHOD_INDEX] as NativePointer;
        const size = args[SIZE_INDEX] as number;
        for (let i = 0; i < size * JNI_METHOD_SIZE; i += JNI_METHOD_SIZE) {
            const methodsPtr = methods;

            const namePtr = methodsPtr
                .add(i * Process.pointerSize)
                .readPointer();
            const name = namePtr.readCString();

            const sigOffset = 1;
            const sigPtr = methodsPtr
                .add((i + sigOffset) * Process.pointerSize)
                .readPointer();
            const sig = sigPtr.readCString();

            const addrOffset = 2;
            const addr = methodsPtr
                .add((i + addrOffset) * Process.pointerSize)
                .readPointer();

            if (name === null || sig === null) {
                continue;
            }
            // Attach to each native method to swap JNIEnv
            Interceptor.attach(addr, {
                onEnter (args: NativeArgumentValue[]): void {
                    const check = name + sig;
                    const config = Config.getInstance();
                    const EMPTY_ARRAY_LEN = 0;

                    // Optional include/exclude filtering by name+sig
                    if (config.includeExport.length > EMPTY_ARRAY_LEN) {
                        const included = config.includeExport.filter(
                            (i: string): boolean => check.includes(i)
                        );
                        if (included.length === EMPTY_ARRAY_LEN) {
                            return;
                        }
                    }
                    if (config.excludeExport.length > EMPTY_ARRAY_LEN) {
                        const excluded = config.excludeExport.filter(
                            (e: string): boolean => check.includes(e)
                        );
                        if (excluded.length > EMPTY_ARRAY_LEN) {
                            return;
                        }
                    }

                    // Track per-thread JNIEnv* if not already tracked
                    if (!self.threads.hasJNIEnv(this.threadId)) {
                        self.threads.setJNIEnv(
                            this.threadId, args[JNI_ENV_INDEX] as NativePointer
                        );
                    }
                    // Replace JNIEnv* with the shadow JNIEnv
                    args[JNI_ENV_INDEX] = self.shadowJNIEnv;
                }
            });
        }
    }

    /**
     * Dispatches post-processing logic based on the JNI method name
     * (e.g. GetMethodID, GetJavaVM, RegisterNatives).
     */
    private handleJNIInterceptResult (
        method: JNIMethod,
        args: NativeArgumentValue[],
        ret: NativeReturnValue
    ): void {
        const name = method.name;

        if (["GetMethodID", "GetStaticMethodID"].includes(name)) {
            this.handleGetMethodResult(args, ret);
        } else if (method.name === "GetJavaVM") {
            this.handleGetJavaVM(args, ret);
        } else if (method.name === "RegisterNatives") {
            this.handleRegisterNatives(args);
        }
    }

    /**
     * Creates a normal (non-vararg) interceptor for a given JNI method.
     *
     * The generated NativeCallback:
     *  - replaces env with the real JNIEnv* for this thread;
     *  - optionally expands trailing va_list/jvalue* arguments using
     *    arch-specific helpers (addJavaArgsForJNIIntercept);
     *  - builds a JNIInvocationContext and runs before/after callbacks;
     *  - calls the real JNI function via NativeFunction(methodPtr, ...);
     *  - performs any special post-processing needed for this method.
     *
     * @param id        Index into JNI_ENV_METHODS.
     * @param methodPtr Address of the real JNI function.
     */
    private createJNIIntercept (
        id: number,
        methodPtr: NativePointer
    ): NativeCallback {
        const self = this;
        const METHOD_ID_INDEX = 2;
        const method = JNI_ENV_METHODS[id];
        const config = Config.getInstance();

        const paramTypes = method.args.map(
            (t: string): string => Types.convertNativeJTypeToFridaType(t)
        );
        const retType = Types.convertNativeJTypeToFridaType(method.ret);

        const nativeFunction = new NativeFunction(methodPtr, retType, paramTypes);
        const nativeCallback = new NativeCallback(function (
            this: InvocationContext
        ): NativeReturnValue {
            const threadId = this.threadId;
            const jniEnv = self.threads.getJNIEnv(threadId);
            const args: NativeArgumentValue[] = [].slice.call(arguments);

            // Replace env argument with the real JNIEnv* for this thread
            args[JNI_ENV_INDEX] = jniEnv;

            // Optionally expand trailing va_list/jvalue* into explicit args
            const clonedArgs = self.addJavaArgsForJNIIntercept(method, args);

            const ctx: JNIInvocationContext = {
                jniAddress: methodPtr,
                threadId: threadId,
                methodDef: method,
            };

            // Optional backtrace
            if (config.backtrace === "accurate") {
                ctx.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
            } else if (config.backtrace === "fuzzy") {
                ctx.backtrace = Thread.backtrace(this.context, Backtracer.FUZZY);
            }

            // If argument list changed, attach JavaMethod metadata
            if (args.length !== clonedArgs.length) {
                // eslint-disable-next-line @typescript-eslint/no-base-to-string
                const key = args[METHOD_ID_INDEX].toString();
                ctx.javaMethod = self.methods.get(key);
            }

            // User-defined before-callback sees the expanded arguments
            self.callbackManager.doBeforeCallback(method.name, ctx, clonedArgs);

            // Call the real JNI function with the original (env-fixed) args
            let ret = nativeFunction.apply(null, args);

            // User-defined after-callback
            ret = self.callbackManager.doAfterCallback(method.name, ctx, ret);

            // Handle post-processing for GetMethodID/GetJavaVM/RegisterNatives
            self.handleJNIInterceptResult(method, args, ret);

            return ret;
        } as NativeCallbackImplementation, retType, paramTypes);

        this.references.add(nativeCallback);

        return nativeCallback;
    }

    /**
     * Creates the per-method main callback used for JNI methods with
     * "..." (varargs).
     *
     * The mainCallback is called from the architecture-specific shellcode
     * trampolin with explicit, typed Java arguments (no va_list);
     * 
     * This function:
     *  - replaces the shadow env pointer with the real JNIEnv*;
     *  - attaches backtrace and JavaMethod metadata to invocation context;
     *  - runs before/after callbacks;
     *  - calls the real JNI function via NativeFunction(methodPtr, ...);
     *  - clears the stored backtrace.
     * 
     * Note: Unlike non-varargs interceptors, this callback cannot rely on
     * Frida's InvocationContext for threadId, as the shellcode calls it
     * directly without going through Interceptor.attach/replace. Instead,
     * Process.getCurrentThreadId() is used to retrieve the thread ID.
     *
     * @param method             JNIMethod definition for this JNI call.
     * @param methodPtr          Address of the real JNI function.
     * @param initialparamTypes  Full C parameter list for NativeFunction
     *                           including "..." marker for variadic calls
     *                           (env, obj, mid, "...", Java args), e.g.
     *                           ["pointer", "pointer", "pointer", "...", "int", "double"]
     * @param mainParamTypes     Parameter list for the main callback
     *                           (env, obj, mid, Java args), no "..." marker
     * @param retType            Frida return type for this JNI call.
     * @returns NativeCallback   that handles the varargs JNI invocation.
     */
    private createJNIVarArgMainCallback (
        method: JNIMethod,
        methodPtr: NativePointer,
        initialparamTypes: string[],
        mainParamTypes: string[],
        retType: string
    ): NativeCallback {
        const self = this;

        const mainCallback = new NativeCallback(function (): NativeReturnValue {
            const METHOD_ID_INDEX = 2;
            // Retrieve thread ID directly since shellcode does not provide InvocationContext
            const threadId = Process.getCurrentThreadId();
            
            const args: NativeArgumentValue[] = [].slice.call(arguments);
            const jniEnv = self.threads.getJNIEnv(threadId);
            const key = args[METHOD_ID_INDEX].toString();
            const jmethod = self.methods.get(key);

            // Replace shadow env with real per-thread JNIEnv
            args[JNI_ENV_INDEX] = jniEnv;

            const ctx: JNIInvocationContext = {
                backtrace: self.vaArgsBacktraces.get(threadId),
                jniAddress: methodPtr,
                threadId: threadId,
                methodDef: method,
                javaMethod: jmethod
            };

            self.callbackManager.doBeforeCallback(method.name, ctx, args);

            // Call real JNI varargs function with full C signature including "..."
            let ret = new NativeFunction(
                methodPtr,
                retType,
                initialparamTypes
            ).apply(null, args);

            ret = self.callbackManager.doAfterCallback(method.name, ctx, ret);

            self.vaArgsBacktraces.delete(threadId);

            return ret;
        }, retType, mainParamTypes);

        return mainCallback;
    }

    /**
     * Creates the initial parser callback used by the varargs shellcode
     * trampoline
     * 
     * The parser:
     *  - is called once per JNI varargs call from the shellcode;
     *  - inspects the jmethodID to look up the JavaMethod metadata;
     *  - checks if a mainCallback already exists for this methodID (fast path);
     *  - if a mainCallback already exists for this methodID, returns it;
     *  - otherwise, builds a new mainCallback with the correct C and
     *    JS parameter lists based on the Java method signature, caches it,
     *    and returns it.
     *
     * Type list construction:
     *  - callbackParams: Parameter types for the mainCallback (JS-level).
     *    Uses explicit types for all Java arguments with C vararg promotions
     *    applied (float → double).
     *  - originalParams: Parameter types for the NativeFunction call to the
     *    real JNI function. Includes the "..." marker to indicate variadic
     *    calling convention, followed by the promoted Java argument types.
     * 
     * @param method            JNI method definition from JNI_ENV_METHODS.
     * @param methodPtr         Address of the real JNI function.
     * @returns NativeCallback  that the shellcode calls to obtain the
     *                          mainCallback pointer for a specific methodID.
     */
    private createJNIVarArgInitialCallback (
        method: JNIMethod,
        methodPtr: NativePointer
    ): NativeCallback {
        const self = this;

        const vaArgsCallback = new NativeCallback(function (): NativeReturnValue {
            const METHOD_ID_INDEX = 2;
            const methodId = (arguments[METHOD_ID_INDEX] as NativeArgumentValue).toString();
            const javaMethod = self.methods.get(methodId) as JavaMethod;

            // Fast path: return cached mainCallback if available
            if (self.fastMethodLookup.has(methodId)) {
                return self.fastMethodLookup.get(methodId) as NativeReturnValue;
            }
            
            // Build parameter lists for mainCallback and NativeFunction
            // Base parameters: JNIEnv*, jobject/jclass, jmethodID
            const originalParams = method.args
                .slice(TYPE_NAME_START, TYPE_NAME_END)
                .map((t: string): string => Types.convertNativeJTypeToFridaType(t));
            
            const callbackParams = originalParams.slice(COPY_ARRAY_INDEX);

            // Mark NativeFunction signature as variadic
            originalParams.push("...");

            // Append Java argument types with C vararg promotions
            // float is promoted to double in C variadic functions
            javaMethod.fridaParams.forEach((p: string): void => {
                const promotedType = (p === "float") ? "double" : p;
                callbackParams.push(promotedType);  // mainCallback sees promoted types
                originalParams.push(promotedType);  // NativeFunction also uses promoted types!
            });

            const retType = Types.convertNativeJTypeToFridaType(method.ret);

            // Create and cache the mainCallback for this methodID
            const mainCallback = self.createJNIVarArgMainCallback(
                method, methodPtr, originalParams, callbackParams, retType
            );
            self.references.add(mainCallback);

            self.fastMethodLookup.set(methodId, mainCallback);

            return mainCallback;
        }, "pointer", ["pointer", "pointer", "pointer"]);

        return vaArgsCallback;
    }

    /**
     * Reads a value of the given Frida type from a NativePointer.
     *
     * @param currentPtr Pointer to the value in memory.
     * @param type       Frida type (e.g. "int", "double", "pointer").
     * @param extend     For floats, if true, read as double (vararg promotion).
     */
    private readValue (
        currentPtr: NativePointer,
        type: string,
        extend?: boolean
    ): NativeArgumentValue {
        let val: NativeArgumentValue = NULL;

        if (type === "char") {
            val = currentPtr.readS8();
        } else if (type === "int16") {
            val = currentPtr.readS16();
        } else if (type === "uint16") {
            val = currentPtr.readU16();
        } else if (type === "int") {
            val = currentPtr.readS32();
        } else if (type === "int64") {
            val = currentPtr.readS64();
        } else if (type === "float") {
            if (extend === true) {
                // For varargs, float is promoted to double
                val = currentPtr.readDouble();
            } else {
                val = currentPtr.readFloat();
            }
        } else if (type === "double") {
            val = currentPtr.readDouble();
        } else if (type === "pointer") {
            val = currentPtr.readPointer();
        }

        return val;
    }

    // ---- Architecture-specific hooks that subclasses must implement ----

    /**
     * Emits the architecture-specific shellcode that:
     *  - saves the original call context (registers, return address);
     *  - calls `parser` to obtain the main vararg callback pointer;
     *  - restores the original registers;
     *  - calls the returned main callback with the original ABI;
     *  - jumps back to the original return address.
     */
    protected abstract buildVaArgParserShellcode(
        text: NativePointer,
        data: NativePointer,
        parser: NativeCallback
    ): void;

    /**
     * Initializes internal state for extracting arguments from a va_list
     * according to the platform ABI (x86, x86-64, ARM, ARM64, ...).
     */
    protected abstract setUpVaListArgExtract(vaList: NativePointer): void;

    /**
     * Returns a pointer to the storage location of the index-th argument
     * in the current va_list, according to the platform ABI.
     */
    protected abstract extractVaListArgValue(
        method: JavaMethod,
        index: number
    ): NativePointer;

    /**
     * Resets internal state used for varargs extraction.
     */
    protected abstract resetVaListArgExtract(): void;
}

export { JNIEnvInterceptor };
