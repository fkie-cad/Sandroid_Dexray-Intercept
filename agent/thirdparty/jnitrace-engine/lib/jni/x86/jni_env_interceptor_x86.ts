import { JNIEnvInterceptor } from "../jni_env_interceptor";
import { JNIThreadManager } from "../jni_thread_manager";

import { ReferenceManager } from "../../utils/reference_manager";
import { Types } from "../../utils/types";
import { JavaMethod } from "../../utils/java_method";
import { JNICallbackManager } from "../../internal/jni_callback_manager";

/**
 * x86 (32‑bit) implementation of the JNIEnv interceptor.
 *
 * provides the architecture-specific logic for:
 *  - building a small x86 trampoline that intercepts JNI varargs
 *    calls, captures the original return address, and dispatches
 *    through a dynamically constructed callback; and
 *  - decoding the x86 va_list layout, which is effectively a
 *    linear pointer into a contiguous vararg area.
 */
class JNIEnvInterceptorX86 extends JNIEnvInterceptor {
    /**
     * Pointer to the current va_list used by the JNI “V” call.
     * Treated as a linear block of arguments.
     */
    private vaList: NativePointer;

    /**
     * Current byte offset into vaList pointing to the next
     * argument to be read.
     */
    private vaListOffset: number;

    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        callbackManager: JNICallbackManager
    ) {
        super(references, threads, callbackManager);

        this.vaList = NULL;
        this.vaListOffset = 0;
    }

    /**
     * Generates an x86 trampoline in the given executable page.
     *
     * Layout:
     *   - text          : code emitted by X86Writer (at `text + 0`).
     *   - text+0x400    : parser callback pointer (written here).
     *   - text+0x408    : saved original return address.
     *
     * The trampoline does:
     *   1. Pop the original return address into EAX and save it
     *      at text+0x408.
     *   2. Call the `parser` callback (NativeCallback) using the
     *      original stack layout (env, obj, methodID, va_list, ...).
     *      The parser returns the main JNI callback pointer in EAX.
     *   3. Call the main callback in EAX, again with the original
     *      stack arguments. The JS implementation fixes env and
     *      calls the real JNI function.
     *   4. Jump to the saved original return address, effectively
     *      returning to the JNI caller as if the original function
     *      had just executed `ret`.
     *
     * @param text   Executable page where the trampoline code
     *               will be emitted.
     * @param _      Unused data pointer (x86 uses the same page
     *               for code and data at a fixed offset).
     * @param parser NativeCallback that analyzes the JNI varargs
     *               call and returns a pointer to the main
     *               callback that should handle it.
     */
    protected buildVaArgParserShellcode (
        text: NativePointer,
        _: NativePointer,
        parser: NativeCallback
    ): void {
        // Store parser pointer at text + 0x400 (not actually used by
        // this implementation, but kept for consistency with other
        // architectures).
        const DATA_OFFSET = 0x400;
        text.add(DATA_OFFSET).writePointer(parser);

        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new X86Writer(code, { pc: text });
            // On 32-bit x86, pointerSize = 4, so:
            //   dataOffset      = 0x400 + 4 = 0x404
            //   dataOffset + 4  = 0x408
            //
            // use text+0x408 to store the original return address.
            const dataOffset = DATA_OFFSET + Process.pointerSize;

            // At entry (before any prologue), stack layout is:
            //   [esp+0]  = original return address to JNI caller
            //   [esp+4]  = env
            //   [esp+8]  = obj
            //   [esp+12] = methodID
            //   [esp+16] = va_list
            //
            // pop eax
            //   eax = original return address
            //   esp -> env (first argument)
            cw.putPopReg("eax");

            // Save the original return address in the data area:
            //   mov [text + 0x408], eax
            cw.putMovNearPtrReg(
                text.add(dataOffset + Process.pointerSize), "eax"
            );

            // Call the parser callback:
            //
            //   call parser
            //
            // parser(env, obj, methodID, va_list) will typically ignore
            // env, and only use methodID to construct a mainCallback.
            // It returns the mainCallback pointer in EAX.
            cw.putCallAddress(parser);

            // Call the main callback whose address is now in EAX:
            //
            //   call eax
            //
            // The stack still holds the original arguments:
            //   [esp+4] env, [esp+8] obj, [esp+12] methodID, [esp+16] va_list
            //
            // The TS implementation of mainCallback overwrites args[0]
            // with the correct JNIEnv for this thread, then calls the
            // real JNI function via NativeFunction(methodPtr, ...).
            cw.putCallReg("eax");

            // Finally, jump to the original return address:
            //
            //   jmp dword ptr [text + 0x408]
            //
            // This indirect near jump loads the saved return address
            // and sets EIP to it. Stack pointer is the same as after
            // an ordinary `ret` (because we popped the return address
            // at entry), so from the caller’s point of view the call
            // behaved like the original JNI function.
            cw.putJmpNearPtr(text.add(dataOffset + Process.pointerSize));

            cw.flush();
        });
    }
    
     /**
     * Initializes internal state for extracting arguments from an
     * x86 va_list. Here va_list is treated as a linear block of
     * arguments laid out sequentially in memory.
     *
     * @param vaList Pointer to the va_list structure passed to
     *               the JNI “V” variant function.
     */
    protected setUpVaListArgExtract (vaList: NativePointer): void {
        this.vaList = vaList;
        this.vaListOffset = 0;
    }

     /**
     * Returns a pointer to the storage location of the paramId-th
     * Java argument in the current varargs list.
     *
     * On 32-bit x86, va_list is effectively a pointer into the
     * vararg area, and va_arg() advances it by sizeof(T) each time.
     * This implementation matches that model: it returns:
     *
     *   vaList + currentOffset
     *
     * and then advances currentOffset by the ABI size of the
     * parameter type.
     *
     * The caller is responsible for reading the value with the
     * appropriate type (see readValue()).
     *
     * @param method  JavaMethod describing the Java-side parameter
     *                types for this invocation.
     * @param paramId Zero-based index of the parameter within the
     *                Java argument list.
     */
    protected extractVaListArgValue (
        method: JavaMethod,
        paramId: number
    ): NativePointer {
        let currentPtr = this.vaList.add(this.vaListOffset);
        this.vaListOffset += Types.sizeOf(method.fridaParams[paramId]);
        return currentPtr;
    }

    /**
     * Resets internal state used for varargs extraction so that
     * subsequent uses do not retain offsets or pointers from the
     * previous va_list.
     */
    protected resetVaListArgExtract (): void {
        this.vaList = NULL;
        this.vaListOffset = 0;
    }
}

export { JNIEnvInterceptorX86 };
