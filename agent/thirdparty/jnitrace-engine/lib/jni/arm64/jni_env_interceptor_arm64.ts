import { JNIEnvInterceptor } from "../jni_env_interceptor";
import { JNIThreadManager } from "../jni_thread_manager";

import { ReferenceManager } from "../../utils/reference_manager";
import { JavaMethod } from "../../utils/java_method";
import { JNICallbackManager } from "../../internal/jni_callback_manager";

/**
 * ARM64 implementation of the JNIEnv interceptor.
 *
 * provides the architecture-specific logic for:
 *  - building a small AArch64 trampoline that can intercept JNI
 *    varargs calls, snapshot the CPU state and dispatch through
 *    a dynamically constructed callback; and
 *  - decoding the AArch64 va_list layout (AAPCS64) in order to
 *    reconstruct the Java arguments passed through JNI “V”
 *    variants (e.g. Call<Type>MethodV / CallStatic<Type>MethodV).
 */
class JNIEnvInterceptorARM64 extends JNIEnvInterceptor {
    /**
     * Pointer to va_list.stack: the stack region where arguments
     * are read from once the register save areas are exhausted.
     */
    private stack: NativePointer;
    /**
     * Index of the next stack-slot argument (in units of pointer
     * size) used when reading spillover varargs from `stack`.
     */
    private stackIndex: number;
    /**
     * Pointer to va_list.gr_top: end of the saved general-purpose
     * register area for varargs.
     */
    private grTop: NativePointer;
    /**
     * Pointer to va_list.vr_top: end of the saved FP/SIMD (vector)
     * register area for varargs.
     */
    private vrTop: NativePointer;
    /**
     * Current offset (in bytes) from grTop where the next integer
     * or pointer argument will be read from.
     */
    private grOffs: number;
    /**
     * Counter of how many general-purpose register slots have been
     * consumed so far.
     */
    private grOffsIndex: number;
    /**
     * Current offset (in bytes) from vrTop where the next float or
     * double argument will be read from.
     */
    private vrOffs: number;
    /**
     * Counter of how many FP/SIMD (vector) register slots have
     * been consumed so far.
     */
    private vrOffsIndex: number;

    /**
     * Constructs a new ARM64 JNIEnv interceptor.
     *
     * @param references      Global reference manager used to keep
     *                        allocated memory and callbacks alive.
     * @param threads         JNI thread manager used to track
     *                        per-thread JNIEnv pointers.
     * @param callbackManager Manager responsible for user-defined
     *                        before/after JNI callbacks.
     */
    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        callbackManager: JNICallbackManager
    ) {
        super(references, threads, callbackManager);

        this.stack = NULL;
        this.stackIndex = 0;
        this.grTop = NULL;
        this.vrTop = NULL;
        this.grOffs = 0;
        this.grOffsIndex = 0;
        this.vrOffs = 0;
        this.vrOffsIndex = 0;
    }
    
    /**
     * Creates a minimal stub function that simply returns.
     *
     * The stub is used as an Interceptor target so that Frida
     * will populate an InvocationContext before invoking the
     * actual JNI callback.

     *
     * @returns Pointer to executable memory containing a single
     *          RET instruction.
     */
    public createStubFunction (): NativePointer {
        const stub = Memory.alloc(Process.pageSize);

        Memory.patchCode(stub, Process.pageSize, (code: NativePointer): void => {
            const cw = new Arm64Writer(code, { pc: stub });

            // ret
            const RET = 0xd65f03c0;
            cw.putInstruction(RET);

        });

        return stub;
    }

    /**
     * Generates an AArch64 trampoline in the given executable
     * memory region.
     *
     * The trampoline:
     *  - saves all general-purpose registers x1..x30 (including
     *    LR) into a data area embedded in the same page as `text`;
     *  - loads the `parser` callback pointer from that data area
     *    and calls it to obtain the main JNI callback;
     *  - saves the callback pointer and the current stack pointer
     *    on the stack;
     *  - restores the original register state except for x0 and
     *    the link register;
     *  - restores x0 (main callback pointer) and SP, and calls
     *    the main callback with the original call context; and
     *  - finally loads the saved LR from the data area and
     *    branches to it, effectively returning to the original
     *    caller.
     *
     * @param text   Executable memory where the trampoline code
     *               will be emitted.
     * @param _      Unused data pointer (ARM64 keeps its scratch
     *               data in the same page as `text`).
     * @param parser NativeCallback that analyzes the JNI varargs
     *               call and returns a pointer to the main
     *               callback that should handle it.
     */
    protected buildVaArgParserShellcode (
        text: NativePointer,
        _: NativePointer,
        parser: NativeCallback
    ): void {
        const DATA_OFFSET = 0x400;
        const BITS_IN_BYTE = 8;
        const HALF = 2;
        const NUM_REGS = 31;
        const NUM_REG_NO_LR = 30;
        text.add(DATA_OFFSET).writePointer(parser);

        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new Arm64Writer(code, { pc: text });

            // adrp x0, #0
            const ADRP_X0_0 = 0x90000000;
            cw.putInstruction(ADRP_X0_0);

            // back up all registers - just to be safe
            // for i = 1..30: str x<i>, [x0, #0x408 + i*8]
            for (let i = 1; i < NUM_REGS; i++) {
                let ins = 0xF9000000;

                // src reg
                ins += i;

                const base = 0x408;
                const offset = base + i * Process.pointerSize;

                // dst address, (offset / 8) << 10
                ins += offset / HALF << BITS_IN_BYTE;

                // str x<n>, [x0, #<offset>]
                cw.putInstruction(ins);
            }

            // ldr x0, [x0, #0x400] → load addr of parser
            const LDR_X0_X0_400 = 0xF9420000;
            cw.putInstruction(LDR_X0_X0_400);
            
            // blr x0 → call parser
            const BLR_X0 = 0xD63F0000;
            cw.putInstruction(BLR_X0);

            // stp x0, sp, [sp, #-16]!
            cw.putPushRegReg("x0", "sp");

            // adrp x0, #0
            cw.putInstruction(ADRP_X0_0);

            // restore all registers - apart from lr and sp
            for (let i = 1; i < NUM_REG_NO_LR; i++) {
                let ins = 0xF9400000;

                // src reg
                ins += i;

                const base = 0x408;
                const offset = base + i * Process.pointerSize;

                // dst address
                ins += offset / HALF << BITS_IN_BYTE;

                // ldr x<n>, [x0, #<offset>]
                cw.putInstruction(ins);
            }

            // ldp x0, sp, [sp], #16
            cw.putPopRegReg("x0", "sp");

            // blr x0
            cw.putInstruction(BLR_X0);

            // adrp x1, #0
            const ADRP_X1_0 = 0x90000001;
            cw.putInstruction(ADRP_X1_0);
            
            // ldr x2, [x1, #0x4f8]
            const LDR_X2_X1_4F8 = 0xF9427C22;
            cw.putInstruction(LDR_X2_X1_4F8);

            // br x2
            const BR_X2 = 0xD61F0040;
            cw.putInstruction(BR_X2);

            cw.flush();
        });
    }

    /**
     * Initializes internal state for extracting arguments from an
     * AArch64 va_list (AAPCS64).
     *
     * Reads stack, gr_top, vr_top, gr_offs and vr_offs from the
     * va_list structure and stores them in the corresponding
     * fields, so that subsequent calls to extractVaListArgValue()
     * emulate va_arg().
     *
     * @param vaList Pointer to the va_list structure passed to
     *               the JNI “V” variant function.
     */
    protected setUpVaListArgExtract (vaList: NativePointer): void {
        const vrStart = 2;
        const grOffset = 3;
        const vrOffset = 4;
        this.stack = vaList.readPointer();
        this.stackIndex = 0;
        this.grTop = vaList.add(Process.pointerSize).readPointer();
        this.vrTop = vaList.add(Process.pointerSize * vrStart).readPointer();
        this.grOffs = vaList.add(Process.pointerSize * grOffset).readS32();
        this.grOffsIndex = 0;
        this.vrOffs = vaList.add(Process.pointerSize * grOffset + vrOffset).readS32();
        this.vrOffsIndex = 0;
    }

    /**
     * Returns a pointer to the storage location of the paramId-th
     * Java argument in the current varargs list.
     *
     * Based on the JavaMethod parameter metadata, this decides
     * whether the argument is floating-point (float/double) or
     * integer/pointer, and:
     *
     *  - if there are still FP/SIMD register slots available in
     *    the vr_top/vr_offs region (up to MAX_VR_REG_NUM), returns
     *    a pointer into that region and advances vrOffsIndex; or
     *  - if there are still GPR slots available in the
     *    gr_top/gr_offs region (up to MAX_GR_REG_NUM), returns a
     *    pointer into that region and advances grOffsIndex; or
     *  - otherwise, returns a pointer into the stack overflow
     *    area, advancing stackIndex.
     *
     * The caller is responsible for reading the value using the
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
        const MAX_VR_REG_NUM = 8;
        const VR_REG_SIZE = 2;
        const MAX_GR_REG_NUM = 4;
        let currentPtr = NULL;

        if (method.fridaParams[paramId] === "float" ||
          method.fridaParams[paramId] === "double") {
            if (this.vrOffsIndex < MAX_VR_REG_NUM) {
                currentPtr = this.vrTop
                    .add(this.vrOffs)
                    .add(this.vrOffsIndex * Process.pointerSize * VR_REG_SIZE);

                this.vrOffsIndex++;
            } else {
                currentPtr = this.stack.add(
                    this.stackIndex * Process.pointerSize
                );
                this.stackIndex++;
            }
        } else {
            if (this.grOffsIndex < MAX_GR_REG_NUM) {
                currentPtr = this.grTop
                    .add(this.grOffs)
                    .add(this.grOffsIndex * Process.pointerSize);

                this.grOffsIndex++;
            } else {
                currentPtr = this.stack.add(
                    this.stackIndex * Process.pointerSize
                );
                this.stackIndex++;
            }
        }

        return currentPtr;
    }

    /**
     * Resets internal state used for varargs extraction so that
     * subsequent uses do not retain offsets or pointers from the
     * previous va_list.
     */
    protected resetVaListArgExtract (): void {
        this.stack = NULL;
        this.stackIndex = 0;
        this.grTop = NULL;
        this.vrTop = NULL;
        this.grOffs = 0;
        this.grOffsIndex = 0;
        this.vrOffs = 0;
        this.vrOffsIndex = 0;
    }
}

export { JNIEnvInterceptorARM64 };
