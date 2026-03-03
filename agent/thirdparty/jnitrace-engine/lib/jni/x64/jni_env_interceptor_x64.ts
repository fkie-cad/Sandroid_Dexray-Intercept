import { JNIEnvInterceptor } from "../jni_env_interceptor";
import { JNIThreadManager } from "../jni_thread_manager";

import { ReferenceManager } from "../../utils/reference_manager";
import { JavaMethod } from "../../utils/java_method";
import { JNICallbackManager } from "../../internal/jni_callback_manager";

/**
 * x86-64 implementation of the JNIEnv interceptor.
 *
 * provides the architecture-specific logic for:
 *  - building a trampoline (shellcode) that can intercept JNI
 *    varargs calls, snapshot the CPU state and dispatch through
 *    a dynamically constructed callback; and
 *  - decoding the System V AMD64 va_list layout in order to
 *    reconstruct Java argument values passed through JNI "…"
 *    (e.g. Call<Type>MethodV / CallStatic<Type>MethodV).

 */
class JNIEnvInterceptorX64 extends JNIEnvInterceptor {
    /**
     * Current offset (in bytes) into the general-purpose register area
     * of the va_list’s reg_save_area, used when extracting integer
     * and pointer arguments from varargs.

     */
    private grOffset: number;

    /**
     * Initial general-purpose register offset captured from va_list.
     * Used as a baseline to compute how many GR slots have already
     * been consumed.

     */
    private grOffsetStart: number;

    /**
     * Current offset (in bytes) into the floating-point register area
     * of the va_list’s reg_save_area, used when extracting float and
     * double arguments from varargs.

     */
    private fpOffset: number;

    /**
     * Initial floating-point register offset captured from va_list.
     * Used as a baseline to compute how many FP slots have already
     * been consumed.

     */
    private fpOffsetStart: number;
    /**
     * Pointer to va_list.overflow_arg_area, i.e. the stack region
     * where arguments are read from once the register save area
     * has been exhausted.
     */
    private overflowPtr: NativePointer;
    /**
     * Pointer to va_list.reg_save_area, i.e. the memory area holding
     * spilled argument registers (GPRs followed by XMM registers).
     */
    private dataPtr: NativePointer;

    /**
     * Constructs a new x86-64 JNIEnv interceptor.

     *
     * @param references  Global reference manager used to keep
     *                    allocated memory and callbacks alive.
     * @param threads     JNI thread manager used to track per-thread
     *                    JNIEnv pointers.
     * @param callbackManager  Manager responsible for user-defined
     *                         before/after JNI callbacks.
     */
    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        callbackManager: JNICallbackManager
    ) {
        super(references, threads, callbackManager);

        this.grOffset = 0;
        this.grOffsetStart = 0;
        this.fpOffset = 0;
        this.fpOffsetStart = 0;
        this.overflowPtr = NULL;
        this.dataPtr = NULL;
    }

    /**
     * Generates a small x86-64 trampoline in the given executable
     * memory region.
     *
     * The trampoline:
     *  - saves all relevant GPRs and XMM0–7 plus the original
     *    return address into the `data` buffer;
     *  - calls the given `parser` callback to construct a more
     *    specific JNI callback for the current varargs call, and
     *    stores its address;
     *  - restores the original CPU register state;
     *  - calls the generated “main” callback with the original
     *    argument registers and stack layout; and
     *  - finally jumps to the original return address so that
     *    the caller observes normal control flow.
     *
     * Internally, the save/restore loop uses RDI as a staging
     * register: on each iteration it stores the previous value
     * of RDI into `data` and then loads the next register/XMM
     * value into RDI. The reverse loop rebuilds the original
     * register/XMM state from the contents of `data`.
     *
     * @param text   Executable memory where the trampoline code
     *               will be emitted.
     * @param data   Writable memory used as scratch space for
     *               saving registers, return address and callback
     *               pointer.
     * @param parser NativeCallback that analyzes the JNI varargs
     *               call and returns a pointer to the main
     *               callback that should handle it.
     */
    protected buildVaArgParserShellcode (
        text: NativePointer,
        data: NativePointer,
        parser: NativeCallback
    ): void {
        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new X86Writer(code, { pc: text });
            const XMM_INC_VALUE = 8;
            const SKIP_FIRST_REG = 1;
            
            //66 48 0f 7e c7       	movq   %xmm0,%rdi
            const XMM_MOV_INS_1 = 0x66;
            const XMM_MOV_INS_2 = 0x48;
            const XMM_MOV_INS_3 = 0x0f;
            const XMM_MOV_TO_INS_4 = 0x7e;
            const XMM_MOV_INS_5 = 0xc7;

            const regs = [
                "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax",
                "rbx", "r10", "r11", "r12", "r13", "r14", "r15",
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
                "xmm6", "xmm7"
            ];
            let dataOffset = 0;
            let xmmOffset = 0;

            // Save registers
            // The loop uses RDI as a staging register: on each iteration the
            // previous value of RDI gets stored at data[dataOffset], then the
            // next register/XMM value gets loaded into RDI. The reverse loop below
            // reconstructs the original register/XMM state from data[].
            for (let i = 0; i < regs.length; i++) {
                cw.putMovNearPtrReg(data.add(dataOffset), "rdi");
                dataOffset += Process.pointerSize;

                if (i < regs.length - SKIP_FIRST_REG) {
                    // putMovRegReg only handles GPRs, manually create
                    // mov between XMM and GPR with SSE instruction
                    if (regs[i + SKIP_FIRST_REG].includes("xmm")) {
                        cw.putU8(XMM_MOV_INS_1);
                        cw.putU8(XMM_MOV_INS_2);
                        cw.putU8(XMM_MOV_INS_3);
                        cw.putU8(XMM_MOV_TO_INS_4);
                        cw.putU8(XMM_MOV_INS_5 + xmmOffset * XMM_INC_VALUE);
                        xmmOffset++;
                    } else {
                        cw.putMovRegReg(
                            "rdi", regs[i + SKIP_FIRST_REG] as X86Register
                        );
                    }
                }
            }

            // prepare for reverse restore of XMMs
            xmmOffset--;

            // pop rdi; load original return address into rdi
            cw.putPopReg("rdi");
            
            // save return address in data[dataOffset]
            cw.putMovNearPtrReg(data.add(dataOffset), "rdi");
            dataOffset += Process.pointerSize;

            // call parser callback with original call registers rsi, rdx, rcx, r8, r9 (rest on stack)
            // original ret addr rdi
            // createJNIVarArgInitialCallback computes mainCallback and returns address in rax
            cw.putCallAddress(parser);
            
            // mov [data+dataOffset], rax; store mainCallback pointer returned in rax
            cw.putMovNearPtrReg(data.add(dataOffset), "rax");
            dataOffset += Process.pointerSize;

            const REG_SIZE = 2;
            const END_INDEX = 1;
            const SKIP_FIRST_COPY = 0;
            const FIRST_ELEM_INDEX = 0;

            // switch dst and src for restoring, e.g. movq xmm7,rdi
            const XMM_MOV_FROM_INS_4 = 0x6e;

            let regRestoreOffset = dataOffset - Process.pointerSize * REG_SIZE;

            // Restore original register state
            for (let i = regs.length - END_INDEX; i >= FIRST_ELEM_INDEX; i--) {
                regRestoreOffset = i * Process.pointerSize;

                cw.putMovRegNearPtr("rdi", data.add(regRestoreOffset));

                if (i > SKIP_FIRST_COPY) {
                    if (regs[i].includes("xmm")) {
                        cw.putU8(XMM_MOV_INS_1);
                        cw.putU8(XMM_MOV_INS_2);
                        cw.putU8(XMM_MOV_INS_3);
                        cw.putU8(XMM_MOV_FROM_INS_4);
                        cw.putU8(XMM_MOV_INS_5 + xmmOffset * XMM_INC_VALUE);
                        xmmOffset--;
                    } else {
                        cw.putMovRegReg(regs[i] as X86Register, "rdi");
                    }
                }
            }

            /**
             * data[0 .. N-1] → saved regs
             * data[N] → saved return address
             * data[N+1] → mainCallback pointer (from parser)
             * dataOffset → (N+2) * 8 (after storing rax)
             */

            // save original rdi
            cw.putMovNearPtrReg(data.add(dataOffset), "rdi");
            const rdiBackup = dataOffset;
            dataOffset += Process.pointerSize;

            // load rdi = mainCallback pointer from data buffer
            const cbAddressOffset = rdiBackup - Process.pointerSize;
            cw.putMovRegNearPtr("rdi", data.add(cbAddressOffset));

            // r13 = mainCallback
            cw.putMovNearPtrReg(data.add(dataOffset), "r13");
            const r13Backup = dataOffset;
            cw.putMovRegReg("r13", "rdi");

            // rdi = original rdi (JNIEnv* env) again
            cw.putMovRegNearPtr("rdi", data.add(rdiBackup));
            // call mainCallback(env, obj, mid, ...) with original call context
            cw.putCallReg("r13");
            // restore r13
            cw.putMovRegNearPtr("r13", data.add(r13Backup));

            // retAddressOffset = (N+1)*8 - 8 = N*8 → index N → saved return address
            const retAddressOffset = cbAddressOffset - Process.pointerSize;
            // jmp [saved_retaddr]
            cw.putJmpNearPtr(data.add(retAddressOffset));

            // write buffered instructions to text page
            cw.flush();
        });
    }


    /**
     * Initializes internal state for extracting arguments from a
     * System V AMD64 va_list.
     *
     * Reads gp_offset, fp_offset, overflow_arg_area and
     * reg_save_area from the va_list structure and stores them
     * in the corresponding fields so that subsequent calls to
     * extractVaListArgValue() behave like va_arg().
     *
     * @param vaList Pointer to the va_list structure passed to
     *               the JNI “V” variant function.
     */
    protected setUpVaListArgExtract (vaList: NativePointer): void {
        const FP_OFFSET = 4;
        const DATA_OFFSET = 2;
        
        // gp_offset
        this.grOffset = vaList.readU32();
        this.grOffsetStart = this.grOffset;
        // fp_offset
        this.fpOffset = vaList.add(FP_OFFSET).readU32();
        this.fpOffsetStart = this.fpOffset;
        // overflow_arg_area
        this.overflowPtr = vaList.add(Process.pointerSize).readPointer();
        // reg_save_area
        this.dataPtr = vaList.add(Process.pointerSize * DATA_OFFSET)
            .readPointer();
    }

    /**
     * Returns a pointer to the storage location of the paramId-th
     * Java argument in the current varargs list.
     *
     * Based on the JavaMethod parameter metadata, this decides
     * whether the argument is floating-point (float/double) or
     * integer/pointer, and:
     *
     *  - if there are still register slots available in
     *    reg_save_area (according to gp_offset/fp_offset and
     *    MAX_GR_REG_NUM / MAX_FP_REG_NUM), returns a pointer
     *    into reg_save_area and advances the corresponding
     *    offset; or
     *  - otherwise, returns a pointer into overflow_arg_area,
     *    computed using reverse indexing to match the stack
     *    layout of the varargs portion.
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
        // Each FP (Floating Point) register slot in reg_save_area is 16 bytes = 2 * sizeof(void *)
        const FP_REG_SIZE = 2;
        // Maximum number of GR and FP register slots usable for these varargs
        const MAX_GR_REG_NUM = 2;
        const MAX_FP_REG_NUM = 14;
        const OFFSET = 1;

        let currentPtr = NULL;

        if (method.fridaParams[paramId] === "float" ||
                method.fridaParams[paramId] === "double") {
            const fpDelta = this.fpOffset - this.fpOffsetStart;
            if (fpDelta / Process.pointerSize < MAX_FP_REG_NUM) {
                currentPtr = this.dataPtr.add(this.fpOffset);

                this.fpOffset += Process.pointerSize * FP_REG_SIZE;
            } else {
                const reverseId = method.fridaParams.length - paramId - OFFSET;
                currentPtr = this.overflowPtr.add(
                    reverseId * Process.pointerSize
                );
            }
        } else {
            const grDelta = this.grOffset - this.grOffsetStart;
            if (grDelta / Process.pointerSize < MAX_GR_REG_NUM) {
                currentPtr = this.dataPtr.add(this.grOffset);

                this.grOffset += Process.pointerSize;
            } else {
                const reverseId = method.fridaParams.length - paramId - OFFSET;
                currentPtr = this.overflowPtr.add(
                    reverseId * Process.pointerSize
                );
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
        this.grOffset = 0;
        this.grOffsetStart = 0;
        this.fpOffset = 0;
        this.fpOffsetStart = 0;
        this.overflowPtr = NULL;
        this.dataPtr = NULL;
    }
}

export { JNIEnvInterceptorX64 };
