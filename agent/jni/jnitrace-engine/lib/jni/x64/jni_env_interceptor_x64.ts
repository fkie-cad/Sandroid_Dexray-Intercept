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
 *    "..." varargs calls, snapshot the CPU state and dispatch
 *    through a dynamically constructed callback
 *  - decoding the System V AMD64 va_list layout in order to
 *    reconstruct Java argument values passed through JNI "V"
 *    (e.g. Call<Type>MethodV / CallStatic<Type>MethodV).
 * 
 * Key implementation details:
 *  - uses RIP-relative addressing for position-independent code.
 *  - stores shellcode data within the same page as the code (at
 *    offset +0x400) to guarantee addresses are within ±2GB for
 *    32-bit displacement encoding.
 *  - handles System V AMD64 vararg ABI: up to 6 GP registers
 *    (RDI, RSI, RDX, RCX, R8, R9) and 8 FP registers (XMM0-XMM7).

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
    private regSavePtr: NativePointer;

    /**
     * Constructs a new x86-64 JNIEnv interceptor.
     *
     * @param references      Global reference manager used to keep
     *                        allocated memory and callbacks alive.
     * @param threads         JNI thread manager used to track per-thread
     *                        JNIEnv pointers.
     * @param callbackManager Manager responsible for user-defined
     *                        before/after JNI callbacks.
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
        this.regSavePtr = NULL;
    }

    /**
     * Generates a small x86-64 trampoline in the given executable
     * memory region.
     *
     * The trampoline:
     *  - saves all relevant GPRs (RDI-R15) and XMM0–7 plus the 
     *    original return address into an in-page data area;
     *  - calls the given `parser` callback to construct a method-
     *    specific JNI callback for the current varargs call, and
     *    stores the returned callback pointer;
     *  - restores the original CPU register state;
     *  - calls the generated “main” callback with the original
     *    argument registers and stack layout;
     *  - finally jumps to the original return address so that
     *    the caller observes normal control flow.
     *
     * Register save/restore strategy:
     *  - Uses RDI as a staging register: on each iteration, the
     *    previous value of RDI is stored into the data area, then
     *    the next register/XMM value is loaded into RDI.
     *  - The reverse loop rebuilds the original register/XMM state
     *    from the saved data.
     *
     * Data storage:
     *  - Instead of using a separate data page (which can fail if
     *    >2GB away due to RIP-relative displacement limits), this
     *    implementation uses an in-page data area at `text + 0x400`.
     *  - This guarantees all RIP-relative accesses are within the
     *    ±2GB range required for x86-64 encoding.
     *
     * @param text   Executable memory where the trampoline code
     *               will be emitted.
     * @param _data  Unused parameter (kept for API compatibility;
     *               data is stored within the text page instead).
     * @param parser NativeCallback that analyzes the JNI varargs
     *               call and returns a pointer to the main callback
     *               that should handle it.
     */
    protected buildVaArgParserShellcode (
        text: NativePointer,
        _data: NativePointer,
        parser: NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>
    ): void {
        // Use in-page data area to guarantee RIP-relative addresses
        // are within ±2GB (32-bit signed displacement limit).
        const dataBase = text.add(0x400);

        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new X86Writer(code, { pc: text });
            const XMM_INC_VALUE = 8;
            const SKIP_FIRST_REG = 1;

            // SSE instruction bytes for movq between XMM and GPR
            // 66 48 0f 7e c7       movq   %xmm0,%rdi
            const XMM_MOV_INS_1 = 0x66;
            const XMM_MOV_INS_2 = 0x48;
            const XMM_MOV_INS_3 = 0x0f;
            const XMM_MOV_TO_INS_4 = 0x7e;   // movq %xmm, %rdi
            // switch dst and src for restoring, e.g. movq xmm7,rdi
            const XMM_MOV_FROM_INS_4 = 0x6e; // movq %rdi, %xmm
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
            // previous value of RDI gets stored at dataBase[dataOffset], then the
            // next register/XMM value gets loaded into RDI. The reverse loop below
            // reconstructs the original register/XMM state from dataBase[].
            for (let i = 0; i < regs.length; i++) {
                // Store previous RDI value
                cw.putMovNearPtrReg(dataBase.add(dataOffset), "rdi");
                dataOffset += Process.pointerSize;

                // putMovRegReg only handles GPRs, manually create
                // mov between XMM and GPR with SSE instruction
                if (i < regs.length - SKIP_FIRST_REG) {
                    if (regs[i + SKIP_FIRST_REG].includes("xmm")) {
                        // putMovRegReg only handles GPRs, manually create
                        // mov between XMM and GPR with SSE instruction
                        // movq %xmmN, %rdi
                        cw.putU8(XMM_MOV_INS_1);
                        cw.putU8(XMM_MOV_INS_2);
                        cw.putU8(XMM_MOV_INS_3);
                        cw.putU8(XMM_MOV_TO_INS_4);
                        cw.putU8(XMM_MOV_INS_5 + xmmOffset * XMM_INC_VALUE);
                        xmmOffset++;
                    } else {
                        // mov %reg, %rdi
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
            
            // save return address in dataBase[dataOffset]
            cw.putMovNearPtrReg(dataBase.add(dataOffset), "rdi");
            dataOffset += Process.pointerSize;

            // call parser callback with original call registers
            // rsi, rdx, rcx, r8, r9 (rest on stack)
            // original ret addr rdi
            // createJNIVarArgInitialCallback computes mainCallback
            // and returns address in rax
            cw.putCallAddress(parser);
            
            // mov [dataBase+dataOffset], rax; 
            // store mainCallback pointer returned in rax
            cw.putMovNearPtrReg(dataBase.add(dataOffset), "rax");
            dataOffset += Process.pointerSize;

            const REG_SIZE = 2;
            const END_INDEX = 1;
            const SKIP_FIRST_COPY = 0;
            const FIRST_ELEM_INDEX = 0;

            let regRestoreOffset = dataOffset - Process.pointerSize * REG_SIZE;

            // Restore original register state
            for (let i = regs.length - END_INDEX; i >= FIRST_ELEM_INDEX; i--) {
                regRestoreOffset = i * Process.pointerSize;
                cw.putMovRegNearPtr("rdi", dataBase.add(regRestoreOffset));

                if (i > SKIP_FIRST_COPY) {
                    if (regs[i].includes("xmm")) {
                        // movq %rdi, %xmmN
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

            // Data layout at this point:
            //   dataBase[0..N-1]  : saved registers
            //   dataBase[N]       : saved return address
            //   dataBase[N+1]     : mainCallback pointer
            //   dataOffset        : (N+2) * 8

            // temporarily save original rdi
            cw.putMovNearPtrReg(dataBase.add(dataOffset), "rdi");
            const rdiBackup = dataOffset;
            dataOffset += Process.pointerSize;

            // load rdi = mainCallback pointer from dataOffset
            const cbAddressOffset = rdiBackup - Process.pointerSize;
            cw.putMovRegNearPtr("rdi", dataBase.add(cbAddressOffset));

            // move callback pointer to R13 (callee-saved)
            cw.putMovNearPtrReg(dataBase.add(dataOffset), "r13");
            const r13Backup = dataOffset;
            cw.putMovRegReg("r13", "rdi");

            // rdi = original rdi (JNIEnv* env) again
            cw.putMovRegNearPtr("rdi", dataBase.add(rdiBackup));
            // call mainCallback(env, obj, mid, ...) with original call context
            cw.putCallReg("r13");
            // restore r13
            cw.putMovRegNearPtr("r13", dataBase.add(r13Backup));

            // retAddressOffset = (N+1)*8 - 8 = N*8 → index N → saved return address
            const retAddressOffset = cbAddressOffset - Process.pointerSize;
            // jmp [saved_retaddr]
            cw.putJmpNearPtr(dataBase.add(retAddressOffset));

            // write buffered instructions to text page
            cw.flush();
        });
    }

    /**
     * Initializes internal state for extracting arguments from a
     * System V AMD64 va_list.
     *
     * The va_list structure on x86-64 SysV ABI has the following layout:
     *
     *   typedef struct {
     *       unsigned int gp_offset;      // Offset into GP reg save area
     *       unsigned int fp_offset;      // Offset into FP reg save area
     *       void *overflow_arg_area;     // Stack overflow area
     *       void *reg_save_area;         // Saved register area
     *   } va_list[1];
     *
     * This function reads these fields and stores them in instance
     * variables so that subsequent calls to extractVaListArgValue()
     * can emulate va_arg() behavior.
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
        this.regSavePtr = vaList.add(Process.pointerSize * DATA_OFFSET).readPointer();
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
     * appropriate type (see readValue() in the base class).
     *
     * System V AMD64 ABI vararg registers:
     *  - Up to 6 GP arguments: RDI, RSI, RDX, RCX, R8, R9
     *  - Up to 8 FP arguments: XMM0-XMM7
     *  - Additional arguments spill to the stack
     * 
     * @param method  JavaMethod describing the Java-side parameter
     *                types for this invocation.
     * @param paramId Zero-based index of the parameter within the
     *                Java argument list.
     * @returns       Pointer to the memory location holding the
     *                argument value.
     */
    protected extractVaListArgValue (
        method: JavaMethod,
        paramId: number
    ): NativePointer {
        // Each FP (Floating Point) register slot in reg_save_area
        // is 16 bytes = 2 * sizeof(void *)
        const FP_REG_SIZE = 2;
        // Maximum GR and FP register slots per SysV AMD64 ABI
        const MAX_GR_REG_NUM = 6;  // up to 6 GP varargs (RDI,RSI,RDX,RCX,R8,R9)
        const MAX_FP_REG_NUM = 8;  // up to 8 XMM varargs (XMM0-XMM7)
        const OFFSET = 1;

        let currentPtr = NULL;

        if (method.fridaParams[paramId] === "float" ||
            method.fridaParams[paramId] === "double") {
            // Floating-point argument
            const fpDelta = this.fpOffset - this.fpOffsetStart;
            if (fpDelta / Process.pointerSize < MAX_FP_REG_NUM) {
                // Still have FP register slots available
                currentPtr = this.regSavePtr.add(this.fpOffset);
                this.fpOffset += Process.pointerSize * FP_REG_SIZE;
            } else {
                // Spilled to stack
                const reverseId = method.fridaParams.length - paramId - OFFSET;
                currentPtr = this.overflowPtr.add(reverseId * Process.pointerSize);
            }
        } else {
            // Integer/pointer argument
            const grDelta = this.grOffset - this.grOffsetStart;
            if (grDelta / Process.pointerSize < MAX_GR_REG_NUM) {
                // Still have GP register slots available
                currentPtr = this.regSavePtr.add(this.grOffset);
                this.grOffset += Process.pointerSize;
            } else {
                // Spilled to stack
                const reverseId = method.fridaParams.length - paramId - OFFSET;
                currentPtr = this.overflowPtr.add(reverseId * Process.pointerSize);
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
        this.regSavePtr = NULL;
    }
}

export { JNIEnvInterceptorX64 };