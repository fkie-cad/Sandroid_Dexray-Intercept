// @ts-nocheck
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
     * Creates a small ARM64 stub function suitable for Interceptor.replace().
     *
     * populates page from Memory.alloc() with a NOP sled followed by a RET:
     * - yields normal writable page that Interceptor.replace() can patch with
     *   its trampoline
     * - short sequence of NOPs (8 instructions) provides sufficient space for
     *   the ARM64 trampoline while keeping the stub simple
     *
     * @returns Pointer to the beginning of the stub function.
     */
    public createStubFunction (): NativePointer {
        const stub = Memory.alloc(Process.pageSize);
        const NOP = 0xd503201f;
        const RET = 0xd65f03c0;

        // NOP sled
        for (let i = 0; i < 8; i++) {
            stub.add(i * 4).writeU32(NOP);
        }
        // Final RET
        stub.add(8 * 4).writeU32(RET);

        return stub;
    }

    /**
     * Generates an AArch64 trampoline in the given executable
     * memory region, that intercepts JNI varargs calls,
     * dispatches through parser callback, and calls method-
     * specific mainCallback
     *
     * Trampoline must preserve both general-purpose registers
     * (x1-x30) and floating-point registers (v0-v7) across the
     * parser call, because:
     *  - parser is a normal C function that may clobber all
     *    registers
     *  - mainCallback expects to receive the original argument 
     *    values in both GPRs and FP registers according to the
     *    AAPCS64 ABI
     * 
     * On ARM64, variadic functions pass float and double 
     * arguments in FP registers (v0-v7) as per the AAPCS64
     * calling convention. If these registers are not preserved,
     * the mainCallback will read garbage values when accessing
     * its double/float parameters.
     * 
     * References:
     *  - https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
     * #parameter-passing
     *  - https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
     * #appendix-variable-argument-lists
     * 
     * The trampoline:
     *  - saves all general-purpose registers x1..x30 (including
     *    LR) into a data area embedded in the same page as `text`;
     *  - must also preserve floating-point registers (v0-v7) 
     *    across the parser call, v0-v7 (FP regs) to memory
     *  - loads the `parser` callback pointer from that data area
     *    and calls it, returns JNI  mainCallback pointer in x0;
     *  - saves the callback pointer and the current stack pointer
     *    on the stack;
     *  - restores the original register state (x1-x29 and v0-v7) 
     *    from memory, except for x0 and the link register;
     *  - restores x0 (main callback pointer) and SP, and calls
     *    the main callback with the original call context; and
     *  - finally loads the saved LR from the data area and
     *    branches to it, effectively returning to the original
     *    caller.
     *
     * Memory layout in text page:
     *  - text+0x000:       Shellcode begins here
     *  - text+0x400:       Parser callback pointer (NativeCallback)
     *  - text+0x408-0x4f0: Saved x1-x30 (30 registers * 8 bytes)
     *  - text+0x4f8:       Saved link register (for return)
     *  - text+0x500-0x53f: Saved v0-v7 (8 registers * 8 bytes each)
     * 
     * @param text   Executable memory where the trampoline code
     *               will be emitted.
     * @param _      Unused data pointer (ARM64 keeps its scratch
     *               data in the same page as `text`).
     * @param parser NativeCallback that analyzes the JNI varargs
     *               call and returns a pointer to the 
     *               mainCallback that should handle it.
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
        const NUM_FP_REGS = 8;  // v0-v7
        
        // Store parser pointer at text+0x400
        text.add(DATA_OFFSET).writePointer(parser);

        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new Arm64Writer(code, { pc: text });

            /**
             * Set up base pointer for data access
             * 
             * - adrp x0, #0
             * - Sets x0 to the page-aligned address containing current PC (text page)
             */
            const ADRP_X0_0 = 0x90000000;
            cw.putInstruction(ADRP_X0_0);

            /**
             * Save general-purpose registers x1..x30
             *
             * - x0 is used as base pointer and will be overwritten multiple times
             * - x1-x30 are saved to preserve original call arguments and link register
             */
            for (let i = 1; i < NUM_REGS; i++) {
                // Construct: STR x<i>, [x0, #(0x408 + i*8)]
                let ins = 0xF9000000; // Base opcode for STR Xt, [Xn, #imm]
                ins += i;             // Source register: Rt = x<i>
                const base = 0x408;
                const offset = base + i * Process.pointerSize;
                // Immediate is scaled by 8 for 64-bit stores
                ins += offset / HALF << BITS_IN_BYTE;
                cw.putInstruction(ins);
            }

            /**
            * Save floating-point registers v0-v7
            *
            * - ARM64 AAPCS64: Float/double arguments are passed in v0-v7 even
            * - for variadic functions. These must be preserved across the parser
            * - call, otherwise mainCallback will read garbage values.
            */
            for (let i = 0; i < NUM_FP_REGS; i++) {
                // Construct: STR Dt, [x0, #(0x500 + i*8)]
                // Uses 64-bit FP store (D register = lower 64 bits of V register)
                const FP_SAVE_BASE = 0x500;  // Start after GPR save area
                const offset = FP_SAVE_BASE + i * 8;
                const imm12 = offset / 8;    // Scaled immediate
                
                let ins = 0xFD000000;  // Base opcode for STR Dt, [Xn, #imm]
                ins += i;              // Source register: Dt = d<i> (v<i>) (bits 0-4)
                ins += (imm12 << 10);  // Immediate field: imm12 (bits 10-21)
                
                cw.putInstruction(ins);
            }

            /**
             * Load and call parser callback
             *
             * - ldr x0, [x0, #0x400]
             * - Loads parser pointer (stored at text+0x400) into x0
             */
            const LDR_X0_X0_400 = 0xF9420000;
            cw.putInstruction(LDR_X0_X0_400);
            
            // blr x0
            // Calls parser with original x1, x2, etc. (env, obj, methodID, ...)
            // Parser clobbers all registers and returns mainCallback pointer in x0
            const BLR_X0 = 0xD63F0000;
            cw.putInstruction(BLR_X0);

            /**
             * Preserve mainCallback pointer and stack pointer
             *
             * - stp x0, sp, [sp, #-16]!
             * - Pushes mainCallback pointer (x0) and current sp onto stack
             */
            cw.putPushRegReg("x0", "sp");

            // Reload base pointer for restoration
            // adrp x0, #0
            cw.putInstruction(ADRP_X0_0);

            
            // Restore general-purpose registers x1-x29
            // x30 (link register) is restored later; x0 is restored after
            for (let i = 1; i < NUM_REG_NO_LR; i++) {
                let ins = 0xF9400000;
                ins += i;
                const base = 0x408;
                const offset = base + i * Process.pointerSize;
                ins += offset / HALF << BITS_IN_BYTE;
                cw.putInstruction(ins);
            }

            /**
             * Restore floating-point registers v0-v7
             *
             * - Critical: Restores original float/double argument values so that
             *   mainCallback receives correct values in FP registers
             */
            for (let i = 0; i < NUM_FP_REGS; i++) {
                // Construct: LDR Dt, [x0, #(0x500 + i*8)]
                const FP_SAVE_BASE = 0x500;
                const offset = FP_SAVE_BASE + i * 8;
                const imm12 = offset / 8;

                let ins = 0xFD400000;  // Base opcode for LDR Dt, [Xn, #imm]
                ins += i;              // Destination register: Dt = d<i> (v<i>)
                ins += (imm12 << 10);  // Immediate field

                cw.putInstruction(ins);
            }

            /**
             * Restore mainCallback pointer and call it
             *
             * - ldp x0, sp, [sp], #16
             * - Restores mainCallback pointer into x0 and original sp
             */
            cw.putPopRegReg("x0", "sp");

            // blr x0
            // Calls mainCallback with fully restored register state
            // (x1-x29, v0-v7 all contain original argument values)
            cw.putInstruction(BLR_X0);

            /**
             * Return to original caller
             * 
             * Reload base pointer to access saved link register
             * adrp x1, #0
             */
            const ADRP_X1_0 = 0x90000001;
            cw.putInstruction(ADRP_X1_0);
            
            // ldr x2, [x1, #0x4f8]
            // Loads saved x30 (link register) from text+0x4f8
            const LDR_X2_X1_4F8 = 0xF9427C22;
            cw.putInstruction(LDR_X2_X1_4F8);

            // br x2
            // Branches to original return address (restores control to caller)
            const BR_X2 = 0xD61F0040;
            cw.putInstruction(BR_X2);

            cw.flush();
        });
    }

    /**
     * Initializes internal state for extracting arguments from an
     * AArch64 va_list (AAPCS64).
     *
     * This implementation assumes the toolchain’s va_list layout is:
     *
     *   struct {
     *       void *stack;    // overflow_arg_area
     *       void *gr_top;   // end of saved GPR area
     *       void *vr_top;   // end of saved FP/SIMD area
     *       int   gr_offs;  // byte offset into GPR area
     *       int   vr_offs;  // byte offset into FP/SIMD area
     *   };
     *
     * and reads stack, gr_top, vr_top, gr_offs and vr_offs from that
     * structure into the corresponding fields, so that subsequent
     * calls to extractVaListArgValue() emulate va_arg() for this ABI.
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
