import { JNIEnvInterceptor } from "../jni_env_interceptor";
import { JNIThreadManager } from "../jni_thread_manager";

import { Types } from "../../utils/types";
import { ReferenceManager } from "../../utils/reference_manager";
import { JavaMethod } from "../../utils/java_method";
import { JNICallbackManager } from "../../internal/jni_callback_manager";

/**
 * ARM (32‑bit) implementation of the JNIEnv interceptor.
 *
 * provides the architecture-specific logic for:
 *  - building a small ARM32 trampoline that intercepts JNI
 *    varargs calls, snapshots r0–r3 and LR, and dispatches
 *    through a dynamically constructed callback; and
 *  - decoding the ARM32 va_list layout used by the JNI “V”
 *    variants on this platform.
 */
class JNIEnvInterceptorARM extends JNIEnvInterceptor {
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
     * Creates a minimal stub function that just returns.
     *
     * push {lr}; pop {pc} is a standard ARM idiom for "ret".
     * Frida uses this stub as an Interceptor target so that
     * an InvocationContext is available before the actual
     * JNI callback runs.
     */
    public createStubFunction (): NativePointer {
        const stub = Memory.alloc(Process.pageSize);

        Memory.patchCode(stub, Process.pageSize, (code: NativePointer): void => {
            const cw = new ArmWriter(code, { pc: stub });

            // push { lr }
            const PUSH_LR = 0xe52de004;
            cw.putInstruction(PUSH_LR);
            // pop { pc }
            const POP_PC = 0xe49df004;
            cw.putInstruction(POP_PC);
            cw.flush();
        });

        return stub;
    }

    /**
     * Generates an ARM32 trampoline in the given executable page.
     *
     * Layout:
     *   - text    : code emitted by ArmWriter (at `text + 0`).
     *   - text+0x400 : pointer to `parser` callback.
     *   - text+0x418.. : saved r0–r3 and LR.
     *
     * The trampoline does:
     *   1. Save r0–r3 and LR to the data area (PC‑relative).
     *   2. Load parser pointer from text+0x400 into r0 and BLX to it;
     *      parser returns mainCallback pointer in r0.
     *   3. Restore r1–r3 so mainCallback sees original args in r1–r3.
     *   4. BLX r0 (mainCallback), which fixes env in JS and calls
     *      the real JNI function.
     *   5. Load saved LR and BX to it to return to original caller.
     *
     * @param text   Executable page where trampoline is emitted.
     * @param _      Unused data pointer (ARM32 uses the same page
     *               for code and data).
     * @param parser NativeCallback that analyzes the JNI varargs
     *               call and returns a pointer to the main callback.
     */
    protected buildVaArgParserShellcode (
        text: NativePointer,
        _: NativePointer,
        parser: NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>
    ): void {
        const DATA_OFFSET = 0x400;

        // Store parser pointer at text + 0x400 for later PC-relative load
        text.add(DATA_OFFSET).writePointer(parser);

        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new ArmWriter(code, { pc: text });

            // nops for the context interceptor to overwrite
            // 4 NOPs reserved for another interceptor to overwrite if needed.
            cw.putNop();
            cw.putNop();
            cw.putNop();
            cw.putNop();

            // Save r0..r3 and LR to PC-relative slots in the data region.
            //
            // Because ARM's PC is (current_instr_addr + 8), each STR with
            // the same immediate (#0x400) stores to slightly different
            // addresses as PC advances: text+0x418, text+0x41C, etc.

            // str r0, [pc, #0x400]  ; effective addr -> text + 0x418
            const STR_R0_PC_400 = 0xe58f0400;
            cw.putInstruction(STR_R0_PC_400);

            // str r1, [pc, #0x400]  ; effective addr -> text + 0x41C
            const STR_R1_PC_400 = 0xe58f1400;
            cw.putInstruction(STR_R1_PC_400);

            // str r2, [pc, #0x400]  ; effective addr -> text + 0x420
            const STR_R2_PC_400 = 0xe58f2400;
            cw.putInstruction(STR_R2_PC_400);

            // str r3, [pc, #0x400]  ; effective addr -> text + 0x424
            const STR_R3_PC_400 = 0xe58f3400;
            cw.putInstruction(STR_R3_PC_400);

            // str lr, [pc, #0x400]  ; effective addr -> text + 0x428
            const STR_LR_PC_400 = 0xe58fe400;
            cw.putInstruction(STR_LR_PC_400);

            // Load parser pointer from text+0x400 into r0 and call it.
            //
            // At this instruction, PC = (instr_addr + 8), so the #0x3D4
            // immediate is chosen such that PC + 0x3D4 == text + 0x400.
            // The immediate encodes PC-relative address that lands on
            // the DATA_OFFSET slot.
            //
            // ldr r0, [pc, #0x3d4]  ; -> *(text + 0x400) = parser
            const LDR_R0_PC_3D4 = 0xe59f03d4;
            cw.putInstruction(LDR_R0_PC_3D4);
            // blx r0
            // Call parser(env, obj, methodID, va_list).
            // BLX also uses bit 0 of r0 to select ARM vs Thumb state and
            // stores the return address in LR to return correctly to
            // the next instruction in this trampoline regardless of state.
            const BLX_R0 = 0xe12fff30;
            cw.putInstruction(BLX_R0);

            // parser(env, obj, methodID, va_list) returns mainCallback in r0.

            // Restore r1..r3 (original obj, methodID, va_list) from data area
            // so mainCallback sees original arguments in r1..r3.
            //
            // Each LDR uses the same #0x3E8 immediate, but PC is different
            // for each instruction, so PC+0x3E8 lands on text+0x41C/0x420/0x424.

            // ldr r1, [pc, #0x3e8]  ; effective addr -> text + 0x41C
            const LDR_R1_PC_3E8 = 0xe59f13e8;
            cw.putInstruction(LDR_R1_PC_3E8);

            // ldr r2, [pc, #0x3e8]  ; effective addr -> text + 0x420
            const LDR_R2_PC_3E8 = 0xe59f23e8;
            cw.putInstruction(LDR_R2_PC_3E8);

            // ldr r3, [pc, #0x3e8]  ; effective addr -> text + 0x424
            const LDR_R3_PC_3E8 = 0xe59f33e8;
            cw.putInstruction(LDR_R3_PC_3E8);

            // Call mainCallback; r0 is the function pointer, r1..r3 are
            // original JNI arguments. The JS callback will overwrite
            // the first argument with the thread's JNIEnv.

            //blx r0
            cw.putInstruction(BLX_R0);

            // Restore LR from data area and branch to it, effectively
            // returning to the original caller in the correct state
            // (ARM or Thumb) based on the LSB of the saved address.
            //
            // ldr r1, [pc, #0x3e4]  ; effective addr -> text + 0x428 (saved LR)
            const LDR_R1_PC_3E4 = 0xe59f13e4;
            cw.putInstruction(LDR_R1_PC_3E4);

            // bx r1
            // Branch to the saved LR of the original caller, and use the
            // LSB of that address to return in the correct instruction set
            // (ARM or Thumb). This ensures we return exactly as the original
            // JNI function would have.
            const BX_R1 = 0xe12fff11;
            cw.putInstruction(BX_R1);

            cw.flush();
        });
    }

    /**
     * Initializes internal state for extracting arguments from an
     * ARM32 va_list. Here va_list is treated as a linear block of
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
     * This implementation assumes varargs are laid out linearly in
     * memory starting at vaList, so it simply returns:
     *
     *   vaList + currentOffset
     *
     * and advances currentOffset by the size of that argument.
     */
    protected extractVaListArgValue (
        method: JavaMethod,
        paramId: number
    ): NativePointer {
        const currentPtr = this.vaList.add(this.vaListOffset);
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

export { JNIEnvInterceptorARM };