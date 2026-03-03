/**
 * Keeps NativePointer references alive for the lifetime of the engine.

 *
 * Native code (shellcode, shadow JNIEnv/JavaVM tables, NativeCallbacks)
 * holds raw pointers into memory allocated via Frida. To prevent the
 * JavaScript engine from garbage-collecting those objects while native
 * code still uses them, store strong references here.
 *
 * Entries are typically added once and kept for the duration of the
 * process; release() exists for completeness but is rarely used.
 */
class ReferenceManager {
    private readonly references: Map<string, NativePointer>;

    public constructor () {
        this.references = new Map<string, NativePointer>();
    }

    public add (ref: NativePointer): void {
        this.references.set(ref.toString(), ref);
    }

    public release (ref: NativePointer): void {
        if (this.references.has(ref.toString())) {
            this.references.delete(ref.toString());
        }
    }
}

export { ReferenceManager };
