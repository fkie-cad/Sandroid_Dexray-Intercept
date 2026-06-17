/**
 * Compatibility shim: @types/frida-gum v16 → v19.
 * These global types existed in v16 but were removed/renamed in v19.
 */
declare global {
    type NativeArgumentValue = NativePointer;
    type NativeReturnValue = NativePointer;
}

export {};