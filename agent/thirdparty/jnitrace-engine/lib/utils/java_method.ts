import { Types } from "./types";


/**
 * Abstracts a Java method referenced in native code.
 * Parses a JVM method descriptor, e.g.:
 *   (II)I
 *   (Ljava/lang/String;[I)V
 *   ([[I[[Ljava/lang/String;)V
 *
 * Multi-dimensional array descriptors (e.g. "[[I", "[[Ljava/lang/String;")
 * are preserved in `params`. When converted via Types.convertJTypeToNativeJType
 * and Types.convertNativeJTypeToFridaType they are treated as generic
 * object/array pointers at the JNI/Frida type level.
 */
class JavaMethod {
    private readonly _signature: string;
    private readonly _params: string[];
    private readonly _ret: string;

    public constructor(signature: string) {
        this._signature = signature;
        let params: string[] = [];
        let ret = "V";

        try{
            const parsed = JavaMethod.parseMethodDescriptor(signature);
            params = parsed.params;
            ret = parsed.ret;
        } catch(e){
            // Fallback: mimic original behavior
            // - No params
            // - Unknown return type
            send({
                type: "warning",
                message: `Failed to parse Java method signature: ${signature}`,
                error: e instanceof Error ? e.message : String(e),
            });
            params = [];
            ret = "unknown";
        }
        
        this._params = params;
        this._ret = ret;
    }

     /**
     * Parse a JVM method descriptor into parameter descriptors and return descriptor.
     * Example:
     *   "(II)I" -> params: ["I", "I"], ret: "I"
     *   "(Ljava/lang/String;[I)V" -> params: ["Ljava/lang/String;", "[I"], ret: "V"
     *   "([[I[[Ljava/lang/String;)V" -> params: ["[[I", "[[Ljava/lang/String;"], ret: "V"
     */
    private static parseMethodDescriptor(signature: string): {
        params: string[];
        ret: string;
    } {
        const params: string[] = [];
        // default to void if somehow missing; spec always has a ret
        let ret = "V";

        // Sanity check: must start with '(' and have a ')'
        const start = signature.indexOf("(");
        const end = signature.indexOf(")");
        if (start === -1 || end === -1 || end < start) {
            throw new Error(`Invalid method signature: ${signature}`);
        }

        const paramPart = signature.slice(start + 1, end);
        const retPart = signature.slice(end + 1);

        // parse parameter parameters one by one
        let i = 0;
        while (i < paramPart.length) {
                    const desc = this.readTypeDescriptor(paramPart, i);
                    params.push(desc.type);
                    i = desc.nextIndex;
        }

        // parse the return descriptor
        if(retPart.length==0){
            throw new Error(`Missing return type in signature: ${signature}`);
        } else{
            const desc = this.readTypeDescriptor(retPart, 0);
            ret = desc.type;
        }

        return { params, ret };
    }

    /**
     * Read a single JVM type descriptor starting at index `i`.
     * Handles:
     *   - primitive: B, S, I, J, F, D, C, Z, V
     *   - object:   L...;
     *   - arrays:   [<descriptor> (any dimensions)
     *
     * Returns the full type descriptor string and the next index.
     */
    private static readTypeDescriptor(descriptor: string, i: number): {
        type: string;
        nextIndex: number;
    }{
        const len = descriptor.length;
        if (i >= len) {
            throw new Error(`Unexpected end of descriptor: ${descriptor}`);
        }

        // Handle array dimensions: one or more "["
        let arrayPrefix = "";
        while(i < len && descriptor.charAt(i)=="["){
            arrayPrefix += "[";
            i++;
        }

        if (i >= len) {
            throw new Error(`Unexpected end of descriptor after '[': ${descriptor}`);
        }

        const c = descriptor.charAt(i);

        // primitive or void
        const primitiveTypes = ["B", "S", "I", "J", "F", "D", "C", "Z", "V"];
        if (primitiveTypes.includes(c)){
           return{
            type: arrayPrefix + c,
            nextIndex: i+1
           }
        }

        if( c=== "L"){
            const semicolonIndex = descriptor.indexOf(";",i);
            if (semicolonIndex === -1) {
                throw new Error(`Unterminated object descriptor in: ${descriptor}`);
            }
            const base = descriptor.substring(i,semicolonIndex+1);

            return{
                type: arrayPrefix + base,
                nextIndex: semicolonIndex + 1
            };
        }

        // Unknown descriptor; treat as "unknown" to avoid crashing
        return {
            type: arrayPrefix + "unknown",
            nextIndex: i + 1
        };
    }

    /**
     * Get the Java param types for the method.
     * E.g. ["I", "Ljava/lang/String;", "[I"]
     */
    public get params (): string[] {
        return this._params;
    }

    /**
     * Get the Java param types as native jtypes (e.g. jint, jstring, jintArray).
     */
    public get nativeParams (): string[] {
        const nativeParams: string[] = [];
        this._params.forEach((p: string): void => {
            const nativeJType = Types.convertJTypeToNativeJType(p);

            nativeParams.push(nativeJType);
        });
        return nativeParams;
    }

    /**
     * Get the Java params as Frida native types (e.g. "int", "pointer").
     */
    public get fridaParams (): string[] {
        const fridaParams: string[] = [];
        this._params.forEach((p: string): void => {
            const nativeJType = Types.convertJTypeToNativeJType(p);
            const fridaType = Types.convertNativeJTypeToFridaType(nativeJType);

            fridaParams.push(fridaType);
        });
        return fridaParams;
    }

    /**
     * Get the Java return type of the method.
     */
    public get ret (): string {
        return this._ret;
    }

    /**
     * Get the Java return type as a Frida native type.
     */
    public get fridaRet (): string {
        const jTypeRet = Types.convertJTypeToNativeJType(this._ret);
        return Types.convertNativeJTypeToFridaType(jTypeRet);
    }

    public get signature(): string {
        return this._signature;
    }
}

export { JavaMethod };