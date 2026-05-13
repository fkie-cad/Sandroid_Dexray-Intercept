import { Java, JavaWrapper } from "./javalib.js";
import { hookError } from "./error_utils.js";

/**
 * Wraps Java.perform with availability check and error isolation.
 *
 * Does:
 * - Checks Java.available before calling Java.perform
 * - Catches and logs any exception thrown from the callback
 * - Does not rethrow — sibling install calls are unaffected on failure
 *
 * @param context  Hook context for error logging, e.g. "aes:install_aes_secrets"
 * @param fn       Hook installation logic to run inside Java.perform
 */
export function safePerform(context: string, fn: () => void): void {
    if (!Java.available) {
        hookError(context, new Error("Java runtime not available"));
        return;
    }
    try {
        Java.perform(fn);
    } catch (error) {
        hookError(context, error);
    }
}

/**
 * Safe alternative to Java.use — returns null instead of throwing.
 *
 * Does:
 * - Resolves the Java class by name
 * - Returns null and logs if class is not available in the target app
 *
 * Caller must null-check the result before use.
 *
 * @param className  Fully qualified Java class name
 * @param context    Hook context for error logging
 */
export function safeUse(className: string, context: string): JavaWrapper | null {
    try {
        return Java.use(className);
    } catch (error) {
        hookError(`${context}:${className}`, error);
        return null;
    }
}

/**
 * Safe alternative to method.overload() — returns null instead of throwing.
 *
 * Does:
 * - Resolves the specific overload by signature
 * - Returns null and logs if the overload does not exist (e.g. API level differences)
 *
 * Caller must null-check before assigning .implementation.
 *
 * @param method      Java method object
 * @param context     Hook context for error logging
 * @param signatures  Java type signatures for the target overload
 */
export function safeOverload(
    method: any,
    context: string,
    ...signatures: string[]
): any | null {
    if (!method) {
        hookError(
            `${context}:overload[${signatures.join(", ")}]`,
            new Error("Method is null or undefined")
        );
        return null;
    }
    try {
        return method.overload(...signatures);
    } catch (error) {
        hookError(`${context}:overload[${signatures.join(", ")}]`, error);
        return null;
    }
}

/**
 * HOF wrapper for .implementation assignments — runtime error isolation.
 *
 * Does:
 * - Returns a regular function (required for correct Frida 'this' injection)
 * - Forwards 'this' (the Java object instance) to hookLogic and to the fallback
 * - Injects original as the first argument to hookLogic
 * - On failure: logs error and calls through to original — app behavior is preserved
 *
 * hookLogic signature: function(original, ...methodArgs) — 'this' is the Java instance
 *
 * @param context    Hook context for error logging
 * @param original   Original method for guaranteed call-through on failure
 * @param hookLogic  Hook body — first param is always original, then method args
 */
export function safeImplementation(
    context: string,
    original: any,
    hookLogic: (original: any, ...args: any[]) => any
): (...args: any[]) => any {
    return function (this: any, ...args: any[]): any {
        try {
            return hookLogic.apply(this, [original, ...args]);
        } catch (error) {
            hookError(context, error);
            return original.apply(this, args);
        }
    };
}

/**
 * Wraps setImmediate/setTimeout callbacks with their own error boundary.
 *
 * Does:
 * - Catches and logs exceptions thrown inside the deferred callback
 *
 * Because:
 * - Deferred callbacks execute after the install function has returned
 * - The install-time try-catch is gone by then — failures are otherwise silent
 *
 * @param context  Hook context for error logging
 * @param fn       The deferred function to wrap
 */
export function safeDeferred(context: string, fn: () => void): () => void {
    return function (): void {
        try {
            fn();
        } catch (error) {
            hookError(`${context}:deferred`, error);
        }
    };
}