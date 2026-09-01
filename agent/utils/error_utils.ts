import { devlog } from "./logging.js";

/**
 * Normalizes any caught value to an Error instance.
 *
 * Does:
 * - Returns value unchanged if already an Error
 * - Wraps non-Error thrown values (strings, numbers, objects) in a new Error
 * - Falls back to placeholder message if value cannot be stringified
 */
export function ensureError(value: unknown): Error {
    if (value instanceof Error) return value;

    let stringified = "[Unable to stringify thrown value]";
    try {
        stringified = JSON.stringify(value);
    } catch {
        try {
            stringified = String(value);
        } catch {
            // absolute fallback
        }
    }

    return new Error(`Non-Error value thrown: ${stringified}`);
}

/**
 * Single logging point for all hook failures.
 *
 * Does:
 * - Normalizes any thrown value to Error via ensureError
 * - Logs with context prefix via devlog
 *
 * @param context  Where the failure occurred — convention: "module:class.method"
 * @param error    Raw caught value, any type
 */
export function hookError(context: string, error: unknown): void {
    const normalized = ensureError(error);
    devlog(`[HOOK ERROR] [${context}] ${normalized.message}`);
}

/**
 * Single logging point for exceptions deliberately propagated from a hook's
 * call-through to the original implementation (see PropagateException).
 *
 * Unlike hookError, this does not indicate a failure in the hook itself - the
 * hook ran successfully and the underlying original call threw its own
 * exception (e.g. a legitimate negative-path result from the target app or
 * platform). Logged for diagnostic visibility only.
 *
 * @param context  Where the call-through occurred — same convention as hookError
 * @param cause    The original exception being propagated, unwrapped
 */
export function hookPropagate(context: string, cause: unknown): void {
    const normalized = ensureError(cause);
    devlog(`[HOOK PROPAGATE] [${context}] ${normalized.message}`);
}