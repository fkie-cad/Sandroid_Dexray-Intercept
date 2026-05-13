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