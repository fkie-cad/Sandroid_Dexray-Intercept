/**
 * safe_native.ts
 *
 * Native-side counterpart to safe_java.ts.
 *
 * Where safe_java.ts isolates failures in Java.perform / Java.use / overload /
 * .implementation, this module isolates failures in native symbol resolution,
 * Interceptor.attach, Interceptor.replace and NativeFunction construction.
 *
 * Same contract as safe_java.ts:
 *   - Resolution helpers return null (and log) instead of throwing. The caller
 *     null-checks and bails out, so one missing symbol never aborts an install.
 *   - Hook bodies run inside an error boundary so a bad hook never takes down
 *     sibling installs, and never leaks an exception into Frida's runtime.
 *
 * KEY DIFFERENCE FROM THE JAVA SIDE:
 *   Interceptor.attach is OBSERVATIONAL — the original native function always
 *   runs regardless of whether onEnter/onLeave throws. So the attach boundary
 *   only needs to catch + log; there is nothing to "call through" to.
 *   The call-through pattern from safeImplementation only has a native analog
 *   for Interceptor.replace, where YOUR NativeCallback is the function and the
 *   original runs only if you invoke it. That lives in safeReplace below.
 *
 * Module / NativeFunction / Interceptor / NativeCallback are ambient frida-gum
 * globals, so (unlike Java in safe_java.ts) nothing is imported for them.
 */

import { hookError } from "./error_utils.js";

/**
 * Keeps NativeCallback / NativeFunction references alive for the lifetime of a
 * replacement. Without this, the GC can collect the callback out from under
 * Interceptor.replace and the process crashes the next time the hook fires.
 */
const retained: any[] = [];

/**
 * Safe alternative to native export resolution — returns null instead of throwing.
 *
 * Does:
 * - Resolves an exported symbol to its absolute address
 * - Returns null and logs if the module or symbol is not present
 *   (library not loaded yet, stripped symbol, API-level / arch differences)
 *
 * Caller must null-check before passing the result to safeAttach / safeReplace.
 *
 * Frida 17+ note: the static Module.findExportByName/getExportByName are gone.
 * All resolution is centralised here, so a Frida 16 <-> 17 move is a one-liner:
 *   Frida 16: const a = Module.findExportByName(moduleName, exportName);
 *   Frida 17: as written below (global lookup when moduleName === null).
 *
 * @param moduleName Module to search, or null for a (slower) global lookup
 * @param exportName Exported symbol name, e.g. "open", "EVP_DecryptInit_ex"
 * @param context    Hook context for error logging, e.g. "native_crypto:install"
 */
export function safeResolveExport(
  moduleName: string | null,
  exportName: string,
  context: string
): NativePointer | null {
  try {
    const address =
      moduleName === null
        ? Module.findGlobalExportByName(exportName)
        : Process.findModuleByName(moduleName)?.findExportByName(exportName) ?? null;

    if (address === null) {
      hookError(
        `${context}:${exportName}`,
        new Error(
          `Native export not found: ${exportName}` +
            (moduleName ? ` in ${moduleName}` : " (global)")
        )
      );
      return null;
    }
    return address;
  } catch (error) {
    hookError(`${context}:${exportName}`, error);
    return null;
  }
}

/**
 * Safe alternative to `new NativeFunction(...)` — returns null instead of throwing.
 *
 * Does:
 * - Builds a callable wrapper for a native function at a resolved address
 * - Returns null and logs on a null address or signature mismatch
 *
 * Mirrors safeOverload: it produces the callable you will actually invoke, and
 * the caller null-checks before use.
 *
 * @param address  Resolved function address (e.g. from safeResolveExport)
 * @param retType  Return type, e.g. "int", "pointer", "void"
 * @param argTypes Argument types, e.g. ["pointer", "int"]
 * @param context  Hook context for error logging
 * @param options  Optional NativeFunctionOptions (abi, scheduling, exceptions...)
 */
export function safeNativeFunction(
  address: NativePointer | null,
  retType: NativeFunctionReturnType,
  argTypes: NativeFunctionArgumentType[],
  context: string,
  options?: NativeFunctionOptions
): NativeFunction<any, any> | null {
  if (!address || address.isNull()) {
    hookError(`${context}:NativeFunction`, new Error("Address is null or undefined"));
    return null;
  }
  try {
    return new NativeFunction(address, retType, argTypes, options);
  } catch (error) {
    hookError(`${context}:NativeFunction`, error);
    return null;
  }
}

/**
 * Internal: wrap a single onEnter / onLeave callback in an error boundary.
 *
 * Does:
 * - Returns a regular function (required for correct Frida 'this' injection —
 *   'this' is the InvocationContext, used to carry state from onEnter to onLeave)
 * - Catches and logs any exception thrown inside the callback body
 *
 * Because:
 * - attach is observational: the original native function runs no matter what.
 *   Swallowing here keeps Frida's global error path clean and sibling hooks
 *   alive. There is nothing to call through to.
 */
function wrapInvocationCallback<TArg>(
  context: string,
  phase: "onEnter" | "onLeave",
  fn: (this: InvocationContext, arg: TArg) => void
): (this: InvocationContext, arg: TArg) => void {
  return function (this: InvocationContext, arg: TArg): void {
    try {
      fn.call(this, arg);
    } catch (error) {
      hookError(`${context}:${phase}`, error);
    }
  };
}

/**
 * Safe alternative to Interceptor.attach — per-hook error isolation.
 *
 * Does:
 * - Null-checks the target (skips + logs if resolution failed upstream)
 * - Wraps onEnter / onLeave in their own error boundaries
 * - Omits any callback you didn't supply (Frida perf recommendation)
 * - Returns the InvocationListener on success, or null on failure so the
 *   surrounding install function keeps going
 *
 * State passed onEnter -> onLeave via 'this' survives the wrapper. If onEnter
 * can throw before stashing a value on 'this', guard for undefined in onLeave.
 *
 * @param target    Resolved function address (e.g. from safeResolveExport), or null
 * @param context   Hook context for error logging, e.g. "native_open:install"
 * @param callbacks { onEnter?, onLeave? } — same shape as Interceptor.attach
 */
export function safeAttach(
  target: NativePointer | null,
  context: string,
  callbacks: {
    onEnter?: (this: InvocationContext, args: InvocationArguments) => void;
    onLeave?: (this: InvocationContext, retval: InvocationReturnValue) => void;
  }
): InvocationListener | null {
  if (!target || target.isNull()) {
    hookError(context, new Error("Attach target is null or undefined"));
    return null;
  }

  const wrapped: {
    onEnter?: (this: InvocationContext, args: InvocationArguments) => void;
    onLeave?: (this: InvocationContext, retval: InvocationReturnValue) => void;
  } = {};

  if (callbacks.onEnter) {
    wrapped.onEnter = wrapInvocationCallback(context, "onEnter", callbacks.onEnter);
  }
  if (callbacks.onLeave) {
    wrapped.onLeave = wrapInvocationCallback(context, "onLeave", callbacks.onLeave);
  }

  try {
    return Interceptor.attach(target, wrapped);
  } catch (error) {
    hookError(context, error);
    return null;
  }
}

/**
 * Convenience: resolve an export and attach to it in one call.
 *
 * The 90% case — collapses safeResolveExport + safeAttach so install functions
 * stay flat. Returns null (already logged) if either resolution or attach fails.
 *
 * @param moduleName Module name, or null for a global lookup
 * @param exportName Exported symbol to hook
 * @param context    Hook context for error logging
 * @param callbacks  { onEnter?, onLeave? }
 */
export function safeAttachExport(
  moduleName: string | null,
  exportName: string,
  context: string,
  callbacks: {
    onEnter?: (this: InvocationContext, args: InvocationArguments) => void;
    onLeave?: (this: InvocationContext, retval: InvocationReturnValue) => void;
  }
): InvocationListener | null {
  const address = safeResolveExport(moduleName, exportName, context);
  if (!address) return null;
  return safeAttach(address, `${context}:${exportName}`, callbacks);
}

/**
 * Safe alternative to Interceptor.replace — the native analog of safeImplementation.
 *
 * Does:
 * - Installs a NativeCallback wrapping your logic in place of the function
 * - Builds a call-through handle to the ORIGINAL so your logic can proceed
 * - On failure inside your logic: logs the error and calls the ORIGINAL with the
 *   same args — target behavior is preserved, exactly like safeImplementation
 * - Retains the callback + original so the GC can't collect them mid-hook
 *
 * Unlike attach, replace hands you full control: the original only runs if YOU
 * call it. replaceLogic receives `original` as its first argument (call it to
 * proceed), then the native args. 'this' is the CallbackContext.
 *
 * CALL-THROUGH SAFETY (Frida 17): the original is taken from the pointer that
 * Interceptor.replaceFast returns, NOT from the (now-patched) target address.
 * That pointer is a non-re-entrant trampoline, so calling `original(...)` runs
 * the real function instead of recursing back into this replacement. We fall
 * back to plain Interceptor.replace on older Frida builds that lack replaceFast.
 *
 * The signature (retType / argTypes) MUST match the real function, otherwise
 * arguments and return values are marshalled wrong.
 *
 * @param target       Resolved function address, or null
 * @param context      Hook context for error logging
 * @param retType      Native return type
 * @param argTypes     Native argument types
 * @param replaceLogic function(original, ...args) — your replacement body
 * @returns true if the replacement was installed, false otherwise
 */
export function safeReplace(
  target: NativePointer | null,
  context: string,
  retType: NativeFunctionReturnType,
  argTypes: NativeFunctionArgumentType[],
  replaceLogic: (this: any, original: NativeFunction<any, any> | null, ...args: any[]) => any
): boolean {
  if (!target || target.isNull()) {
    hookError(context, new Error("Replace target is null or undefined"));
    return false;
  }

  try {
    // Captured after installation (see below). The NativeCallback body only runs
    // when the replaced function is later called, by which point `original` is set.
    let original: NativeFunction<any, any> | null = null;

    const replacement = new NativeCallback(
      function (this: any, ...args: any[]): any {
        try {
          return replaceLogic.call(this, original, ...args);
        } catch (error) {
          hookError(context, error);
          return original ? original(...args) : undefined; // guaranteed call-through on failure
        }
      },
      // retType/argTypes are typed for NativeFunction (the call-through handle);
      // NativeCallback uses the structurally-identical NativeCallback* unions.
      retType as NativeCallbackReturnType,
      argTypes as NativeCallbackArgumentType[]
    );

    // replaceFast returns a non-re-entrant pointer to the original — the safe
    // way to call through. Plain replace gives no such handle, so on the legacy
    // path we wrap the target address directly (best effort).
    const originalPtr =
      typeof (Interceptor as any).replaceFast === "function"
        ? Interceptor.replaceFast(target, replacement)
        : (Interceptor.replace(target, replacement), target);

    original = new NativeFunction(originalPtr, retType, argTypes);
    retained.push(replacement, original);
    return true;
  } catch (error) {
    hookError(context, error);
    return false;
  }
}

/**
 * Convenience: resolve an export and replace it in one call.
 *
 * Mirror of safeAttachExport for the replace path — collapses safeResolveExport
 * + safeReplace. Returns false (already logged) if resolution or replace fails.
 *
 * @param moduleName   Module name, or null for a global lookup
 * @param exportName   Exported symbol to replace
 * @param context      Hook context for error logging
 * @param retType      Native return type
 * @param argTypes     Native argument types
 * @param replaceLogic function(original, ...args) — your replacement body
 * @returns true if the replacement was installed, false otherwise
 */
export function safeReplaceExport(
  moduleName: string | null,
  exportName: string,
  context: string,
  retType: NativeFunctionReturnType,
  argTypes: NativeFunctionArgumentType[],
  replaceLogic: (this: any, original: NativeFunction<any, any> | null, ...args: any[]) => any
): boolean {
  const address = safeResolveExport(moduleName, exportName, context);
  if (!address) return false;
  return safeReplace(address, `${context}:${exportName}`, retType, argTypes, replaceLogic);
}

/**
 * Safe alternative to Module.enumerateExports() + manual substring matching.
 *
 * Uses Frida's ApiResolver, which is the idiomatic way to find native symbols by
 * glob/substring. It is the right tool here because the symbols we hunt for are
 * C++ mangled (e.g. the export whose name contains "OpenCommon"), so an exact
 * findExportByName is impossible — we genuinely need a pattern search.
 *
 * Why this is "safe":
 * - The "module" resolver is always available on Android (unlike "objc"/"swift").
 * - A glob that matches nothing — because the library isn't loaded or the symbol
 *   is stripped — yields an EMPTY array, never a throw. This folds the old
 *   throwing Process.getModuleByName(...).enumerateExports() pattern (module
 *   lookup could throw, then we iterated in JS) into one non-throwing call.
 * - We still wrap construction/query in a boundary for malformed queries or
 *   unusual platforms, returning [] (already logged) so callers degrade cleanly.
 *
 * NOTE: ApiResolverMatch.name is "moduleName!symbolName" (the module is part of
 * the canonical name), NOT the bare symbol. Use stripModulePrefix() before
 * feeding a match name to safeResolveExport/findExportByName.
 *
 * A fresh resolver is created per call on purpose — frida-gum recommends not
 * reusing a resolver across batches to avoid looking at stale module data.
 *
 * @param query   Resolver query, e.g. "exports:libart.so!*OpenCommon*" (suffix
 *                with "/i" for case-insensitive matching)
 * @param context Hook context for error logging
 */
export function safeEnumerateMatches(query: string, context: string): ApiResolverMatch[] {
  try {
    return new ApiResolver("module").enumerateMatches(query);
  } catch (error) {
    hookError(`${context}:${query}`, error);
    return [];
  }
}

/**
 * Extracts the bare symbol name from an ApiResolverMatch.name of the form
 * "moduleName!symbolName". Returns the input unchanged if there is no "!".
 *
 * Companion to safeEnumerateMatches: ApiResolver reports module-qualified names,
 * but findExportByName / safeResolveExport expect the bare symbol.
 *
 * @param matchName A name from ApiResolverMatch.name, e.g. "libart.so!_ZN3art..."
 */
export function stripModulePrefix(matchName: string): string {
  return matchName.substring(matchName.indexOf("!") + 1);
}

// NOTE on DebugSymbol: the natural home for a safe DebugSymbol.fromAddress
// wrapper would be here, but its only consumer is logging.ts, which sits BELOW
// the error-reporting layer (error_utils -> logging). Routing it through
// hookError would create a logging -> safe_native -> error_utils -> logging
// cycle, so logging.ts guards DebugSymbol.fromAddress inline and silently
// instead. No safe wrapper lives here to avoid an orphaned, uncallable export.
