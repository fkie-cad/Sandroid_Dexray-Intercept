import { enable_stacktrace } from "../hooking_profile_loader.js";
import { Java } from "./javalib.js";
import { devlog } from "./logging.js";

export interface NativeBacktraceFrame {
    address: string;
    module: {
        name: string;
        base: string;
        path: string;
    } | null;
    symbol: {
        address: string;
        name: string | null;
        moduleName: string | null;
    } | null;
}

export type NativeBacktraceMode = "accurate" | "fuzzy";

export function collectJavaStackTrace(): string[] | undefined {
    if (!enable_stacktrace) {
        return undefined;
    }

    try {
        const Thread = Java.use("java.lang.Thread");
        const frames = Thread.currentThread().getStackTrace();
        const out: string[] = [];
        for (let i = 0; i < frames.length; i++) {
            out.push(frames[i].toString());
        }
        return out;
    } catch (e) {
        devlog(`[stacktrace] Failed to collect Java stack trace: ${e}`);
        return undefined;
    }
}

export function buildBacktrace(bt: any): NativeBacktraceFrame[] | undefined {
    if (!bt || !Array.isArray(bt)) {
        return undefined;
    }

    const frames: NativeBacktraceFrame[] = [];
    let previousAddressStr: string | null = null;

    for (const addr of bt) {
        try {
            const addressStr = addr.toString();

            // Thread.backtrace(context, Backtracer.ACCURATE) can return the same
            // address twice in a row when called from an onLeave handler. Skip
            // immediate duplicates only (backlog item: buildBacktrace() dedup fix).
            if (addressStr === previousAddressStr) {
                continue;
            }
            previousAddressStr = addressStr;

            const mod = Process.findModuleByAddress(addr);
            const sym = DebugSymbol.fromAddress(addr);

            frames.push({
                address: addressStr,
                module: mod
                    ? {
                        name: mod.name,
                        base: mod.base.toString(),
                        path: mod.path
                    }
                    : null,
                symbol: sym
                    ? {
                        address: sym.address.toString(),
                        name: sym.name,
                        moduleName: sym.moduleName
                    }
                    : null
            });
        } catch (e) {
            // If anything fails, at least keep the raw address
            frames.push({
                address: addr.toString(),
                module: null,
                symbol: null
            });
            previousAddressStr = null;
        }
    }

    return frames.length > 0 ? frames : undefined;
}

export function collectNativeBacktrace(
    context?: CpuContext,
    mode: NativeBacktraceMode = "accurate"
): NativeBacktraceFrame[] | undefined {
    if (!enable_stacktrace || !context) {
        return undefined;
    }

    try {
        const backtracer = mode === "fuzzy" ? Backtracer.FUZZY : Backtracer.ACCURATE;
        return buildBacktrace(Thread.backtrace(context, backtracer));
    } catch (e) {
        devlog(`[stacktrace] Failed to collect native backtrace: ${e}`);
        return undefined;
    }
}