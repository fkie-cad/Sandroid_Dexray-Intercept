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

    for (const addr of bt) {
        try {
            const addressStr = addr.toString();
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
        }
    }

    return frames.length > 0 ? frames : undefined;
}

export function collectNativeBacktrace(context?: CpuContext): NativeBacktraceFrame[] | undefined {
    if (!enable_stacktrace || !context) {
        return undefined;
    }

    try {
        return buildBacktrace(Thread.backtrace(context, Backtracer.ACCURATE));
    } catch (e) {
        devlog(`[stacktrace] Failed to collect native backtrace: ${e}`);
        return undefined;
    }
}