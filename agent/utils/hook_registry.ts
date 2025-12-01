/**
 * Hook Registry - Manages native hook lifecycle for runtime reconfiguration
 *
 * This module tracks native Interceptor.attach() hooks and allows them to be
 * detached/reattached at runtime when hooks are enabled/disabled via the API.
 */

import { devlog } from "./logging.js";

interface NativeHookEntry {
    id: string;
    hookName: string;  // Config key like 'socket_hooks', 'file_system_hooks'
    target: NativePointer;
    callbacks: InvocationListenerCallbacks;
    listener: InvocationListener | null;
}

/**
 * Registry for managing native hooks with detach/reattach capability
 */
class HookRegistry {
    private nativeHooks: Map<string, NativeHookEntry> = new Map();

    /**
     * Register and attach a native hook
     *
     * @param id - Unique identifier for this hook (e.g., 'socket_hooks.libc.socket')
     * @param hookName - Config key (e.g., 'socket_hooks')
     * @param target - Target function pointer
     * @param callbacks - Frida InvocationListenerCallbacks (onEnter/onLeave)
     * @returns The attached InvocationListener
     */
    registerNativeHook(
        id: string,
        hookName: string,
        target: NativePointer,
        callbacks: InvocationListenerCallbacks
    ): InvocationListener {
        // Attach the hook
        const listener = Interceptor.attach(target, callbacks);

        // Store for later management
        this.nativeHooks.set(id, {
            id,
            hookName,
            target,
            callbacks,
            listener
        });

        devlog(`[HookRegistry] Registered native hook: ${id} (${hookName})`);
        return listener;
    }

    /**
     * Enable or disable all native hooks for a given hook name
     *
     * @param hookName - Config key (e.g., 'socket_hooks')
     * @param enabled - Whether to enable or disable
     */
    setNativeHooksEnabled(hookName: string, enabled: boolean): void {
        let affected = 0;

        for (const [id, entry] of this.nativeHooks) {
            if (entry.hookName !== hookName) continue;

            if (enabled && entry.listener === null) {
                // Reattach the hook
                try {
                    entry.listener = Interceptor.attach(entry.target, entry.callbacks);
                    affected++;
                    devlog(`[HookRegistry] Reattached: ${id}`);
                } catch (e) {
                    devlog(`[HookRegistry] Failed to reattach ${id}: ${e}`);
                }
            } else if (!enabled && entry.listener !== null) {
                // Detach the hook
                try {
                    entry.listener.detach();
                    entry.listener = null;
                    affected++;
                    devlog(`[HookRegistry] Detached: ${id}`);
                } catch (e) {
                    devlog(`[HookRegistry] Failed to detach ${id}: ${e}`);
                }
            }
        }

        if (affected > 0) {
            devlog(`[HookRegistry] ${enabled ? 'Enabled' : 'Disabled'} ${affected} native hooks for ${hookName}`);
        }
    }

    /**
     * Check if any native hooks are registered for a hook name
     */
    hasNativeHooks(hookName: string): boolean {
        for (const entry of this.nativeHooks.values()) {
            if (entry.hookName === hookName) return true;
        }
        return false;
    }

    /**
     * Get list of all registered hook IDs
     */
    getRegisteredHooks(): string[] {
        return Array.from(this.nativeHooks.keys());
    }

    /**
     * Get statistics about registered hooks
     */
    getStats(): { total: number; attached: number; detached: number } {
        let attached = 0;
        let detached = 0;

        for (const entry of this.nativeHooks.values()) {
            if (entry.listener !== null) {
                attached++;
            } else {
                detached++;
            }
        }

        return { total: this.nativeHooks.size, attached, detached };
    }
}

// Singleton instance
export const hookRegistry = new HookRegistry();
