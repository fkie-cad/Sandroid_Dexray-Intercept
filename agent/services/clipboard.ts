import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "CLIPBOARD"

function createClipboardEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

/**
 * Clipboard instrumentation (based on AppMon’s clipboard hooks).
 *  https://github.com/dpnishant/appmon/tree/master/scripts/Android
 *  https://github.com/dpnishant/appmon/blob/master/scripts/Android/Clipboard/Clipboard.js
 *
 * Original version used raw Java.perform + Java.use and a single try/catch.
 * This version wraps installation and method hooks via:
 *   - safePerform   (Java.perform boundary)
 *   - safeUse       (class resolution)
 *   - safeImplementation (method implementation boundary)
 */
function hook_clipboard() {
    safePerform("clipboard:hook_clipboard", () => {
        const ClipboardManager = safeUse(
            "android.content.ClipboardManager",
            "clipboard:hook_clipboard"
        );
        if (!ClipboardManager) return;

        const Thread = safeUse(
            "java.lang.Thread",
            "clipboard:hook_clipboard"
        );
        if (!Thread) return;

        const threadInstance = Thread.$new();

        // Hook setPrimaryClip(ClipData)
        const setPrimaryClipRef = ClipboardManager.setPrimaryClip;
        if (setPrimaryClipRef) {
            setPrimaryClipRef.implementation = safeImplementation(
                "clipboard:ClipboardManager.setPrimaryClip",
                setPrimaryClipRef,
                function (original, clip: any) {
                    const stack = threadInstance.currentThread().getStackTrace();

                    try {
                        const itemCount = clip ? clip.getItemCount() : 0;

                        for (let i = 0; i < itemCount; i++) {
                            const item = clip.getItemAt(i);
                            let contentType = "unknown";
                            let content: string | null = null;

                            try {
                                if (item.getIntent()) {
                                    contentType = "intent";
                                    content = item.getIntent().toString();
                                } else if (item.getHtmlText()) {
                                    contentType = "html_text";
                                    content = item.getHtmlText().toString();
                                } else if (item.getUri()) {
                                    contentType = "uri";
                                    content = item.getUri().toString();
                                } else if (item.getText()) {
                                    contentType = "text";
                                    content = item.getText().toString();
                                } else {
                                    contentType = "string";
                                    content = item.toString();
                                }
                            } catch (inner) {
                                contentType = "error";
                                content = `<error extracting item: ${inner}>`;
                            }

                            createClipboardEvent("clipboard.set_primary_clip", {
                                library: "android.content.ClipboardManager",
                                method: "setPrimaryClip",
                                item_index: i,
                                total_items: itemCount,
                                content_type: contentType,
                                content: content,
                                content_length: content ? content.length : 0,
                                stack_trace: Where(stack)
                            });
                        }
                    } catch (e) {
                        createClipboardEvent("clipboard.set_primary_clip_internal_error", {
                            error_message: (e as Error).toString(),
                            library: "android.content.ClipboardManager",
                            method: "setPrimaryClip",
                            stack_trace: Where(stack)
                        });
                    }

                    return original.call(this, clip);
                }
            );
        }

        // Hook getPrimaryClip()
        // Hook getPrimaryClip to also track clipboard reads
        const getPrimaryClipRef = ClipboardManager.getPrimaryClip;
        if (getPrimaryClipRef) {
            getPrimaryClipRef.implementation = safeImplementation(
                "clipboard:ClipboardManager.getPrimaryClip",
                getPrimaryClipRef,
                function (original) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = original.call(this);

                    createClipboardEvent("clipboard.get_primary_clip", {
                        library: "android.content.ClipboardManager",
                        method: "getPrimaryClip",
                        has_clip: result !== null,
                        item_count: result ? result.getItemCount() : 0,
                        stack_trace: Where(stack)
                    });

                    return result;
                }
            );
        }
    });
}

export function install_clipboard_hooks() {
    devlog("\n");
    devlog("install clipboard hooks");

    try {
        hook_clipboard();
    } catch (error) {
        devlog(`[HOOK] Failed to install clipboard hooks: ${error}`);
    }
}

