import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { hook_config } from "../hooking_profile_loader.js"

const PROFILE_HOOKING_TYPE: string = "CLIPBOARD"
const HOOK_NAME = 'clipboard_hooks'

function createClipboardEvent(eventType: string, data: any): void {
    // Check if hook is enabled at runtime
    if (!hook_config[HOOK_NAME]) {
        return;
    }
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}
/**
 * 
/**
 * https://github.com/dpnishant/appmon/tree/master/scripts/Android
 * 
 * https://github.com/dpnishant/appmon/blob/master/scripts/Android/Clipboard/Clipboard.js
 * 
 */

function hook_clipboard(){
    Java.perform(() => {
        try {
            const Context = Java.use("android.content.Context");
            const ClipboardManager = Java.use("android.content.ClipboardManager");
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();

            ClipboardManager.setPrimaryClip.implementation = function(clip: any) {
                const stack = threadInstance.currentThread().getStackTrace();
                
                for (let i = 0; i < clip.getItemCount(); i++) {
                    const item = clip.getItemAt(i);
                    let contentType = "unknown";
                    let content = null;

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

                    createClipboardEvent("clipboard.set_primary_clip", {
                        library: 'android.content.ClipboardManager',
                        method: 'setPrimaryClip',
                        item_index: i,
                        total_items: clip.getItemCount(),
                        content_type: contentType,
                        content: content,
                        content_length: content ? content.length : 0,
                        stack_trace: Where(stack)
                    });
                }
                
                return this.setPrimaryClip.apply(this, arguments);
            };

            // Hook getPrimaryClip to also track clipboard reads
            ClipboardManager.getPrimaryClip.implementation = function() {
                const stack = threadInstance.currentThread().getStackTrace();
                const result = this.getPrimaryClip();
                
                createClipboardEvent("clipboard.get_primary_clip", {
                    library: 'android.content.ClipboardManager',
                    method: 'getPrimaryClip',
                    has_clip: result !== null,
                    item_count: result ? result.getItemCount() : 0,
                    stack_trace: Where(stack)
                });
                
                return result;
            };

        } catch (error) {
            createClipboardEvent("clipboard.error", {
                error_message: (error as Error).toString(),
                error_type: "hook_clipboard"
            });
        }
    });
}




export function install_clipboard_hooks(){
    devlog("\n")
    devlog("install clipboard hooks");

    try {
        hook_clipboard();
    } catch (error) {
        devlog(`[HOOK] Failed to install clipboard hooks: ${error}`);
    }
}

