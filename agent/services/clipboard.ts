import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"


const PROFILE_HOOKING_TYPE: string = "CLIPBOARD"
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
        const Context = Java.use("android.content.Context");
        const ClipboardManager = Java.use("android.content.ClipboardManager");

        ClipboardManager.setPrimaryClip.implementation = function(clip: any) {
            for (let i = 0; i < clip.getItemCount(); i++) {
                let send_data: any = {
                    event_type: 'Java::Clipboard',
                    lib: 'android.content.ClipboardManager',
                    method: 'setPrimaryClip',
                    artifact: []
                };
                let data: any = { argSeq: 0 };

                if (clip.getItemAt(i).getIntent()) {
                    data.name = "Intent";
                    data.value = clip.getItemAt(i).getIntent().toString();
                } else if (clip.getItemAt(i).getHtmlText()) {
                    data.name = "HTML Text";
                    data.value = clip.getItemAt(i).getHtmlText().toString();
                } else if (clip.getItemAt(i).getUri()) {
                    data.name = "URI";
                    data.value = clip.getItemAt(i).getUri().toString();
                } else if (clip.getItemAt(i).getText()) {
                    data.name = "Text";
                    data.value = clip.getItemAt(i).getText().toString();
                } else {
                    data.name = "String";
                    data.value = clip.getItemAt(i).toString();
                }

                send_data.artifact.push(data);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
            }
            return this.setPrimaryClip.apply(this, arguments);
        };
    });

}




export function install_clipboard_hooks(){
    devlog("\n")
    devlog("install clipboard hooks");
    hook_clipboard();

}

