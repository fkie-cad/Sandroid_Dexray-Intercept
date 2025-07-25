import { log, devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "IPC_INTENT"


function hook(intent: any): void {
    const text: string[] = [];
    let tmp: any = null;

    tmp = intent.getComponent();
    if (tmp) {
        text.push(`Activity: ${tmp.getClassName()}`);
    }
    tmp = intent.getAction();
    if (tmp) {
        text.push(`Action: ${tmp}`);
    }
    tmp = intent.getData();
    if (tmp) {
        text.push(`URI: ${tmp}`);
    }
    tmp = intent.getType();
    if (tmp) {
        text.push(`Type: ${tmp}`);
    }
    tmp = intent.getExtras();
    if (tmp) {
        const keys = tmp.keySet().iterator();
        while (keys.hasNext()) {
            const key = keys.next();
            let value = tmp.get(key);
            let type = "null";
            if (value) {
                try {
                    type = value.getClass().getSimpleName();
                    if (value.getClass().isArray()) {
                        value = Java.use('org.json.JSONArray').$new(value);
                    }
                    value = value.toString();
                } catch (error) {
                    value = null;
                }
            }
            text.push(value ? `Extras: ${key} (${type}): ${value}` : `Extras: ${key} (${type})`);
        }
    }
    text.push("--------------------");
    am_send(PROFILE_HOOKING_TYPE,text.join("\n"));
}

function hookGetData(this: any): any {
    hook(this);
    return this.getData();
}

function hookGetIntent(this: any): any {
    const intent = this.getIntent();
    hook(intent);
    return intent;
}


function intent_hooks(){
setTimeout(() => {
    Java.perform(() => {
        const Intent = Java.use("android.content.Intent");
        Intent.getData.implementation = hookGetData;
        // const Activity = Java.use("android.app.Activity");
        // Activity.getIntent.implementation = hookGetIntent;
    });
}, 0);
}


export function install_intent_hooks(){
    devlog("\n")
    devlog("install intent hooks");
    intent_hooks();

}