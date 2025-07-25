import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"

const PROFILE_HOOKING_TYPE: string = "CAMERA"

/**
 * 
 * 
 * 
 */

function hook_camera(){

}



export function install_camera_hooks(){
    devlog("\n")
    devlog("install camera hooks");
    hook_camera();

}