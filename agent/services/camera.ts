import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { hook_config } from "../hooking_profile_loader.js"

const PROFILE_HOOKING_TYPE: string = "CAMERA"
const HOOK_NAME = 'camera_hooks'

function createCameraEvent(eventType: string, data: any): void {
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

function hook_camera(){
    Java.perform(() => {
        try {
            const Camera = Java.use("android.hardware.Camera");
            const Camera2CameraManager = Java.use("android.hardware.camera2.CameraManager");
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();

            // Hook Camera.open methods (legacy API)
            if (Camera.open) {
                Camera.open.overload().implementation = function() {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = this.open();
                    
                    createCameraEvent("camera.legacy.open", {
                        library: 'android.hardware.Camera',
                        method: 'open',
                        camera_id: 'default',
                        success: result !== null,
                        stack_trace: Where(stack)
                    });
                    
                    return result;
                };

                Camera.open.overload('int').implementation = function(cameraId: number) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = this.open(cameraId);
                    
                    createCameraEvent("camera.legacy.open", {
                        library: 'android.hardware.Camera',
                        method: 'open',
                        camera_id: cameraId,
                        success: result !== null,
                        stack_trace: Where(stack)
                    });
                    
                    return result;
                };
            }

            // Hook Camera2 CameraManager methods
            if (Camera2CameraManager.openCamera) {
                Camera2CameraManager.openCamera.overload('java.lang.String', 'android.hardware.camera2.CameraDevice$StateCallback', 'android.os.Handler').implementation = function(cameraId: string, callback: any, handler: any) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    
                    createCameraEvent("camera.camera2.open", {
                        library: 'android.hardware.camera2.CameraManager',
                        method: 'openCamera',
                        camera_id: cameraId,
                        has_callback: callback !== null,
                        has_handler: handler !== null,
                        stack_trace: Where(stack)
                    });
                    
                    return this.openCamera(cameraId, callback, handler);
                };
            }

            // Hook getCameraIdList
            if (Camera2CameraManager.getCameraIdList) {
                Camera2CameraManager.getCameraIdList.implementation = function() {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = this.getCameraIdList();
                    
                    createCameraEvent("camera.camera2.get_camera_list", {
                        library: 'android.hardware.camera2.CameraManager',
                        method: 'getCameraIdList',
                        camera_count: result ? result.length : 0,
                        camera_ids: result ? result : [],
                        stack_trace: Where(stack)
                    });
                    
                    return result;
                };
            }

        } catch (error) {
            createCameraEvent("camera.error", {
                error_message: (error as Error).toString(),
                error_type: "hook_camera"
            });
        }
    });
}



export function install_camera_hooks(){
    devlog("\n")
    devlog("install camera hooks");

    try {
        hook_camera();
    } catch (error) {
        devlog(`[HOOK] Failed to install camera hooks: ${error}`);
    }
}