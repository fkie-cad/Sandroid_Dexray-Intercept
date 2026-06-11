import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "CAMERA"

function createCameraEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

/**
 * Camera instrumentation (legacy Camera + Camera2).
 *
 * Original version used raw Java.perform + Java.use and direct implementation
 * overrides. This version uses:
 *   - safePerform      for Java.perform
 *   - safeUse          for class lookup
 *   - safeOverload     for overloaded methods
 *   - safeImplementation for per-method error isolation
 */


function hook_camera() {
    safePerform("camera:hook_camera", () => {
        const Thread = safeUse("java.lang.Thread", "camera:hook_camera");
        if (!Thread) return;
        const threadInstance = Thread.$new();

        // --- Legacy Camera API (android.hardware.Camera) ---

        const Camera = safeUse("android.hardware.Camera", "camera:hook_camera");
        if (Camera) {
            // Camera.open() - default camera
            // Hook Camera.open methods (legacy API)
            const cameraOpenDefault = safeOverload(
                Camera.open,
                "camera:Camera.open[default]"
            );
            if (cameraOpenDefault) {
                cameraOpenDefault.implementation = safeImplementation(
                    "camera:Camera.open[default]",
                    cameraOpenDefault,
                    function (original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);

                        createCameraEvent("camera.legacy.open", {
                            library: "android.hardware.Camera",
                            method: "open",
                            camera_id: "default",
                            success: result !== null,
                            stack_trace: Where(stack)
                        });

                        return result;
                    }
                );
            }

            // Camera.open(int cameraId)
            const cameraOpenWithId = safeOverload(
                Camera.open,
                "camera:Camera.open[int]",
                "int"
            );
            if (cameraOpenWithId) {
                cameraOpenWithId.implementation = safeImplementation(
                    "camera:Camera.open[int]",
                    cameraOpenWithId,
                    function (original, cameraId: number) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this, cameraId);

                        createCameraEvent("camera.legacy.open", {
                            library: "android.hardware.Camera",
                            method: "open",
                            camera_id: cameraId,
                            success: result !== null,
                            stack_trace: Where(stack)
                        });

                        return result;
                    }
                );
            }
        }

        // --- Camera2 API (android.hardware.camera2.CameraManager) ---

        const Camera2CameraManager = safeUse(
            "android.hardware.camera2.CameraManager",
            "camera:hook_camera"
        );
        if (Camera2CameraManager) {
            // CameraManager.openCamera(String cameraId, StateCallback, Handler)
            const openCameraRef = safeOverload(
                Camera2CameraManager.openCamera,
                "camera:CameraManager.openCamera",
                "java.lang.String",
                "android.hardware.camera2.CameraDevice$StateCallback",
                "android.os.Handler"
            );
            // Hook Camera2 CameraManager methods
            if (openCameraRef) {
                openCameraRef.implementation = safeImplementation(
                    "camera:CameraManager.openCamera",
                    openCameraRef,
                    function (original, cameraId: string, callback: any, handler: any) {
                        const stack = threadInstance.currentThread().getStackTrace();

                        createCameraEvent("camera.camera2.open", {
                            library: "android.hardware.camera2.CameraManager",
                            method: "openCamera",
                            camera_id: cameraId,
                            has_callback: callback !== null,
                            has_handler: handler !== null,
                            stack_trace: Where(stack)
                        });

                        return original.call(this, cameraId, callback, handler);
                    }
                );
            }

            // CameraManager.getCameraIdList()
            const getCameraIdListRef = Camera2CameraManager.getCameraIdList;
            // Hook getCameraIdList
            if (getCameraIdListRef) {
                getCameraIdListRef.implementation = safeImplementation(
                    "camera:CameraManager.getCameraIdList",
                    getCameraIdListRef,
                    function (original) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        const result = original.call(this);

                        createCameraEvent("camera.camera2.get_camera_list", {
                            library: "android.hardware.camera2.CameraManager",
                            method: "getCameraIdList",
                            camera_count: result ? result.length : 0,
                            camera_ids: result ? result : [],
                            stack_trace: Where(stack)
                        });

                        return result;
                    }
                );
            }
        }
    });
}

export function install_camera_hooks() {
    devlog("\n");
    devlog("install camera hooks");

    try {
        hook_camera();
    } catch (error) {
        devlog(`[HOOK] Failed to install camera hooks: ${error}`);
    }
}