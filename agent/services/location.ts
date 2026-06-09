import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "LOCATION_ACCESS"

function createLocationEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

/**
 * https://github.com/iddoeldor/frida-snippets?tab=readme-ov-file#change-location
 */

function hook_location() {
    safePerform("location:hook_location", () => {
        const LocationManager = safeUse(
            'android.location.LocationManager',
            "location:hook_location"
        );
        const Location = safeUse(
            'android.location.Location',
            "location:hook_location"
        );
        const threadDef = safeUse('java.lang.Thread', "location:hook_location");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        if (LocationManager) {
            const getLastKnown = safeOverload(
                LocationManager.getLastKnownLocation,
                "location:LocationManager.getLastKnownLocation",
                'java.lang.String'
            );
            if (getLastKnown) {
                getLastKnown.implementation = safeImplementation(
                    "location:LocationManager.getLastKnownLocation",
                    getLastKnown,
                    function(original, provider: string) {
                        const result = original.call(this, provider);
                        const stack = threadInstance.currentThread().getStackTrace();
                        if (result !== null) {
                            const latitude = result.getLatitude();
                            const longitude = result.getLongitude();
                            const accuracy = result.getAccuracy();
                            createLocationEvent("location.last_known_location", {
                                library: 'android.location.LocationManager',
                                method: 'getLastKnownLocation',
                                provider: provider,
                                latitude: latitude,
                                longitude: longitude,
                                accuracy: accuracy,
                                has_location: true,
                                stack_trace: Where(stack)
                            });
                        } else {
                            createLocationEvent("location.last_known_location", {
                                library: 'android.location.LocationManager',
                                method: 'getLastKnownLocation',
                                provider: provider,
                                has_location: false,
                                stack_trace: Where(stack)
                            });
                        }
                        return result;
                    }
                );
            }

            const requestUpdatesBasic = safeOverload(
                LocationManager.requestLocationUpdates,
                "location:LocationManager.requestLocationUpdates",
                'java.lang.String', 'long', 'float', 'android.location.LocationListener'
            );
            if (requestUpdatesBasic) {
                requestUpdatesBasic.implementation = safeImplementation(
                    "location:LocationManager.requestLocationUpdates[basic]",
                    requestUpdatesBasic,
                    function(original, provider: string, minTime: number, minDistance: number, listener: any) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createLocationEvent("location.request_updates", {
                            library: 'android.location.LocationManager',
                            method: 'requestLocationUpdates',
                            provider: provider,
                            min_time_ms: minTime,
                            min_distance_m: minDistance,
                            has_listener: listener !== null,
                            overload: 'basic',
                            stack_trace: Where(stack)
                        });
                        return original.call(this, provider, minTime, minDistance, listener);
                    }
                );
            }

            // API-level conditional overload, safeOverload returns null gracefully if absent
            const requestUpdatesLooper = safeOverload(
                LocationManager.requestLocationUpdates,
                "location:LocationManager.requestLocationUpdates",
                'java.lang.String', 'long', 'float',
                'android.location.LocationListener', 'android.os.Looper'
            );
            if (requestUpdatesLooper) {
                requestUpdatesLooper.implementation = safeImplementation(
                    "location:LocationManager.requestLocationUpdates[with_looper]",
                    requestUpdatesLooper,
                    function(original, provider: string, minTime: number, minDistance: number, listener: any, looper: any) {
                        const stack = threadInstance.currentThread().getStackTrace();
                        createLocationEvent("location.request_updates", {
                            library: 'android.location.LocationManager',
                            method: 'requestLocationUpdates',
                            provider: provider,
                            min_time_ms: minTime,
                            min_distance_m: minDistance,
                            has_listener: listener !== null,
                            has_looper: looper !== null,
                            overload: 'with_looper',
                            stack_trace: Where(stack)
                        });
                        return original.call(this, provider, minTime, minDistance, listener, looper);
                    }
                );
            }
        }

        if (Location) {
            // capture reference before assigning .implementation for non-overload methods
            const getLatitudeRef = Location.getLatitude;
            getLatitudeRef.implementation = safeImplementation(
                "location:Location.getLatitude",
                getLatitudeRef,
                function(original) {
                    const latitude = original.call(this);
                    const stack = threadInstance.currentThread().getStackTrace();
                    createLocationEvent("location.get_latitude", {
                        library: 'android.location.Location',
                        method: 'getLatitude',
                        latitude: latitude,
                        stack_trace: Where(stack)
                    });
                    return latitude;
                }
            );

            const getLongitudeRef = Location.getLongitude;
            getLongitudeRef.implementation = safeImplementation(
                "location:Location.getLongitude",
                getLongitudeRef,
                function(original) {
                    const longitude = original.call(this);
                    const stack = threadInstance.currentThread().getStackTrace();
                    createLocationEvent("location.get_longitude", {
                        library: 'android.location.Location',
                        method: 'getLongitude',
                        longitude: longitude,
                        stack_trace: Where(stack)
                    });
                    return longitude;
                }
            );
        }
    });
}

function hook_playstore_location_api() {
    safePerform("location:hook_playstore_location_api", () => {
        // optional class, safeUse returns null if GMS not present
        const FusedLocationProviderClient = safeUse(
            'com.google.android.gms.location.FusedLocationProviderClient',
            "location:hook_playstore_location_api"
        );
        if (!FusedLocationProviderClient) return;

        const threadDef = safeUse('java.lang.Thread', "location:hook_playstore_location_api");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // zero-argument overload, safeOverload called with no signatures
        const getLastLocation = safeOverload(
            FusedLocationProviderClient.getLastLocation,
            "location:FusedLocationProviderClient.getLastLocation"
        );
        if (getLastLocation) {
            getLastLocation.implementation = safeImplementation(
                "location:FusedLocationProviderClient.getLastLocation",
                getLastLocation,
                function(original) {
                    const stack = threadInstance.currentThread().getStackTrace();
                    const result = original.call(this);
                    createLocationEvent("location.fused_provider.get_last_location", {
                        library: 'com.google.android.gms.location.FusedLocationProviderClient',
                        method: 'getLastLocation',
                        provider: 'google_play_services',
                        stack_trace: Where(stack)
                    });
                    return result;
                }
            );
        }
    });
}

export function install_location_hooks() {
    devlog("\n");
    devlog("install location hooks");

    try {
        hook_location();
    } catch (error) {
        devlog(`[HOOK] Failed to install location hooks: ${error}`);
    }

    try {
        hook_playstore_location_api();
    } catch (error) {
        devlog(`[HOOK] Failed to install Play Store location API hooks: ${error}`);
    }
}