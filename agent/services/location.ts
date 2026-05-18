import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"
import { safePerform, safeUse, safeOverload } from "../utils/safe_java.js"

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
        const LocationManager = safeUse('android.location.LocationManager', "location:hook_location");
        const Location = safeUse('android.location.Location', "location:hook_location");
        const threadDef = safeUse('java.lang.Thread', "location:hook_location");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // Hook LocationManager's getLastKnownLocation method
        if (LocationManager) {
            const getLastKnown = safeOverload(
                LocationManager.getLastKnownLocation,
                "location:LocationManager.getLastKnownLocation",
                'java.lang.String'
            );
            if (getLastKnown) {
                getLastKnown.implementation = function(provider: string) {
                    const result = this.getLastKnownLocation(provider);
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
                };
            }

            // Hook LocationManager's requestLocationUpdates method
            const requestUpdatesBasic = safeOverload(
                LocationManager.requestLocationUpdates,
                "location:LocationManager.requestLocationUpdates",
                'java.lang.String', 'long', 'float', 'android.location.LocationListener'
            );
            if (requestUpdatesBasic) {
                requestUpdatesBasic.implementation = function(
                    provider: string, minTime: number, minDistance: number, listener: any
                ) {
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

                            return this.requestLocationUpdates(provider, minTime, minDistance, listener);
                        };
                    }

            // API-level conditional — safeOverload returns null gracefully if absent
            const requestUpdatesLooper = safeOverload(
                LocationManager.requestLocationUpdates,
                "location:LocationManager.requestLocationUpdates",
                'java.lang.String', 'long', 'float',
                'android.location.LocationListener', 'android.os.Looper'
            );
            if (requestUpdatesLooper) {
                requestUpdatesLooper.implementation = function(
                    provider: string, minTime: number, minDistance: number,
                    listener: any, looper: any
                ) {
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
                    
                    return this.requestLocationUpdates(provider, minTime, minDistance, listener, looper);
                };
            }
        }
        
            // Hook Location's getLatitude and getLongitude methods
            if (Location) {
                Location.getLatitude.implementation = function() {
                    const latitude = this.getLatitude();
                    const stack = threadInstance.currentThread().getStackTrace();
                    createLocationEvent("location.get_latitude", {
                        library: 'android.location.Location',
                        method: 'getLatitude',
                        latitude: latitude,
                        stack_trace: Where(stack)
                    });

                    return latitude;
                };

                Location.getLongitude.implementation = function () {
                    const longitude = this.getLongitude();
                    const stack = threadInstance.currentThread().getStackTrace();
                    
                    createLocationEvent("location.get_longitude", {
                        library: 'android.location.Location',
                        method: 'getLongitude',
                        longitude: longitude,
                        stack_trace: Where(stack)
                    });

                    return longitude;
                };
            }
        });
    }


function hook_playstore_location_api() {
    safePerform("location:hook_playstore_location_api", () => {
        // optional class — safeUse returns null if GMS not present
        const FusedLocationProviderClient = safeUse(
            'com.google.android.gms.location.FusedLocationProviderClient',
            "location:hook_playstore_location_api"
        );
        if (!FusedLocationProviderClient) return;

        const threadDef = safeUse('java.lang.Thread', "location:hook_playstore_location_api");
        if (!threadDef) return;
        const threadInstance = threadDef.$new();

        // zero-argument overload — safeOverload called with no signatures
        const getLastLocation = safeOverload(
            FusedLocationProviderClient.getLastLocation,
            "location:FusedLocationProviderClient.getLastLocation"
        );
        if (getLastLocation) {
            getLastLocation.implementation = function() {
                const stack = threadInstance.currentThread().getStackTrace();
                const result = this.getLastLocation();
                createLocationEvent("location.fused_provider.get_last_location", {
                    library: 'com.google.android.gms.location.FusedLocationProviderClient',
                    method: 'getLastLocation',
                    provider: 'google_play_services',
                    stack_trace: Where(stack)
                });
                return result;
            };
        }
    });
}


export function install_location_hooks(){
    devlog("\n")
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