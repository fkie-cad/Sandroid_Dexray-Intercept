import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
import { Where } from "../utils/misc.js"

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
 * 
 * 
 * https://github.com/iddoeldor/frida-snippets?tab=readme-ov-file#change-location
 */

function hook_location(){
    Java.perform(() => {
        try {
            const LocationManager = Java.use('android.location.LocationManager');
            const Location = Java.use('android.location.Location');
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();

            // Hook LocationManager's getLastKnownLocation method
            LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider: string) {
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

            // Hook LocationManager's requestLocationUpdates method
            LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function (provider: string, minTime: number, minDistance: number, listener: any) {
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

            if (LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener', 'android.os.Looper')) {
                LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener', 'android.os.Looper').implementation = function (provider: string, minTime: number, minDistance: number, listener: any, looper: any) {
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

            // Hook Location's getLatitude and getLongitude methods
            Location.getLatitude.implementation = function () {
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

        } catch (error) {
            createLocationEvent("location.error", {
                error_message: (error as Error).toString(),
                error_type: "hook_location"
            });
        }
    });
}

function hook_playstore_location_api(){
    Java.perform(() => {
        try {
            const FusedLocationProviderClient = Java.use('com.google.android.gms.location.FusedLocationProviderClient');
            const threadDef = Java.use('java.lang.Thread');
            const threadInstance = threadDef.$new();

            // Hook FusedLocationProviderClient's getLastLocation method
            FusedLocationProviderClient.getLastLocation.overload().implementation = function () {
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

        } catch (error) {
            // Google Play Services location API may not be available
            devlog("Google Play Services location API not available: " + (error as Error).toString());
        }
    });
}



export function install_location_hooks(){
    devlog("\n")
    devlog("install location hooks");
    hook_location();
    hook_playstore_location_api()
}