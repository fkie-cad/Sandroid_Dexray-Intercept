import { devlog, am_send } from "../utils/logging.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "LOCATION_ACCESS"

// Prevent duplicate requestLocationUpdates events when Android framework overloads
// delegate internally, e.g. 4-arg provider overload -> 5-arg looper overload.
let _inLocationRequestUpdates = false;

// Prevent duplicate fused-location events if public GMS wrapper methods delegate
// into internal implementation classes that are hooked separately.
let _inFusedGetLastLocation = false;

// Tracks concrete GMS client classes hooked after discovery through the public
// LocationServices factory, preventing repeated implementation assignments.
const _hookedFusedLocationClasses = new Set<string>();

// Suppress Location getter events caused by extracting a Location object inside
// the getLastKnownLocation hook itself.
let _inLocationExtraction = false;

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
                        const java_stack_trace = collectJavaStackTrace();
                        if (result !== null) {
                            _inLocationExtraction = true;
                            try {
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
                                    ...(java_stack_trace ? { java_stack_trace } : {})
                                });
                            } finally {
                                _inLocationExtraction = false;
                            }
                        } else {
                            createLocationEvent("location.last_known_location", {
                                library: 'android.location.LocationManager',
                                method: 'getLastKnownLocation',
                                provider: provider,
                                has_location: false,
                                ...(java_stack_trace ? { java_stack_trace } : {})
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
                        if (_inLocationRequestUpdates) {
                            return original.call(this, provider, minTime, minDistance, listener);
                        }

                        _inLocationRequestUpdates = true;
                        try {
                            const java_stack_trace = collectJavaStackTrace();
                            createLocationEvent("location.request_updates", {
                                library: 'android.location.LocationManager',
                                method: 'requestLocationUpdates',
                                provider: provider,
                                min_time_ms: minTime,
                                min_distance_m: minDistance,
                                has_listener: listener !== null,
                                overload: 'basic',
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                            return original.call(this, provider, minTime, minDistance, listener);
                        } finally {
                            _inLocationRequestUpdates = false;
                        }
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
                        if (_inLocationRequestUpdates) {
                            return original.call(this, provider, minTime, minDistance, listener, looper);
                        }

                        _inLocationRequestUpdates = true;
                        try {
                            const java_stack_trace = collectJavaStackTrace();
                            createLocationEvent("location.request_updates", {
                                library: 'android.location.LocationManager',
                                method: 'requestLocationUpdates',
                                provider: provider,
                                min_time_ms: minTime,
                                min_distance_m: minDistance,
                                has_listener: listener !== null,
                                has_looper: looper !== null,
                                overload: 'with_looper',
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                            return original.call(this, provider, minTime, minDistance, listener, looper);
                        } finally {
                            _inLocationRequestUpdates = false;
                        }
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
                    if (_inLocationExtraction) {
                        return original.call(this);
                    }

                    const latitude = original.call(this);
                    const java_stack_trace = collectJavaStackTrace();

                    createLocationEvent("location.get_latitude", {
                        library: 'android.location.Location',
                        method: 'getLatitude',
                        latitude: latitude,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });

                    return latitude;
                }
            );

            const getLongitudeRef = Location.getLongitude;
            getLongitudeRef.implementation = safeImplementation(
                "location:Location.getLongitude",
                getLongitudeRef,
                function(original) {
                    if (_inLocationExtraction) {
                        return original.call(this);
                    }

                    const longitude = original.call(this);
                    const java_stack_trace = collectJavaStackTrace();

                    createLocationEvent("location.get_longitude", {
                        library: 'android.location.Location',
                        method: 'getLongitude',
                        longitude: longitude,
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });

                    return longitude;
                }
            );
        }
    });
}


function hook_playstore_location_api() {
    safePerform("location:hook_playstore_location_api", () => {

        /**
         * Hooks getLastLocation overloads on a concrete GMS client class.
         *
         * FusedLocationProviderClient is an abstract public API. Depending on
         * the installed Play Services version, LocationServices returns an
         * internal implementation with a version-specific name. The public
         * factory hooks below discover that implementation at runtime instead
         * of relying on a hardcoded internal class name.
         */
        function hookFusedClientClass(className: string): void {
            if (!className || _hookedFusedLocationClasses.has(className)) {
                return;
            }

            const FusedClient = safeUse(
                className,
                "location:hook_playstore_location_api"
            );
            if (!FusedClient || !(FusedClient as any).getLastLocation) {
                return;
            }

            // Mark only after class and method resolution succeeded, allowing a
            // later factory call to retry if an implementation was unavailable.
            _hookedFusedLocationClasses.add(className);

            // Modern common API: getLastLocation()
            const noArg = safeOverload(
                (FusedClient as any).getLastLocation,
                `location:${className}.getLastLocation[]`
            );
            if (noArg) {
                noArg.implementation = safeImplementation(
                    `location:${className}.getLastLocation[]`,
                    noArg,
                    function(original) {
                        if (_inFusedGetLastLocation) {
                            return original.call(this);
                        }

                        _inFusedGetLastLocation = true;
                        try {
                            const java_stack_trace = collectJavaStackTrace();
                            const result = original.call(this);

                            createLocationEvent("location.fused_provider.get_last_location", {
                                library: className,
                                method: "getLastLocation",
                                provider: "google_play_services",
                                overload: "no_arg",
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });

                            return result;
                        } finally {
                            _inFusedGetLastLocation = false;
                        }
                    }
                );
            }

            // Newer GMS overload: getLastLocation(LastLocationRequest)
            const withRequest = safeOverload(
                (FusedClient as any).getLastLocation,
                `location:${className}.getLastLocation[LastLocationRequest]`,
                "com.google.android.gms.location.LastLocationRequest"
            );
            if (withRequest) {
                withRequest.implementation = safeImplementation(
                    `location:${className}.getLastLocation[LastLocationRequest]`,
                    withRequest,
                    function(original, request: any) {
                        if (_inFusedGetLastLocation) {
                            return original.call(this, request);
                        }

                        _inFusedGetLastLocation = true;
                        try {
                            const java_stack_trace = collectJavaStackTrace();
                            const result = original.call(this, request);

                            createLocationEvent("location.fused_provider.get_last_location", {
                                library: className,
                                method: "getLastLocation",
                                provider: "google_play_services",
                                overload: "last_location_request",
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });

                            return result;
                        } finally {
                            _inFusedGetLastLocation = false;
                        }
                    }
                );
            }
        }

        /**
         * Hooks public LocationServices factory overloads. Each factory call
         * returns the concrete FusedLocationProviderClient implementation used
         * by the installed Google Play Services version; that returned class is
         * then hooked before control returns to the target app.
         */
        const LocationServices = safeUse(
            "com.google.android.gms.location.LocationServices",
            "location:hook_playstore_location_api"
        );
        if (!LocationServices) return;

        const getClientForActivity = safeOverload(
            (LocationServices as any).getFusedLocationProviderClient,
            "location:LocationServices.getFusedLocationProviderClient[Activity]",
            "android.app.Activity"
        );
        if (getClientForActivity) {
            getClientForActivity.implementation = safeImplementation(
                "location:LocationServices.getFusedLocationProviderClient[Activity]",
                getClientForActivity,
                function(original, activity: any) {
                    const client = original.call(this, activity);

                    if (client && client.$className) {
                        hookFusedClientClass(client.$className);
                    }

                    return client;
                }
            );
        }

        const getClientForContext = safeOverload(
            (LocationServices as any).getFusedLocationProviderClient,
            "location:LocationServices.getFusedLocationProviderClient[Context]",
            "android.content.Context"
        );
        if (getClientForContext) {
            getClientForContext.implementation = safeImplementation(
                "location:LocationServices.getFusedLocationProviderClient[Context]",
                getClientForContext,
                function(original, context: any) {
                    const client = original.call(this, context);

                    if (client && client.$className) {
                        hookFusedClientClass(client.$className);
                    }

                    return client;
                }
            );
        }

        // Keep the public class as a fallback for callers that dispatch through
        // it directly rather than through a factory-returned concrete class.
        hookFusedClientClass(
            "com.google.android.gms.location.FusedLocationProviderClient"
        );
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