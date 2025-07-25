import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"


const PROFILE_HOOKING_TYPE: string = "LOCATION_ACCESS"

/**
 * 
 * 
 * https://github.com/iddoeldor/frida-snippets?tab=readme-ov-file#change-location
 */

function hook_location(){
    Java.perform(function () {
    const LocationManager = Java.use('android.location.LocationManager');
    const Location = Java.use('android.location.Location');
    

    // Hook LocationManager's getLastKnownLocation method
    LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider: string) {
        const result = this.getLastKnownLocation(provider);
        if (result !== null) {
            const latitude = result.getLatitude();
            const longitude = result.getLongitude();
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(`event_type: getLastKnownLocation, Provider: ${provider}, Lat: ${latitude}, Long: ${longitude}`));
        } else {
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(`event_type: getLastKnownLocation, Provider: ${provider}, No location found`));
        }
        return result;
    };

    // Hook LocationManager's requestLocationUpdates method
    LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function (provider: string, minTime: number, minDistance: number, listener: any) {
        am_send(PROFILE_HOOKING_TYPE, `requestLocationUpdates called. Provider: ${provider}, MinTime: ${minTime}, MinDistance: ${minDistance}`);
        return this.requestLocationUpdates(provider, minTime, minDistance, listener);
    };

    LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener', 'android.os.Looper').implementation = function (provider: string, minTime: number, minDistance: number, listener: any, looper: any) {
        am_send(PROFILE_HOOKING_TYPE, JSON.stringify(`event_type: requestLocationUpdates, Provider: ${provider}, MinTime: ${minTime}, MinDistance: ${minDistance}, Looper: ${looper}`));
        return this.requestLocationUpdates(provider, minTime, minDistance, listener, looper);
    };

    // Hook Location's getLatitude and getLongitude methods
    Location.getLatitude.implementation = function () {
        const latitude = this.getLatitude();
        am_send(PROFILE_HOOKING_TYPE, JSON.stringify(`event_type: Location.getLatitude, Latitude: ${latitude}`));
        return latitude;
    };

    Location.getLongitude.implementation = function () {
        const longitude = this.getLongitude();
        am_send(PROFILE_HOOKING_TYPE, JSON.stringify(`event_type: Location.getLongitude, Longitude: ${longitude}`));
        return longitude;
    };
    })

}

function hook_playstore_location_api(){
    Java.perform(function () {
        try{
            const FusedLocationProviderClient = Java.use('com.google.android.gms.location.FusedLocationProviderClient');

            // Define OnSuccessListener class
            const OnSuccessListener = Java.registerClass({
                name: 'com.example.OnSuccessListener',
                implements: [Java.use('com.google.android.gms.tasks.OnSuccessListener')],
                methods: {
                    onSuccess: function (location: any) {
                        if (location !== null) {
                            const latitude = location.getLatitude();
                            const longitude = location.getLongitude();
                            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(`event_type: FusedLocationProviderClient.getLastLocation, Lat: ${latitude}, Long: ${longitude}`));
                        } else {
                            am_send(PROFILE_HOOKING_TYPE, JSON.stringify('event_type: FusedLocationProviderClient.getLastLocation called, Result: No location found'));
                        }
                    }
                }
            });

            // Hook FusedLocationProviderClient's getLastLocation method
        FusedLocationProviderClient.getLastLocation.overload().implementation = function () {
            const result = this.getLastLocation();
            result.addOnSuccessListener(OnSuccessListener.$new());
            return result;
        };
        }catch(error){
            // currently do nothing because it usually means that the API is not available
        }
    })
}



export function install_location_hooks(){
    devlog("\n")
    devlog("install location hooks");
    hook_location();
    hook_playstore_location_api()
}