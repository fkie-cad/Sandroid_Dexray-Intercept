package com.test.servicese2e;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
import android.hardware.Camera;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.Uri;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Looper;
import android.os.Handler;
import android.os.HandlerThread;
import android.provider.Settings;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {

    private static final String TAG = "SERVICES_E2E";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // All test sections run synchronously on the main thread before onCreate()
        // returns. Theme.NoDisplay requires finish() before onResume() completes -
        // a background thread would violate this contract on Android 11+.
        Log.i(TAG, "ServicesE2E started");

        try {

            try {
                runBluetoothTests();
                Log.i(TAG, "runBluetoothTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runBluetoothTests failed", t);
            }

            try {
                runClipboardTests();
                Log.i(TAG, "runClipboardTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runClipboardTests failed", t);
            }

            try {
                runLocationTests();
                Log.i(TAG, "runLocationTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runLocationTests failed", t);
            }

            try {
                runTelephonyTests();
                Log.i(TAG, "runTelephonyTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runTelephonyTests failed", t);
            }

            // last - legacy Camera.open() causes a native HAL crash on emulator
            try {
                runCameraTests();
                Log.i(TAG, "runCameraTests completed");
            } catch (Throwable t) {
                Log.e(TAG, "runCameraTests failed", t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "unexpected error in ServicesE2E", t);
        } finally {
            Log.i(TAG, "ServicesE2E finished");
            finish();
        }
    }

    // ------------------------------------------------------------
    // Bluetooth (adapter, device, GATT characteristic)
    // ------------------------------------------------------------

    private void runBluetoothTests() {
        Log.i(TAG, "runBluetoothTests started");

        BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();

        if (adapter != null) {
            try {
                adapter.enable();
            } catch (Throwable t) {
                Log.w(TAG, "adapter.enable failed: " + t.getMessage());
            }
            try {
                adapter.disable();
            } catch (Throwable t) {
                Log.w(TAG, "adapter.disable failed: " + t.getMessage());
            }
            try {
                adapter.startDiscovery();
            } catch (Throwable t) {
                Log.w(TAG, "adapter.startDiscovery failed: " + t.getMessage());
            }
            try {
                BluetoothDevice device = adapter.getRemoteDevice("00:11:22:33:44:55");
                device.createBond();
            } catch (Throwable t) {
                Log.w(TAG, "device.createBond failed: " + t.getMessage());
            }
            try {
                String address = adapter.getAddress();
                Log.i(TAG, "BluetoothAdapter.getAddress: " + address);
            } catch (Throwable t) {
                Log.w(TAG, "adapter.getAddress failed: " + t.getMessage());
            }
        } else {
            Log.w(TAG, "BluetoothAdapter not available");
        }

        // BluetoothGattCharacteristic.setValue hook trigger - no peer needed
        try {
            UUID uuid = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
            BluetoothGattCharacteristic characteristic = new BluetoothGattCharacteristic(
                    uuid,
                    BluetoothGattCharacteristic.PROPERTY_WRITE,
                    BluetoothGattCharacteristic.PERMISSION_WRITE
            );
            characteristic.setValue(new byte[]{0x01, 0x02, 0x03});
            Log.i(TAG, "BluetoothGattCharacteristic.setValue completed");
        } catch (Throwable t) {
            Log.e(TAG, "BluetoothGattCharacteristic.setValue failed", t);
        }

        // BluetoothGatt.readCharacteristic hook trigger
        // connectGatt returns synchronously before connection - method entry fires hook
        // readCharacteristic returns false (not connected), which is expected
        if (adapter != null) {
            BluetoothGatt gatt = null;
            try {
                BluetoothDevice gattTarget = adapter.getRemoteDevice("00:11:22:33:44:55");
                UUID gattUuid = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
                BluetoothGattCharacteristic gattChar = new BluetoothGattCharacteristic(
                        gattUuid,
                        BluetoothGattCharacteristic.PROPERTY_READ,
                        BluetoothGattCharacteristic.PERMISSION_READ
                );
                gatt = gattTarget.connectGatt(this, false, new BluetoothGattCallback() {});
                Log.i(TAG, "connectGatt result: " + (gatt != null ? "non-null" : "null"));

                if (gatt != null) {
                    boolean readResult = gatt.readCharacteristic(gattChar);
                    Log.i(TAG, "BluetoothGatt.readCharacteristic returned: " + readResult);
                } else {
                    Log.w(TAG, "BluetoothGatt.readCharacteristic skipped - connectGatt returned null");
                }
            } catch (Throwable t) {
                Log.e(TAG, "BluetoothGatt.readCharacteristic test failed: "
                        + t.getClass().getSimpleName() + " - " + t.getMessage());
            } finally {
                if (gatt != null) {
                    gatt.close();
                }
            }
        }
    }

    // ------------------------------------------------------------
    // Camera (legacy and Camera2)
    // ------------------------------------------------------------

    private void runCameraTests() {
        Log.i(TAG, "runCameraTests started");

        // legacy Camera API crashes in native HAL on emulator - skip on emulator
        // CAM-1 and CAM-2 hooks are only testable on real hardware
        if (isEmulator()) {
            Log.i(TAG, "runCameraTests: emulator detected - skipping legacy Camera.open()");
        } else {
            Camera camera = null;
            try {
                camera = Camera.open();
                Log.i(TAG, "Camera.open() succeeded");
            } catch (Throwable t) {
                Log.w(TAG, "Camera.open() failed: " + t.getMessage());
            } finally {
                if (camera != null) camera.release();
            }

            camera = null;
            try {
                camera = Camera.open(0);
                Log.i(TAG, "Camera.open(0) succeeded");
            } catch (Throwable t) {
                Log.w(TAG, "Camera.open(0) failed: " + t.getMessage());
            } finally {
                if (camera != null) camera.release();
            }
        }

        // Camera2 - works on emulator and real hardware
        CameraManager manager = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
        if (manager != null) {
            String[] ids = null;
            try {
                ids = manager.getCameraIdList();
                Log.i(TAG, "CameraManager.getCameraIdList: " + ids.length + " camera(s)");
            } catch (Throwable t) {
                Log.e(TAG, "getCameraIdList failed", t);
            }

            if (ids != null) {
                // callbacks dispatched on a background thread - main thread
                // must not be blocked while waiting for its own looper
                HandlerThread cameraThread = new HandlerThread("camera-e2e");
                cameraThread.start();
                Handler cameraHandler = new Handler(cameraThread.getLooper());

                for (String id : ids) {
                    try {
                        CountDownLatch latch = new CountDownLatch(1);
                        manager.openCamera(id, new CameraDevice.StateCallback() {
                            @Override
                            public void onOpened(CameraDevice cameraDevice) {
                                Log.i(TAG, "CameraManager.openCamera id=" + id + " opened");
                                latch.countDown();
                                cameraDevice.close();
                            }
                            @Override
                            public void onDisconnected(CameraDevice cameraDevice) {
                                Log.w(TAG, "CameraManager.openCamera id=" + id + " disconnected");
                                latch.countDown();
                                cameraDevice.close();
                            }
                            @Override
                            public void onError(CameraDevice cameraDevice, int error) {
                                Log.w(TAG, "CameraManager.openCamera id=" + id + " error=" + error);
                                latch.countDown();
                                cameraDevice.close();
                            }
                        }, cameraHandler);
                        latch.await(2, TimeUnit.SECONDS);
                    } catch (Throwable t) {
                        Log.e(TAG, "openCamera id=" + id + " failed", t);
                    }
                }

                cameraThread.quitSafely();
            }
        } else {
            Log.w(TAG, "CameraManager not available");
        }
    }

    // ------------------------------------------------------------
    // Clipboard
    // ------------------------------------------------------------

    private void runClipboardTests() {
        Log.i(TAG, "runClipboardTests started");

        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) {
            Log.w(TAG, "ClipboardManager not available");
            return;
        }

        try {
            ClipData clip = ClipData.newPlainText("label", "services-e2e-clipboard");
            cm.setPrimaryClip(clip);
            Log.i(TAG, "ClipboardManager.setPrimaryClip completed");
        } catch (Throwable t) {
            Log.e(TAG, "setPrimaryClip failed", t);
        }

        try {
            ClipData result = cm.getPrimaryClip();
            Log.i(TAG, "ClipboardManager.getPrimaryClip item count: "
                    + (result != null ? result.getItemCount() : "null"));
        } catch (Throwable t) {
            Log.e(TAG, "getPrimaryClip failed", t);
        }
    }

    // ------------------------------------------------------------
    // Location (LocationManager, Location, FusedLocationProviderClient)
    // ------------------------------------------------------------

    private void runLocationTests() {
        Log.i(TAG, "runLocationTests started");

        LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        if (lm != null) {
            try {
                lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                Log.i(TAG, "getLastKnownLocation(GPS) completed");
            } catch (Throwable t) {
                Log.w(TAG, "getLastKnownLocation(GPS) failed: " + t.getMessage());
            }
            try {
                lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                Log.i(TAG, "getLastKnownLocation(NETWORK) completed");
            } catch (Throwable t) {
                Log.w(TAG, "getLastKnownLocation(NETWORK) failed: " + t.getMessage());
            }

            LocationListener listener = new LocationListener() {
                @Override public void onLocationChanged(Location location) {}
                @Override public void onStatusChanged(String p, int s, Bundle e) {}
                @Override public void onProviderEnabled(String p) {}
                @Override public void onProviderDisabled(String p) {}
            };

            try {
                lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 1000L, 1.0f, listener);
                Log.i(TAG, "requestLocationUpdates(GPS, basic) completed");
            } catch (Throwable t) {
                Log.w(TAG, "requestLocationUpdates(GPS, basic) failed: " + t.getMessage());
            }
            try {
                lm.requestLocationUpdates(LocationManager.NETWORK_PROVIDER,
                        1000L, 1.0f, listener, Looper.getMainLooper());
                Log.i(TAG, "requestLocationUpdates(NETWORK, looper) completed");
            } catch (Throwable t) {
                Log.w(TAG, "requestLocationUpdates(NETWORK, looper) failed: " + t.getMessage());
            }
        } else {
            Log.w(TAG, "LocationManager not available");
        }

        // Location.getLatitude / getLongitude hook triggers - no provider needed
        try {
            Location loc = new Location("services-e2e");
            loc.setLatitude(1.23);
            loc.setLongitude(4.56);
            double lat = loc.getLatitude();
            double lon = loc.getLongitude();
            Log.i(TAG, "Location lat=" + lat + " lon=" + lon);
        } catch (Throwable t) {
            Log.e(TAG, "Location object test failed", t);
        }

        // FusedLocationProviderClient hook trigger
        try {
            FusedLocationProviderClient fused =
                    LocationServices.getFusedLocationProviderClient(this);
            fused.getLastLocation();
            Log.i(TAG, "FusedLocationProviderClient.getLastLocation completed");
        } catch (Throwable t) {
            Log.w(TAG, "FusedLocationProviderClient.getLastLocation failed: " + t.getMessage());
        }
    }

    // ------------------------------------------------------------
    // Telephony / device info / system properties / content queries
    // ------------------------------------------------------------

    private void runTelephonyTests() {
        Log.i(TAG, "runTelephonyTests started");

        try {
            runSmsTests();
            Log.i(TAG, "runSmsTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runSmsTests failed", t);
        }

        try {
            runDeviceInfoTests();
            Log.i(TAG, "runDeviceInfoTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runDeviceInfoTests failed", t);
        }

        try {
            runWifiAndBluetoothInfoTests();
            Log.i(TAG, "runWifiAndBluetoothInfoTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runWifiAndBluetoothInfoTests failed", t);
        }

        try {
            runSystemPropertiesTests();
            Log.i(TAG, "runSystemPropertiesTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runSystemPropertiesTests failed", t);
        }

        try {
            runContentResolverTests();
            Log.i(TAG, "runContentResolverTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runContentResolverTests failed", t);
        }

        try {
            runSettingsSecureTests();
            Log.i(TAG, "runSettingsSecureTests completed");
        } catch (Throwable t) {
            Log.e(TAG, "runSettingsSecureTests failed", t);
        }
    }

    private void runSmsTests() {
        Log.i(TAG, "runSmsTests started");
        SmsManager sms = SmsManager.getDefault();
        if (sms == null) {
            Log.w(TAG, "SmsManager not available");
            return;
        }
        try {
            sms.sendTextMessage("12345", null, "services-e2e-text", null, null);
            Log.i(TAG, "SmsManager.sendTextMessage completed");
        } catch (Throwable t) {
            Log.w(TAG, "sendTextMessage failed: " + t.getMessage());
        }
        try {
            ArrayList<String> parts = new ArrayList<>();
            parts.add("part-one");
            parts.add("part-two");
            sms.sendMultipartTextMessage("12345", null, parts, null, null);
            Log.i(TAG, "SmsManager.sendMultipartTextMessage completed");
        } catch (Throwable t) {
            Log.w(TAG, "sendMultipartTextMessage failed: " + t.getMessage());
        }
    }

    private void runDeviceInfoTests() {
        Log.i(TAG, "runDeviceInfoTests started");
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        if (tm != null) {
            try {
                Log.i(TAG, "TelephonyManager.getLine1Number: " + tm.getLine1Number());
            } catch (Throwable t) {
                Log.w(TAG, "getLine1Number failed: " + t.getMessage());
            }
            try {
                Log.i(TAG, "TelephonyManager.getSubscriberId: " + tm.getSubscriberId());
            } catch (Throwable t) {
                Log.w(TAG, "getSubscriberId failed: " + t.getMessage());
            }
            try {
                Log.i(TAG, "TelephonyManager.getDeviceId: " + tm.getDeviceId());
            } catch (Throwable t) {
                Log.w(TAG, "getDeviceId failed: " + t.getMessage());
            }
            try {
                Log.i(TAG, "TelephonyManager.getImei: " + tm.getImei());
            } catch (Throwable t) {
                Log.w(TAG, "getImei failed: " + t.getMessage());
            }
            try {
                Log.i(TAG, "TelephonyManager.getSimOperator: " + tm.getSimOperator());
            } catch (Throwable t) {
                Log.w(TAG, "getSimOperator failed: " + t.getMessage());
            }
        } else {
            Log.w(TAG, "TelephonyManager not available");
        }
        try {
            Log.i(TAG, "Build MODEL=" + Build.MODEL
                    + " DEVICE=" + Build.DEVICE
                    + " PRODUCT=" + Build.PRODUCT);
        } catch (Throwable t) {
            Log.w(TAG, "Build property read failed: " + t.getMessage());
        }
    }

    private void runWifiAndBluetoothInfoTests() {
        Log.i(TAG, "runWifiAndBluetoothInfoTests started");
        BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
        if (adapter != null) {
            try {
                Log.i(TAG, "BluetoothAdapter.getAddress: " + adapter.getAddress());
            } catch (Throwable t) {
                Log.w(TAG, "BluetoothAdapter.getAddress failed: " + t.getMessage());
            }
        }
        try {
            WifiManager wm = (WifiManager) getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                WifiInfo info = wm.getConnectionInfo();
                if (info != null) {
                    try {
                        Log.i(TAG, "WifiInfo.getMacAddress: " + info.getMacAddress());
                    } catch (Throwable t) {
                        Log.w(TAG, "getMacAddress failed: " + t.getMessage());
                    }
                    try {
                        Log.i(TAG, "WifiInfo.getSSID: " + info.getSSID());
                    } catch (Throwable t) {
                        Log.w(TAG, "getSSID failed: " + t.getMessage());
                    }
                    try {
                        Log.i(TAG, "WifiInfo.getBSSID: " + info.getBSSID());
                    } catch (Throwable t) {
                        Log.w(TAG, "getBSSID failed: " + t.getMessage());
                    }
                } else {
                    Log.w(TAG, "WifiInfo not available - no active connection");
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "Wifi info tests failed", t);
        }
    }

    private void runSystemPropertiesTests() {
        Log.i(TAG, "runSystemPropertiesTests started");
        try {
            Class<?> spClass = Class.forName("android.os.SystemProperties");
            Method get = spClass.getMethod("get", String.class);
            Object value = get.invoke(null, "ro.build.version.release");
            Log.i(TAG, "SystemProperties.get(ro.build.version.release)=" + value);
        } catch (Throwable t) {
            Log.e(TAG, "SystemProperties.get failed", t);
        }
    }

    private void runContentResolverTests() {
        Log.i(TAG, "runContentResolverTests started");
        ContentResolver cr = getContentResolver();
        Uri gsfUri = Uri.parse("content://com.google.android.gsf.gservicesa");
        Uri otherUri = Settings.Secure.CONTENT_URI;

        try {
            Bundle args = new Bundle();
            args.putString("e2e_key", "e2e_value");
            CancellationSignal cs = new CancellationSignal();
            cr.query(gsfUri, null, args, cs);
            Log.i(TAG, "ContentResolver.query(Uri, Bundle, CancellationSignal) completed");
        } catch (Throwable t) {
            Log.w(TAG, "ContentResolver.query(Uri,Bundle) failed: " + t.getMessage());
        }

        try {
            cr.query(otherUri, null, "name=?", new String[]{"android_id"}, "name ASC");
            Log.i(TAG, "ContentResolver.query(Uri, String, String[], String) completed");
        } catch (Throwable t) {
            Log.w(TAG, "ContentResolver.query(5-arg) failed: " + t.getMessage());
        }

        try {
            CancellationSignal cs2 = new CancellationSignal();
            cr.query(otherUri, null, "name=?", new String[]{"android_id"}, null, cs2);
            Log.i(TAG, "ContentResolver.query(Uri, String, String[], String, CancellationSignal) completed");
        } catch (Throwable t) {
            Log.w(TAG, "ContentResolver.query(6-arg) failed: " + t.getMessage());
        }
    }

    private void runSettingsSecureTests() {
        Log.i(TAG, "runSettingsSecureTests started");
        try {
            String androidId = Settings.Secure.getString(
                    getContentResolver(), Settings.Secure.ANDROID_ID);
            Log.i(TAG, "Settings.Secure.ANDROID_ID: " + androidId);
        } catch (Throwable t) {
            Log.e(TAG, "Settings.Secure.getString failed", t);
        }
    }

    // ------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------

    // returns true when running on a standard Android emulator
    // covers AOSP emulator, Google APIs emulator and Genymotion
    private static boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("sdk_gphone")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.DEVICE.startsWith("generic")
                || Build.PRODUCT.equals("google_sdk");
    }
}