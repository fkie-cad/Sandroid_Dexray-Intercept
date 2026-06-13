// tests/android_apps/e2e_tests/ServicesE2E/app/src/main/java/com/test/servicese2e/MainActivity.java
package com.test.servicese2e;

import android.app.Activity;
import android.app.PendingIntent;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Context;
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
import android.provider.Settings;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Log;

import android.hardware.Camera;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;

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

        Log.i(TAG, "ServicesE2E started");

        try {
            Thread t = new Thread(() -> {
                try {
                    runBluetoothTests();
                    runCameraTests();
                    runClipboardTests();
                    runLocationTests();
                    runTelephonyTests();
                } catch (Throwable t1) {
                    Log.e(TAG, "Error in service tests", t1);
                } finally {
                    runOnUiThread(this::finish);
                }
            });
            t.start();
        } catch (Throwable t) {
            Log.e(TAG, "Error in ServicesE2E", t);
            finish();
        }
    }

    // ------------------------------------------------------------
    // Bluetooth (adapter, device, GATT characteristic)
    // ------------------------------------------------------------

    private void runBluetoothTests() {
        Log.i(TAG, "runBluetoothTests");
        try {
            BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
            if (adapter != null) {
                try {
                    adapter.enable();
                } catch (Throwable ignored) {
                }
                try {
                    adapter.disable();
                } catch (Throwable ignored) {
                }
                try {
                    adapter.startDiscovery();
                } catch (Throwable ignored) {
                }

                try {
                    BluetoothDevice device = adapter.getRemoteDevice("00:11:22:33:44:55");
                    device.createBond();
                } catch (Throwable ignored) {
                }

                try {
                    String address = adapter.getAddress();
                    Log.i(TAG, "BluetoothAdapter.getAddress(): " + address);
                } catch (Throwable ignored) {
                }
            }

            try {
                UUID uuid = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
                BluetoothGattCharacteristic characteristic =
                        new BluetoothGattCharacteristic(
                                uuid,
                                BluetoothGattCharacteristic.PROPERTY_WRITE,
                                BluetoothGattCharacteristic.PERMISSION_WRITE
                        );
                characteristic.setValue(new byte[]{0x01, 0x02, 0x03});
            } catch (Throwable t) {
                Log.e(TAG, "Error in BluetoothGattCharacteristic test", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runBluetoothTests", t);
        }
    }

    // ------------------------------------------------------------
    // Camera (legacy and Camera2)
    // ------------------------------------------------------------

    private void runCameraTests() {
        Log.i(TAG, "runCameraTests");
        try {
            Camera camera = null;
            try {
                camera = Camera.open();
            } catch (Throwable ignored) {
            }
            if (camera != null) {
                camera.release();
            }

            camera = null;
            try {
                camera = Camera.open(0);
            } catch (Throwable ignored) {
            }
            if (camera != null) {
                camera.release();
            }

            CameraManager manager =
                    (CameraManager) getSystemService(Context.CAMERA_SERVICE);
            if (manager != null) {
                try {
                    String[] ids = manager.getCameraIdList();
                    for (String id : ids) {
                        try {
                            CountDownLatch latch = new CountDownLatch(1);
                            manager.openCamera(id, new CameraDevice.StateCallback() {
                                @Override
                                public void onOpened(CameraDevice cameraDevice) {
                                    latch.countDown();
                                    cameraDevice.close();
                                }

                                @Override
                                public void onDisconnected(CameraDevice cameraDevice) {
                                    latch.countDown();
                                    cameraDevice.close();
                                }

                                @Override
                                public void onError(CameraDevice cameraDevice, int error) {
                                    latch.countDown();
                                    cameraDevice.close();
                                }
                            }, null);
                            latch.await(1, TimeUnit.SECONDS);
                        } catch (Throwable ignored) {
                        }
                    }
                } catch (Throwable t) {
                    Log.e(TAG, "Error in CameraManager tests", t);
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runCameraTests", t);
        }
    }

    // ------------------------------------------------------------
    // Clipboard
    // ------------------------------------------------------------

    private void runClipboardTests() {
        Log.i(TAG, "runClipboardTests");
        try {
            ClipboardManager cm =
                    (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                ClipData clip =
                        ClipData.newPlainText("label", "services-e2e-clipboard");
                cm.setPrimaryClip(clip);

                ClipData result = cm.getPrimaryClip();
                if (result != null) {
                    Log.i(TAG, "Clipboard item count: " + result.getItemCount());
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runClipboardTests", t);
        }
    }

    // ------------------------------------------------------------
    // Location (LocationManager, Location, FusedLocationProviderClient)
    // ------------------------------------------------------------

    private void runLocationTests() {
        Log.i(TAG, "runLocationTests");
        try {
            LocationManager lm =
                    (LocationManager) getSystemService(Context.LOCATION_SERVICE);
            if (lm != null) {
                try {
                    lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                } catch (Throwable ignored) {
                }
                try {
                    lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                } catch (Throwable ignored) {
                }

                LocationListener listener = new LocationListener() {
                    @Override
                    public void onLocationChanged(Location location) {
                    }

                    @Override
                    public void onStatusChanged(String provider, int status, Bundle extras) {
                    }

                    @Override
                    public void onProviderEnabled(String provider) {
                    }

                    @Override
                    public void onProviderDisabled(String provider) {
                    }
                };

                try {
                    lm.requestLocationUpdates(
                            LocationManager.GPS_PROVIDER,
                            1000L,
                            1.0f,
                            listener
                    );
                } catch (Throwable ignored) {
                }

                try {
                    lm.requestLocationUpdates(
                            LocationManager.NETWORK_PROVIDER,
                            1000L,
                            1.0f,
                            listener,
                            Looper.getMainLooper()
                    );
                } catch (Throwable ignored) {
                }
            }

            try {
                Location loc = new Location("services-e2e");
                loc.setLatitude(1.23);
                loc.setLongitude(4.56);
                double lat = loc.getLatitude();
                double lon = loc.getLongitude();
                Log.i(TAG, "Location lat=" + lat + " lon=" + lon);
            } catch (Throwable t) {
                Log.e(TAG, "Error in Location object test", t);
            }

            try {
                FusedLocationProviderClient fused =
                        LocationServices.getFusedLocationProviderClient(this);
                fused.getLastLocation();
            } catch (Throwable t) {
                Log.e(TAG, "Error in FusedLocationProviderClient test", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runLocationTests", t);
        }
    }

    // ------------------------------------------------------------
    // Telephony / device info / system properties / content queries
    // ------------------------------------------------------------

    private void runTelephonyTests() {
        Log.i(TAG, "runTelephonyTests");
        try {
            runSmsTests();
            runDeviceInfoTests();
            runWifiAndBluetoothInfoTests();
            runSystemPropertiesTests();
            runContentResolverTests();
            runSettingsSecureTests();
        } catch (Throwable t) {
            Log.e(TAG, "Error in runTelephonyTests", t);
        }
    }

    private void runSmsTests() {
        Log.i(TAG, "runSmsTests");
        try {
            SmsManager sms = SmsManager.getDefault();
            if (sms != null) {
                try {
                    sms.sendTextMessage("12345", null,
                            "services-e2e-text", null, null);
                } catch (Throwable t) {
                    Log.e(TAG, "sendTextMessage failed", t);
                }

                try {
                    ArrayList<String> parts = new ArrayList<>();
                    parts.add("part-one");
                    parts.add("part-two");
                    sms.sendMultipartTextMessage(
                            "12345",
                            null,
                            parts,
                            null,
                            null
                    );
                } catch (Throwable t) {
                    Log.e(TAG, "sendMultipartTextMessage failed", t);
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runSmsTests", t);
        }
    }

    private void runDeviceInfoTests() {
        Log.i(TAG, "runDeviceInfoTests");
        try {
            TelephonyManager tm =
                    (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
            if (tm != null) {
                try {
                    String line1 = tm.getLine1Number();
                    Log.i(TAG, "TelephonyManager.getLine1Number(): " + line1);
                } catch (Throwable t) {
                    Log.e(TAG, "getLine1Number failed", t);
                }

                try {
                    String subId = tm.getSubscriberId();
                    Log.i(TAG, "TelephonyManager.getSubscriberId(): " + subId);
                } catch (Throwable t) {
                    Log.e(TAG, "getSubscriberId failed", t);
                }

                try {
                    String devId = tm.getDeviceId();
                    Log.i(TAG, "TelephonyManager.getDeviceId(): " + devId);
                } catch (Throwable t) {
                    Log.e(TAG, "getDeviceId failed", t);
                }

                try {
                    String imei = tm.getImei();
                    Log.i(TAG, "TelephonyManager.getImei(): " + imei);
                } catch (Throwable t) {
                    Log.e(TAG, "getImei failed", t);
                }

                try {
                    String op = tm.getSimOperator();
                    Log.i(TAG, "TelephonyManager.getSimOperator(): " + op);
                } catch (Throwable t) {
                    Log.e(TAG, "getSimOperator failed", t);
                }
            }

            try {
                String model = Build.MODEL;
                String device = Build.DEVICE;
                String product = Build.PRODUCT;
                Log.i(TAG, "Build properties: MODEL=" + model +
                        " DEVICE=" + device +
                        " PRODUCT=" + product);
            } catch (Throwable t) {
                Log.e(TAG, "Build property read failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runDeviceInfoTests", t);
        }
    }

    private void runWifiAndBluetoothInfoTests() {
        Log.i(TAG, "runWifiAndBluetoothInfoTests");
        try {
            BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
            if (adapter != null) {
                try {
                    String addr = adapter.getAddress();
                    Log.i(TAG, "Bluetooth address: " + addr);
                } catch (Throwable t) {
                    Log.e(TAG, "BluetoothAdapter.getAddress failed", t);
                }
            }

            try {
                WifiManager wm = (WifiManager) getApplicationContext()
                        .getSystemService(Context.WIFI_SERVICE);
                if (wm != null) {
                    WifiInfo info = wm.getConnectionInfo();
                    if (info != null) {
                        try {
                            String mac = info.getMacAddress();
                            Log.i(TAG, "WifiInfo.getMacAddress(): " + mac);
                        } catch (Throwable t) {
                            Log.e(TAG, "getMacAddress failed", t);
                        }
                        try {
                            String ssid = info.getSSID();
                            Log.i(TAG, "WifiInfo.getSSID(): " + ssid);
                        } catch (Throwable t) {
                            Log.e(TAG, "getSSID failed", t);
                        }
                        try {
                            String bssid = info.getBSSID();
                            Log.i(TAG, "WifiInfo.getBSSID(): " + bssid);
                        } catch (Throwable t) {
                            Log.e(TAG, "getBSSID failed", t);
                        }
                    }
                }
            } catch (Throwable t) {
                Log.e(TAG, "Wifi info tests failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runWifiAndBluetoothInfoTests", t);
        }
    }

    private void runSystemPropertiesTests() {
        Log.i(TAG, "runSystemPropertiesTests");
        try {
            Class<?> spClass = Class.forName("android.os.SystemProperties");
            Method get = spClass.getMethod("get", String.class);
            Object value = get.invoke(null, "ro.build.version.release");
            Log.i(TAG, "SystemProperties.get(ro.build.version.release) = " + value);
        } catch (Throwable t) {
            Log.e(TAG, "SystemProperties.get failed", t);
        }
    }

    private void runContentResolverTests() {
        Log.i(TAG, "runContentResolverTests");
        try {
            ContentResolver cr = getContentResolver();
            Uri gsfUri = Uri.parse("content://com.google.android.gsf.gservicesa");
            Uri otherUri = Settings.Secure.CONTENT_URI;

            try {
                Bundle args = new Bundle();
                args.putString("e2e_key", "e2e_value");
                CancellationSignal cs = new CancellationSignal();
                cr.query(gsfUri, null, args, cs);
            } catch (Throwable t) {
                Log.e(TAG, "ContentResolver.query(URI,BUNDLE) failed", t);
            }

            try {
                cr.query(
                        otherUri,
                        null,
                        "name=?",
                        new String[]{"android_id"},
                        "name ASC"
                );
            } catch (Throwable t) {
                Log.e(TAG, "ContentResolver.query(URI,String,String,String[],String) failed", t);
            }

            try {
                CancellationSignal cs2 = new CancellationSignal();
                cr.query(
                        otherUri,
                        null,
                        "name=?",
                        new String[]{"android_id"},
                        null,
                        cs2
                );
            } catch (Throwable t) {
                Log.e(TAG, "ContentResolver.query(URI,String,String,String[],String,CancellationSignal) failed", t);
            }
        } catch (Throwable t) {
            Log.e(TAG, "Error in runContentResolverTests", t);
        }
    }

    private void runSettingsSecureTests() {
        Log.i(TAG, "runSettingsSecureTests");
        try {
            ContentResolver cr = getContentResolver();
            String androidId = Settings.Secure.getString(
                    cr,
                    Settings.Secure.ANDROID_ID
            );
            Log.i(TAG, "Settings.Secure.ANDROID_ID: " + androidId);
        } catch (Throwable t) {
            Log.e(TAG, "Settings.Secure.getString failed", t);
        }
    }
}