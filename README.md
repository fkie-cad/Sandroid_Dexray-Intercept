<div align="center">
    <img src="assets/logo.png" alt="Dexray Intercept Logo" width="400"/>
    <p></p><strong>Android Binary API Tracer</strong>
</div>

# SanDroid - Dexray Intercept
![version](https://img.shields.io/badge/version-0.2.7.2-blue) [![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.png?id=py&r=r&ts=1683906897&type=6e&v=0.2.7.2&x2=0)](https://badge.fury.io/py/dexray-intercept) [![CI](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/ci.yml)
[![Ruff](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/lint.yml)
[![Publish status](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/publish.yml)

Dexray Intercept is part of the dynamic Sandbox Sandroid. Its purpose is to create runtime profiles to track the behavior of an Android application. This is done utilizing frida.

## Install

Just install it with pip:
```bash
python3 -m pip install dexray-intercept
```

This will install Dexray Intercept as command line tool `ammm` or `dexray-intercept`. 
Further it will provide a package `dexray_intercept`. More on how to use the package below. 

## Run

Ensure that your Android device is rooted. The `frida-server` will be installed to the latest version automaticly. Than you can use Dexray Intercept by just invoking the following command:

```bash
ammm <target app>
```

Here an example on monitoring the chrome app on our AVD:
```bash
ammm Chrome
        Dexray Intercept
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿SanDroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
[*] starting app profiling
[*] press Ctrl+C to stop the profiling ...

[*] Filesystem profiling informations:
[*] [Libc::read] Read FD (anon_inode:[eventfd],0x7ac6b67540,8)

[*] Filesystem profiling informations:
[*] [Libc::read] Read FD (anon_inode:[eventfd],0x7fcb41c990,8
```



## Run as package 

In order to use this project just install Dexray Intercept as a package and use 

```python
from dexray_intercept import AppProfiler 
 ...
profiler = AppProfiler(process_session, parsed.verbose, output_format="CMD", base_path=None, deactivate_unlink=False)
profiler.start_profiling()
...
profiler.finish_app_profiling()

```
Ensure that you provide this function with a frida process handle.

### SanDroid usage

In order to run it as a package in SanDroid ensure that you also installed the `JobManager` from [AndroidFridaManager](https://github.com/fkie-cad/AndroidFridaManager). This allows running multpitle frida sessions in different threads.
All you have to do is running the following code:
```python
from AndroidFridaManager import JobManager
from dexray_intercept import AppProfiler 

job_manager = JobManager()
app_package = "net.classwindexampleyear.bookseapiececountry"
profiler = AppProfiler(job_manager.process_session, True, output_format="JSON", base_path=None, deactivate_unlink=False)
frida_script_path = profiler.get_frida_script()

job_manager.setup_frida_session(app_package, profiler.on_appProfiling_message)
job = job_manager.start_job(frida_script_path, custom_hooking_handler_name=profiler.on_appProfiling_message)

# close only the job and the frida session keeps active to run other frida scripts
# job_manager.stop_job_with_id(job.job_id) 
job_manager.stop_app_with_closing_frida(app_package) # stops the frida session and the app and all frida jobs

profiler.write_profiling_log() # write the log data to profile.json
# instead of writing it to a file the JSON output will just be returned
# profiler.get_profiling_log_as_JSON() 
```
Ensure that no other part of your code is trying to connect to the frida server (no other frida session).
In order to test this you can try the following sample: [catelites_2018_01_19.apk](https://gitlab.fkie.fraunhofer.de/def/androidmalwaremotionmonitor/-/blob/main/samples/unpacking/catelites_2018_01_19.apk?ref_type=heads). The name for the package is `net.classwindexampleyear.bookseapiececountry`. Ensure that your AVD is running on Android 9, so that the sample can execute everything of its malicious code. You can install this sample simple with `adb install samples/unpacking/catelites_2018_01_19.apk`.

## Compile and Development
 
In order to compile this project ensure that `npm` and `frida-compile` running on your system and installed into your path.
Than just invoke the following command in to get the latest frida agent compiled:
```bash
$ cd <AppProfiling-Project>
$ npm install .
> Dexray Intercept@0.0.1.5 prepare
> npm run build


> Dexray Intercept@0.0.1.5 build
> frida-compile agent/hooking_profile_loader.ts -o src/dexray_intercept/profiling.js


up to date, audited 75 packages in 6s

19 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities
```

This ensures that the latest frida scripts/hooks are used in `ammm`.

In order to do adjustments in the python code it is recommend to install `ammm` with pip utilizing the editable mode:
```bash
python3 -m pip install -e . 
```
This way local changed in the python code gets reflected without creating a new version of the package.


## Requirements

By just invoking the following command in this directory the `setup.py` should be used to install `ammm` as a local python package to your system:
```bash
python3 -m pip install .
``` 


### Dev

In order to compile the TypeScript frida hooks we need the `frida-compile` ([link](https://github.com/frida/frida-compile)) project. Which will be bundled with `frida-tools`. 
```bash
python3 -m pip install frida-tools
```
Besides this we need also support for `frida-java-bridge` and the internal frida types:
```bash
npm install frida-java-bridge@latest --save
npm install --save-dev @types/frida-gum@latest
```

### Deep Unpacking

When unpacking, applications may load DexCode—previously pointed to distinct memory blocks—into a DexFile, which represents the code being executed. For instance, some applications may restore instructions immediately before execution. In such cases, SanDroid is unable to revert the instructions back into the DexFile. Further research is necessary to resolve this issue

## Samples

The password for unzipping the samples is `androidtrainingpassword`

### Example case Sara

First we extract and install the sample:
```bash
$ cd samples
$ unzip -P androidtrainingpassword Sara_androidtrainingpassword.zip 
$ cd ..
$ adb install samples/Sara.apk
```

Next we have identify the bundle identifier of the intalled app:
```bash
$ frida-ps -Uai
  PID  Name           Identifier
-----  -------------  ---------------------------------------
 1836  Google         com.google.android.googlequicksearchbox
 1836  Google         com.google.android.googlequicksearchbox
 1677  Messages       com.google.android.apps.messaging
  927  SIM Toolkit    com.android.stk
12185  Settings       com.android.settings
    -  Calendar       com.google.android.calendar
    -  Camera         com.android.camera2
    -  Chrome         com.android.chrome
    -  Clock          com.google.android.deskclock
    -  Contacts       com.google.android.contacts
    -  Drive          com.google.android.apps.docs
    -  Files          com.google.android.documentsui
    -  Gmail          com.google.android.gm
    -  Maps           com.google.android.apps.maps
    -  Phone          com.google.android.dialer
    -  Photos         com.google.android.apps.photos
    -  Sara           com.termuxhackers.id
    -  YouTube        com.google.android.youtube
```

In our case it is `com.termuxhackers.id`. So we can spawn this malware sample with the following command line (keep in mind to create a snapshot for your device):
```bash
$ adb shell adb shell am start -n "com.termuxhackers.id/com.MainAcitivy" -a android.intent.action.MAIN -c android.intent.category.LAUNCHER
$ ammm Sara
        Dexray Intercept
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿SanDroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
[*] attaching to app: Sara
[*] starting app profiling
[*] press Ctrl+C to stop the profiling ...

[*] Filesystem profiling informations:
[*] [Libc::open] Open file '/data/misc/profiles/cur/0/com.termuxhackers.id/primary.prof' (fd: 97)
```

### Example case koler.apk

Again at first we have to extract the sample and install it to the device

```bash
$ unzip -P infected 18a82a21158f23148fbb58f39f597d482c186c8d2905540e750533a0df363705.zip
Archive:  18a82a21158f23148fbb58f39f597d482c186c8d2905540e750533a0df363705.zip
  inflating: 18a82a21158f23148fbb58f39f597d482c186c8d2905540e750533a0df363705
$ mv 18a82a21158f23148fbb58f39f597d482c186c8d2905540e750533a0df363705 koler.apk
$ adb install koler.apk
Performing Streamed Install
Success
```
Now we have to identify the name of the app so we can later attach to it:

```bash
frida-ps -Uai
  PID  Name           Identifier
-----  -------------  -------------------------------------------
12095  Chrome         com.android.chrome
 1836  Google         com.google.android.googlequicksearchbox
 1836  Google         com.google.android.googlequicksearchbox
 1677  Messages       com.google.android.apps.messaging
  927  SIM Toolkit    com.android.stk
12185  Settings       com.android.settings
    -  Calendar       com.google.android.calendar
    -  Camera         com.android.camera2
    -  Clock          com.google.android.deskclock
    -  Contacts       com.google.android.contacts
    -  Drive          com.google.android.apps.docs
    -  Files          com.google.android.documentsui
    -  Gmail          com.google.android.gm
    -  Maps           com.google.android.apps.maps
    -  Phone          com.google.android.dialer
    -  Photos         com.google.android.apps.photos
    -  Pornhub        upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq
```

This sample actually is unpacking itself and normaly we could see this in `Dexray Intercept` if we able to spawn the app. Unfortunately there is a bug with frida itself that the latest frida version (since version 16.0.4) is unable to spawn the target app without getting a timeout error. Currently we identify that this frida bug is related whenever an app is requesting runtime permissions (more [infos](https://github.com/frida/frida/issues/2005)). It seems that this bug is fixed in the latest frida version.

So we now just spawn this malware using `Dexray Intercept` and see some interesting output:

```bash
$ ammm -s upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq 
        Dexray Intercept
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿SanDroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
[*] attaching to app: Pornhub
[*] starting app profiling
[*] press Ctrl+C to stop the profiling ...

[*] Filesystem profiling informations:
[*] [Libc::open] Open file '/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/cache/WebView/Default/HTTP Cache/Cache_Data/510c1bd5457bae66_0' (fd: 187)
[*] Filesystem profiling informations:
[*] [+] Unlink : /data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/cache/WebView/Default/HTTP Cache/Cache_Data/todelete_510c1bd5457bae66_0_1
[*] Filesystem profiling informations:
[*] [Libc::open] Open file '/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/app_webview/Default/Session Storage/LOG' (fd: 5)
[*] Filesystem profiling informations:
[*] [Libc::open] Open file '/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/app_webview/Default/Session Storage/LOCK' (fd: -1)
[*] Filesystem profiling informations:
[*] [Libc::open] Open file '/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/app_webview/Default/Session Storage/LOCK' (fd: 68)
[*] Filesystem profiling informations:
[*] [Libc::write] Write FD (/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/app_webview/Default/Session Storage/LOG,0x77d9937d10,156)

[*] Filesystem profiling informations:
[*] [Libc::open] Open file '/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/app_webview/Default/Session Storage/MANIFEST-000001' (fd: 70)
[*] Filesystem profiling informations:
[*] [Libc::write] Write FD (/data/user/0/upehfmf.xrppcuzqolwhmwxnfyes.xctrbzkvipjazq/app_webview/Default/Session Storage/MANIFEST-000001,0x77d9938010,7
...
```

## Roadmap

- [ x ] Create templates for the different hookings we want to install in order to get a runtime profile
- [ ] Create a test application which is using all the different features which we want to hook (we need some sort of ground truth in order to test our hooks)
- [ ] Implement the actual hooks 
- [ ] The format to print the monitored information
- [ ] https://attack.mitre.org/matrices/mobile/ add this as a final result so we can say what kind of Attacks the Application is using
- [ ] We want to track also things like "this are privacy issues", "this might lead to bugs" ...