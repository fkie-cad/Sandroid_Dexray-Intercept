<div align="center">
    <img src="assets/logo.png" alt="Dexray Intercept Logo" width="400"/>
    <p></p><strong>Android Binary API Tracer</strong>
</div>

# Sandroid - Dexray Intercept
![version](https://img.shields.io/badge/version-0.2.9.8-blue) [![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.png?id=py&r=r&ts=1683906897&type=6e&v=0.2.9.8&x2=0)](https://badge.fury.io/py/dexray-intercept) [![CI](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Intercept/actions/workflows/ci.yml)
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

Ensure that your Android device is rooted. The `frida-server` will be installed to the latest version automatically. Then you can use Dexray Intercept by just invoking the following command:

```bash
ammm <target app>
```

### Hook Selection (New Feature)

All hooks are **disabled by default** for optimal performance. Enable hooks based on your analysis needs:

```bash
# Enable specific hooks
ammm --enable-aes <app_name>                    # Enable AES crypto hooks
ammm --enable-web <app_name>                    # Enable web/HTTP hooks
ammm --enable-aes --enable-web <app_name>       # Enable multiple hooks

# Enable hook groups
ammm --hooks-crypto <app_name>                  # Enable all crypto hooks
ammm --hooks-network <app_name>                 # Enable all network hooks  
ammm --hooks-filesystem <app_name>              # Enable all file system hooks

# Enable all hooks (performance impact)
ammm --hooks-all <app_name>                     # Enable all available hooks

# Use package identifier instead of app name
ammm -s com.example.package --hooks-crypto
```

### Available Hook Categories

- **Crypto**: `--hooks-crypto` (AES, encodings, keystore, certificates)
- **Network**: `--hooks-network` (HTTP, sockets, SSL/TLS)
- **File System**: `--hooks-filesystem` (file operations, databases, shared preferences)
- **IPC**: `--hooks-ipc` (intents, broadcasts, binder, shared preferences)
- **Process**: `--hooks-process` (DEX unpacking, native libraries, runtime)
- **Services**: `--hooks-services` (camera, location, telephony, bluetooth)

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
⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
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

### New API (Recommended)

Install Dexray Intercept as a package and use the new modular architecture:

```python
from dexray_intercept import AppProfiler, setup_frida_device
from dexray_intercept.services.hook_manager import HookManager

# Connect to device and get process
device = setup_frida_device()
process = device.attach("com.example.app")

# Configure hooks (all disabled by default for performance)
hook_config = {
    'aes_hooks': True,
    'web_hooks': True, 
    'file_system_hooks': True,
    'keystore_hooks': True
}

# Create profiler with new architecture
profiler = AppProfiler(
    process, 
    verbose_mode=True,
    output_format="JSON",
    hook_config=hook_config,
    enable_stacktrace=True
)

# Start profiling
script = profiler.start_profiling()

# ... let app run and collect data ...

# Get results
profile_data = profiler.get_profile_data()
json_output = profiler.get_profiling_log_as_json()

# Runtime hook management
profiler.enable_hook('socket_hooks', True)  # Enable more hooks at runtime
enabled_hooks = profiler.get_enabled_hooks()  # Check what's enabled

# Stop profiling
profiler.stop_profiling()
```

### Hook Categories

Enable specific hook groups based on your analysis needs:

```python
# Crypto hooks
hook_config = {
    'aes_hooks': True,
    'encodings_hooks': True, 
    'keystore_hooks': True
}

# Network hooks  
hook_config = {
    'web_hooks': True,
    'socket_hooks': True
}

# File system hooks
hook_config = {
    'file_system_hooks': True,
    'database_hooks': True
}

# Enable all hooks (performance impact)
profiler.enable_all_hooks()

# Enable hook groups
profiler.enable_hook_group('crypto')  # Enable all crypto-related hooks
```

### Legacy API (Backward Compatibility)

The old API is still available for backward compatibility:

```python
from dexray_intercept import AppProfilerLegacy
# OR use environment variable: DEXRAY_FORCE_OLD_ARCH=true

profiler = AppProfilerLegacy(process_session, verbose=True, output_format="CMD", 
                           base_path=None, deactivate_unlink=False)
profiler.instrument()  # Old method name
# ... 
profiler.finish_app_profiling()  # Old method name
```

### Sandroid usage

In order to run it as a package in Sandroid ensure that you also installed the `JobManager` from [AndroidFridaManager](https://github.com/fkie-cad/AndroidFridaManager). This allows running multpitle frida sessions in different threads.
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

When unpacking, applications may load DexCode—previously pointed to distinct memory blocks—into a DexFile, which represents the code being executed. For instance, some applications may restore instructions immediately before execution. In such cases, Sandroid is unable to revert the instructions back into the DexFile. Further research is necessary to resolve this issue

## Acknowledgments

Dexray Intercept builds upon the excellent work of various open-source projects and researchers in the Android security and dynamic analysis community. We would like to acknowledge the following projects that have inspired or contributed to our implementation:

### Core Frida Framework
- **[Frida](https://frida.re/)** - The dynamic instrumentation toolkit that powers our runtime analysis capabilities
- **[frida-java-bridge](https://github.com/frida/frida-java-bridge)** - Essential for Java/Android runtime instrumentation

### Hook Implementations & Techniques
- **[AppMon](https://github.com/dpnishant/appmon)** by @dpnishant - Provided foundational hooks for runtime analysis, IPC monitoring, clipboard access, and database operations
- **[Android-Malware-Sandbox](https://github.com/Areizen/Android-Malware-Sandbox)** by @Areizen - Base64 encoding hooks and socket monitoring techniques  
- **[RMS-Runtime-Mobile-Security](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security)** by @m0bilesecurity - Keystore analysis and certificate pinning detection
- **[Medusa](https://github.com/Ch0pin/medusa)** by @Ch0pin - Runtime analysis patterns and DEX unpacking techniques
- **[frida-android-libbinder](https://github.com/Hamz-a/frida-android-libbinder)** by @Hamz-a - Android Binder IPC analysis
- **[frida-snippets](https://github.com/iddoeldor/frida-snippets)** by @iddoeldor - Location spoofing and utility functions

### Android Security Research
- **[BlackDex](https://github.com/CodingGay/BlackDex)** by @CodingGay - DEX unpacking and anti-analysis bypass techniques
- **[Frida-Python-Binding](https://github.com/Mind0xP/Frida-Python-Binding)** by @Mind0xP - Python integration patterns for Frida

### SQLite & Database Analysis
- **[SQLite Database Hook](https://codeshare.frida.re/@ninjadiary/sqlite-database/)** by @ninjadiary - Database monitoring techniques

We extend our gratitude to these projects and their maintainers for advancing the state of Android security analysis and making their work available to the community.

## Roadmap

- [ x ] Create templates for the different hookings we want to install in order to get a runtime profile
- [ ] Create a test application which is using all the different features which we want to hook (we need some sort of ground truth in order to test our hooks)
- [ ] Implement the actual hooks 
- [ x ] The format to print the monitored information
- [ ] https://attack.mitre.org/matrices/mobile/ add this as a final result so we can say what kind of Attacks the Application is using
- [ ] We want to track also things like "this are privacy issues", "this might lead to bugs" ...