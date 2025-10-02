#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .appProfiling import AppProfiler, FridaBasedException, setup_frida_handler
import sys
import time
import frida
import argparse
from .about import __version__
from .about import __author__
from AndroidFridaManager import FridaManager


def print_logo():
    print("""        Dexray Intercept
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
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""")
    print(f"        version: {__version__}\n")



class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("Dexray Intercept v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)


def interactive_hook_selection():
    """Interactive prompt for selecting hooks to enable"""
    print("\n=== Dexray-Intercept Hook Selection ===")
    print("Select which hook categories to enable (y/n for each):\n")

    hook_groups = {
        'crypto': {
            'name': 'Crypto Hooks',
            'description': 'AES, encodings, keystore operations',
            'hooks': ['aes_hooks', 'encodings_hooks', 'keystore_hooks']
        },
        'network': {
            'name': 'Network Hooks',
            'description': 'Web requests, sockets, HTTP/HTTPS traffic',
            'hooks': ['web_hooks', 'socket_hooks']
        },
        'filesystem': {
            'name': 'Filesystem Hooks',
            'description': 'File operations, database access',
            'hooks': ['file_system_hooks', 'database_hooks']
        },
        'ipc': {
            'name': 'IPC Hooks',
            'description': 'Binder, intents, broadcasts, shared preferences',
            'hooks': ['shared_prefs_hooks', 'binder_hooks', 'intent_hooks', 'broadcast_hooks']
        },
        'process': {
            'name': 'Process Hooks',
            'description': 'Native libraries, runtime, DEX unpacking',
            'hooks': ['dex_unpacking_hooks', 'java_dex_unpacking_hooks', 'native_library_hooks', 'process_hooks', 'runtime_hooks']
        },
        'services': {
            'name': 'Service Hooks',
            'description': 'Bluetooth, camera, clipboard, location, telephony',
            'hooks': ['bluetooth_hooks', 'camera_hooks', 'clipboard_hooks', 'location_hooks', 'telephony_hooks']
        },
        'bypass': {
            'name': 'Anti-Analysis Bypass Hooks',
            'description': 'Root, frida, debugger, emulator detection',
            'hooks': ['bypass_hooks']
        }
    }

    selected_hooks = {}

    for key, group in hook_groups.items():
        while True:
            response = input(f"{group['name']} ({group['description']}): [y/n] ").strip().lower()
            if response in ['y', 'n', 'yes', 'no']:
                if response in ['y', 'yes']:
                    for hook in group['hooks']:
                        selected_hooks[hook] = True
                break
            print("Please enter 'y' or 'n'")

    if not selected_hooks:
        print("\n⚠ Warning: No hooks selected. Dexray-intercept will run but won't capture any events.")
        response = input("Continue without hooks? [y/n] ").strip().lower()
        if response not in ['y', 'yes']:
            print("Aborting...")
            sys.exit(0)
    else:
        print(f"\n✓ Enabled {len(selected_hooks)} hook(s)")

    return selected_hooks


def parse_hook_config(parsed_args, use_interactive=False):
    """Convert CLI arguments to hook configuration dictionary

    Args:
        parsed_args: Parsed command line arguments
        use_interactive: If True and no hooks specified, prompt user interactively
    """
    hook_config = {}

    # Handle group selections
    if parsed_args.hooks_all:
        # Enable all hooks
        return {hook: True for hook in [
            'file_system_hooks', 'database_hooks', 'dex_unpacking_hooks', 
            'java_dex_unpacking_hooks', 'native_library_hooks', 'shared_prefs_hooks',
            'binder_hooks', 'intent_hooks', 'broadcast_hooks', 'aes_hooks',
            'encodings_hooks', 'keystore_hooks', 'web_hooks', 'socket_hooks',
            'process_hooks', 'runtime_hooks', 'bluetooth_hooks', 'camera_hooks',
            'clipboard_hooks', 'location_hooks', 'telephony_hooks', 'bypass_hooks'
        ]}
    
    if parsed_args.hooks_crypto:
        hook_config.update({
            'aes_hooks': True,
            'encodings_hooks': True,
            'keystore_hooks': True
        })
    
    if parsed_args.hooks_network:
        hook_config.update({
            'web_hooks': True,
            'socket_hooks': True
        })
    
    if parsed_args.hooks_filesystem:
        hook_config.update({
            'file_system_hooks': True,
            'database_hooks': True
        })
    
    if parsed_args.hooks_ipc:
        hook_config.update({
            'shared_prefs_hooks': True,
            'binder_hooks': True,
            'intent_hooks': True,
            'broadcast_hooks': True
        })
    
    if parsed_args.hooks_process:
        hook_config.update({
            'dex_unpacking_hooks': True,
            'java_dex_unpacking_hooks': True,
            'native_library_hooks': True,
            'process_hooks': True,
            'runtime_hooks': True
        })
    
    if parsed_args.hooks_services:
        hook_config.update({
            'bluetooth_hooks': True,
            'camera_hooks': True,
            'clipboard_hooks': True,
            'location_hooks': True,
            'telephony_hooks': True
        })
    
    if parsed_args.hooks_bypass:
        hook_config.update({
            'bypass_hooks': True
        })
    
    # Handle individual hook selections
    individual_hooks = {
        'enable_aes': 'aes_hooks',
        'enable_keystore': 'keystore_hooks',
        'enable_encodings': 'encodings_hooks',
        'enable_web': 'web_hooks',
        'enable_sockets': 'socket_hooks',
        'enable_filesystem': 'file_system_hooks',
        'enable_database': 'database_hooks',
        'enable_dex_unpacking': 'dex_unpacking_hooks',
        'enable_java_dex': 'java_dex_unpacking_hooks',
        'enable_native_libs': 'native_library_hooks',
        'enable_shared_prefs': 'shared_prefs_hooks',
        'enable_binder': 'binder_hooks',
        'enable_intents': 'intent_hooks',
        'enable_broadcasts': 'broadcast_hooks',
        'enable_process': 'process_hooks',
        'enable_runtime': 'runtime_hooks',
        'enable_bluetooth': 'bluetooth_hooks',
        'enable_camera': 'camera_hooks',
        'enable_clipboard': 'clipboard_hooks',
        'enable_location': 'location_hooks',
        'enable_telephony': 'telephony_hooks',
        'enable_bypass': 'bypass_hooks'
    }
    
    for arg_name, hook_name in individual_hooks.items():
        if getattr(parsed_args, arg_name, False):
            hook_config[hook_name] = True

    # If no hooks specified and interactive mode requested, prompt user
    if not hook_config and use_interactive:
        hook_config = interactive_hook_selection()

    return hook_config


def setup_frida_server():
    afm_obj = FridaManager()
    if not afm_obj.is_frida_server_running():
        print("installing latest frida-server. This may take a while ....\n")
        afm_obj.install_frida_server()
        afm_obj.run_frida_server()
        time.sleep(15)

def main():
    parser = ArgParser(
        add_help=False,
        description="The Dexray Intercept is part of the dynamic Sandbox SanDroid. Its purpose is to create runtime profiles to track the behavior of an Android application.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=r"""
Examples:
  %(prog)s <App-Name/PID> 
  %(prog)s -s com.example.app
  %(prog)s --enable_spawn_gating -v <App-Name/PID>
  %(prog)s --enable-fritap --enable-aes com.example.app
  %(prog)s --enable-fritap --fritap-output-dir ./logs --hooks-all com.example.app
""")

    args = parser.add_argument_group("Arguments")
    args.add_argument("-f", "--frida", metavar="<version>", const=True, action="store_const", 
                      help="Install and run the frida-server to the target device. By default the latest version will be installed.")
    args.add_argument("exec", metavar="<executable/app name/pid>", 
                      help="target app to create the runtime profile")                
    args.add_argument("-H", "--host", metavar="<ip:port>", required=False, default="",
                      help="Attach to a process on remote frida device")
    args.add_argument('--version', action='version',version='Dexray Intercept v{version}'.format(version=__version__))
    args.add_argument("-s", "--spawn", required=False, action="store_const", const=True,
                      help="Spawn the executable/app instead of attaching to a running process")
    args.add_argument("-fg", "--foreground", required=False, action="store_const", const=True,
                      help="Attaching to the foreground app")
    args.add_argument("--enable_spawn_gating", required=False, action="store_const", const=True,
                      help="Catch newly spawned processes. ATTENTION: These could be unrelated to the current process!")
    args.add_argument("-v","--verbose", required=False, action="store_const", const=True, default=False,
                      help="Show verbose output. This could very noisy.")
    args.add_argument("-st", "--enable-full-stacktrace", required=False, action="store_const", const=True, default=False,
                      help="Enable full stack traces for hook invocations (shows call origin in binary)")
    args.add_argument("--non-interactive", required=False, action="store_const", const=True, default=False,
                      help="Disable interactive hook selection prompt (use with caution - no hooks will be enabled without explicit flags)")
    args.add_argument("--enable-fritap", required=False, action="store_const", const=True, default=False,
                      help="Enable fritap for TLS key extraction and traffic capture")
    args.add_argument("--fritap-output-dir", metavar="<directory>", required=False, default="./fritap_output",
                      help="Directory for fritap output files (default: ./fritap_output)")
    args.add_argument("--custom-script", metavar="<path>", action="append", required=False,
                      help="Load custom Frida script file(s) alongside dexray-intercept hooks (can be used multiple times)")
    
    # Hook selection arguments
    hooks = parser.add_argument_group("Hook Selection (all disabled by default)")
    hooks.add_argument("--hooks-all", required=False, action="store_const", const=True, default=False,
                       help="Enable all available hooks")
    hooks.add_argument("--hooks-crypto", required=False, action="store_const", const=True, default=False,
                       help="Enable crypto hooks (AES, encodings, keystore)")
    hooks.add_argument("--hooks-network", required=False, action="store_const", const=True, default=False,
                       help="Enable network hooks (web, sockets)")
    hooks.add_argument("--hooks-filesystem", required=False, action="store_const", const=True, default=False,
                       help="Enable filesystem hooks (file operations, database)")
    hooks.add_argument("--hooks-ipc", required=False, action="store_const", const=True, default=False,
                       help="Enable IPC hooks (binder, intents, broadcasts, shared prefs)")
    hooks.add_argument("--hooks-process", required=False, action="store_const", const=True, default=False,
                       help="Enable process hooks (native libs, runtime, DEX unpacking)")
    hooks.add_argument("--hooks-services", required=False, action="store_const", const=True, default=False,
                       help="Enable service hooks (bluetooth, camera, clipboard, location, telephony)")
    hooks.add_argument("--hooks-bypass", required=False, action="store_const", const=True, default=False,
                       help="Enable anti-analysis bypass hooks (root, frida, debugger, emulator detection)")
    
    # Individual hook arguments
    hooks.add_argument("--enable-aes", action="store_true", help="Enable AES hooks")
    hooks.add_argument("--enable-keystore", action="store_true", help="Enable keystore hooks")
    hooks.add_argument("--enable-encodings", action="store_true", help="Enable encoding hooks")
    hooks.add_argument("--enable-web", action="store_true", help="Enable web hooks")
    hooks.add_argument("--enable-sockets", action="store_true", help="Enable socket hooks")
    hooks.add_argument("--enable-filesystem", action="store_true", help="Enable filesystem hooks")
    hooks.add_argument("--enable-database", action="store_true", help="Enable database hooks")
    hooks.add_argument("--enable-dex-unpacking", action="store_true", help="Enable DEX unpacking hooks")
    hooks.add_argument("--enable-java-dex", action="store_true", help="Enable Java DEX hooks (may crash apps)")
    hooks.add_argument("--enable-native-libs", action="store_true", help="Enable native library hooks")
    hooks.add_argument("--enable-shared-prefs", action="store_true", help="Enable shared preferences hooks")
    hooks.add_argument("--enable-binder", action="store_true", help="Enable binder hooks")
    hooks.add_argument("--enable-intents", action="store_true", help="Enable intent hooks")
    hooks.add_argument("--enable-broadcasts", action="store_true", help="Enable broadcast hooks")
    hooks.add_argument("--enable-process", action="store_true", help="Enable process hooks")
    hooks.add_argument("--enable-runtime", action="store_true", help="Enable runtime hooks")
    hooks.add_argument("--enable-bluetooth", action="store_true", help="Enable bluetooth hooks")
    hooks.add_argument("--enable-camera", action="store_true", help="Enable camera hooks")
    hooks.add_argument("--enable-clipboard", action="store_true", help="Enable clipboard hooks")
    hooks.add_argument("--enable-location", action="store_true", help="Enable location hooks")
    hooks.add_argument("--enable-telephony", action="store_true", help="Enable telephony hooks")
    hooks.add_argument("--enable-bypass", action="store_true", help="Enable anti-analysis bypass hooks")
    
    parsed = parser.parse_args()
    script_name = sys.argv[0]

    if parsed.frida:
        setup_frida_server()
        exit(2)

    setup_frida_server()
    print_logo()

    try:
        if len(sys.argv) > 1 or parsed.foreground:
            target_process = parsed.exec
            device = setup_frida_handler(parsed.host, parsed.enable_spawn_gating)
            # Handle spawn/attach coordination with fritap
            if parsed.spawn and parsed.enable_fritap:
                # When fritap is enabled in spawn mode, fritap handles spawning
                # dexray-intercept just attaches to the target by name after fritap spawns it
                print(f"[*] fritap spawn mode - fritap will spawn '{target_process}', dexray-intercept will attach")
                process_session = None  # Will be set after fritap initializes
                pid = None  # No PID management needed when fritap spawns
            elif parsed.spawn:
                # Normal spawn mode without fritap
                print("[*] spawning app: "+ target_process)
                try:
                    pid = device.spawn(target_process)
                    process_session = device.attach(pid)
                except frida.NotSupportedError as e:
                    print(f"\n[-] Failed to spawn app: {str(e)}")
                    print("\nPossible solutions:")
                    print("  1. Restart frida-server on device: adb shell killall frida-server")
                    print("  2. Check if app is installed: adb shell pm list packages | grep {0}".format(target_process))
                    print("  3. Try attach mode instead: remove -s flag and start app manually first")
                    print("  4. Check device connection: adb devices")
                    sys.exit(1)
                except frida.ServerNotRunningError:
                    print("\n[-] Frida server is not running on the device")
                    print("  Run with -f flag to install and start frida-server")
                    sys.exit(1)
                except frida.ProcessNotFoundError:
                    print(f"\n[-] App not found: {target_process}")
                    print("  Check if package is installed: adb shell pm list packages | grep {0}".format(target_process))
                    sys.exit(1)
                except Exception as e:
                    print(f"\n[-] Unexpected error while spawning app: {type(e).__name__}: {str(e)}")
                    print("  Try restarting frida-server or check device connection")
                    sys.exit(1)
            else:
                # Attach mode (works the same whether fritap is enabled or not)
                if parsed.foreground:
                    target_process = device.get_frontmost_application()
                    if target_process is None or len(target_process.identifier) < 2:
                        print("[-] unable to attach to the frontmost application. Aborting ...")
                        sys.exit(1)

                    target_process = target_process.identifier

                print("[*] attaching to app: "+ target_process)
                try:
                    process_session = device.attach(int(target_process) if target_process.isnumeric() else target_process)
                    pid = None  # No PID in attach mode
                except frida.ProcessNotFoundError:
                    print(f"\n[-] Process not found: {target_process}")
                    print("  Make sure the app is running. Possible solutions:")
                    print("  1. Start app manually on device")
                    print("  2. Use spawn mode with -s flag")
                    print("  3. Check running processes: adb shell ps | grep {0}".format(target_process))
                    sys.exit(1)
                except frida.ServerNotRunningError:
                    print("\n[-] Frida server is not running on the device")
                    print("  Run with -f flag to install and start frida-server")
                    sys.exit(1)
                except Exception as e:
                    print(f"\n[-] Failed to attach to process: {type(e).__name__}: {str(e)}")
                    print("  Try restarting frida-server or check if app is running")
                    sys.exit(1)
            print("[*] starting app profiling")

            # Parse hook configuration from CLI arguments
            # Enable interactive mode if no hooks specified on command line (unless --non-interactive flag set)
            use_interactive = not parsed.non_interactive
            hook_config = parse_hook_config(parsed, use_interactive=use_interactive)
            enabled_hooks = [hook for hook, enabled in hook_config.items() if enabled]
            if enabled_hooks:
                print(f"[*] enabled hooks: {', '.join(enabled_hooks)}")
            else:
                print("[*] no hooks enabled - dexray-intercept will not capture events")
            
            if parsed.enable_fritap:
                print(f"[*] fritap enabled - output directory: {parsed.fritap_output_dir}")
            
            if parsed.custom_script:
                print(f"[*] custom scripts enabled: {', '.join(parsed.custom_script)}")
            
            # Create AppProfiler with target and spawn mode information
            profiler = AppProfiler(
                process_session, 
                parsed.verbose, 
                output_format="CMD", 
                base_path=None, 
                deactivate_unlink=False, 
                hook_config=hook_config, 
                enable_stacktrace=parsed.enable_full_stacktrace, 
                enable_fritap=parsed.enable_fritap, 
                fritap_output_dir=parsed.fritap_output_dir,
                target_name=target_process,
                spawn_mode=parsed.spawn,
                custom_scripts=parsed.custom_script
            )
            
            # Handle fritap spawn mode - attach to target after fritap initializes
            if parsed.spawn and parsed.enable_fritap:
                # Start fritap first (without dexray-intercept hooks)
                print("[*] starting fritap first")
                profiler._start_fritap(target_process)
                
                # Wait for fritap to spawn and initialize the target
                print("[*] waiting for fritap to spawn target...")
                time.sleep(5)
                
                # Now attach dexray-intercept to the fritap-spawned target
                print(f"[*] attaching dexray-intercept to fritap-spawned target: {target_process}")
                try:
                    process_session = device.attach(target_process)
                    profiler.set_process_session(process_session)
                    print("[*] successfully attached to fritap-spawned target")
                except Exception as e:
                    print(f"[-] failed to attach to fritap-spawned target: {e}")
                    print("[-] make sure fritap successfully spawned the target")
                    profiler._stop_fritap()  # Clean up fritap on failure
                    raise
                
                # Now start dexray-intercept hooks (fritap is already running)
                print("[*] starting dexray-intercept hooks")
                profiler.start_profiling(target_process)
            else:
                # Normal profiling start (or fritap attach mode)
                profiler.start_profiling(target_process)


            #handle_instrumentation(process_session, parsed.verbose)
            print("[*] press Ctrl+C to stop the profiling ...\n")
        else:
            print("\n[-] missing argument.")
            print(f"[-] Invoke it with the target process to hook:\n    {script_name} <excutable/app name/pid>")
            exit(2)
        
        # Only resume if we spawned the process ourselves (not fritap)
        if parsed.spawn and not parsed.enable_fritap and pid is not None:
            device.resume(pid)
            time.sleep(1) # without it Java.perform silently fails
        
        # Wait for user input with enhanced handling for fritap coordination
        try:
            if parsed.enable_fritap:
                print("[*] fritap is running - press Ctrl+C to send interrupt to fritap and stop profiling")
                print("[*] fritap will finish writing its capture files before exiting")
            sys.stdin.read()
        except KeyboardInterrupt:
            # This will be handled in the outer KeyboardInterrupt handler
            raise
    except frida.TransportError as fe:
        print(f"[-] Problems while attaching to frida-server: {fe}")
        exit(2)
    except FridaBasedException as e:
        print(f"[-] Frida based error: {e}")
        exit(2)
    except frida.TimedOutError as te:
        print(f"[-] TimeOutError: {te}")
        exit(2)
    except frida.ProcessNotFoundError as pe:
        print(f"[-] ProcessNotFoundError: {pe}")
        exit(2)
    except KeyboardInterrupt:
        print("\\n[*] interrupt received - stopping profiling")
        if isinstance(profiler, AppProfiler):
            # Enhanced shutdown with fritap coordination
            if parsed.enable_fritap:
                print("[*] sending interrupt to fritap and waiting for it to finish")
                profiler.send_interrupt_to_fritap()
                
                # Wait a bit for fritap to receive and process the interrupt
                print("[*] waiting for fritap to complete capture...")
                if not profiler.wait_for_fritap(timeout=15):
                    print("[-] fritap did not finish within timeout, forcing shutdown")
                else:
                    print("[*] fritap finished successfully")
            
            # Stop dexray-intercept profiling
            profiler.stop_profiling()
            profiler.write_profiling_log(target_process)
        pass

if __name__ == "__main__":
    main()
