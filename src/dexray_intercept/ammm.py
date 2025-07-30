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


def parse_hook_config(parsed_args):
    """Convert CLI arguments to hook configuration dictionary"""
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
            'clipboard_hooks', 'location_hooks', 'telephony_hooks'
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
        'enable_telephony': 'telephony_hooks'
    }
    
    for arg_name, hook_name in individual_hooks.items():
        if getattr(parsed_args, arg_name, False):
            hook_config[hook_name] = True
    
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
            if parsed.spawn:
                print("[*] spawning app: "+ target_process)
                pid = device.spawn(target_process)
                process_session = device.attach(pid)
            else:
                if parsed.foreground:
                    target_process = device.get_frontmost_application()
                    if target_process is None or len(target_process.identifier) < 2:
                        print("[-] unable to attach to the frontmost application. Aborting ...")

                    target_process = target_process.identifier

                print("[*] attaching to app: "+ target_process)
                process_session = device.attach(int(target_process) if target_process.isnumeric() else target_process)
            print("[*] starting app profiling")
            
            # Parse hook configuration from CLI arguments
            hook_config = parse_hook_config(parsed)
            enabled_hooks = [hook for hook, enabled in hook_config.items() if enabled]
            if enabled_hooks:
                print(f"[*] enabled hooks: {', '.join(enabled_hooks)}")
            else:
                print("[*] no hooks enabled - use --help to see hook options")
            
            # Assuming 'process' is a valid frida.Process object
            profiler = AppProfiler(process_session, parsed.verbose, output_format="CMD", base_path=None, deactivate_unlink=False, hook_config=hook_config, enable_stacktrace=parsed.enable_full_stacktrace)
            profiler.start_profiling()


            #handle_instrumentation(process_session, parsed.verbose)
            print("[*] press Ctrl+C to stop the profiling ...\n")
        else:
            print("\n[-] missing argument.")
            print(f"[-] Invoke it with the target process to hook:\n    {script_name} <excutable/app name/pid>")
            exit(2)
        
        if parsed.spawn:
            device.resume(pid)
            time.sleep(1) # without it Java.perform silently fails
        sys.stdin.read()
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
        if isinstance(profiler, AppProfiler):
            profiler.write_profiling_log(target_process)
        pass

if __name__ == "__main__":
    main()
