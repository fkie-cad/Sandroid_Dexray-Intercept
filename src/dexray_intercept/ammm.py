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
            # Assuming 'process' is a valid frida.Process object
            profiler = AppProfiler(process_session, parsed.verbose, output_format="CMD", base_path=None, deactivate_unlink=False)
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
