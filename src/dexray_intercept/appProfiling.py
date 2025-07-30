#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import os
from .deviceUtils import getFilePath, create_unpacking_folder, get_orig_path, get_filename_from_path, is_benign_dump, pull_file_from_device
from .resultManager import handle_output
import json
from datetime import datetime
from colorama import Fore
from .parser import parse_file_system_event, parse_native_lib_loading, parse_shared_pref, parse_aes, dex_loading_parser, parse_socket_infos, parse_web_infos, parse_telephony_infos, remove_empty_entries, get_event_type_infos, get_demangled_method_for_DEX_unpacking, parse_broadcast_infos, url_parser, parse_generic_infos, hexdump

# Define a custom exception for handling frida based exceptions
class FridaBasedException(Exception):
    pass


class AppProfiler:
    def __init__(self, process, verbose_mode=False, output_format="CMD", base_path=None, deactivate_unlink=False, path_filters=None, hook_config=None, enable_stacktrace=False):
        self.process = process
        self.verbose_mode = verbose_mode
        self.output_format = output_format
        self.base_path = base_path
        self.deactivate_unlink = deactivate_unlink
        self.script = None
        self.benign_path, self.malicious_path = create_unpacking_folder(base_path)
        self.DO_DEBUGGING = verbose_mode
        self.startup = True
        self.startup_unlink = True
        self.ORG_FILE_LOCATION = ""
        self.SCRIPT_DO_TESTING = True
        self.frida_agent_script = "profiling.js"
        self.skip_output = False
        self.output_data = {}
        self.downloaded_origins = {}
        self.dex_list = []
        self.path_filters = path_filters  # New: filter(s) as a string or a list
        self.enable_stacktrace = enable_stacktrace  # Enable full stack traces
        
        # Hook configuration - all hooks disabled by default
        self.hook_config = self._init_hook_config(hook_config)


    def _init_hook_config(self, hook_config):
        """Initialize hook configuration with all hooks disabled by default"""
        default_config = {
            # File system hooks
            'file_system_hooks': False,
            'database_hooks': False,
            
            # DEX and native library hooks
            'dex_unpacking_hooks': False,
            'java_dex_unpacking_hooks': False,
            'native_library_hooks': False,
            
            # IPC hooks
            'shared_prefs_hooks': False,
            'binder_hooks': False,
            'intent_hooks': False,
            'broadcast_hooks': False,
            
            # Crypto hooks
            'aes_hooks': False,
            'encodings_hooks': False,
            'keystore_hooks': False,
            
            # Network hooks
            'web_hooks': False,
            'socket_hooks': False,
            
            # Process hooks
            'process_hooks': False,
            'runtime_hooks': False,
            
            # Service hooks
            'bluetooth_hooks': False,
            'camera_hooks': False,
            'clipboard_hooks': False,
            'location_hooks': False,
            'telephony_hooks': False,
        }
        
        if hook_config:
            default_config.update(hook_config)
        
        return default_config

    def update_script(self, script):
        self.script = script
    
    def enable_hook(self, hook_name, enabled=True):
        """Enable or disable a specific hook at runtime"""
        if hook_name in self.hook_config:
            self.hook_config[hook_name] = enabled
            if self.script:
                # Send updated hook configuration to Frida script
                self.script.post({'type': 'hook_config', 'payload': {hook_name: enabled}})
        else:
            raise ValueError(f"Unknown hook: {hook_name}")
    
    def get_enabled_hooks(self):
        """Return list of currently enabled hooks"""
        return [hook for hook, enabled in self.hook_config.items() if enabled]

    
    def handle_output(self, data, category, output_format, timestamp):
        """
        Handles output based on the specified format.

        :param data: The content to be outputted or saved.
        :param category: The category or class type of the data.
        :param output_format: "CMD" for command line output (and JSON as well), "JSON" for JSON file output only.
        """
        if "creating local copy of unpacked file" in data:
            self.skip_output = True

        if "Unpacking detected!" in data:
            self.skip_output = False

        if self.skip_output:
            return

        # Process JSON output for all formats
        if category not in self.output_data:
            self.output_data[category] = []

        if category == "FILE_SYSTEM":
            if data.startswith("[Java:") or data.startswith("[Libc:"):
                parsed_data = parse_file_system_event(data, timestamp)
                self.output_data[category].append(parsed_data)
        elif category == "PROCESS_NATIVE_LIB":
            parsed_data = parse_native_lib_loading(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "IPC_SHARED-PREF":
            parsed_data = parse_shared_pref(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "CRYPTO_AES":
            parsed_data = parse_aes(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "NETWORK_SOCKETS":
            parsed_data = parse_socket_infos(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "WEB":
            parsed_data = parse_web_infos(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "TELEPHONY":
            parsed_data = parse_telephony_infos(data, timestamp)
            self.output_data[category].append(parsed_data)
        else:
            parsed_data = parse_generic_infos(data, timestamp, category)
            self.output_data[category].append(parsed_data)

        # Handle CMD-specific output
        if output_format == "CMD":
            if category == "console_dev":
                if data == "Unkown":
                    return
                print("[***] " + data)
            elif category == "error":
                print("[-] " + data)
            elif category == "newline":
                print()
            elif category == "FILE_SYSTEM":
                if data.startswith("[Libc::write]"):
                    return
                else:
                    print("[*] " + data)
            elif category == "DEX_LOADING":
                if "even_type" in data:
                    dex_unpacking_method = get_event_type_infos(data)
                    demangled_version = get_demangled_method_for_DEX_unpacking(dex_unpacking_method)
                    demangled_method_name_tmp = demangled_version.split("::")[1:]
                    demangled_method_name = '::'.join(demangled_method_name_tmp)
                    print(f"[*] Method used for unpacking: {demangled_method_name}")
                else:
                    print("[*] " + data)
            elif category == "WEB":
                if "URI" in data or "Java::net.url" in data:
                    parsed_data = url_parser(data, timestamp)
                    print(f"[*] [{parsed_data['event_type']}] URI: {parsed_data['uri']}")

                if "HttpURLConnectionImpl" in data and "event_type" not in data:
                    print(f"[*] [OkHttp]: {data}")

                parsed_data_web = parse_web_infos(data, timestamp)
                if parsed_data_web is not None:
                    if "body" in parsed_data_web:
                        print(f"[*] {parsed_data_web['event_type']}: Headers: {parsed_data_web['headers']}")
                        print(f"[*] {parsed_data_web['event_type']}: Body: {parsed_data_web['body']}\n\n")
            elif category == "IPC_BROADCAST":
                parsed_data = parse_broadcast_infos(data, timestamp)
                print(f"[*] [Broadcast] {parsed_data['event_type']}")
                if "intent_name" in parsed_data:
                    print(f"[*] [Broadcast] Intent component name: {parsed_data['intent_name']}\n")
            elif category == "IPC_SHARED-PREF":
                parsed_data = parse_shared_pref(data, timestamp)
                if "value" in parsed_data:
                    print(f"[*] SharedPref Content: {parsed_data['value']}\n")
                else:
                    print("[*] SharedPref: " + data)
            elif category == "CRYPTO_AES":
                parsed_data = parse_aes(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type == 'crypto.cipher.operation':
                        print(f"\n[*] AES {parsed_data.get('operation_mode_desc', 'UNKNOWN')} Operation:")
                        print(f"    Algorithm: {parsed_data.get('algorithm', 'N/A')}")
                        
                        # Display input data with hexdump
                        if 'input_hex' in parsed_data and parsed_data['input_hex']:
                            print(f"    Input ({parsed_data.get('input_length', 0)} bytes):")
                            input_dump = hexdump(parsed_data['input_hex'], header=True, ansi=True)
                            if input_dump:
                                for line in input_dump.split('\n'):
                                    print(f"      {line}")
                        
                        # Display output data with hexdump  
                        if 'output_hex' in parsed_data and parsed_data['output_hex']:
                            print(f"    Output ({parsed_data.get('output_length', 0)} bytes):")
                            output_dump = hexdump(parsed_data['output_hex'], header=True, ansi=True)
                            if output_dump:
                                for line in output_dump.split('\n'):
                                    print(f"      {line}")
                        
                        # Display plaintext if available (truncated for terminal)
                        if 'plaintext' in parsed_data and parsed_data['plaintext']:
                            plaintext = parsed_data['plaintext']
                            if len(plaintext) > 100:
                                truncated_plaintext = plaintext[:100] + "..."
                                print(f"    Plaintext: {truncated_plaintext}")
                            else:
                                print(f"    Plaintext: {plaintext}")
                        
                        print()
                    elif event_type == 'crypto.key.creation':
                        print(f"[*] AES Key Created:")
                        print(f"    Algorithm: {parsed_data.get('algorithm', 'N/A')}")
                        print(f"    Key Length: {parsed_data.get('key_length', 0)} bytes")
                        if 'key_hex' in parsed_data and parsed_data['key_hex']:
                            print(f"    Key:")
                            key_dump = hexdump(parsed_data['key_hex'], header=True, ansi=True)
                            if key_dump:
                                for line in key_dump.split('\n'):
                                    print(f"      {line}")
                        print()
                    elif event_type == 'crypto.iv.creation':
                        print(f"[*] AES IV Created:")
                        print(f"    IV Length: {parsed_data.get('iv_length', 0)} bytes")
                        if 'iv_hex' in parsed_data and parsed_data['iv_hex']:
                            print(f"    IV:")
                            iv_dump = hexdump(parsed_data['iv_hex'], header=True, ansi=True)
                            if iv_dump:
                                for line in iv_dump.split('\n'):
                                    print(f"      {line}")
                        print()
                    else:
                        print("[*] " + data + "\n")
                else:
                    print("[*] " + data + "\n")
            elif category == "NETWORK_SOCKETS":
                parsed_data = parse_socket_infos(data, timestamp)
                if parsed_data is None:
                    return
                else:
                    print("[*] Network Infos: " + data)
            elif category == "TELEPHONY":
                parsed_data = parse_telephony_infos(data, timestamp)
                if "key" in parsed_data:
                    print(f"[*] Java::SystemProperties: {parsed_data['event']}")
                    print(f"[*] Java::SystemProperties key: {parsed_data['key']}\n")
                elif "event" in parsed_data:
                    print(f"[*] Java::TelephonyManager: {parsed_data['event']}")
                    print(f"[*] Java::TelephonyManager returning: {parsed_data['return']}\n")
                else:
                    print("[*] TELEPHONY: " + data + "\n")
            else:
                print("[*] " + data)
        else:
            return

    
    
    def callback_wrapper(self):
        def wrapped_handler(message, data):
            self.on_appProfiling_message(None, message, data)
        
        return wrapped_handler
    
    
    def on_appProfiling_message(self,job, message, data):
        if self.script is None:
            self.script = job.script

        if self.startup and message.get('payload') == 'verbose_mode':
            self.script.post({'type': 'verbose_mode', 'payload': self.verbose_mode})
            self.startup = False

        if self.startup_unlink and message.get('payload') == 'deactivate_unlink':
            self.script.post({'type': 'deactivate_unlink', 'payload': self.deactivate_unlink})
            self.startup_unlink = False

        if message.get('payload') == 'hook_config':
            self.script.post({'type': 'hook_config', 'payload': self.hook_config})
        if message.get('payload') == 'enable_stacktrace':
            self.script.post({'type': 'enable_stacktrace', 'payload': self.enable_stacktrace})

        # Send the path filter rules once to the agent
        if self.path_filters is not None:
            # Ensure value is a list:
            filters = self.path_filters if isinstance(self.path_filters, list) else [self.path_filters]
            self.script.post({'type': 'path_filters', 'payload': filters})
            # optionally, set self.path_filters = None to send only once 
            self.path_filters = None

        if message["type"] == 'error' and self.DO_DEBUGGING:
            event_time = datetime.now().isoformat()
            self.handle_output("Error in frida script:", "error", self.output_format, event_time)
            if 'stack' in message:
                self.handle_output(message['stack'], "error", self.output_format, event_time)
            else:
                self.handle_output("[plain message]: " + str(message), "error", self.output_format, event_time)
            self.handle_output("", "newline", self.output_format, event_time)
            return
        elif message["type"] == 'error':
            return  # just return silently when we are not in verbose_mode

        p = message["payload"]
        if "profileType" not in p:
            return

        if p["profileType"] == "console":
            self.handle_output(p["console"], p["profileType"], self.output_format, p["timestamp"])
        elif p["profileType"] == "console_dev" and self.DO_DEBUGGING:
            if len(p["console_dev"]) > 3:
                self.handle_output(p["console_dev"], p["profileType"], self.output_format, p["timestamp"])
        elif p["profileType"] == "FILE_SYSTEM" and self.SCRIPT_DO_TESTING:
            if "stat" not in p["profileContent"] and "/system/fonts/" not in p["profileContent"]:
                self.handle_output(p["profileContent"], p["profileType"], self.output_format, p["timestamp"])
        elif p["profileType"] == "DATABASE":
            self.handle_output(p["profileContent"] + "\n", p["profileType"], self.output_format, p["timestamp"])
        elif p["profileType"] == "DEX_LOADING":
            if p["profileContent"] not in self.dex_list:
                self.dex_list.append(p["profileContent"])
            if "dumped" in p["profileContent"]:
                if self.output_format == "CMD":
                    print("")
                filePath = getFilePath(p["profileContent"])
                self.dump(filePath, self.ORG_FILE_LOCATION, self.benign_path, self.malicious_path, p["profileType"], self.output_format, p["timestamp"])
            else:
                if self.output_format == "CMD":
                    self.handle_output(p["profileContent"], p["profileType"], self.output_format, p["timestamp"])
                if "orig location" in p["profileContent"]:
                    self.ORG_FILE_LOCATION = get_orig_path(p["profileContent"])
        elif p["profileType"] == "DYNAMIC_LIB_LOADING":
            self.handle_output(p["profileContent"], p["profileType"], self.output_format, p["timestamp"])
        elif p["profileType"] == "CRYPTO_AES":
            self.handle_output(p["profileContent"], p["profileType"], self.output_format, p["timestamp"])
        else:
            if 'profileContent' in p:
                self.handle_output(p["profileContent"], p["profileType"], self.output_format, p["timestamp"])
            else:
                self.handle_output("Unkown", p["profileType"], self.output_format, p["timestamp"])


    def instrument(self):
        try:
            runtime = "qjs"
            with open(os.path.join(os.path.dirname(__file__), self.frida_agent_script), encoding='utf8', newline='\n') as f:
                script_string = f.read()
                self.script = self.process.create_script(script_string, runtime=runtime)

            self.script.on("message", self.callback_wrapper())
            self.script.load()
            return self.script

        except frida.ProcessNotFoundError:
            raise FridaBasedException("Unable to find target process")
        except frida.InvalidOperationError:
            raise FridaBasedException("Invalid operation! Please run AM³ in debug mode in order to understand the source of this error and report it.")
        except frida.TransportError:
            raise FridaBasedException("Timeout error due to some internal frida error's. Try to restart frida-server again.")
        except frida.ProtocolError:
            raise FridaBasedException("Connection is closed. Probably the target app crashed")


    def start_profiling(self):
        self.script = self.instrument()
        return self.script
    

    def finish_app_profiling(self):
        if self.script:
            self.script.unload()

    
    def get_frida_script(self):
        return os.path.join(os.path.dirname(__file__), self.frida_agent_script)


    def dump(self, filePath, orig_path, benign_path, malicious_path, category ,output_format, timestamp):
        parsed_data = {}
        file_name = get_filename_from_path(filePath)

        if orig_path in self.downloaded_origins:
            previously_downloaded_file = self.downloaded_origins[orig_path]
            if output_format == "CMD":
                self.handle_output(f"File '{file_name}' has already been dumped as {previously_downloaded_file}\n", category ,output_format,timestamp)
            return

        if is_benign_dump(orig_path):
            dump_path = benign_path +"/"+ file_name
            pull_file_from_device(filePath, dump_path, category ,output_format)
            if output_format == "CMD":
                self.handle_output(Fore.GREEN +f"dumped benign DEX to: {dump_path}\n", category ,output_format,timestamp)
            else:
                parsed_data = dex_loading_parser(self.dex_list)
                parsed_data["unpacking"] = "True"
                parsed_data["dumped"] = dump_path
                parsed_data["timestamp"] = timestamp
                self.handle_output(parsed_data, category ,output_format,timestamp)
                self.dex_list.clear()
        else:
            if output_format == "CMD":
                self.handle_output("Unpacking detected!", category ,output_format,timestamp)
            else:
                parsed_data = dex_loading_parser(self.dex_list)
                parsed_data["unpacking"] = "True"
            dump_path = malicious_path +"/"+ file_name
            pull_file_from_device(filePath, dump_path, category ,output_format)

            if output_format == "CMD":
                self.handle_output(Fore.RED + f"dumped DEX payload to: {dump_path}\n", category ,output_format,timestamp)
            else:
                parsed_data["dumped"] = dump_path
                parsed_data["timestamp"] = timestamp
                self.handle_output(parsed_data, category ,output_format,timestamp)
                self.dex_list.clear()
        
        self.downloaded_origins[orig_path] = file_name

    
    def get_profiling_log_as_JSON(self):
        self.output_data = remove_empty_entries(self.output_data)
        return json.dumps(self.output_data, indent=4)


    def convert_exceptions(self, obj):
        if isinstance(obj, Exception):
            return str(obj)
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


    def write_profiling_log(self, filename="profile.json"):
        """
        Writes all collected data to a JSON file.
        """
        try:
            current_time = datetime.now()
            timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")

            # Ensure filename is safe
            base_filename = filename.replace(" ", "_")  # Replace spaces with underscores
            safe_filename = f"profile_{base_filename}_{timestamp}.json"

            with open(safe_filename, "w") as file:
                self.output_data = remove_empty_entries(self.output_data)
                json.dump(self.output_data, file, indent=4, default=self.convert_exceptions)
        except Exception as e:
            print("[-] Error: "+e)
            debug_file = filename + "_debug.txt"
            with open(debug_file, "w") as file:
                file.write(str(self.output_data))
                file.close()


def setup_frida_handler(host="", enable_spawn_gating=False):
    try:
        if len(host) > 4:
            # we can also use the IP address ot the target machine instead of using USB - e.g. when we have multpile AVDs
            device = frida.get_device_manager().add_remote_device(host)
        else:
            device = frida.get_usb_device()

        # to handle forks
        def on_child_added(child):
            handle_output(f"Attached to child process with pid {child.pid}","none","CMD")
            # Note: This function needs to be called from within an AppProfiler instance
            # self.instrument(device.attach(child.pid))
            device.resume(child.pid)

        # if the target process is starting another process 
        def on_spawn_added(spawn):
            handle_output(f"Process spawned with pid {spawn.pid}. Name: {spawn.identifier}","none","CMD")
            # Note: This function needs to be called from within an AppProfiler instance
            # self.instrument(device.attach(spawn.pid))
            device.resume(spawn.pid)

        device.on("child_added", on_child_added)
        if enable_spawn_gating:
            device.enable_spawn_gating()
            device.on("spawn_added", on_spawn_added)
        
        return device
    

    except frida.InvalidArgumentError:
        raise FridaBasedException("Unable to find device")
    except frida.ServerNotRunningError:
        raise FridaBasedException("Frida server not running. Start frida-server and try it again.")
