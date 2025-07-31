#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import os
from .deviceUtils import getFilePath, create_unpacking_folder, get_orig_path, get_filename_from_path, is_benign_dump, pull_file_from_device
from .resultManager import handle_output
import json
from datetime import datetime
from colorama import Fore
from .parser_legacy import parse_file_system_event, parse_native_lib_loading, parse_shared_pref, parse_aes, parse_binder, parse_intent, dex_loading_parser, parse_socket_infos, parse_web_infos, parse_telephony_infos, remove_empty_entries, get_event_type_infos, get_demangled_method_for_DEX_unpacking, parse_broadcast_infos, parse_generic_infos, hexdump, parse_process_creation, parse_runtime_hooks, parse_service_hooks

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
        elif category == "PROCESS_CREATION":
            parsed_data = parse_process_creation(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "RUNTIME_HOOKS":
            parsed_data = parse_runtime_hooks(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category in ["BLUETOOTH", "TELEPHONY", "LOCATION_ACCESS", "CLIPBOARD", "CAMERA"]:
            parsed_data = parse_service_hooks(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "IPC_SHARED-PREF":
            parsed_data = parse_shared_pref(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "IPC_BINDER":
            parsed_data = parse_binder(data, timestamp)
            self.output_data[category].append(parsed_data)
        elif category == "IPC_INTENT":
            parsed_data = parse_intent(data, timestamp)
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
                    parsed_data = parse_file_system_event(data, timestamp)
                    if parsed_data:
                        event_type = parsed_data.get('event_type', 'unknown')
                        
                        if event_type == 'file.create':
                            print("\n[*] [File] File Creation:")
                            print(f"[*] Operation: {parsed_data.get('operation', 'Unknown')}")
                            print(f"[*] File Path: {parsed_data.get('file_path', 'Unknown')}")
                            if 'parent_path' in parsed_data:
                                print(f"[*] Parent: {parsed_data['parent_path']}")
                                print(f"[*] Child: {parsed_data['child_path']}")
                        
                        elif event_type == 'file.stream.create':
                            print("\n[*] [File] Stream Creation:")
                            print(f"[*] Operation: {parsed_data.get('operation', 'Unknown')}")
                            print(f"[*] Stream Type: {parsed_data.get('stream_type', 'Unknown')}")
                            print(f"[*] File Path: {parsed_data.get('file_path', 'Unknown')}")
                        
                        elif event_type == 'file.read':
                            print("\n[*] [File] Read Operation:")
                            print(f"[*] Operation: {parsed_data.get('operation', 'Unknown')}")
                            print(f"[*] File Path: {parsed_data.get('file_path', 'Unknown')}")
                            print(f"[*] Buffer Size: {parsed_data.get('buffer_size', 0)} bytes")
                            if 'offset' in parsed_data:
                                print(f"[*] Offset: {parsed_data['offset']}, Length: {parsed_data.get('length', 0)}")
                            if 'bytes_read' in parsed_data:
                                print(f"[*] Bytes Read: {parsed_data['bytes_read']}")
                            
                            # Display data if available
                            if 'hexdump_display' in parsed_data and parsed_data['hexdump_display']:
                                print("[*] Data:")
                                for line in parsed_data['hexdump_display'].split('\n'):
                                    print(f"    {line}")
                            elif 'plaintext' in parsed_data and parsed_data['plaintext']:
                                plaintext = parsed_data['plaintext']
                                if len(plaintext) > 100:
                                    plaintext = plaintext[:100] + "..."
                                print(f"[*] Content: {plaintext}")
                        
                        elif event_type == 'file.write':
                            print("\n[*] [File] Write Operation:")
                            print(f"[*] Operation: {parsed_data.get('operation', 'Unknown')}")
                            print(f"[*] File Path: {parsed_data.get('file_path', 'Unknown')}")
                            print(f"[*] Buffer Size: {parsed_data.get('buffer_size', 0)} bytes")
                            if 'offset' in parsed_data:
                                print(f"[*] Offset: {parsed_data['offset']}, Length: {parsed_data.get('length', 0)}")
                            if parsed_data.get('is_large_data', False):
                                print(f"[*] Data truncated (showing {parsed_data.get('displayed_length', 0)} of {parsed_data.get('original_length', 0)} bytes)")
                            
                            # Display data based on file type
                            file_type = parsed_data.get('file_type', 'other')
                            if file_type == 'xml' and 'plaintext' in parsed_data:
                                plaintext = parsed_data['plaintext']
                                if len(plaintext) > 200:
                                    plaintext = plaintext[:200] + "..."
                                print(f"[*] XML Content: {plaintext}")
                            elif file_type == 'binary' and 'hexdump_display' in parsed_data:
                                print("[*] Binary Data:")
                                for line in parsed_data['hexdump_display'].split('\n'):
                                    print(f"    {line}")
                            elif 'hexdump_display' in parsed_data and parsed_data['hexdump_display']:
                                print("[*] Data:")
                                for line in parsed_data['hexdump_display'].split('\n'):
                                    print(f"    {line}")
                            elif 'plaintext' in parsed_data and parsed_data['plaintext']:
                                plaintext = parsed_data['plaintext']
                                if len(plaintext) > 100:
                                    plaintext = plaintext[:100] + "..."
                                print(f"[*] Content: {plaintext}")
                        
                        elif event_type.startswith('file.delete'):
                            print(f"\n[*] [File] File Deletion ({event_type}):")
                            print(f"[*] File Path: {parsed_data.get('file_path', 'Unknown')}")
                        
                        else:
                            # Fallback for unknown filesystem events or legacy format
                            print(f"[*] [File] {event_type}: {data}")
                        
                        print()
                    else:
                        # Fallback for unparseable data
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
                parsed_data_web = parse_web_infos(data, timestamp)
                if parsed_data_web is not None:
                    event_type = parsed_data_web.get('event_type', 'unknown')
                    
                    # Handle different web event types
                    if event_type.startswith('url.'):
                        print(f"[*] [{event_type}] URL: {parsed_data_web.get('url', 'unknown')}")
                        if 'req_method' in parsed_data_web:
                            print(f"[*] [{event_type}] Method: {parsed_data_web['req_method']}")
                    
                    elif event_type.startswith('uri.'):
                        print(f"[*] [{event_type}] URI: {parsed_data_web.get('uri', 'unknown')}")
                    
                    elif event_type.startswith('http.') or event_type.startswith('https.'):
                        print(f"[*] [{event_type}] URL: {parsed_data_web.get('url', 'unknown')}")
                        if 'status_code' in parsed_data_web:
                            print(f"[*] [{event_type}] Status: {parsed_data_web['status_code']}")
                        if 'method' in parsed_data_web:
                            print(f"[*] [{event_type}] Method: {parsed_data_web['method']}")
                    
                    elif event_type.startswith('okhttp.'):
                        print(f"[*] [{event_type}] URL: {parsed_data_web.get('url', 'unknown')}")
                        if 'headers' in parsed_data_web and parsed_data_web['headers']:
                            print(f"[*] [{event_type}] Headers: {parsed_data_web['headers']}")
                        if 'body' in parsed_data_web and parsed_data_web['body']:
                            body = parsed_data_web['body']
                            if len(body) > 100:
                                body = body[:100] + "..."
                            print(f"[*] [{event_type}] Body: {body}")
                    
                    elif event_type.startswith('webview.'):
                        print(f"[*] [{event_type}] URL: {parsed_data_web.get('url', 'N/A')}")
                        if 'data' in parsed_data_web and parsed_data_web['data']:
                            print(f"[*] [{event_type}] Data: {parsed_data_web['data']}")
                        if 'mime_type' in parsed_data_web:
                            print(f"[*] [{event_type}] MIME Type: {parsed_data_web['mime_type']}")
                    
                    else:
                        # Fallback for unknown web events
                        print(f"[*] [{event_type}] {data}")
                    
                    print()
            elif category == "IPC_BINDER":
                parsed_data = parse_binder(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type == 'binder.transaction':
                        transaction_desc = parsed_data.get('transaction_desc', 'Unknown')
                        sender_pid = parsed_data.get('sender_pid', 'unknown')
                        code = parsed_data.get('code', 'unknown')
                        data_size = parsed_data.get('data_size', 0)
                        print(f"\n[*] [Binder] {transaction_desc}:")
                        print(f"[*] Sender PID: {sender_pid}, Code: {code}, Data Size: {data_size} bytes")
                        if 'payload_hex' in parsed_data and parsed_data['payload_hex']:
                            payload_preview = parsed_data['payload_hex'][:200] + "..." if len(parsed_data['payload_hex']) > 200 else parsed_data['payload_hex']
                            print(f"[*] Payload Preview: {payload_preview}")
                    else:
                        print(f"[*] [Binder] {event_type}: {data}")
                    
                    print()
            elif category == "IPC_BROADCAST":
                parsed_data = parse_broadcast_infos(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type.startswith('broadcast.'):
                        print(f"\n[*] [Broadcast] {event_type}:")
                        if 'intent_name' in parsed_data:
                            print(f"[*] Intent: {parsed_data['intent_name']}")
                        if 'intent_details' in parsed_data:
                            details = parsed_data['intent_details']
                            if details.get('action'):
                                print(f"[*] Action: {details['action']}")
                            if details.get('component'):
                                print(f"[*] Component: {details['component']}")
                            if details.get('data_uri'):
                                print(f"[*] Data URI: {details['data_uri']}")
                    elif event_type.startswith('activity.'):
                        print(f"\n[*] [Activity] {event_type}:")
                        if 'intent_name' in parsed_data:
                            print(f"[*] Intent: {parsed_data['intent_name']}")
                    elif event_type.startswith('service.'):
                        print(f"\n[*] [Service] {event_type}:")
                        if 'intent_name' in parsed_data:
                            print(f"[*] Service: {parsed_data['intent_name']}")
                    else:
                        print(f"[*] [Broadcast] {event_type}: {data}")
                    
                    print()
            elif category == "IPC_INTENT":
                parsed_data = parse_intent(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type.startswith('intent.'):
                        print(f"\n[*] [Intent] {event_type}:")
                        if 'intent_name' in parsed_data:
                            print(f"[*] Intent: {parsed_data['intent_name']}")
                        if 'intent' in parsed_data:
                            intent_info = parsed_data['intent']
                            if intent_info.get('action'):
                                print(f"[*] Action: {intent_info['action']}")
                            if intent_info.get('component'):
                                print(f"[*] Component: {intent_info['component']}")
                            if intent_info.get('data_uri'):
                                print(f"[*] Data URI: {intent_info['data_uri']}")
                            if intent_info.get('mime_type'):
                                print(f"[*] MIME Type: {intent_info['mime_type']}")
                        if 'extras_formatted' in parsed_data and parsed_data['extras_formatted']:
                            print("[*] Extras:")
                            for extra in parsed_data['extras_formatted']:
                                print(f"    {extra}")
                    else:
                        print(f"[*] [Intent] {event_type}: {data}")
                    
                    print()
            elif category == "IPC_SHARED-PREF":
                parsed_data = parse_shared_pref(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type.startswith('shared_prefs.'):
                        if 'key' in parsed_data and 'value' in parsed_data:
                            print(f"[*] [{event_type}] {parsed_data['key']} = {parsed_data['value']}")
                        elif 'file' in parsed_data:
                            print(f"[*] [{event_type}] File: {parsed_data['file']}")
                        else:
                            print(f"[*] [{event_type}] {parsed_data.get('method', 'unknown')}")
                    
                    elif event_type.startswith('datastore'):
                        if 'key' in parsed_data and 'value' in parsed_data:
                            print(f"[*] [{event_type}] {parsed_data['key']} = {parsed_data['value']}")
                        elif 'data' in parsed_data:
                            print(f"[*] [{event_type}] Data: {parsed_data['data']}")
                        else:
                            print(f"[*] [{event_type}] {parsed_data.get('method', 'unknown')}")
                    
                    else:
                        # Fallback for legacy format
                        if "value" in parsed_data:
                            print(f"[*] SharedPref Content: {parsed_data['value']}")
                        else:
                            print(f"[*] [{event_type}] {data}")
                    
                    print()
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
                        print("[*] AES Key Created:")
                        print(f"    Algorithm: {parsed_data.get('algorithm', 'N/A')}")
                        print(f"    Key Length: {parsed_data.get('key_length', 0)} bytes")
                        if 'key_hex' in parsed_data and parsed_data['key_hex']:
                            print("    Key:")
                            key_dump = hexdump(parsed_data['key_hex'], header=True, ansi=True)
                            if key_dump:
                                for line in key_dump.split('\n'):
                                    print(f"      {line}")
                        print()
                    elif event_type == 'crypto.iv.creation':
                        print("[*] AES IV Created:")
                        print(f"    IV Length: {parsed_data.get('iv_length', 0)} bytes")
                        if 'iv_hex' in parsed_data and parsed_data['iv_hex']:
                            print("    IV:")
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
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type.startswith('socket.'):
                        operation = parsed_data.get('operation', 'Socket Operation')
                        socket_desc = parsed_data.get('socket_description', 'Unknown Socket')
                        print(f"\n[*] [Socket] {operation} ({socket_desc}):")
                        
                        if 'socket_descriptor' in parsed_data:
                            print(f"[*] Socket FD: {parsed_data['socket_descriptor']}")
                        
                        if 'local_address' in parsed_data:
                            print(f"[*] Local: {parsed_data['local_address']}")
                            
                        if 'remote_address' in parsed_data:
                            print(f"[*] Remote: {parsed_data['remote_address']}")
                            
                        if 'connection_string' in parsed_data:
                            print(f"[*] Connection: {parsed_data['connection_string']}")
                            
                        if 'data_length' in parsed_data:
                            print(f"[*] Data Length: {parsed_data['data_length']} bytes")
                            
                        if 'has_buffer' in parsed_data and parsed_data['has_buffer']:
                            print("[*] Buffer Data: Available")
                    else:
                        print(f"[*] [Socket] {event_type}: {data}")
                    
                    print()
            elif category == "PROCESS_CREATION":
                parsed_data = parse_process_creation(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type == 'process.creation':
                        print("\n[*] [Process] New Process Creation:")
                        if 'nice_name' in parsed_data:
                            print(f"[*] Process Name: {parsed_data['nice_name']}")
                        if 'uid' in parsed_data:
                            print(f"[*] UID: {parsed_data['uid']}")
                        if 'gid' in parsed_data:
                            print(f"[*] GID: {parsed_data['gid']}")
                        if 'target_sdk_version' in parsed_data:
                            print(f"[*] Target SDK: {parsed_data['target_sdk_version']}")
                        if 'abi' in parsed_data:
                            print(f"[*] ABI: {parsed_data['abi']}")
                    
                    elif event_type in ['process.kill', 'process.signal']:
                        action = 'Kill Process' if event_type == 'process.kill' else 'Send Signal'
                        print(f"\n[*] [Process] {action}:")
                        if 'target_pid' in parsed_data:
                            print(f"[*] Target PID: {parsed_data['target_pid']}")
                        if 'signal' in parsed_data:
                            print(f"[*] Signal: {parsed_data['signal']}")
                    
                    elif event_type.startswith('process.fork'):
                        print(f"\n[*] [Process] Fork Operation ({event_type}):")
                        if 'caller_pid' in parsed_data:
                            print(f"[*] Caller PID: {parsed_data['caller_pid']}")
                        if 'child_pid' in parsed_data:
                            print(f"[*] Child PID: {parsed_data['child_pid']}")
                        if 'success' in parsed_data:
                            print(f"[*] Success: {parsed_data['success']}")
                    
                    elif event_type.startswith('process.system'):
                        print(f"\n[*] [Process] System Command ({event_type}):")
                        if 'command' in parsed_data:
                            print(f"[*] Command: {parsed_data['command']}")
                        if 'return_value' in parsed_data:
                            print(f"[*] Return Value: {parsed_data['return_value']}")
                    
                    else:
                        print(f"[*] [Process] {event_type}: {data}")
                    
                    print()
            elif category == "RUNTIME_HOOKS":
                parsed_data = parse_runtime_hooks(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    if event_type == 'runtime.exec':
                        print("\n[*] [Runtime] Command Execution:")
                        if 'command' in parsed_data:
                            print(f"[*] Command: {parsed_data['command']}")
                        if 'working_directory' in parsed_data:
                            print(f"[*] Working Directory: {parsed_data['working_directory']}")
                        if 'environment' in parsed_data:
                            print(f"[*] Environment: {parsed_data['environment']}")
                    
                    elif event_type in ['runtime.load_library', 'runtime.load']:
                        action = 'Load Library' if event_type == 'runtime.load_library' else 'Load'
                        print(f"\n[*] [Runtime] {action}:")
                        if 'library_name' in parsed_data:
                            print(f"[*] Library: {parsed_data['library_name']}")
                        if 'filename' in parsed_data:
                            print(f"[*] Filename: {parsed_data['filename']}")
                    
                    elif event_type.startswith('reflection.'):
                        if event_type in ['reflection.class_for_name', 'reflection.load_class']:
                            action = 'Class.forName' if event_type == 'reflection.class_for_name' else 'ClassLoader.loadClass'
                            print(f"\n[*] [Reflection] {action}:")
                            if 'class_name' in parsed_data:
                                print(f"[*] Class: {parsed_data['class_name']}")
                            if 'initialize' in parsed_data:
                                print(f"[*] Initialize: {parsed_data['initialize']}")
                            if 'resolve' in parsed_data:
                                print(f"[*] Resolve: {parsed_data['resolve']}")
                        
                        elif event_type in ['reflection.get_method', 'reflection.get_declared_method']:
                            access = 'Public' if event_type == 'reflection.get_method' else 'Declared'
                            print(f"\n[*] [Reflection] Get {access} Method:")
                            if 'class_name' in parsed_data:
                                print(f"[*] Class: {parsed_data['class_name']}")
                            if 'method_name' in parsed_data:
                                print(f"[*] Method: {parsed_data['method_name']}")
                            if 'method_signature' in parsed_data:
                                print(f"[*] Signature: {parsed_data['method_signature']}")
                        
                        elif event_type == 'reflection.method_invoke':
                            print("\n[*] [Reflection] Method Invoke:")
                            if 'method_name' in parsed_data:
                                print(f"[*] Method: {parsed_data['method_name']}")
                            if 'target_instance' in parsed_data:
                                print(f"[*] Target: {parsed_data['target_instance']}")
                            if 'arguments' in parsed_data and parsed_data['arguments']:
                                print(f"[*] Arguments: {parsed_data['arguments']}")
                            if 'result' in parsed_data and parsed_data['result']:
                                result = parsed_data['result']
                                if len(result) > 100:
                                    result = result[:100] + "..."
                                print(f"[*] Result: {result}")
                        
                        else:
                            print(f"[*] [Reflection] {event_type}: {data}")
                    
                    else:
                        print(f"[*] [Runtime] {event_type}: {data}")
                    
                    print()
            elif category in ["BLUETOOTH", "TELEPHONY", "LOCATION_ACCESS", "CLIPBOARD", "CAMERA"]:
                parsed_data = parse_service_hooks(data, timestamp)
                if parsed_data:
                    event_type = parsed_data.get('event_type', 'unknown')
                    
                    # Bluetooth events
                    if event_type.startswith('bluetooth.'):
                        print(f"\n[*] [Bluetooth] {parsed_data.get('event_description', event_type)}:")
                        if 'characteristic_uuid' in parsed_data:
                            print(f"[*] Characteristic UUID: {parsed_data['characteristic_uuid']}")
                        if 'device_address' in parsed_data:
                            print(f"[*] Device Address: {parsed_data['device_address']}")
                        if 'device_name' in parsed_data:
                            print(f"[*] Device Name: {parsed_data['device_name']}")
                        if 'value_hex' in parsed_data:
                            print(f"[*] Value (hex): {parsed_data['value_hex']}")
                    
                    # Telephony events
                    elif event_type.startswith('telephony.'):
                        print(f"\n[*] [Telephony] {parsed_data.get('event_description', event_type)}:")
                        if 'destination_address' in parsed_data:
                            print(f"[*] Destination: {parsed_data['destination_address']}")
                        if 'message_text' in parsed_data:
                            text = parsed_data['message_text']
                            if len(text) > 100:
                                text = text[:100] + "..."
                            print(f"[*] Message: {text}")
                        if 'phone_number' in parsed_data:
                            print(f"[*] Phone Number: {parsed_data['phone_number']}")
                        if 'imei' in parsed_data:
                            print(f"[*] IMEI: {parsed_data['imei']}")
                        if 'property_key' in parsed_data:
                            print(f"[*] Property: {parsed_data['property_key']} = {parsed_data.get('property_value', 'N/A')}")
                    
                    # Location events
                    elif event_type.startswith('location.'):
                        print(f"\n[*] [Location] {parsed_data.get('event_description', event_type)}:")
                        if 'provider' in parsed_data:
                            print(f"[*] Provider: {parsed_data['provider']}")
                        if 'latitude' in parsed_data and 'longitude' in parsed_data:
                            print(f"[*] Coordinates: {parsed_data['latitude']}, {parsed_data['longitude']}")
                        if 'accuracy' in parsed_data:
                            print(f"[*] Accuracy: {parsed_data['accuracy']}m")
                        if 'has_location' in parsed_data:
                            print(f"[*] Has Location: {parsed_data['has_location']}")
                    
                    # Clipboard events
                    elif event_type.startswith('clipboard.'):
                        print(f"\n[*] [Clipboard] {parsed_data.get('event_description', event_type)}:")
                        if 'content_type' in parsed_data:
                            print(f"[*] Content Type: {parsed_data['content_type']}")
                        if 'content' in parsed_data and parsed_data['content']:
                            content = parsed_data['content']
                            if len(content) > 100:
                                content = content[:100] + "..."
                            print(f"[*] Content: {content}")
                        if 'item_count' in parsed_data:
                            print(f"[*] Items: {parsed_data['item_count']}")
                    
                    # Camera events
                    elif event_type.startswith('camera.'):
                        print(f"\n[*] [Camera] {parsed_data.get('event_description', event_type)}:")
                        if 'camera_id' in parsed_data:
                            print(f"[*] Camera ID: {parsed_data['camera_id']}")
                        if 'camera_count' in parsed_data:
                            print(f"[*] Available Cameras: {parsed_data['camera_count']}")
                        if 'success' in parsed_data:
                            print(f"[*] Success: {parsed_data['success']}")
                    
                    else:
                        print(f"[*] [Service] {event_type}: {data}")
                    
                    print()
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
            raise FridaBasedException("Invalid operation! Please run Dexray Intercept in debug mode in order to understand the source of this error and report it.")
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
