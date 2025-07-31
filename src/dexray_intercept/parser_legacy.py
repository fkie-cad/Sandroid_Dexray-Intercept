#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from xml.dom.minidom import parseString
import json
import cxxfilt


def demangle(symbol: str) -> str:
    try:
        demangled = cxxfilt.demangle(symbol)
        # Use regex to extract the function name from the demangled string
        function_name_match = re.search(r'(\w+::)*\w+', demangled)
        if function_name_match:
            return function_name_match.group(0)
        else:
            return "Unknown function name"
    except Exception as e:
        print(f"Error demangling symbol {symbol}: {e}")
        return "Demangling error"


def escape_special_characters(data: str) -> str:
    return data.replace('\"','\\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\u001b','\\u001b')


def unescape_special_characters(data: str) -> str:
    return data.replace('\\\"','\"').replace('\\n', '\n').replace('\\t', '\t').replace('\\u001b','\u001b')


def hexdump(hex_string: str, header: bool = True, ansi: bool = True) -> str:
    """
    Convert hex string to hexdump format with colors like the old frida hexdump
    
    Args:
        hex_string: Hex string (e.g., "48656c6c6f")
        header: Whether to show the header row
        ansi: Whether to use ANSI color codes
        
    Returns:
        Formatted hexdump string
    """
    if not hex_string:
        return ""
    
    # Remove any spaces or non-hex characters
    hex_clean = ''.join(c for c in hex_string if c in '0123456789abcdefABCDEF')
    
    if len(hex_clean) == 0:
        return ""
    
    # Convert hex string to bytes
    try:
        if len(hex_clean) % 2 != 0:
            hex_clean = '0' + hex_clean  # pad with leading zero
        bytes_data = bytes.fromhex(hex_clean)
    except ValueError:
        return f"Invalid hex data: {hex_string}"
    
    # ANSI color codes
    if ansi:
        colors = {
            'reset': '\033[0m',
            'gray': '\033[90m',      # header and separators
            'cyan': '\033[36m',      # hex values
            'green': '\033[32m',     # printable ASCII
            'yellow': '\033[33m'     # non-printable (dots)
        }
    else:
        colors = {k: '' for k in ['reset', 'gray', 'cyan', 'green', 'yellow']}
    
    result = []
    
    # Header row
    if header:
        header_line = f"{colors['gray']}           00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f{colors['reset']}"
        result.append(header_line)
    
    # Process 16 bytes per line
    for i in range(0, len(bytes_data), 16):
        # Address offset
        address = f"{i:08x}"
        line = f"{colors['gray']}{address}{colors['reset']}  "
        
        # Hex values
        hex_part = ""
        ascii_part = ""
        
        for j in range(16):
            if i + j < len(bytes_data):
                byte_val = bytes_data[i + j]
                hex_part += f"{colors['cyan']}{byte_val:02x}{colors['reset']} "
                
                # ASCII representation
                if 32 <= byte_val <= 126:  # printable ASCII
                    ascii_part += f"{colors['green']}{chr(byte_val)}{colors['reset']}"
                else:
                    ascii_part += f"{colors['yellow']}.{colors['reset']}"
            else:
                hex_part += "   "
                ascii_part += " "
            
            # Add extra space after 8 bytes
            if j == 7:
                hex_part += " "
        
        # Combine hex and ASCII parts
        line += hex_part + f" {colors['gray']}|{colors['reset']}{ascii_part}{colors['gray']}|{colors['reset']}"
        result.append(line)
    
    return '\n'.join(result)

def format_xml_content(xml_content: str) -> str:
    # Parse the XML string and pretty-print it
    try:
        xml = parseString(xml_content)
        return xml.toprettyxml(indent="    ")
    except Exception as e:
        print(f"Error formatting XML content: {e}")
        return xml_content

def parse_file_system_event(raw_data, event_time):
    try:
        # First, try to parse as JSON (new format)
        try:
            data = json.loads(raw_data)
            
            # Ensure timestamp is set
            if 'timestamp' not in data:
                data["timestamp"] = event_time
            
            # Handle hexdump for display if data_hex is present
            if 'data_hex' in data and data['data_hex']:
                hex_data = data['data_hex']
                
                # Add plaintext conversion for ASCII-compatible data
                if data.get('should_dump_ascii', False):
                    data['plaintext'] = hex_to_string_safe(hex_data)
                
                # Add formatted hexdump for display
                if data.get('should_dump_hex', False) or data.get('file_type') in ['binary', 'xml']:
                    data['hexdump_display'] = hexdump(hex_data, header=True, ansi=True)
                
                # Handle truncation if needed
                if data.get('is_large_data', False):
                    max_len = data.get('max_display_length', 1024)
                    if len(hex_data) > max_len * 2:  # hex string is 2x byte length
                        data['truncated'] = True
                        data['original_length'] = len(hex_data) // 2
                        data['displayed_length'] = max_len
            
            return data
            
        except (json.JSONDecodeError, ValueError):
            # Fall back to legacy string parsing
            pass
        
        # Legacy parser for raw file system event data
        if raw_data.startswith("[Java::"):
            pattern = re.compile(
                r"\[(?P<event_type>[^\]]+)\] Write (?P<bytes>\d+) bytes from offset (?P<offset>\d+)\s+\((?P<file_path>[^)]+)\):\\n\\u001b\[33m(?P<content>.*?)\\u001b\[0m"
            )
            raw_string = escape_special_characters(raw_data)
            match = pattern.search(raw_string)

            if not match:
                if raw_data.startswith("[Java::File.new"):
                    parts = raw_data.split(" ")
                    event_type = parts[0].strip("[]")
                    content = raw_data.split(" : ")[1].strip()

                    return {
                        "event_type": event_type,
                        "file_path" : content,
                        "timestamp": event_time
                    }
                else:
                    parts = raw_data.split("]")
                    event_type = parts[0].strip("[]")
                    content = parts[1].strip()

                    return {
                        "event_type": event_type,
                        "payload" : content,
                        "timestamp": event_time
                    }

            else:
                 # Extract information from the match
                event_type = match.group("event_type")
                bytes_written = int(match.group("bytes"))
                offset = int(match.group("offset"))
                file_path = match.group("file_path")
                raw_content = match.group("content")
                #content = raw_content.replace('\\n', '\n').replace('\\u001b', '').replace('[33m', '').replace('[0m', '').replace('&quot;', '"').replace('\/', '/')
                content = unescape_special_characters(raw_content)
                
                # Structure the information in a dictionary
                return {
                    "event_type": event_type,
                    "bytes_written": bytes_written,
                    "offset": offset,
                    "file_path": file_path,
                    "content": content,
                    "timestamp": event_time
                }
        elif raw_data.startswith("[Libc"):
            parts = raw_data.split("]")
            event_type = parts[0].strip("[]")
            if parts[1].startswith(" Open"):
                path_parts = parts[1].split("'")
                path = path_parts[1]
                fd = path_parts[2].split(":")[1].strip()[:-1]
                
                return {
                    "event_type": event_type,
                    "file_path": path,
                    "fd": fd,
                    "timestamp": event_time
                }
            elif parts[1].startswith(" Write"):
                info_parts = parts[1].split(",")
                path = info_parts[0].split("(")[1]
                fd = info_parts[1].strip()
                buffer_addr = info_parts[2]
                written = info_parts[3].split(")")[0]
                return {
                    "event_type": event_type,
                    "file_path": path,
                    "fd": fd,
                    "buffer_address":buffer_addr,
                    "bytes_written": written,
                    
                    "timestamp": event_time
                }
            elif parts[1].startswith(" Read"):
                info_parts = parts[1].split(",")
                path = info_parts[0].split("(")[1]
                fd = info_parts[1].strip()
                buffer_addr = info_parts[2]
                read_bytes = info_parts[3].split(")")[0]
                return {
                    "event_type": event_type,
                    "file_path": path,
                    "fd": fd,
                    "buffer_address":buffer_addr,
                    "bytes_read": read_bytes,     
                    "timestamp": event_time
                }
            else:
                path = parts[1].split("Deleting:")[1]
                return {
                    "event_type": event_type,
                    "file_path": path[:-1],
                    "event": "deleting file",
                    "timestamp": event_time
                }

            
        else:
            parts = raw_data.split(" ")
            event_type = parts[0].strip("[]")
            file_path = parts[4].strip("'()")
            fd = int(parts[6].strip("()")) if "fd:" in parts[6] else None
            
            return {
                "event_type": event_type,
                "file_path": file_path,
                "fd": fd,
                "timestamp": event_time
            }
    except Exception as e:
        event_type = "Unknown"
        exception_info = e

        return {
            "event_type": event_type,
            "payload": raw_data,
            "exception": exception_info,
            "timestamp": event_time
        }


def parse_native_lib_loading(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Add load status description if present
        if 'event_type' in data:
            event_type = data['event_type']
            if event_type == 'native.library.load':
                data['event_description'] = 'Native library loading attempt'
            elif event_type == 'native.library.loaded':
                data['event_description'] = 'Native library loaded successfully'
            elif event_type == 'native.library.load_failed':
                data['event_description'] = 'Native library loading failed'
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format with string parsing
        return parse_native_lib_loading_legacy(raw_data, event_time)
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_native_lib_loading_legacy(raw_data, event_time):
    """Fallback parser for old native library hook format"""
    parts = raw_data.split("]")
    event_type = parts[0].strip("[]")
    try:
        return {
                "event_type": event_type,
                "loaded_library": parts[1].split(":")[1],
                "timestamp": event_time
            }
    except Exception as e:
        event_type = "Unknown"
        exception_info = e

        return {
            "event_type": event_type,
            "payload": raw_data,
            "exception": exception_info,
            "timestamp": event_time
        }

def parse_process_creation(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Add process action description if present
        if 'event_type' in data:
            event_type = data['event_type']
            if event_type == 'process.creation':
                data['event_description'] = 'New process creation'
            elif event_type == 'process.kill':
                data['event_description'] = 'Process termination'
            elif event_type == 'process.signal':
                data['event_description'] = 'Process signal sent'
            elif event_type.startswith('process.fork'):
                data['event_description'] = 'Process fork operation'
            elif event_type.startswith('process.execve'):
                data['event_description'] = 'Process exec operation'
            elif event_type.startswith('process.system'):
                data['event_description'] = 'System command execution'
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format with string parsing
        return parse_process_creation_legacy(raw_data, event_time)
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_process_creation_legacy(raw_data, event_time):
    """Fallback parser for old process creation hook format"""
    try:
        # Try to parse as generic JSON first (old format may have used this)
        data = json.loads(raw_data)
        if 'timestamp' not in data:
            data["timestamp"] = event_time
        return data
    except json.JSONDecodeError:
        # If not JSON, treat as raw string
        return {
            "event_type": "process.legacy",
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        return {
            "event_type": "legacy_parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_runtime_hooks(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Add runtime operation description if present
        if 'event_type' in data:
            event_type = data['event_type']
            if event_type == 'runtime.exec':
                data['event_description'] = 'Runtime command execution'
            elif event_type == 'runtime.load_library':
                data['event_description'] = 'Runtime library loading (loadLibrary)'
            elif event_type == 'runtime.load':
                data['event_description'] = 'Runtime library loading (load)'
            elif event_type.startswith('reflection.'):
                if event_type == 'reflection.class_for_name':
                    data['event_description'] = 'Reflection class loading (forName)'
                elif event_type == 'reflection.load_class':
                    data['event_description'] = 'Reflection class loading (loadClass)'
                elif event_type == 'reflection.get_method':
                    data['event_description'] = 'Reflection method retrieval (getMethod)'
                elif event_type == 'reflection.get_declared_method':
                    data['event_description'] = 'Reflection method retrieval (getDeclaredMethod)'
                elif event_type == 'reflection.method_invoke':
                    data['event_description'] = 'Reflection method invocation'
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format with string parsing
        return parse_runtime_hooks_legacy(raw_data, event_time)
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_runtime_hooks_legacy(raw_data, event_time):
    """Fallback parser for old runtime/reflection hook format"""
    try:
        # Try to parse as generic JSON first (old format may have used this)
        data = json.loads(raw_data)
        if 'timestamp' not in data:
            data["timestamp"] = event_time
        return data
    except json.JSONDecodeError:
        # If not JSON, treat as raw string (old reflection format)
        if raw_data.startswith("[Reflection::"):
            return {
                "event_type": "reflection.legacy",
                "message": raw_data,
                "timestamp": event_time
            }
        else:
            return {
                "event_type": "runtime.legacy",
                "payload": raw_data,
                "timestamp": event_time
            }
    except Exception as e:
        return {
            "event_type": "legacy_parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_service_hooks(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Add service operation description if present
        if 'event_type' in data:
            event_type = data['event_type']
            
            # Bluetooth events
            if event_type.startswith('bluetooth.'):
                if event_type == 'bluetooth.gatt.read_characteristic':
                    data['event_description'] = 'Bluetooth GATT characteristic read'
                elif event_type == 'bluetooth.gatt.set_characteristic_value':
                    data['event_description'] = 'Bluetooth GATT characteristic write'
                elif event_type == 'bluetooth.adapter.get_default':
                    data['event_description'] = 'Bluetooth adapter access'
                elif event_type == 'bluetooth.adapter.enable':
                    data['event_description'] = 'Bluetooth adapter enable'
                elif event_type == 'bluetooth.device.create_bond':
                    data['event_description'] = 'Bluetooth device pairing'
            
            # Telephony events
            elif event_type.startswith('telephony.'):
                if event_type == 'telephony.sms.send_text':
                    data['event_description'] = 'SMS text message sent'
                elif event_type == 'telephony.sms.send_multipart':
                    data['event_description'] = 'SMS multipart message sent'
                elif event_type == 'telephony.manager.get_phone_number':
                    data['event_description'] = 'Phone number access'
                elif event_type == 'telephony.manager.get_imei':
                    data['event_description'] = 'Device IMEI access'
                elif event_type == 'telephony.manager.get_imsi':
                    data['event_description'] = 'SIM IMSI access'
                elif event_type == 'telephony.system_properties.get':
                    data['event_description'] = 'System property access'
            
            # Location events
            elif event_type.startswith('location.'):
                if event_type == 'location.last_known_location':
                    data['event_description'] = 'Last known location access'
                elif event_type == 'location.request_updates':
                    data['event_description'] = 'Location updates requested'
                elif event_type == 'location.get_latitude':
                    data['event_description'] = 'Latitude coordinate access'
                elif event_type == 'location.get_longitude':
                    data['event_description'] = 'Longitude coordinate access'
            
            # Clipboard events
            elif event_type.startswith('clipboard.'):
                if event_type == 'clipboard.set_primary_clip':
                    data['event_description'] = 'Clipboard data written'
                elif event_type == 'clipboard.get_primary_clip':
                    data['event_description'] = 'Clipboard data read'
            
            # Camera events
            elif event_type.startswith('camera.'):
                if event_type == 'camera.legacy.open':
                    data['event_description'] = 'Camera opened (legacy API)'
                elif event_type == 'camera.camera2.open':
                    data['event_description'] = 'Camera opened (Camera2 API)'
                elif event_type == 'camera.camera2.get_camera_list':
                    data['event_description'] = 'Camera list enumeration'
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format with string parsing
        return parse_service_hooks_legacy(raw_data, event_time)
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_service_hooks_legacy(raw_data, event_time):
    """Fallback parser for old service hook formats"""
    try:
        # Try to parse as generic JSON first (old format may have used this)
        data = json.loads(raw_data)
        if 'timestamp' not in data:
            data["timestamp"] = event_time
        return data
    except json.JSONDecodeError:
        # If not JSON, treat as raw string
        return {
            "event_type": "service.legacy",
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        return {
            "event_type": "legacy_parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_shared_pref(raw_data, event_time):
    parts = raw_data.split("]")
    event_type = parts[0].strip("[]")
    try:
        # Regular expression to extract JSON parts
        json_pattern = re.compile(r'\{.*\}')
        match = json_pattern.search(raw_data)
        if match:
            json_str = match.group()
            json_obj = json.loads(json_str)
            # Add further elements to JSON object
            json_obj["timestamp"] = event_time
            return json_obj
    except Exception as e:
        event_type = "Unknown"
        exception_info = e

        return {
            "event_type": event_type,
            "payload": raw_data,
            "exception": exception_info,
            "timestamp": event_time
        }


# Constants for the mode mapping of AES
# more at: https://docs.oracle.com/javase%2F8%2Fdocs%2Fapi%2F%2F/constant-values.html#javax.crypto.Cipher.ENCRYPT_MODE
MODE_MAPPING = {
    1: "ENCRYPT_MODE",  # PUBLIC_KEY
    2: "DECRYPT_MODE",  # PRIVATE_KEY
    3: "WRAP_MODE",  # SECRET_KEY
    4: "UNWRAP_MODE"
}

def hex_to_string(hex_str):
    bytes_object = bytes.fromhex(hex_str)
    return bytes_object.decode("utf-8", errors='replace')

def hex_to_string_safe(hex_str):
    """Safe hex to string conversion with better error handling"""
    if not hex_str or not isinstance(hex_str, str):
        return None
    try:
        # Remove any whitespace and ensure even length
        hex_str = hex_str.replace(" ", "").replace("\n", "")
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        
        bytes_object = bytes.fromhex(hex_str)
        # Try UTF-8 first, then fall back to latin-1 for binary data
        try:
            return bytes_object.decode("utf-8")
        except UnicodeDecodeError:
            # For binary data, show printable chars and dots for non-printable
            return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes_object)
    except ValueError:
        return f"<invalid_hex: {hex_str[:50]}{'...' if len(hex_str) > 50 else ''}>"

def parse_aes(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Handle operation mode mapping if present
        if 'operation_mode' in data:
            mode_num = data['operation_mode']
            mode_name = MODE_MAPPING.get(mode_num, f"UNKNOWN_MODE_{mode_num}")
            data['operation_mode_desc'] = f"{mode_name} ({mode_num})"
            
            # Extract plaintext based on operation mode
            if mode_name == "ENCRYPT_MODE" and 'input_hex' in data:
                data['plaintext'] = hex_to_string_safe(data['input_hex'])
            elif mode_name == "DECRYPT_MODE" and 'output_hex' in data:
                data['plaintext'] = hex_to_string_safe(data['output_hex'])
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format with regex parsing
        return parse_aes_legacy(raw_data, event_time)
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }

def parse_aes_legacy(raw_data, event_time):
    """Fallback parser for old AES hook format"""
    try:
        # Regular expression to extract JSON parts
        json_pattern = re.compile(r'\{.*\}')
        match = json_pattern.search(raw_data)
        if match:
            json_str = match.group()
            data = json.loads(json_str)

            if 'opmode' in data:
                mode = MODE_MAPPING.get(data['opmode'], None)
                data['opmode'] = mode + " (" + str(data['opmode']) + ")"
                if mode == "ENCRYPT_MODE" and 'arg' in data:
                    data['plaintext'] = hex_to_string_safe(data['arg'])
                elif mode == "DECRYPT_MODE" and 'result' in data:
                    data['plaintext'] = hex_to_string_safe(data['result'])
            
            data["timestamp"] = event_time
            return data
    except Exception as e:
        return {
            "event_type": "legacy_parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }


def parse_binder(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Add transaction type description
        if 'transaction_type' in data:
            trans_type = data['transaction_type']
            if trans_type == 'BC_TRANSACTION':
                data['transaction_desc'] = 'Binder Transaction'
            elif trans_type == 'BC_REPLY':
                data['transaction_desc'] = 'Binder Reply'
            else:
                data['transaction_desc'] = f'Unknown ({trans_type})'
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format
        return {
            "event_type": "binder.legacy",
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }


def dex_loading_parser(lines):
    parsed_data = {}
    even_not_identified = True
    try:
        for line in lines:
            match = re.match(r'\s*(?P<key>[^:]+)\s*:\s*(?P<value>.+)\s*', line)
            if match:
                key = match.group('key').strip()
                value = match.group('value').strip()
                if value.isdigit():
                    value = int(value)
                parsed_data[key] = value

                if "even_type" in parsed_data and even_not_identified:
                    #type_parts = parsed_data["even_type"].split("::")
                    #lib_name = type_parts[0]
                    
                    #demangled_fct_name = demangle(type_parts[1])
                    #print(f"{lines} : {demangled_fct_name}")
                    #parsed_data["even_type"] = lib_name +"::" +demangled_fct_name
                    parsed_data["even_type"] = get_demangled_method_for_DEX_unpacking(parsed_data["even_type"])
                    even_not_identified = False

    except Exception as exception_info:
        parsed_data["event_type"] = "Unpacking:Unknown"
        parsed_data["payload"] = str(lines)
        parsed_data["eception"] = exception_info       

    return parsed_data


def parse_socket_infos(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Add socket type description
        if 'socket_type' in data:
            socket_type = data['socket_type']
            if socket_type in ['tcp', 'tcp6']:
                data['socket_description'] = 'TCP Socket'
            elif socket_type in ['udp', 'udp6']:
                data['socket_description'] = 'UDP Socket'
            else:
                data['socket_description'] = f'Socket ({socket_type})'
        
        # Format connection info for easy display
        if 'local_ip' in data and 'local_port' in data:
            data['local_address'] = f"{data['local_ip']}:{data['local_port']}"
        
        if 'remote_ip' in data and 'remote_port' in data:
            data['remote_address'] = f"{data['remote_ip']}:{data['remote_port']}"
        
        # Add method description
        if 'method' in data:
            method = data['method']
            if method == 'connect':
                data['operation'] = 'Socket Connection'
            elif method == 'bind':
                data['operation'] = 'Socket Binding'
            elif method in ['read', 'recv', 'recvfrom']:
                data['operation'] = 'Data Received'
            elif method in ['write', 'send', 'sendto']:
                data['operation'] = 'Data Sent'
            else:
                data['operation'] = f'Socket {method.title()}'
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format
        try:
            # Regular expression to extract JSON parts
            json_pattern = re.compile(r'\{.*\}')
            match = json_pattern.search(raw_data)
            if match:
                json_str = match.group()
                data = json.loads(json_str)
                data["timestamp"] = event_time
                return data
        except Exception:
            pass
        
        return {
            "event_type": "socket.legacy",
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }


def parse_web_infos(raw_data, event_time):
    event_type = "WEB::unknown"
    try:
        # Regular expression to extract JSON parts
        json_pattern = re.compile(r'\{.*\}')
        match = json_pattern.search(raw_data)
        if match:
            json_str = match.group()
            data = json.loads(json_str)
            
            # Add further elements to JSON object´
            data["timestamp"] = event_time
            return data
        else:
            return {
            "event_type": event_type,
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        exception_info = e

        return {
            "event_type": event_type,
            "payload": raw_data,
            "exception": exception_info,
            "timestamp": event_time
        }


def parse_generic_infos(raw_data, event_time, category):
    event_type = category+"::unknown"
    return {
        "event_type": event_type,
        "payload": raw_data,
        "timestamp": event_time
    }



def parse_telephony_infos(raw_data, event_time):
    event_type = "Telephony::unknown"
    try:
        # Regular expression to extract JSON parts
        json_pattern = re.compile(r'\{.*\}')
        match = json_pattern.search(raw_data)
        if match:
            json_str = match.group()
            data = json.loads(json_str)
            
            # Add further elements to JSON object´
            data["timestamp"] = event_time
            return data
        else:
            #print(f"telephony: {raw_data}")
            return {
            "event_type": event_type,
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        exception_info = e

        return {
            "event_type": event_type,
            "payload": raw_data,
            "exception": exception_info,
            "timestamp": event_time
        }


def add_timestmap(raw_data, event_time):
        timestamp = event_time
        
        return {
            "payload": raw_data,
            "timestamp": timestamp
        }

def remove_empty_entries(my_dict):
    return {key: value for key, value in my_dict.items() if value}


def get_event_type_infos(line):
    match = re.match(r'\s*(?P<key>[^:]+)\s*:\s*(?P<value>.+)\s*', line)
    if match:
        value = match.group('value').strip()

    return value


def parse_intent_value_for_broadcasts(intent_value):
    intent_name = None
    intent_flag = None

    # Try to match the "flg=... cmp=..." pattern
    intent_name_match = re.search(r'cmp=([^ ]+)', intent_value)
    intent_flag_match = re.search(r'flg=([^ ]+)', intent_value)

    if intent_name_match:
        intent_name = intent_name_match.group(1)
    if intent_flag_match:
        intent_flag = intent_flag_match.group(1)

    # If the above pattern doesn't match, try the "#Intent;component=...;end" pattern
    if not intent_name:
        intent_name_match = re.search(r'#Intent;component=([^;]+);end', intent_value)
        if intent_name_match:
            intent_name = intent_name_match.group(1)

    return intent_name, intent_flag

def parse_broadcast_infos(raw_data, timestamp):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Handle new structured format
        if 'intent' in data:
            intent_info = data['intent']
            
            # Extract component name if available
            if 'component' in intent_info:
                data['intent_name'] = intent_info['component']
            elif 'action' in intent_info:
                data['intent_name'] = intent_info['action']
            
            # Extract intent details
            data['intent_details'] = {
                'action': intent_info.get('action'),
                'component': intent_info.get('component'),
                'data_uri': intent_info.get('data_uri'),
                'flags': intent_info.get('flags'),
                'extras': intent_info.get('extras')
            }
        
        # Handle legacy format
        elif 'artifact' in data and data["artifact"]:
            intent_value = data["artifact"][0]["value"]
            intent_name, intent_flag = parse_intent_value_for_broadcasts(intent_value)
            data['intent_name'] = intent_name
            data['intent_flag'] = intent_flag
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = timestamp
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for non-JSON data
        return {
            "event_type": "broadcast.legacy",
            "payload": raw_data,
            "timestamp": timestamp
        }
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": timestamp
        }


def parse_intent(raw_data, event_time):
    try:
        # Direct JSON parsing - new format sends pure JSON
        data = json.loads(raw_data)
        
        # Extract intent information for display
        if 'intent' in data:
            intent_info = data['intent']
            
            # Set intent name for easy access
            if 'component' in intent_info:
                data['intent_name'] = intent_info['component']
            elif 'action' in intent_info:
                data['intent_name'] = intent_info['action']
            
            # Format extras for better display
            if 'extras' in intent_info and intent_info['extras']:
                extras_formatted = []
                for key, extra_data in intent_info['extras'].items():
                    extras_formatted.append(f"{key} ({extra_data['type']}): {extra_data['value']}")
                data['extras_formatted'] = extras_formatted
        
        # Ensure timestamp is set
        if 'timestamp' not in data:
            data["timestamp"] = event_time
            
        return data
        
    except json.JSONDecodeError:
        # Fallback for legacy format (string with line breaks)
        lines = raw_data.split('\n')
        intent_data = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('Activity:'):
                intent_data['component'] = line.replace('Activity:', '').strip()
            elif line.startswith('Action:'):
                intent_data['action'] = line.replace('Action:', '').strip()
            elif line.startswith('URI:'):
                intent_data['data_uri'] = line.replace('URI:', '').strip()
            elif line.startswith('Type:'):
                intent_data['mime_type'] = line.replace('Type:', '').strip()
            elif line.startswith('Extras:'):
                if 'extras_list' not in intent_data:
                    intent_data['extras_list'] = []
                intent_data['extras_list'].append(line.replace('Extras:', '').strip())
        
        return {
            "event_type": "intent.legacy",
            "intent": intent_data,
            "payload": raw_data,
            "timestamp": event_time
        }
    except Exception as e:
        return {
            "event_type": "parse_error",
            "payload": raw_data,
            "error": str(e),
            "timestamp": event_time
        }


def url_parser(json_string,time):
    data = json.loads(json_string)
    
    if data["event_type"] == "Java::net.url":
        parsed_data = {
            "event_type": data["event_type"],
            "uri": data["url"],
            "stack": data["stack"],
            "req_method": data["req_method"],
            "timestamp": time
        }
    elif data["event_type"] == "URI Constructor":
        parsed_data = {
            "event_type": data["event_type"],
            "class": data["class"],
            "method": data["method"],
            "event": data["event"],
            "uri": data["uri"],
            "timestamp": time
        }
    else:
        parsed_data = data

    return parsed_data


def get_demangled_method_for_DEX_unpacking(mangled_name):
    type_parts = mangled_name.split("::")
    lib_name = type_parts[0]                
    demangled_fct_name = demangle(type_parts[1])
    return lib_name +"::" +demangled_fct_name
