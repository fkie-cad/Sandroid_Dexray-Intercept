#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
New parser module that provides backward compatibility while using the new architecture.
This module re-exports functions from the new parser system for legacy code compatibility.
"""

# Import from new architecture
from .utils.hexdump import hexdump, hex_to_string_safe, hex_to_string
from .utils.crypto_utils import demangle, get_demangled_method_for_dex_unpacking, MODE_MAPPING
from .utils.string_utils import escape_special_characters, unescape_special_characters, format_xml_content
from .parsers.factory import parser_factory
from .parsers.dex import DEXParser


# Legacy function wrappers for backward compatibility
def parse_file_system_event(raw_data, event_time):
    """Legacy wrapper for file system event parsing"""
    parser = parser_factory.get_parser("FILE_SYSTEM")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_native_lib_loading(raw_data, event_time):
    """Legacy wrapper for native library loading parsing"""
    parser = parser_factory.get_parser("PROCESS_NATIVE_LIB")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_process_creation(raw_data, event_time):
    """Legacy wrapper for process creation parsing"""
    parser = parser_factory.get_parser("PROCESS_CREATION")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_runtime_hooks(raw_data, event_time):
    """Legacy wrapper for runtime hooks parsing"""
    parser = parser_factory.get_parser("RUNTIME_HOOKS")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_service_hooks(raw_data, event_time):
    """Legacy wrapper for service hooks parsing"""
    # Try different service parsers based on content
    for category in ["BLUETOOTH", "TELEPHONY", "LOCATION_ACCESS", "CLIPBOARD", "CAMERA"]:
        parser = parser_factory.get_parser(category)
        if parser:
            event = parser.parse(raw_data, event_time)
            if event:
                return event.to_dict()
    return None


def parse_shared_pref(raw_data, event_time):
    """Legacy wrapper for shared preferences parsing"""
    parser = parser_factory.get_parser("IPC_SHARED-PREF")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_aes(raw_data, event_time):
    """Legacy wrapper for AES parsing"""
    parser = parser_factory.get_parser("CRYPTO_AES")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_binder(raw_data, event_time):
    """Legacy wrapper for binder parsing"""
    parser = parser_factory.get_parser("IPC_BINDER")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_intent(raw_data, event_time):
    """Legacy wrapper for intent parsing"""
    parser = parser_factory.get_parser("IPC_INTENT")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_socket_infos(raw_data, event_time):
    """Legacy wrapper for socket info parsing"""
    parser = parser_factory.get_parser("NETWORK_SOCKETS")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_web_infos(raw_data, event_time):
    """Legacy wrapper for web info parsing"""
    parser = parser_factory.get_parser("WEB")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_telephony_infos(raw_data, event_time):
    """Legacy wrapper for telephony info parsing"""
    parser = parser_factory.get_parser("TELEPHONY")
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    return None


def parse_broadcast_infos(raw_data, timestamp):
    """Legacy wrapper for broadcast info parsing"""
    parser = parser_factory.get_parser("IPC_BROADCAST")
    if parser:
        event = parser.parse(raw_data, timestamp)
        return event.to_dict() if event else None
    return None


def parse_generic_infos(raw_data, event_time, category):
    """Legacy wrapper for generic info parsing"""
    parser = parser_factory.get_parser(category)
    if parser:
        event = parser.parse(raw_data, event_time)
        return event.to_dict() if event else None
    
    # Fallback to generic event
    return {
        "event_type": f"{category}::unknown",
        "payload": raw_data,
        "timestamp": event_time
    }


def dex_loading_parser(lines):
    """Legacy wrapper for DEX loading parsing"""
    parser = DEXParser()
    return parser.parse_dex_loading_list(lines)


def url_parser(json_string, time):
    """Legacy wrapper for URL parsing"""
    import json
    
    try:
        data = json.loads(json_string)
        
        if data.get("event_type") == "Java::net.url":
            return {
                "event_type": data["event_type"],
                "uri": data.get("url"),
                "stack": data.get("stack"),
                "req_method": data.get("req_method"),
                "timestamp": time
            }
        elif data.get("event_type") == "URI Constructor":
            return {
                "event_type": data["event_type"],
                "class": data.get("class"),
                "method": data.get("method"),
                "event": data.get("event"),
                "uri": data.get("uri"),
                "timestamp": time
            }
        else:
            data["timestamp"] = time
            return data
    except Exception:
        return {"event_type": "url.parse_error", "payload": json_string, "timestamp": time}


def remove_empty_entries(my_dict):
    """Legacy utility function"""
    return {key: value for key, value in my_dict.items() if value}


def get_event_type_infos(line):
    """Legacy utility function"""
    import re
    match = re.match(r'\s*(?P<key>[^:]+)\s*:\s*(?P<value>.+)\s*', line)
    if match:
        return match.group('value').strip()
    return ""


def add_timestmap(raw_data, event_time):
    """Legacy utility function (note: typo preserved for compatibility)"""
    return {
        "payload": raw_data,
        "timestamp": event_time
    }


# Re-export utility functions
__all__ = [
    # Utility functions
    'hexdump', 'hex_to_string_safe', 'hex_to_string',
    'demangle', 'get_demangled_method_for_dex_unpacking',
    'escape_special_characters', 'unescape_special_characters', 'format_xml_content',
    'remove_empty_entries', 'get_event_type_infos', 'add_timestmap',
    
    # Parser functions
    'parse_file_system_event', 'parse_native_lib_loading', 'parse_process_creation',
    'parse_runtime_hooks', 'parse_service_hooks', 'parse_shared_pref', 'parse_aes',
    'parse_binder', 'parse_intent', 'parse_socket_infos', 'parse_web_infos',
    'parse_telephony_infos', 'parse_broadcast_infos', 'parse_generic_infos',
    'dex_loading_parser', 'url_parser',
    
    # Constants
    'MODE_MAPPING'
]