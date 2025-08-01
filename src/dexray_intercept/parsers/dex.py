#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, List
from .base import BaseParser
from ..models.events import DEXEvent
from ..utils.crypto_utils import get_demangled_method_for_dex_unpacking


class DEXParser(BaseParser):
    """Parser for DEX loading and unpacking events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[DEXEvent]:
        """Parse JSON data into DEXEvent"""
        event_type = data.get('event_type', 'dex.unknown')
        
        event = DEXEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes for legacy compatibility
        legacy_field_mapping = {
            'unpacking': 'unpacking',
            'dumped': 'dumped',
            'orig_location': 'orig_location',
            'even_type': 'even_type'
        }
        
        # Map new structured event fields
        new_field_mapping = {
            'hooked_function': 'hooked_function',
            'magic': 'magic',
            'version': 'version',
            'size': 'size',
            'original_location': 'original_location',
            'dumped_path': 'dumped_path',
            'file_type': 'file_type',
            'class_loader_type': 'class_loader_type',
            'file_path': 'file_path',
            'library_path': 'library_path',
            'library_name': 'library_name',
            'method': 'method',
            'loader_type': 'loader_type'
        }
        
        # Apply legacy mapping
        for json_field, event_field in legacy_field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Apply new structured mapping
        for json_field, event_field in new_field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Handle specific event types
        if event_type.startswith('dex.unpacking.'):
            # DEX unpacking events
            if 'hooked_function' in data:
                event.even_type = get_demangled_method_for_dex_unpacking(data['hooked_function'])
        elif event_type.startswith('dex.classloader.'):
            # ClassLoader events
            event.add_metadata('class_loader_operation', True)
        elif event_type.startswith('library.'):
            # Library loading events
            event.add_metadata('library_operation', True)
        
        # Add any remaining metadata
        for key, value in data.items():
            if key not in ['event_type', 'timestamp'] and not hasattr(event, key):
                event.add_metadata(key, value)
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[DEXEvent]:
        """Parse legacy DEX data (typically from dex_loading_parser)"""
        try:
            # Handle list of lines (from dex_loading_parser)
            if isinstance(raw_data, list):
                return self._parse_dex_lines(raw_data, timestamp)
            elif isinstance(raw_data, str):
                # Handle single string data
                lines = raw_data.split('\n')
                return self._parse_dex_lines(lines, timestamp)
            else:
                return self.handle_parse_error(str(raw_data), timestamp, "Unknown DEX data format")
                
        except Exception as e:
            return self.handle_parse_error(str(raw_data), timestamp, str(e))
    
    def _parse_dex_lines(self, lines: List[str], timestamp: str) -> Optional[DEXEvent]:
        """Parse DEX data from list of lines"""
        event = DEXEvent("dex.loading", timestamp)
        parsed_data = {}
        even_not_identified = True
        
        try:
            for line in lines:
                if isinstance(line, str):
                    match = re.match(r'\s*(?P<key>[^:]+)\s*:\s*(?P<value>.+)\s*', line)
                    if match:
                        key = match.group('key').strip()
                        value = match.group('value').strip()
                        if value.isdigit():
                            value = int(value)
                        parsed_data[key] = value

                        if "even_type" in parsed_data and even_not_identified:
                            # Demangle the method name for DEX unpacking
                            event.even_type = get_demangled_method_for_dex_unpacking(parsed_data["even_type"])
                            even_not_identified = False
            
            # Set parsed data as metadata
            for key, value in parsed_data.items():
                if hasattr(event, key):
                    setattr(event, key, value)
                else:
                    event.add_metadata(key, value)

        except Exception as exception_info:
            event.event_type = "Unpacking:Unknown"
            event.add_metadata('payload', str(lines))
            event.add_metadata('exception', str(exception_info))
        
        return event
    
    def parse_dex_loading_list(self, lines: List[str]) -> dict:
        """Parse DEX loading data from list of lines - legacy compatibility method"""
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
                        parsed_data["even_type"] = get_demangled_method_for_dex_unpacking(parsed_data["even_type"])
                        even_not_identified = False

        except Exception as exception_info:
            parsed_data["event_type"] = "Unpacking:Unknown"
            parsed_data["payload"] = str(lines)
            parsed_data["exception"] = exception_info       

        return parsed_data