#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional
from .base import BaseParser
from ..models.events import FileSystemEvent
from ..utils.hexdump import hex_to_string_safe, hexdump
from ..utils.string_utils import escape_special_characters, unescape_special_characters


class FileSystemParser(BaseParser):
    """Parser for file system events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[FileSystemEvent]:
        """Parse JSON data into FileSystemEvent"""
        event_type = data.get('event_type', 'file.unknown')
        file_path = data.get('file_path', data.get('path', ''))
        
        event = FileSystemEvent(event_type, file_path, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'operation': 'operation',
            'buffer_size': 'buffer_size',
            'offset': 'offset',
            'length': 'length',
            'data_hex': 'data_hex',
            'file_type': 'file_type',
            'is_large_data': 'is_large_data',
            'fd': 'fd',
            'parent_path': 'parent_path',
            'child_path': 'child_path',
            'stream_type': 'stream_type',
            'bytes_read': 'bytes_read',
            'bytes_written': 'bytes_written',
            'should_dump_ascii': None,  # Used for processing
            'should_dump_hex': None,    # Used for processing
            'max_display_length': None, # Used for processing
            'displayed_length': 'displayed_length',
            'original_length': 'original_length'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data and event_field:
                setattr(event, event_field, data[json_field])
        
        # Handle hexdump for display if data_hex is present
        if data.get('data_hex'):
            hex_data = data['data_hex']
            
            # Add plaintext conversion for ASCII-compatible data
            if data.get('should_dump_ascii', False):
                event.plaintext = hex_to_string_safe(hex_data)
            
            # Add formatted hexdump for display
            if data.get('should_dump_hex', False) or data.get('file_type') in ['binary', 'xml']:
                event.hexdump_display = hexdump(hex_data, header=True, ansi=True)
            
            # Handle truncation if needed
            if data.get('is_large_data', False):
                max_len = data.get('max_display_length', 1024)
                if len(hex_data) > max_len * 2:  # hex string is 2x byte length
                    event.add_metadata('truncated', True)
                    event.add_metadata('original_length', len(hex_data) // 2)
                    event.add_metadata('displayed_length', max_len)
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[FileSystemEvent]:
        """Parse legacy string data into FileSystemEvent"""
        try:
            # Legacy parser for raw file system event data
            if raw_data.startswith("[Java::"):
                return self._parse_java_legacy(raw_data, timestamp)
            elif raw_data.startswith("[Libc"):
                return self._parse_libc_legacy(raw_data, timestamp)
            else:
                return self._parse_generic_legacy(raw_data, timestamp)
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))
    
    def _parse_java_legacy(self, raw_data: str, timestamp: str) -> Optional[FileSystemEvent]:
        """Parse legacy Java file system events"""
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

                return FileSystemEvent(event_type, content, timestamp)
            else:
                parts = raw_data.split("]")
                event_type = parts[0].strip("[]")
                content = parts[1].strip()

                event = FileSystemEvent(event_type, "", timestamp)
                event.add_metadata('payload', content)
                return event
        else:
            # Extract information from the match
            event_type = match.group("event_type")
            bytes_written = int(match.group("bytes"))
            offset = int(match.group("offset"))
            file_path = match.group("file_path")
            raw_content = match.group("content")
            content = unescape_special_characters(raw_content)
            
            event = FileSystemEvent(event_type, file_path, timestamp)
            event.bytes_written = bytes_written
            event.offset = offset
            event.plaintext = content
            
            return event
    
    def _parse_libc_legacy(self, raw_data: str, timestamp: str) -> Optional[FileSystemEvent]:
        """Parse legacy Libc file system events"""
        parts = raw_data.split("]")
        event_type = parts[0].strip("[]")
        
        if parts[1].startswith(" Open"):
            path_parts = parts[1].split("'")
            path = path_parts[1]
            fd = path_parts[2].split(":")[1].strip()[:-1]
            
            event = FileSystemEvent(event_type, path, timestamp)
            event.fd = fd
            return event
            
        elif parts[1].startswith(" Write"):
            info_parts = parts[1].split(",")
            path = info_parts[0].split("(")[1]
            fd = info_parts[1].strip()
            buffer_addr = info_parts[2]
            written = info_parts[3].split(")")[0]
            
            event = FileSystemEvent(event_type, path, timestamp)
            event.fd = fd
            event.add_metadata('buffer_address', buffer_addr)
            event.bytes_written = written
            return event
            
        elif parts[1].startswith(" Read"):
            info_parts = parts[1].split(",")
            path = info_parts[0].split("(")[1]
            fd = info_parts[1].strip()
            buffer_addr = info_parts[2]
            read_bytes = info_parts[3].split(")")[0]
            
            event = FileSystemEvent(event_type, path, timestamp)
            event.fd = fd
            event.add_metadata('buffer_address', buffer_addr)
            event.bytes_read = read_bytes
            return event
        else:
            path = parts[1].split("Deleting:")[1][:-1]
            event = FileSystemEvent(event_type, path, timestamp)
            event.add_metadata('event', 'deleting file')
            return event
    
    def _parse_generic_legacy(self, raw_data: str, timestamp: str) -> Optional[FileSystemEvent]:
        """Parse generic legacy file system events"""
        parts = raw_data.split(" ")
        event_type = parts[0].strip("[]")
        file_path = parts[4].strip("'()") if len(parts) > 4 else ""
        fd = int(parts[6].strip("()")) if len(parts) > 6 and "fd:" in parts[6] else None
        
        event = FileSystemEvent(event_type, file_path, timestamp)
        if fd is not None:
            event.fd = fd
        
        return event