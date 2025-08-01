#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Optional
from .base import BaseParser
from ..models.events import ProcessEvent


class ProcessParser(BaseParser):
    """Parser for process events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[ProcessEvent]:
        """Parse JSON data into ProcessEvent"""
        event_type = data.get('event_type', 'process.unknown')
        
        event = ProcessEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'nice_name': 'nice_name',
            'uid': 'uid',
            'gid': 'gid',
            'target_sdk_version': 'target_sdk_version',
            'abi': 'abi',
            'target_pid': 'target_pid',
            'signal': 'signal',
            'caller_pid': 'caller_pid',
            'child_pid': 'child_pid',
            'success': 'success',
            'command': 'command',
            'return_value': 'return_value',
            'library_name': 'library_name',
            'filename': 'filename',
            'working_directory': 'working_directory',
            'environment': 'environment'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Add process action description if present
        if event_type == 'process.creation':
            event.event_description = 'New process creation'
        elif event_type == 'process.kill':
            event.event_description = 'Process termination'
        elif event_type == 'process.signal':
            event.event_description = 'Process signal sent'
        elif event_type.startswith('process.fork'):
            event.event_description = 'Process fork operation'
        elif event_type.startswith('process.execve'):
            event.event_description = 'Process exec operation'
        elif event_type.startswith('process.system'):
            event.event_description = 'System command execution'
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[ProcessEvent]:
        """Parse legacy string data into ProcessEvent"""
        try:
            # Try to parse as generic JSON first (old format may have used this)
            try:
                data = json.loads(raw_data)
                return self.parse_json_data(data, timestamp)
            except json.JSONDecodeError:
                # If not JSON, treat as raw string
                event = ProcessEvent("process.legacy", timestamp)
                event.add_metadata('payload', raw_data)
                return event
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))


class RuntimeParser(BaseParser):
    """Parser for runtime events (exec, library loading, reflection)"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[ProcessEvent]:
        """Parse JSON data into ProcessEvent for runtime operations"""
        event_type = data.get('event_type', 'runtime.unknown')
        
        event = ProcessEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'command': 'command',
            'working_directory': 'working_directory',
            'environment': 'environment',
            'library_name': 'library_name',
            'filename': 'filename',
            'class_name': None,      # Add to metadata
            'method_name': None,     # Add to metadata
            'method_signature': None, # Add to metadata
            'initialize': None,      # Add to metadata
            'resolve': None,         # Add to metadata
            'target_instance': None, # Add to metadata
            'arguments': None,       # Add to metadata
            'result': None           # Add to metadata
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                if event_field:
                    setattr(event, event_field, data[json_field])
                else:
                    event.add_metadata(json_field, data[json_field])
        
        # Add runtime operation description
        if event_type == 'runtime.exec':
            event.event_description = 'Runtime command execution'
        elif event_type == 'runtime.load_library':
            event.event_description = 'Runtime library loading (loadLibrary)'
        elif event_type == 'runtime.load':
            event.event_description = 'Runtime library loading (load)'
        elif event_type.startswith('reflection.'):
            if event_type == 'reflection.class_for_name':
                event.event_description = 'Reflection class loading (forName)'
            elif event_type == 'reflection.load_class':
                event.event_description = 'Reflection class loading (loadClass)'
            elif event_type == 'reflection.get_method':
                event.event_description = 'Reflection method retrieval (getMethod)'
            elif event_type == 'reflection.get_declared_method':
                event.event_description = 'Reflection method retrieval (getDeclaredMethod)'
            elif event_type == 'reflection.method_invoke':
                event.event_description = 'Reflection method invocation'
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[ProcessEvent]:
        """Parse legacy string data into ProcessEvent"""
        try:
            # Try to parse as generic JSON first (old format may have used this)
            try:
                data = json.loads(raw_data)
                return self.parse_json_data(data, timestamp)
            except json.JSONDecodeError:
                # If not JSON, treat as raw string (old reflection format)
                if raw_data.startswith("[Reflection::"):
                    event = ProcessEvent("reflection.legacy", timestamp)
                    event.add_metadata('message', raw_data)
                    return event
                else:
                    event = ProcessEvent("runtime.legacy", timestamp)
                    event.add_metadata('payload', raw_data)
                    return event
                    
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))


class NativeLibParser(BaseParser):
    """Parser for native library loading events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[ProcessEvent]:
        """Parse JSON data into ProcessEvent for native library loading"""
        event_type = data.get('event_type', 'native.library.unknown')
        
        event = ProcessEvent(event_type, timestamp)
        
        # Map specific fields for native library events
        field_mapping = {
            'library_name': 'library_name',
            'library_path': 'library_path',
            'filename': 'filename',
            'loaded_library': 'library_name',  # Legacy field
            'method': 'method',
            'loader_type': 'loader_type'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Handle new structured library events
        if event_type.startswith('library.system.'):
            event.event_description = f'System.{data.get("method", "unknown")} called'
            event.loader_type = 'System'
        elif event_type.startswith('library.runtime.'):
            event.event_description = f'Runtime.{data.get("method", "unknown")} called'
            event.loader_type = 'Runtime'
        elif event_type == 'library.hook_error':
            event.event_description = 'Library hook installation error'
        # Legacy event types
        elif event_type == 'native.library.load':
            event.event_description = 'Native library loading attempt'
        elif event_type == 'native.library.loaded':
            event.event_description = 'Native library loaded successfully'
        elif event_type == 'native.library.load_failed':
            event.event_description = 'Native library loading failed'
        
        # Add any remaining metadata
        for key, value in data.items():
            if key not in ['event_type', 'timestamp'] and not hasattr(event, key):
                event.add_metadata(key, value)
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[ProcessEvent]:
        """Parse legacy string data for native library loading"""
        try:
            parts = raw_data.split("]")
            event_type = parts[0].strip("[]")
            
            event = ProcessEvent(event_type, timestamp)
            
            if len(parts) > 1 and ":" in parts[1]:
                event.library_name = parts[1].split(":")[1].strip()
            
            return event
            
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))