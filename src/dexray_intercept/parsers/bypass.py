#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from .base import BaseParser
from ..models.events import Event


class BypassEvent(Event):
    """Event representing an anti-analysis bypass operation"""
    
    def __init__(self, event_type: str, timestamp: str):
        super().__init__(event_type, timestamp)
        self.bypass_category = None
        self.detection_method = None
        self.original_value = None
        self.bypassed_value = None
        self.action = None
        self.file_path = None
        self.command = None
        self.package_name = None
        self.process_name = None
        self.property_name = None
        self.library_name = None
        self.host = None
        self.port = None
        self.original_result = None
        self.bypassed_result = None
        
    def get_event_data(self):
        data = {
            "event_type": self.event_type,
            "bypass_category": self.bypass_category,
            "detection_method": self.detection_method,
            "action": self.action
        }
        
        # Add non-None fields
        if self.original_value is not None:
            data["original_value"] = self.original_value
        if self.bypassed_value is not None:
            data["bypassed_value"] = self.bypassed_value
        if self.file_path:
            data["file_path"] = self.file_path
        if self.command:
            data["command"] = self.command
        if self.package_name:
            data["package_name"] = self.package_name
        if self.process_name:
            data["process_name"] = self.process_name
        if self.property_name:
            data["property_name"] = self.property_name
        if self.library_name:
            data["library_name"] = self.library_name
        if self.host:
            data["host"] = self.host
        if self.port:
            data["port"] = self.port
        if self.original_result is not None:
            data["original_result"] = self.original_result
        if self.bypassed_result is not None:
            data["bypassed_result"] = self.bypassed_result
            
        return data


class BypassParser(BaseParser):
    """Parser for anti-analysis bypass events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[BypassEvent]:
        """Parse JSON data into BypassEvent"""
        event_type = data.get('event_type', 'bypass.unknown')
        
        event = BypassEvent(event_type, timestamp)
        
        # Determine bypass category from event type
        if 'bypass.root' in event_type:
            event.bypass_category = 'root_detection'
        elif 'bypass.frida' in event_type:
            event.bypass_category = 'frida_detection'
        elif 'bypass.debugger' in event_type:
            event.bypass_category = 'debugger_detection'
        elif 'bypass.emulator' in event_type:
            event.bypass_category = 'emulator_detection'
        elif 'bypass.hook' in event_type:
            event.bypass_category = 'hook_detection'
        else:
            event.bypass_category = 'unknown'
        
        # Map common fields
        field_mapping = {
            'detection_method': 'detection_method',
            'action': 'action',
            'file_path': 'file_path',
            'command': 'command',
            'package_name': 'package_name',
            'process_name': 'process_name',
            'library_name': 'library_name',
            'host': 'host',
            'port': 'port'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Handle various value fields
        value_mappings = {
            'original_result': 'original_result',
            'bypassed_result': 'bypassed_result',
            'original_value': 'original_value',
            'bypassed_value': 'bypassed_value',
            'original_tags': 'original_value',
            'bypassed_tags': 'bypassed_value',
            'original_name': 'original_value',
            'bypassed_name': 'bypassed_value',
            'original_line': 'original_value',
            'bypassed_line': 'bypassed_value',
            'original_flags': 'original_value',
            'property': 'property_name',
            'filtered_class': 'original_value'
        }
        
        for json_field, event_field in value_mappings.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Add metadata for enhanced context
        self._add_bypass_metadata(event, data)
        
        return event
    
    def _add_bypass_metadata(self, event: BypassEvent, data: dict):
        """Add bypass-specific metadata"""
        bypass_descriptions = {
            'bypass.root.file_check': 'Root detection via file existence check',
            'bypass.root.command_execution': 'Root detection via shell command execution',
            'bypass.root.build_tags': 'Root detection via Build.TAGS property',
            'bypass.root.package_check': 'Root detection via installed packages check',
            'bypass.frida.file_check': 'Frida detection via file existence check',
            'bypass.frida.port_check': 'Frida detection via port scanning',
            'bypass.frida.process_check': 'Frida detection via process list scanning',
            'bypass.frida.thread_check': 'Frida detection via thread name analysis',
            'bypass.debugger.connection_check': 'Debugger detection via Debug.isDebuggerConnected()',
            'bypass.debugger.flag_check': 'Debugger detection via ApplicationInfo flags',
            'bypass.debugger.tracer_check': 'Debugger detection via TracerPid status',
            'bypass.emulator.build_property': 'Emulator detection via Build properties',
            'bypass.emulator.system_property': 'Emulator detection via system properties',
            'bypass.hook.stack_trace': 'Hook detection via stack trace analysis',
            'bypass.hook.library_check': 'Hook detection via library verification'
        }
        
        description = bypass_descriptions.get(event.event_type, f'Unknown bypass: {event.event_type}')
        event.add_metadata('description', description)
        
        # Add bypass category metadata
        event.add_metadata('category', event.bypass_category)
        
        # Add severity metadata
        severity_mapping = {
            'root_detection': 'high',
            'frida_detection': 'critical', 
            'debugger_detection': 'high',
            'emulator_detection': 'medium',
            'hook_detection': 'critical'
        }
        
        severity = severity_mapping.get(event.bypass_category, 'medium')
        event.add_metadata('severity', severity)
        
        # Add technique information
        if event.bypass_category == 'root_detection':
            event.add_metadata('mitre_technique', 'T1622')  # Debugger Evasion
            event.add_metadata('technique_name', 'Debugger Evasion')
        elif event.bypass_category == 'frida_detection':
            event.add_metadata('mitre_technique', 'T1622')  # Debugger Evasion  
            event.add_metadata('technique_name', 'Dynamic Analysis Evasion')
        elif event.bypass_category == 'emulator_detection':
            event.add_metadata('mitre_technique', 'T1497')  # Virtualization/Sandbox Evasion
            event.add_metadata('technique_name', 'Virtualization/Sandbox Evasion')
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[BypassEvent]:
        """Parse legacy string data (not used for bypass events)"""
        return None