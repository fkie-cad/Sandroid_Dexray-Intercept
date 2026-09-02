#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional

from .base import BaseParser
from ..models.events import BypassEvent


class BypassParser(BaseParser):
    """Parser for anti-analysis bypass events"""

    def parse_json_data(
        self,
        data: dict,
        timestamp: str
    ) -> Optional[BypassEvent]:
        """Parse JSON data into BypassEvent"""
        event_type = data.get('event_type', 'bypass.unknown')
        event = BypassEvent(event_type, timestamp)

        if event_type.startswith('bypass.root.'):
            event.bypass_category = 'root_detection'
        elif event_type.startswith('bypass.frida.'):
            event.bypass_category = 'frida_detection'
        elif event_type.startswith('bypass.debugger.'):
            event.bypass_category = 'debugger_detection'
        elif event_type.startswith('bypass.emulator.'):
            event.bypass_category = 'emulator_detection'
        elif event_type.startswith('bypass.hook.'):
            event.bypass_category = 'hook_detection'
        else:
            event.bypass_category = 'unknown'

        field_mapping = {
            'detection_method': 'detection_method',
            'action': 'action',
            'file_path': 'file_path',
            'command': 'command',
            'package_name': 'package_name',
            'process_name': 'process_name',
            'property': 'property_name',
            'library_name': 'library_name',
            'host': 'host',
            'port': 'port',
            'original_result': 'original_result',
            'bypassed_result': 'bypassed_result',
            'original_value': 'original_value',
            'bypassed_value': 'bypassed_value',
        }

        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])

        value_aliases = {
            'original_tags': 'original_value',
            'bypassed_tags': 'bypassed_value',
            'original_name': 'original_value',
            'bypassed_name': 'bypassed_value',
            'original_line': 'original_value',
            'bypassed_line': 'bypassed_value',
            'original_flags': 'original_value',
            'filtered_class': 'original_value',
        }

        for json_field, event_field in value_aliases.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])

        first_class_source_fields = set(field_mapping)
        for key, value in data.items():
            if key not in {'event_type', 'timestamp'} and key not in first_class_source_fields:
                event.add_metadata(key, value)

        self._add_bypass_metadata(event)
        return event

    def _add_bypass_metadata(self, event: BypassEvent):
        """Add category-level analytical metadata."""
        bypass_descriptions = {
            'bypass.root.file_check':
                'Root detection via file existence check',
            'bypass.root.command_execution':
                'Root detection via shell command execution',
            'bypass.root.build_tags':
                'Root detection via Build.TAGS property',
            'bypass.root.package_check':
                'Root detection via installed package enumeration',
            'bypass.frida.file_check':
                'Frida detection via file existence check',
            'bypass.frida.port_check':
                'Frida detection via port scanning',
            'bypass.frida.process_check':
                'Frida detection via process list scanning',
            'bypass.frida.thread_check':
                'Frida detection via thread name analysis',
            'bypass.debugger.connection_check':
                'Debugger detection via Debug.isDebuggerConnected()',
            'bypass.debugger.flag_check':
                'Debugger detection via ApplicationInfo flags',
            'bypass.debugger.tracer_check':
                'Debugger detection via TracerPid status',
            'bypass.emulator.build_property':
                'Emulator detection via Build properties',
            'bypass.emulator.system_property':
                'Emulator detection via system properties',
            'bypass.hook.stack_trace':
                'Hook detection via stack trace analysis',
            'bypass.hook.library_check':
                'Hook detection via library verification',
        }

        event.add_metadata(
            'description',
            bypass_descriptions.get(
                event.event_type,
                f'Unknown bypass: {event.event_type}'
            )
        )
        event.add_metadata('category', event.bypass_category)

        severity_mapping = {
            'root_detection': 'high',
            'frida_detection': 'critical',
            'debugger_detection': 'high',
            'emulator_detection': 'medium',
            'hook_detection': 'critical',
        }
        event.add_metadata(
            'severity',
            severity_mapping.get(event.bypass_category, 'medium')
        )

        if event.bypass_category == 'root_detection':
            event.add_metadata('mitre_technique', 'T1622')
            event.add_metadata('technique_name', 'Debugger Evasion')
        elif event.bypass_category == 'frida_detection':
            event.add_metadata('mitre_technique', 'T1622')
            event.add_metadata('technique_name', 'Dynamic Analysis Evasion')
        elif event.bypass_category == 'emulator_detection':
            event.add_metadata('mitre_technique', 'T1497')
            event.add_metadata(
                'technique_name',
                'Virtualization/Sandbox Evasion'
            )

    def parse_legacy_data(
        self,
        raw_data: str,
        timestamp: str
    ) -> Optional[BypassEvent]:
        """Bypass events are structured JSON only."""
        return None