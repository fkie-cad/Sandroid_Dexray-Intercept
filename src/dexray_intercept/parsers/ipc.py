#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Optional
from .base import BaseParser
from ..models.events import IPCEvent


class IPCParser(BaseParser):
    """Base parser for IPC events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[IPCEvent]:
        """Parse JSON data into IPCEvent"""
        event_type = data.get('event_type', 'ipc.unknown')
        
        event = IPCEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'key': 'key',
            'value': 'value',
            'file': 'file',
            'method': 'method',
            'data': 'data',
            'intent_name': 'intent_name',
            'intent': 'intent',
            'intent_details': 'intent_details',
            'intent_flag': 'intent_flag',
            'extras_formatted': 'extras_formatted',
            'transaction_type': 'transaction_type',
            'sender_pid': 'sender_pid',
            'code': 'code',
            'data_size': 'data_size',
            'payload_hex': 'payload_hex'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        return event


class SharedPrefsParser(IPCParser):
    """Parser for shared preferences events"""
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[IPCEvent]:
        """Parse legacy shared preferences data"""
        try:
            parts = raw_data.split("]")
            event_type = parts[0].strip("[]")
            
            # Regular expression to extract JSON parts
            json_pattern = re.compile(r'\{.*\}')
            match = json_pattern.search(raw_data)
            
            if match:
                json_str = match.group()
                json_obj = json.loads(json_str)
                
                event = IPCEvent(event_type, timestamp)
                
                # Map JSON object fields
                for key, value in json_obj.items():
                    if hasattr(event, key):
                        setattr(event, key, value)
                    else:
                        event.add_metadata(key, value)
                
                return event
            else:
                return self.handle_parse_error(raw_data, timestamp, "No JSON found in shared prefs data")
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))


class BinderParser(IPCParser):
    """Parser for binder events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[IPCEvent]:
        """Parse JSON data into IPCEvent for binder operations"""
        event = super().parse_json_data(data, timestamp)
        
        # Add transaction type description
        if event and event.transaction_type:
            trans_type = event.transaction_type
            if trans_type == 'BC_TRANSACTION':
                event.transaction_desc = 'Binder Transaction'
            elif trans_type == 'BC_REPLY':
                event.transaction_desc = 'Binder Reply'
            else:
                event.transaction_desc = f'Unknown ({trans_type})'
        
        return event


class IntentParser(IPCParser):
    """Parser for intent events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[IPCEvent]:
        """Parse JSON data into IPCEvent for intent operations"""
        event = super().parse_json_data(data, timestamp)
        
        # Extract intent information for display
        if event and event.intent:
            intent_info = event.intent
            
            # Set intent name for easy access
            if 'component' in intent_info:
                event.intent_name = intent_info['component']
            elif 'action' in intent_info:
                event.intent_name = intent_info['action']
            
            # Format extras for better display
            if 'extras' in intent_info and intent_info['extras']:
                extras_formatted = []
                for key, extra_data in intent_info['extras'].items():
                    if isinstance(extra_data, dict) and 'type' in extra_data and 'value' in extra_data:
                        extras_formatted.append(f"{key} ({extra_data['type']}): {extra_data['value']}")
                    else:
                        extras_formatted.append(f"{key}: {extra_data}")
                event.extras_formatted = extras_formatted
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[IPCEvent]:
        """Parse legacy intent data"""
        try:
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
            
            event = IPCEvent("intent.legacy", timestamp)
            event.intent = intent_data
            event.add_metadata('payload', raw_data)
            
            return event
            
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))


class BroadcastParser(IPCParser):
    """Parser for broadcast events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[IPCEvent]:
        """Parse JSON data into IPCEvent for broadcast operations"""
        event = super().parse_json_data(data, timestamp)
        
        # Handle new structured format
        if event and event.intent:
            intent_info = event.intent
            
            # Extract component name if available
            if 'component' in intent_info:
                event.intent_name = intent_info['component']
            elif 'action' in intent_info:
                event.intent_name = intent_info['action']
            
            # Extract intent details
            event.intent_details = {
                'action': intent_info.get('action'),
                'component': intent_info.get('component'),
                'data_uri': intent_info.get('data_uri'),
                'flags': intent_info.get('flags'),
                'extras': intent_info.get('extras')
            }
        
        # Handle legacy format with artifact field
        elif event and hasattr(event, 'metadata') and 'artifact' in event.metadata:
            artifact = event.metadata['artifact']
            if artifact and len(artifact) > 0:
                intent_value = artifact[0].get("value", "")
                intent_name, intent_flag = self._parse_intent_value_for_broadcasts(intent_value)
                event.intent_name = intent_name
                event.intent_flag = intent_flag
        
        return event
    
    def _parse_intent_value_for_broadcasts(self, intent_value):
        """Parse intent value from broadcast legacy format"""
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