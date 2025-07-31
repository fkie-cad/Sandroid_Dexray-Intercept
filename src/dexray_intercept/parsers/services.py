#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Optional
from .base import BaseParser
from ..models.events import ServiceEvent


class ServiceParser(BaseParser):
    """Parser for Android system service events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[ServiceEvent]:
        """Parse JSON data into ServiceEvent"""
        event_type = data.get('event_type', 'service.unknown')
        
        event = ServiceEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'characteristic_uuid': 'characteristic_uuid',
            'device_address': 'device_address',
            'device_name': 'device_name',
            'value_hex': 'value_hex',
            'destination_address': 'destination_address',
            'message_text': 'message_text',
            'phone_number': 'phone_number',
            'imei': 'imei',
            'property_key': 'property_key',
            'property_value': 'property_value',
            'provider': 'provider',
            'latitude': 'latitude',
            'longitude': 'longitude',
            'accuracy': 'accuracy',
            'has_location': 'has_location',
            'content_type': 'content_type',
            'content': 'content',
            'item_count': 'item_count',
            'camera_id': 'camera_id',
            'camera_count': 'camera_count',
            'success': 'success'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Add service operation description based on event type
        self._add_event_description(event, event_type)
        
        return event
    
    def _add_event_description(self, event: ServiceEvent, event_type: str):
        """Add descriptive text for service events"""
        
        # Bluetooth events
        if event_type.startswith('bluetooth.'):
            if event_type == 'bluetooth.gatt.read_characteristic':
                event.event_description = 'Bluetooth GATT characteristic read'
            elif event_type == 'bluetooth.gatt.set_characteristic_value':
                event.event_description = 'Bluetooth GATT characteristic write'
            elif event_type == 'bluetooth.adapter.get_default':
                event.event_description = 'Bluetooth adapter access'
            elif event_type == 'bluetooth.adapter.enable':
                event.event_description = 'Bluetooth adapter enable'
            elif event_type == 'bluetooth.device.create_bond':
                event.event_description = 'Bluetooth device pairing'
        
        # Telephony events
        elif event_type.startswith('telephony.'):
            if event_type == 'telephony.sms.send_text':
                event.event_description = 'SMS text message sent'
            elif event_type == 'telephony.sms.send_multipart':
                event.event_description = 'SMS multipart message sent'
            elif event_type == 'telephony.manager.get_phone_number':
                event.event_description = 'Phone number access'
            elif event_type == 'telephony.manager.get_imei':
                event.event_description = 'Device IMEI access'
            elif event_type == 'telephony.manager.get_imsi':
                event.event_description = 'SIM IMSI access'
            elif event_type == 'telephony.system_properties.get':
                event.event_description = 'System property access'
        
        # Location events
        elif event_type.startswith('location.'):
            if event_type == 'location.last_known_location':
                event.event_description = 'Last known location access'
            elif event_type == 'location.request_updates':
                event.event_description = 'Location updates requested'
            elif event_type == 'location.get_latitude':
                event.event_description = 'Latitude coordinate access'
            elif event_type == 'location.get_longitude':
                event.event_description = 'Longitude coordinate access'
        
        # Clipboard events
        elif event_type.startswith('clipboard.'):
            if event_type == 'clipboard.set_primary_clip':
                event.event_description = 'Clipboard data written'
            elif event_type == 'clipboard.get_primary_clip':
                event.event_description = 'Clipboard data read'
        
        # Camera events
        elif event_type.startswith('camera.'):
            if event_type == 'camera.legacy.open':
                event.event_description = 'Camera opened (legacy API)'
            elif event_type == 'camera.camera2.open':
                event.event_description = 'Camera opened (Camera2 API)'
            elif event_type == 'camera.camera2.get_camera_list':
                event.event_description = 'Camera list enumeration'
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[ServiceEvent]:
        """Parse legacy string data into ServiceEvent"""
        try:
            # Try to parse as generic JSON first (old format may have used this)
            try:
                data = json.loads(raw_data)
                return self.parse_json_data(data, timestamp)
            except json.JSONDecodeError:
                # If not JSON, treat as raw string
                event = ServiceEvent("service.legacy", timestamp)
                event.add_metadata('payload', raw_data)
                return event
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))


class TelephonyParser(ServiceParser):
    """Specialized parser for telephony events"""
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[ServiceEvent]:
        """Parse legacy telephony data with special handling"""
        try:
            # Regular expression to extract JSON parts
            json_pattern = re.compile(r'\{.*\}')
            match = json_pattern.search(raw_data)
            
            if match:
                json_str = match.group()
                data = json.loads(json_str)
                
                event = ServiceEvent("telephony.legacy", timestamp)
                
                # Map telephony-specific fields
                for key, value in data.items():
                    if hasattr(event, key):
                        setattr(event, key, value)
                    else:
                        event.add_metadata(key, value)
                
                return event
            else:
                # Handle raw telephony data
                event = ServiceEvent("telephony.legacy", timestamp)
                event.add_metadata('payload', raw_data)
                return event
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))