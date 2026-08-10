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
            # generic hook metadata
            'library':                'library',
            'method':                 'method',
            # bluetooth GATT
            'characteristic_uuid':    'characteristic_uuid',
            'value_hex':              'value_hex',
            'value_length':           'value_length',
            # bluetooth adapter / device
            'adapter_available':      'adapter_available',
            'kill_apps':              'kill_apps',
            'mac_address':            'mac_address',
            'device_address':         'device_address',
            'device_name':            'device_name',
            # SMS
            'destination_address':    'destination_address',
            'service_center_address': 'service_center_address',
            'message_text':           'message_text',
            'text_length':            'text_length',
            'message_parts':          'message_parts',
            'parts_count':            'parts_count',
            'has_sent_intent':        'has_sent_intent',
            'has_delivery_intent':    'has_delivery_intent',
            'has_sent_intents':       'has_sent_intents',
            'has_delivery_intents':   'has_delivery_intents',
            # telephony manager
            'phone_number':           'phone_number',
            'imsi':                   'imsi',
            'device_id':              'device_id',
            'imei':                   'imei',
            'sim_operator':           'sim_operator',
            'denied':                 'denied',
            'error':                  'error',
            # system / build
            'property_key':           'property_key',
            'property_value':         'property_value',
            'build_properties':       'build_properties',
            # wifi
            'ssid':                   'ssid',
            'bssid':                  'bssid',
            # content resolver
            'uri':                    'uri',
            'has_result':             'has_result',
            'action':                 'action',
            # secure settings - hook emits settings_key / settings_value
            'settings_key':           'settings_key',
            'settings_value':         'settings_value',
            
            # location
            'provider':               'provider',
            'latitude':               'latitude',
            'longitude':              'longitude',
            'accuracy':               'accuracy',
            'has_location':           'has_location',
            'min_time_ms':            'min_time_ms',
            'min_distance_m':         'min_distance_m',
            'has_listener':           'has_listener',
            'has_looper':             'has_looper',
            'overload':               'overload',

            # clipboard
            'content_type':           'content_type',
            'content':                'content',
            'item_count':             'item_count',
            'has_clip':               'has_clip',
            'item_index':             'item_index',
            'total_items':            'total_items',
            'content_length':         'content_length',
            'error_message':          'error_message',

            # camera
            'camera_id':              'camera_id',
            'camera_count':           'camera_count',
            'camera_ids':             'camera_ids',
            'has_callback':           'has_callback',
            'has_handler':            'has_handler',
            'has_executor':           'has_executor',

            # generic
            'success':                'success',
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
            elif event_type == 'bluetooth.gatt.get_characteristic_value':
                event.event_description = 'Bluetooth GATT characteristic value read after async callback'
            elif event_type == 'bluetooth.adapter.get_default':
                event.event_description = 'Bluetooth adapter access'
            elif event_type == 'bluetooth.adapter.enable':
                event.event_description = 'Bluetooth adapter enable'
            elif event_type == 'bluetooth.adapter.disable':
                event.event_description = 'Bluetooth adapter disable'
            elif event_type == 'bluetooth.adapter.start_discovery':
                event.event_description = 'Bluetooth device discovery started'
            elif event_type == 'bluetooth.adapter.get_address':
                event.event_description = 'Bluetooth adapter MAC address access'
            elif event_type == 'bluetooth.device.create_bond':
                event.event_description = 'Bluetooth device pairing'

        # Telephony events
        elif event_type.startswith('telephony.'):
            if event_type == 'telephony.sms.send_text':
                event.event_description = 'SMS text message send requested'
            elif event_type == 'telephony.sms.send_multipart':
                event.event_description = 'SMS multipart message send requested'
            elif event_type == 'telephony.manager.get_phone_number':
                event.event_description = 'Phone number access'
            elif event_type == 'telephony.manager.get_imsi':
                event.event_description = 'SIM IMSI access'
            elif event_type == 'telephony.manager.get_device_id':
                event.event_description = 'Device ID access'
            elif event_type == 'telephony.manager.get_imei':
                event.event_description = 'Device IMEI access'
            elif event_type == 'telephony.manager.get_sim_operator':
                event.event_description = 'SIM operator access'
            elif event_type == 'telephony.system_properties.get':
                event.event_description = 'System property access'
            elif event_type == 'telephony.build.snapshot':
                event.event_description = 'Device build properties snapshot'
            elif event_type == 'telephony.wifi.get_mac_address':
                event.event_description = 'WiFi MAC address access'
            elif event_type == 'telephony.wifi.get_ssid':
                event.event_description = 'WiFi SSID access'
            elif event_type == 'telephony.wifi.get_bssid':
                event.event_description = 'WiFi BSSID access'
            elif event_type == 'telephony.content_resolver.query':
                event.event_description = 'Content resolver query'
            elif event_type == 'telephony.content_resolver.query_gsf':
                event.event_description = 'Google Services Framework query'
            elif event_type == 'telephony.secure_settings.get_string':
                event.event_description = 'Secure settings access'

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
            elif event_type == 'location.fused_provider.get_last_location':
                event.event_description = 'Fused location provider last location access'

        # Clipboard events
        elif event_type.startswith('clipboard.'):
            if event_type == 'clipboard.set_primary_clip':
                event.event_description = 'Clipboard data written'
            elif event_type == 'clipboard.get_primary_clip':
                event.event_description = 'Clipboard data read'
            elif event_type == 'clipboard.set_primary_clip_internal_error':
                event.event_description = 'Clipboard write hook extraction error'

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