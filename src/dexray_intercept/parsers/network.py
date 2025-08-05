#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Optional
from .base import BaseParser
from ..models.events import NetworkEvent


class NetworkParser(BaseParser):
    """Parser for network events (web and socket)"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[NetworkEvent]:
        """Parse JSON data into NetworkEvent"""
        event_type = data.get('event_type', 'network.unknown')
        
        event = NetworkEvent(event_type, timestamp)
        
        # Map JSON fields to event attributes
        field_mapping = {
            'url': 'url',
            'uri': 'uri',
            'method': 'method',
            'req_method': 'req_method',
            'status_code': 'status_code',
            'headers': 'headers',
            'body': 'body',
            'data': 'data',
            'mime_type': 'mime_type',
            'socket_type': 'socket_type',
            'socket_descriptor': 'socket_descriptor',
            'local_ip': 'local_ip',
            'local_port': 'local_port',
            'remote_ip': 'remote_ip',
            'remote_port': 'remote_port',
            'data_length': 'data_length',
            'has_buffer': 'has_buffer'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Add socket type description
        if hasattr(event, 'socket_type') and event.socket_type:
            socket_type = event.socket_type
            if socket_type in ['tcp', 'tcp6']:
                event.socket_description = 'TCP Socket'
            elif socket_type in ['udp', 'udp6']:
                event.socket_description = 'UDP Socket'
            else:
                event.socket_description = f'Socket ({socket_type})'
        
        # Format connection info for easy display
        if event.local_ip and event.local_port:
            event.local_address = f"{event.local_ip}:{event.local_port}"
        
        if event.remote_ip and event.remote_port:
            event.remote_address = f"{event.remote_ip}:{event.remote_port}"
        
        # Add method description for socket events
        if 'method' in data:
            method = data['method']
            if method == 'connect':
                event.operation = 'Socket Connection'
            elif method == 'bind':
                event.operation = 'Socket Binding'
            elif method in ['read', 'recv', 'recvfrom']:
                event.operation = 'Data Received'
            elif method in ['write', 'send', 'sendto']:
                event.operation = 'Data Sent'
            else:
                event.operation = f'Socket {method.title()}'
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[NetworkEvent]:
        """Parse legacy string data into NetworkEvent"""
        try:
            # Regular expression to extract JSON parts
            json_pattern = re.compile(r'\{.*\}')
            match = json_pattern.search(raw_data)
            
            if match:
                json_str = match.group()
                data = json.loads(json_str)
                
                # Determine event type from legacy data
                if "event_type" in data:
                    event_type = data["event_type"]
                else:
                    event_type = "network.legacy"
                
                event = NetworkEvent(event_type, timestamp)
                
                # Map legacy fields
                legacy_mapping = {
                    'url': 'url',
                    'uri': 'uri',
                    'req_method': 'req_method',
                    'stack': None,  # Add to metadata
                    'class': None,  # Add to metadata
                    'method': 'method',
                    'event': None   # Add to metadata
                }
                
                for legacy_field, event_field in legacy_mapping.items():
                    if legacy_field in data:
                        if event_field:
                            setattr(event, event_field, data[legacy_field])
                        else:
                            event.add_metadata(legacy_field, data[legacy_field])
                
                return event
            else:
                # Handle non-JSON legacy data
                event = NetworkEvent("network.legacy", timestamp)
                event.add_metadata('payload', raw_data)
                return event
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))


class WebParser(NetworkParser):
    """Specialized parser for web events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[NetworkEvent]:
        """Parse web-specific JSON data"""
        event = super().parse_json_data(data, timestamp)
        
        # Web-specific processing
        if event and event.event_type.startswith(('url.', 'uri.', 'http.', 'https.', 'okhttp.', 'webview.', 'retrofit.', 'volley.', 'websocket.', 'customtabs.', 'x5webview.')):
            # Add web-specific metadata for enhanced context
            if event.event_type.startswith('retrofit.'):
                event.add_metadata('library', 'Retrofit')
                event.add_metadata('type', 'REST API Framework')
            elif event.event_type.startswith('volley.'):
                event.add_metadata('library', 'Volley')
                event.add_metadata('type', 'Google HTTP Library')
            elif event.event_type.startswith('websocket.'):
                event.add_metadata('library', 'WebSocket')
                event.add_metadata('type', 'Real-time Communication')
            elif event.event_type.startswith('okhttp.'):
                event.add_metadata('library', 'OkHttp')
                event.add_metadata('type', 'HTTP Client')
            elif event.event_type.startswith('webview.'):
                event.add_metadata('library', 'WebView')
                event.add_metadata('type', 'Embedded Browser')
            elif event.event_type.startswith('customtabs.'):
                event.add_metadata('library', 'Chrome Custom Tabs')
                event.add_metadata('type', 'External Browser Integration')
            elif event.event_type.startswith('x5webview.'):
                event.add_metadata('library', 'X5WebView (Tencent)')
                event.add_metadata('type', 'Embedded Browser (Chinese)')
            
            # Add operation context based on event type
            if 'request' in event.event_type:
                event.operation = 'HTTP Request'
            elif 'response' in event.event_type:
                event.operation = 'HTTP Response'
            elif 'connect' in event.event_type:
                event.operation = 'Connection'
            elif 'send' in event.event_type:
                event.operation = 'Send Data'
            elif 'receive' in event.event_type or 'message' in event.event_type:
                event.operation = 'Receive Data'
            elif 'load' in event.event_type:
                event.operation = 'Load Content'
            elif 'page' in event.event_type:
                event.operation = 'Page Navigation'
        
        return event


class SocketParser(NetworkParser):
    """Specialized parser for socket events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[NetworkEvent]:
        """Parse socket-specific JSON data"""
        event = super().parse_json_data(data, timestamp)
        
        # Socket-specific processing
        if event and event.event_type.startswith('socket.'):
            # Already handled by parent class
            pass
        
        return event