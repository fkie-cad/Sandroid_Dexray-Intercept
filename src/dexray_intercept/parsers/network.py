#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Optional
from .base import BaseParser
from ..models.events import NetworkEvent


def format_socket_address(address: str, port: int) -> str:
    """Format an ip:port pair, bracketing IPv6 literals."""
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

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
            'has_buffer': 'has_buffer',
            'provider_class': 'provider_class',
            'declaring_class': 'declaring_class',
            'overload_signature': 'overload_signature',
            'address_family': 'address_family',
            'protocol': 'protocol',
            'result_code': 'result_code',
            'operation_id': 'operation_id',
            'captured_length': 'captured_length',
            'data_hex': 'data_hex',
            'class_name': 'class_name',
            'host': 'host',
            'port': 'port',
            'endpoint': 'endpoint',
            'timeout': 'timeout',
            'server_info': 'server_info',
            'proxy': 'proxy',
            'backlog': 'backlog',
            'payload_truncated': 'payload_truncated',
            'local_address': 'local_address',
            'remote_address': 'remote_address',
            'connection_string': 'connection_string',
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
        
        # Format connection info for easy display.
        # Skip if the agent already supplied a formatted address (e.g. Java
        # socket hooks send bracketed IPv6 endpoints directly) to avoid
        # clobbering it with an unbracketed reconstruction.
        if not event.local_address and event.local_ip and event.local_port:
            event.local_address = format_socket_address(event.local_ip, event.local_port)
        
        if not event.remote_address and event.remote_ip and event.remote_port:
            event.remote_address = format_socket_address(event.remote_ip, event.remote_port)
        
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
        if event and event.event_type.startswith((
                'url.', 'uri.', 'http.', 'https.', 'okhttp.', 'okhttp_old.',
                'webview.', 'retrofit.', 'volley.', 'websocket.', 'customtabs.',
                'x5webview.'
        )):
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
            elif event.event_type.startswith(('okhttp.', 'okhttp_old.')):
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

    # Fixed OS-level control-socket paths that are plumbing rather than
    # application or library behavior of research interest: per-connection
    # network policy marking, system tracing infrastructure, and PRNG
    # seeding, each using a small, fixed protocol with no payload variance
    # of research interest.
    KNOWN_NOISY_UNIX_ENDPOINTS = {
        "filesystem:/dev/socket/fwmarkd",
        "filesystem:/dev/socket/traced_producer",
        "filesystem:/dev/socket/statsdw",
        "filesystem:/dev/socket/prng_seeder",
        "filesystem:/dev/socket/logdw",
    }

    def __init__(self):
        super().__init__()
        # operation_id values classified as noise on their primary event, so
        # the matching *_data companion (which carries no socket_type/address
        # fields of its own) inherits the same classification.
        self._noisy_operation_ids = set()

    def parse_json_data(self, data: dict, timestamp: str) -> Optional[NetworkEvent]:
        """Parse socket-specific JSON data"""
        event = super().parse_json_data(data, timestamp)

        if event:
            self._classify_socket_noise(event)

        return event

    def _classify_socket_noise(self, event: NetworkEvent) -> None:
        """Tag low-signal native socket chatter for default console suppression.

        Never drops the event or any of its data - JSON profile output is
        unaffected; this only sets metadata consulted by ConsoleFormatter to
        hide the event from the default (non -v) live console view.

        Two independent classifications:

        - known noisy endpoint: local_address/remote_address matches a fixed
          low-value control-socket path (see KNOWN_NOISY_UNIX_ENDPOINTS).
        - unresolved unix endpoint: a unix:stream/unix:dgram event whose
          endpoint was never resolved via a directly observed bind()/
          connect(), typically anonymous socketpair()-based IPC opened
          before agent attach. Generic by construction: it does not fire for
          any socket whose endpoint is resolved, regardless of what opened it.
        """
        event_type = event.event_type

        if not event_type.startswith('socket.native.'):
            return

        if event_type.endswith('_data'):
            operation_id = event.operation_id
            if operation_id and operation_id in self._noisy_operation_ids:
                event.add_metadata('socket_noise_reason', 'inherited')
            return

        local_address = event.local_address or ''
        remote_address = event.remote_address or ''
        noise_reason = None

        if (
            local_address in self.KNOWN_NOISY_UNIX_ENDPOINTS
            or remote_address in self.KNOWN_NOISY_UNIX_ENDPOINTS
        ):
            noise_reason = 'known_noisy_endpoint'
        elif (
            event.socket_type in ('unix:stream', 'unix:dgram')
            and not local_address
            and not remote_address
        ):
            noise_reason = 'unresolved_unix_endpoint'

        if noise_reason:
            event.add_metadata('socket_noise_reason', noise_reason)

            if event.operation_id:
                self._noisy_operation_ids.add(event.operation_id)