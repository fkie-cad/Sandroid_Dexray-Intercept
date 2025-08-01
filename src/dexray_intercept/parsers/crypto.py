#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Optional
from .base import BaseParser
from ..models.events import CryptoEvent
from ..utils.crypto_utils import MODE_MAPPING
from ..utils.hexdump import hex_to_string_safe


class CryptoParser(BaseParser):
    """Parser for cryptographic events"""
    
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[CryptoEvent]:
        """Parse JSON data into CryptoEvent"""
        event_type = data.get('event_type', 'crypto.unknown')
        algorithm = data.get('algorithm')
        
        event = CryptoEvent(event_type, algorithm, timestamp)
        
        # Common field mapping for all crypto events
        field_mapping = {
            'operation_mode': 'operation_mode',
            'input_hex': 'input_hex',
            'output_hex': 'output_hex',
            'input_length': 'input_length',
            'output_length': 'output_length',
            'key_hex': 'key_hex',
            'key_length': 'key_length',
            'iv_hex': 'iv_hex',
            'iv_length': 'iv_length'
        }
        
        for json_field, event_field in field_mapping.items():
            if json_field in data:
                setattr(event, event_field, data[json_field])
        
        # Handle AES-specific operation mode mapping
        if 'operation_mode' in data:
            mode_num = data['operation_mode']
            mode_name = MODE_MAPPING.get(mode_num, f"UNKNOWN_MODE_{mode_num}")
            event.operation_mode_desc = f"{mode_name} ({mode_num})"
            
            # Extract plaintext based on operation mode
            if mode_name == "ENCRYPT_MODE" and 'input_hex' in data:
                event.plaintext = hex_to_string_safe(data['input_hex'])
            elif mode_name == "DECRYPT_MODE" and 'output_hex' in data:
                event.plaintext = hex_to_string_safe(data['output_hex'])
        
        # Handle Base64 encoding/decoding events
        if event_type.startswith('crypto.base64.'):
            if 'input_string' in data:
                event.add_metadata('input_string', data['input_string'])
            if 'output_string' in data:
                event.add_metadata('output_string', data['output_string'])
            if 'decoded_content' in data:
                event.plaintext = data['decoded_content']
            if 'input_content' in data:
                event.plaintext = data['input_content']
            if 'flags' in data:
                event.add_metadata('flags', data['flags'])
            if 'method' in data:
                event.add_metadata('method', data['method'])
        
        # Handle Keystore events
        if event_type.startswith('crypto.keystore.'):
            keystore_fields = ['alias', 'password', 'type', 'provider', 'keystore_type', 
                             'method', 'aliases', 'parameter', 'input_stream']
            for field in keystore_fields:
                if field in data:
                    event.add_metadata(field, data[field])
        
        # Add any remaining metadata
        for key, value in data.items():
            if key not in ['event_type', 'timestamp'] and not hasattr(event, key):
                event.add_metadata(key, value)
        
        return event
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[CryptoEvent]:
        """Parse legacy string data into CryptoEvent"""
        try:
            # Regular expression to extract JSON parts
            json_pattern = re.compile(r'\{.*\}')
            match = json_pattern.search(raw_data)
            
            if match:
                json_str = match.group()
                data = json.loads(json_str)

                event = CryptoEvent("crypto.legacy", timestamp=timestamp)
                
                # Handle legacy opmode field
                if 'opmode' in data:
                    mode = MODE_MAPPING.get(data['opmode'], None)
                    if mode:
                        event.operation_mode = data['opmode']
                        event.operation_mode_desc = mode + " (" + str(data['opmode']) + ")"
                        
                        if mode == "ENCRYPT_MODE" and 'arg' in data:
                            event.plaintext = hex_to_string_safe(data['arg'])
                            event.input_hex = data['arg']
                        elif mode == "DECRYPT_MODE" and 'result' in data:
                            event.plaintext = hex_to_string_safe(data['result'])
                            event.output_hex = data['result']
                
                # Copy other legacy fields
                for key, value in data.items():
                    if key not in ['opmode']:
                        event.add_metadata(key, value)
                
                return event
            else:
                return self.handle_parse_error(raw_data, timestamp, "No JSON found in legacy data")
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))