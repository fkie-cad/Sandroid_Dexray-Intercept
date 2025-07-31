#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from abc import ABC, abstractmethod
from typing import Optional
from ..models.events import Event


class BaseParser(ABC):
    """Base parser class with common JSON parsing logic"""
    
    def parse(self, raw_data: str, timestamp: str) -> Optional[Event]:
        """Parse raw data into an Event object"""
        try:
            # First, try to parse as JSON (new format)
            try:
                data = json.loads(raw_data)
                return self.parse_json_data(data, timestamp)
            except (json.JSONDecodeError, ValueError):
                # Fall back to legacy string parsing
                return self.parse_legacy_data(raw_data, timestamp)
                
        except Exception as e:
            return self.handle_parse_error(raw_data, timestamp, str(e))
    
    @abstractmethod
    def parse_json_data(self, data: dict, timestamp: str) -> Optional[Event]:
        """Parse JSON data into an Event object"""
        pass
    
    def parse_legacy_data(self, raw_data: str, timestamp: str) -> Optional[Event]:
        """Parse legacy string data into an Event object"""
        # Default implementation - can be overridden by subclasses
        return self.handle_parse_error(raw_data, timestamp, "Legacy format not supported")
    
    def handle_parse_error(self, raw_data: str, timestamp: str, error: str) -> Optional[Event]:
        """Handle parsing errors - return a generic event or None"""
        from ..models.events import Event
        
        class ParseErrorEvent(Event):
            def __init__(self, raw_data: str, error: str, timestamp: str):
                super().__init__("parse_error", timestamp)
                self.raw_data = raw_data
                self.error = error
            
            def get_event_data(self):
                return {
                    "payload": self.raw_data,
                    "error": self.error
                }
        
        return ParseErrorEvent(raw_data, error, timestamp)
    
    def ensure_timestamp(self, data: dict, timestamp: str):
        """Ensure timestamp is set in data"""
        if 'timestamp' not in data:
            data['timestamp'] = timestamp