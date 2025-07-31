#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Optional
from .base import BaseFormatter
from ..models.events import Event


class JSONFormatter(BaseFormatter):
    """JSON formatter for structured output"""
    
    def __init__(self, indent: int = 4):
        self.indent = indent
    
    def format_event(self, event: Event) -> Optional[str]:
        """Format event as JSON string"""
        if self.should_skip_event(event):
            return None
        
        try:
            return json.dumps(event.to_dict(), indent=self.indent, default=self._json_serializer)
        except Exception as e:
            # Fallback for problematic events
            return json.dumps({
                'event_type': 'json_format_error',
                'original_event_type': event.event_type,
                'timestamp': event.timestamp,
                'error': str(e)
            }, indent=self.indent)
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for special objects"""
        if isinstance(obj, Exception):
            return str(obj)
        if hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")