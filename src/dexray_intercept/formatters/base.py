#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Optional
from ..models.events import Event


class BaseFormatter(ABC):
    """Base formatter for event output"""
    
    @abstractmethod
    def format_event(self, event: Event) -> Optional[str]:
        """Format an event for output"""
        pass
    
    def format_header(self, event: Event) -> str:
        """Format event header with type and timestamp"""
        return f"[{event.event_type}] {event.timestamp}"
    
    def should_skip_event(self, event: Event) -> bool:
        """Determine if event should be skipped from output"""
        # Default implementation - can be overridden
        return False