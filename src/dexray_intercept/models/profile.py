#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, List, Any
from datetime import datetime
from .events import Event


class ProfileData:
    """Container for profile data with events organized by category"""
    
    def __init__(self):
        self.events: Dict[str, List[Event]] = {}
        self.metadata = {
            'created_at': datetime.now().isoformat(),
            'version': '2.0',
            'total_events': 0
        }
    
    def add_event(self, category: str, event: Event):
        """Add an event to the specified category"""
        if category not in self.events:
            self.events[category] = []
        
        self.events[category].append(event)
        self.metadata['total_events'] += 1
    
    def get_events(self, category: str) -> List[Event]:
        """Get all events for a category"""
        return self.events.get(category, [])
    
    def get_categories(self) -> List[str]:
        """Get all available categories"""
        return list(self.events.keys())
    
    def get_event_count(self, category: str = None) -> int:
        """Get event count for a category or total"""
        if category:
            return len(self.events.get(category, []))
        return self.metadata['total_events']
    
    def remove_empty_categories(self):
        """Remove categories with no events"""
        self.events = {k: v for k, v in self.events.items() if v}
        self.metadata['total_events'] = sum(len(events) for events in self.events.values())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile data to dictionary for serialization"""
        result = {}
        
        # Convert events to dictionaries
        for category, events in self.events.items():
            result[category] = [event.to_dict() for event in events]
        
        # Add metadata
        result['_metadata'] = self.metadata
        
        return result
    
    def to_json(self, indent: int = 4) -> str:
        """Convert profile data to JSON string"""
        self.remove_empty_categories()
        return json.dumps(self.to_dict(), indent=indent, default=self._json_serializer)
    
    def write_to_file(self, filename: str):
        """Write profile data to JSON file"""
        try:
            current_time = datetime.now()
            timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")
            
            # Ensure filename is safe
            base_filename = filename.replace(" ", "_")  # Replace spaces with underscores
            
            # Remove .json extension if present, we'll add it back at the end
            if base_filename.endswith('.json'):
                base_filename = base_filename[:-5]  # Remove '.json'
            
            safe_filename = f"profile_{base_filename}_{timestamp}.json"
            
            with open(safe_filename, "w") as file:
                file.write(self.to_json())
            
            return safe_filename
            
        except Exception as e:
            print(f"[-] Error writing profile to file: {e}")
            # Write debug file
            debug_file = f"{filename}_debug.txt"
            with open(debug_file, "w") as file:
                file.write(str(self.to_dict()))
            return debug_file
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for special objects"""
        if isinstance(obj, Exception):
            return str(obj)
        if hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")
    
    def add_metadata(self, key: str, value: Any):
        """Add metadata to the profile"""
        self.metadata[key] = value
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the profile data"""
        summary = {
            'total_events': self.metadata['total_events'],
            'categories': len(self.events),
            'created_at': self.metadata['created_at'],
            'category_breakdown': {}
        }
        
        for category, events in self.events.items():
            summary['category_breakdown'][category] = len(events)
        
        return summary