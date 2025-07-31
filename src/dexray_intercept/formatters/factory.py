#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from .base import BaseFormatter
from .console import ConsoleFormatter
from .json_formatter import JSONFormatter


class FormatterFactory:
    """Factory for creating appropriate formatters based on output format"""
    
    def __init__(self):
        self._formatters = {}
        self._register_default_formatters()
    
    def _register_default_formatters(self):
        """Register default formatters"""
        self._formatters["CMD"] = ConsoleFormatter()
        self._formatters["JSON"] = JSONFormatter()
    
    def get_formatter(self, output_format: str, **kwargs) -> Optional[BaseFormatter]:
        """Get appropriate formatter for the given output format"""
        if output_format == "CMD":
            verbose_mode = kwargs.get('verbose_mode', False)
            return ConsoleFormatter(verbose_mode=verbose_mode)
        elif output_format == "JSON":
            indent = kwargs.get('indent', 4)
            return JSONFormatter(indent=indent)
        else:
            return self._formatters.get(output_format)
    
    def register_formatter(self, output_format: str, formatter: BaseFormatter):
        """Register a custom formatter for an output format"""
        self._formatters[output_format] = formatter
    
    def get_supported_formats(self):
        """Get list of supported output formats"""
        return list(self._formatters.keys())


# Global factory instance
formatter_factory = FormatterFactory()