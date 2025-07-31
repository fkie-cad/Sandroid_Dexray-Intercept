#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import cxxfilt
import re

# Constants for the mode mapping of AES
# more at: https://docs.oracle.com/javase%2F8%2Fdocs%2Fapi%2F%2F/constant-values.html#javax.crypto.Cipher.ENCRYPT_MODE
MODE_MAPPING = {
    1: "ENCRYPT_MODE",  # PUBLIC_KEY
    2: "DECRYPT_MODE",  # PRIVATE_KEY
    3: "WRAP_MODE",     # SECRET_KEY
    4: "UNWRAP_MODE"
}


def demangle(symbol: str) -> str:
    """Demangle C++ symbol names"""
    try:
        demangled = cxxfilt.demangle(symbol)
        # Use regex to extract the function name from the demangled string
        function_name_match = re.search(r'(\w+::)*\w+', demangled)
        if function_name_match:
            return function_name_match.group(0)
        else:
            return "Unknown function name"
    except Exception as e:
        print(f"Error demangling symbol {symbol}: {e}")
        return "Demangling error"


def get_demangled_method_for_dex_unpacking(mangled_name):
    """Get demangled method name for DEX unpacking"""
    type_parts = mangled_name.split("::")
    lib_name = type_parts[0]                
    demangled_fct_name = demangle(type_parts[1])
    return lib_name + "::" + demangled_fct_name


def get_mode_description(mode_num):
    """Get AES mode description from mode number"""
    mode_name = MODE_MAPPING.get(mode_num, f"UNKNOWN_MODE_{mode_num}")
    return f"{mode_name} ({mode_num})"