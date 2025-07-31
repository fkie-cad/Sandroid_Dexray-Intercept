#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import subprocess
import os
import hashlib


def file_hash(filepath):
    """Compute SHA-256 hash of the file content."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def adb_check_root():
    """Check if ADB has root access"""
    is_magisk_mode = False
    if bool(subprocess.run(['adb', 'shell','su -v'], capture_output=True, text=True).stdout):
        is_magisk_mode = True
        return True, is_magisk_mode

    has_root = bool(subprocess.run(['adb', 'shell','su 0 id -u'], capture_output=True, text=True).stdout)
    return has_root, is_magisk_mode


def get_filename_from_path(path):
    """Extract filename from file path"""
    last_slash_index = path.rfind('/')
    filename = path[last_slash_index + 1:]  # Adding 1 to skip the '/'
    return filename


def has_multidex_ending(s):
    """Check if string has multidex ending pattern"""
    pattern = r"base\.apk!classes\d+\.dex$"
    return bool(re.search(pattern, s))


def is_benign_dump(orig_path):
    """Determine if a dump path is benign or malicious"""
    # This function would contain the logic to classify dumps
    # For now, return a simple heuristic
    if "/system/" in orig_path or "/vendor/" in orig_path:
        return True
    return False


def pull_file_from_device(device_path, local_path, category=None, output_format=None):
    """Pull file from Android device using ADB"""
    try:
        result = subprocess.run(['adb', 'pull', device_path, local_path], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return True
        else:
            print(f"Failed to pull file: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error pulling file from device: {e}")
        return False


def create_unpacking_folder(base_path=None):
    """Create folders for benign and malicious unpacked files"""
    if base_path is None:
        base_path = os.getcwd()
    
    benign_path = os.path.join(base_path, "unpacked", "benign")
    malicious_path = os.path.join(base_path, "unpacked", "malicious")
    
    os.makedirs(benign_path, exist_ok=True)
    os.makedirs(malicious_path, exist_ok=True)
    
    return benign_path, malicious_path


def get_orig_path(profile_content):
    """Extract original path from profile content"""
    # Parse the original location from profile content
    if "orig location" in profile_content:
        return profile_content.split("orig location")[1].strip()
    return ""


def getFilePath(profile_content):
    """Extract file path from profile content"""
    # Parse file path from profile content
    if "dumped" in profile_content:
        lines = profile_content.split('\n')
        for line in lines:
            if line.strip().startswith('/'):
                return line.strip()
    return ""