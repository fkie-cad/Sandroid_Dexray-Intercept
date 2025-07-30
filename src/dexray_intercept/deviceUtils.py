#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import subprocess
import os
import shutil
import hashlib
import colorama
# colorama imported for init only
from .resultManager import handle_output

# some global definitions
colorama.init(autoreset=True) 
is_magisk_mode = False



def file_hash(filepath):
    """Compute SHA-256 hash of the file content."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def adb_check_root():
    global is_magisk_mode
    if bool(subprocess.run(['adb', 'shell','su -v'], capture_output=True, text=True).stdout):
        is_magisk_mode = True
        return True

    return bool(subprocess.run(['adb', 'shell','su 0 id -u'], capture_output=True, text=True).stdout)


def get_filename_from_path(path):
    # Find the last '/' and extract everything after it
    last_slash_index = path.rfind('/')
    filename = path[last_slash_index + 1:]  # Adding 1 to skip the '/'

    return filename


def has_multidex_ending(s):
    # Regular expression that matches 'base.apk!classes' followed by one or more digits (\d+), and ends with '.dex'
    pattern = r"base\.apk!classes\d+\.dex$"

    # Use re.search() to find the pattern at the end of the string
    if re.search(pattern, s):
        return True
    else:
        return False

def pull_file_from_device(remote_path, local_path, category ,output_format):
    """
    Pulls a file from a rooted Android device using ADB and root access.

    Args:
    remote_path (str): The path of the file on the Android device.
    local_path (str): The path where the file will be saved locally.
    """
    
    if is_magisk_mode:
        command = f"adb shell su -c cat {remote_path}"
    else:
        command = f"adb shell su 0 cat {remote_path}"

    with open(local_path, 'wb') as local_file:
        process = subprocess.Popen(command, shell=True, stdout=local_file, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            handle_output("[-] Failed to pull the file:","error","CMD")
            handle_output(stderr.decode(),"error","CMD")
        else:
            handle_output("File successfully pulled from device",category ,output_format)


def getFilePath(dumpString):
    match = re.search(r'@\s+([^\n]+)\n', dumpString)  # get the file path from string
    if match:
        file_path = match.group(1)
        
        # remove the :-character if the Path information starts with it
        if file_path.startswith(":"):
            file_path = file_path[1:]

        return file_path
    else:
        handle_output("No file path found.","error","CMD")


def get_orig_path(dumpString):
    match = re.search(r"/[^\s]+", dumpString)
    if match:
        return match.group(0)  # Return the matched path
    return ""  # Return empty string if no path is found


def create_unpacking_folder(base_path=None):
    """
    Creates a directory named 'unpacked_dumps' in the specified base path (or in the current working directory by default).
    This will be the folder  where everything which looks like unpacking will be dumped to.
    Inside 'unpacked_dumps', it also creates two subdirectories named 'benign' and 'malicious'.
    
    Args:
    base_path (str, optional): The path where the 'unpacked_dumps' directory will be created. Defaults to None, which uses the current working directory.
    """
    # Set the base path to the current working directory if none is provided
    if base_path is None:
        base_path = os.getcwd()
    
    # Construct the path to the 'unpacked_dumps' directory
    unpacked_dumps_path = os.path.join(base_path, 'unpacked_dumps')
    
    # Create the 'unpacked_dumps' directory if it does not exist
    if not os.path.exists(unpacked_dumps_path):
        os.makedirs(unpacked_dumps_path)
        #handle_output(f"Created directory: {unpacked_dumps_path}", category ,output_format)
    
    # Define the paths for the 'benign' and 'malicious' subdirectories
    benign_path = os.path.join(unpacked_dumps_path, 'benign')
    malicious_path = os.path.join(unpacked_dumps_path, 'malicious')
    
    # Create the 'benign' subdirectory if it does not exist
    if not os.path.exists(benign_path):
        os.makedirs(benign_path)
        #handle_output(f"Created subdirectory: {benign_path}", category ,output_format)
    
    # Create the 'malicious' subdirectory if it does not exist
    if not os.path.exists(malicious_path):
        os.makedirs(malicious_path)
        #handle_output(f"Created subdirectory: {malicious_path}", category ,output_format)
    
    return (os.path.abspath(benign_path), os.path.abspath(malicious_path))


def rename_dumped_file(orig_location, dumped_location):
    # Extract the original filename from the original location
    original_filename = os.path.basename(orig_location)
    
    # Get the directory of the dumped file
    dumped_dir = os.path.dirname(dumped_location)
    
    # Create the new path for the dumped file with the original filename
    new_dumped_location = os.path.join(dumped_dir, original_filename)
    
    # Rename the dumped file to its original name
    shutil.move(dumped_location, new_dumped_location)
    
    return new_dumped_location



def move_file(source: str, destination: str, category ,output_format):
    """
    Moves a file from the source path to the destination path.
    
    Args:
    source (str): The path to the file to be moved.
    destination (str): The path where the file should be moved to.
    
    Raises:
    FileNotFoundError: If the source file does not exist.
    Exception: For issues like permission errors or destination path issues.
    """
    # Check if the source file exists
    if not os.path.isfile(source):
        raise FileNotFoundError(f"No file found at {source}")
    
    # Ensure the destination directory exists, create if not
    destination_dir = os.path.dirname(destination)
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)
        handle_output(f"Created directory: {destination_dir}", category ,output_format)
    
    # Move the file
    try:
        shutil.move(source, destination)
        return destination
    except Exception as e:
        handle_output(f"Error moving file from {source} to {destination}: {e}","error","CMD")
        raise


def is_benign_dump(unpacked_file):
    """
    Determines if the specified unpacked_file is typically benign.

    Args:
    unpacked_file (str): The name or identifier of the file to check.

    Returns:
    bool: True if the file is considered benign, False otherwise.
    """

    benign_system_path = "/system/framework/"
    if unpacked_file.startswith(benign_system_path):
        return True

    # this is the main dex file of the APK we just installed, therefore we considers this as begnin although it don't have to be benign
    if unpacked_file.endswith("==/base.apk") or has_multidex_ending(unpacked_file):
        return True

    # Define a set of strings that are known to be benign
    benign_signatures = {
        'base.apk',
        # Add more benign file signatures as needed
    }
    
    # Return True if the unpacked_file is in the benign_signatures set
    return unpacked_file in benign_signatures
