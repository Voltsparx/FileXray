#!/usr/bin/env python3
"""
FileXray - Advanced Multimedia Forensic Analysis Tool
Author: Voltsparx
Contact: voltsparx@gmail.com
Version: 4.0 (Refactored for Modularity and Robust ID)
"""

import os
import sys
import json
import hashlib
import struct
import binascii
import time
import re
import zipfile
import tarfile
import gzip
import base64
import quopri
import math
from datetime import datetime
from pathlib import Path
import platform
import subprocess
import email
import email.policy
from urllib.parse import urlparse, unquote
import xml.etree.ElementTree as ET
import csv
import sqlite3
import logging
import shutil
import argparse

# --- Configuration & Logging ---
# Setup logging
logging.basicConfig(filename='filexray.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Color codes for attractive interface
class Colors:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Dictionary to track module availability
modules_status = {}

def try_import(module_name, import_statement):
    """Dynamically attempts to import optional modules."""
    try:
        exec(import_statement, globals())
        modules_status[module_name] = True
        return True
    except ImportError:
        modules_status[module_name] = False
        return False
    except Exception as e:
        logging.error(f"Error loading module {module_name}: {e}")
        modules_status[module_name] = f"Error: {e}"
        return False

# Attempt to load optional libraries
try_import('Pillow (PIL)', 'from PIL import Image')
try_import('pdfminer.six', 'from pdfminer.high_level import extract_text_to_fp, extract_metadata')
try_import('oletools', 'from olefile import OleFileIO')

# Also try guarded imports so static analyzers (e.g., Pylance) see the names
try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None  # type: ignore

try:
    from pdfminer.pdfdocument import PDFDocument  # type: ignore
    from pdfminer.pdfparser import PDFParser  # type: ignore
except Exception:
    PDFDocument = None  # type: ignore
    PDFParser = None  # type: ignore

# --- File Identification and Handler Mapping ---
# Priority 1: Magic Numbers (File Signatures)
MAGIC_NUMBERS = {
    b'\xff\xd8\xff': 'IMAGE_JPEG',
    b'\x89PNG\r\n\x1a\n': 'IMAGE_PNG',
    b'GIF87a': 'IMAGE_GIF',
    b'GIF89a': 'IMAGE_GIF',
    b'BM': 'IMAGE_BMP',
    b'PK\x03\x04': 'ARCHIVE_ZIP', # Includes .zip, .docx, .xlsx, .jar
    b'\x1f\x8b': 'ARCHIVE_GZ',
    b'ustar\x0000': 'ARCHIVE_TAR',
    b'%PDF-': 'DOCUMENT_PDF',
    b'OggS': 'MEDIA_OGG',
    b'\x49\x44\x33': 'MEDIA_MP3',
    b'MSCF': 'ARCHIVE_CAB',
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'DOCUMENT_OLE' # Word, Excel, PPT (old format)
}

# Priority 2: File Extensions (Fallback)
EXTENSION_MAPPING = {
    # Images
    ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico'): 'IMAGE_OTHER',
    # Archives
    ('.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz'): 'ARCHIVE_OTHER',
    # Documents/Data
    ('.pdf',): 'DOCUMENT_PDF',
    ('.doc', '.xls', '.ppt'): 'DOCUMENT_OLE', # Old formats
    ('.docx', '.xlsx', '.pptx'): 'ARCHIVE_ZIP', # New formats are ZIP archives
    ('.txt', '.log', '.csv'): 'TEXT_PLAIN',
    ('.html', '.xml', '.json', '.yaml', '.yml', '.js', '.py', '.sh'): 'TEXT_CODE',
    ('.db', '.sqlite', '.sqlite3'): 'DATA_SQLITE',
    # Media
    ('.mp3', '.wav', '.mp4', '.avi', '.mov'): 'MEDIA_OTHER',
    # Other
    ('.eml', '.msg'): 'EMAIL_MESSAGE',
}

# --- Utility Class for Core Analysis Functions ---

class FileProcessor:
    """Contains all core analysis logic and handles file-type-specific processing."""
    
    def __init__(self):
        self.output = {}
        self.chunk_size = 65536 # 64KB for reading

    def print_result_section(self, title, data):
        """Prints a section of the analysis results in a standardized format."""
        print(f"\n{Colors.BLUE}{Colors.BOLD}--- {title} ---{Colors.END}")
        if not data:
            print(f"{Colors.YELLOW}[i] No data extracted.{Colors.END}")
            return
            
        if isinstance(data, dict):
            # Print dictionaries as key-value pairs
            for key, value in data.items():
                # Format long values for better readability
                display_value = str(value)
                if len(display_value) > 100:
                    display_value = display_value[:97] + "..."
                
                print(f"  {Colors.CYAN}{key:<20}:{Colors.END} {display_value}")
        elif isinstance(data, list):
            # Print lists as numbered items (for strings/urls/etc)
            for i, item in enumerate(data, 1):
                print(f"  {Colors.CYAN}[{i}]{Colors.END} {item}")
        else:
            # Print raw strings/other types
            print(f"  {data}")

    def identify_file_type(self, file_path):
        """Identifies file type primarily using magic numbers, falling back to extension."""
        
        # 1. Check Magic Numbers
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                for magic, file_type in MAGIC_NUMBERS.items():
                    if header.startswith(magic):
                        return file_type
        except IOError as e:
            logging.error(f"Error reading header for {file_path}: {e}")
            return 'ERROR'
        
        # 2. Check File Extension
        file_extension = Path(file_path).suffix.lower()
        if not file_extension:
            return 'UNKNOWN'
            
        for extensions, file_type in EXTENSION_MAPPING.items():
            if file_extension in extensions:
                return file_type
                
        return 'UNKNOWN'

    def read_file_in_chunks(self, file_path):
        """Generator to read a file in chunks for efficient processing."""
        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(self.chunk_size)
                    if not data:
                        break
                    yield data
        except IOError as e:
            logging.error(f"Error reading file {file_path}: {e}")
            raise

    def calculate_hash(self, file_path, hash_alg='sha256'):
        """Calculates cryptographic hashes (SHA256, MD5) of the file."""
        hasher = hashlib.new(hash_alg)
        try:
            for chunk in self.read_file_in_chunks(file_path):
                hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return f"Error calculating {hash_alg}"

    def calculate_entropy(self, file_path):
        """Calculates the Shannon entropy of the file contents."""
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return 0.0
            
        frequency = {}
        try:
            for chunk in self.read_file_in_chunks(file_path):
                for byte in chunk:
                    frequency[byte] = frequency.get(byte, 0) + 1
        except Exception:
            return "Error calculating entropy"

        entropy = 0.0
        for count in frequency.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)
            
        return round(entropy, 4)

    def extract_strings(self, file_path, min_len=4):
        """Extracts printable ASCII strings from binary data."""
        strings = []
        string_pattern = re.compile(b'[ -~]{%d,}' % min_len)
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                for match in string_pattern.finditer(data):
                    # Decode using utf-8 with replacement for invalid bytes so we retain readable text
                    strings.append(match.group(0).decode('utf-8', errors='replace'))
            return strings
        except Exception:
            return ["Error extracting strings"]

    # --- File-Type Specific Handlers ---

    def analyze_image(self, file_path):
        """Extracts image-specific metadata using Pillow and optionally ExifTool."""
        results = {}
        
        # 1. Pillow (PIL) for basic dimensions/format
        if modules_status.get('Pillow (PIL)'):
            try:
                with Image.open(file_path) as img:
                    results['Dimensions'] = f"{img.width}x{img.height}"
                    results['Image Format'] = img.format
                    results['Color Mode'] = img.mode
            except Exception as e:
                results['Pillow Error'] = str(e)

        # 2. ExifTool (via subprocess)
        # Prefer shutil.which to find exiftool in PATH
        exiftool_path = shutil.which('exiftool')
        if not exiftool_path and platform.system() == 'Windows':
            exiftool_path = shutil.which('exiftool.exe')

        if exiftool_path:
            try:
                cmd = [exiftool_path, '-j', str(file_path)]
                process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
                exif_data = json.loads(process.stdout)[0]
                exclude_keys = ['SourceFile', 'Directory', 'FileName', 'FilePermissions']
                exif_results = {k: v for k, v in exif_data.items() if k not in exclude_keys}
                results['ExifTool Metadata'] = exif_results
            except Exception as e:
                results['ExifTool Error'] = f"Error processing ExifTool output: {e}"
        else:
            results['ExifTool Status'] = "ExifTool not found. Install ExifTool and ensure it's in PATH for deeper metadata."

        return results

    def analyze_pdf(self, file_path):
        """Extracts PDF metadata using pdfminer.six."""
        results = {}
        if modules_status.get('pdfminer.six'):
            try:
                # Use guarded top-level imports to satisfy static analyzers
                if PDFDocument is None or PDFParser is None:
                    raise ImportError("pdfminer.six is not available in the environment")

                with open(file_path, 'rb') as fp:
                    parser = PDFParser(fp)
                    doc = PDFDocument(parser)

                    if getattr(doc, 'info', None):
                        info = doc.info[0]
                        # Decode common metadata fields
                        for key, value in info.items():
                            if isinstance(value, bytes):
                                try:
                                    value = value.decode('utf-8', 'ignore')
                                except Exception:
                                    pass
                            results[str(key).capitalize()] = value
                    
            except Exception as e:
                results['PDFMiner Error'] = str(e)
        else:
            results['Note'] = "Install pdfminer.six for detailed PDF analysis."
            
        return results

    def analyze_archive(self, file_path, file_type):
        """Analyzes content structure of ZIP, GZ, and TAR archives."""
        results = {'Archive Type': file_type}
        
        try:
            if file_type.startswith('ARCHIVE_ZIP'):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    results['File Count'] = len(zf.namelist())
                    results['Internal Files'] = zf.namelist()[:10] # Show first 10
                    if len(zf.namelist()) > 10:
                        results['Internal Files (truncated)'] = f"Showing 10 of {results['File Count']}"
            elif file_type == 'ARCHIVE_GZ':
                with gzip.open(file_path, 'rb') as gf:
                    # Gzip doesn't have a file list, just try to read header/comment
                    results['Comment'] = gf.comment if hasattr(gf, 'comment') else 'N/A'
                    results['Filename (internal)'] = gf.name.decode('utf-8') if hasattr(gf, 'name') and gf.name else 'N/A'
            elif file_type.startswith('ARCHIVE_TAR'):
                with tarfile.open(file_path, 'r') as tf:
                    members = tf.getnames()
                    results['File Count'] = len(members)
                    results['Internal Files'] = members[:10]
                    if len(members) > 10:
                        results['Internal Files (truncated)'] = f"Showing 10 of {results['File Count']}"
        except Exception as e:
            results['Archive Error'] = str(e)
            
        return results

    def analyze_email(self, file_path):
        """Parses EML/MSG files to extract headers, body, and attachments."""
        results = {}
        try:
            with open(file_path, 'rb') as fp:
                msg = email.message_from_binary_file(fp, policy=email.policy.default)
                
                results['Headers'] = {k: msg.get(k) for k in ['From', 'To', 'Subject', 'Date', 'Message-ID']}
                results['Headers'].update({'X-Mailer': msg.get('X-Mailer'), 'MIME-Version': msg.get('MIME-Version')})

                # Check for attachments and body parts
                attachments = []
                body = []
                
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = part.get_content_disposition()
                    
                    if content_disposition == 'attachment':
                        attachments.append(f"{part.get_filename()} ({part.get_content_type()}, {len(part.get_payload(decode=True))} bytes)")
                    elif part.is_multipart() is False:
                        # Extract non-attachment body parts (text/plain or text/html)
                        if content_type.startswith('text/'):
                            payload = part.get_payload(decode=True).decode('utf-8', 'ignore')
                            # Truncate large bodies
                            body_text = payload[:500] + '...' if len(payload) > 500 else payload
                            body.append(f"({content_type}): {body_text.strip()}")
                
                results['Body Content'] = body
                results['Attachments'] = attachments
                
        except Exception as e:
            results['Email Error'] = str(e)
        return results

    def analyze_binary_data(self, file_path):
        """Generic analysis for unhandled or raw binary files (high entropy/unknown)."""
        results = {}
        
        # Check for Base64/Quoted-Printable within strings
        strings = self.extract_strings(file_path)
        base64_strings = [s for s in strings if re.match(r'^[A-Za-z0-9+/=]{100,}$', s)]
        
        results['Potential Base64 Strings'] = base64_strings[:5]
        if len(base64_strings) > 5:
            results['Base64 Strings (truncated)'] = f"Found {len(base64_strings)} potential Base64 strings."

        return results

    def process_file_analysis(self, file_path, file_type):
        """Performs file-type specific analysis based on identified type."""
        
        # Dispatch to specific handler based on file_type
        if file_type.startswith('IMAGE_'):
            self.print_result_section("IMAGE METADATA ANALYSIS", self.analyze_image(file_path))
        elif file_type == 'DOCUMENT_PDF':
            self.print_result_section("PDF METADATA ANALYSIS", self.analyze_pdf(file_path))
        elif file_type.startswith('ARCHIVE_'):
            self.print_result_section("ARCHIVE CONTENT ANALYSIS", self.analyze_archive(file_path, file_type))
        elif file_type == 'EMAIL_MESSAGE':
            self.print_result_section("EMAIL MESSAGE ANALYSIS", self.analyze_email(file_path))
        elif file_type == 'DATA_SQLITE':
             # Note: SQLite analysis requires user to know table/column names, hence is complex.
             # Placeholder for complex analysis
             self.print_result_section("SQLITE/DB ANALYSIS", {"Note": "Advanced DB analysis requires table/query input. Running generic string extraction."})
        elif file_type in ['UNKNOWN', 'ERROR']:
            self.print_result_section("BINARY/UNKNOWN ANALYSIS", self.analyze_binary_data(file_path))
        
        # Always run string extraction for all files except plain text/code
        if not file_type.startswith('TEXT_'):
            extracted_strings = self.extract_strings(file_path)
            self.print_result_section(f"EXTRACTED STRINGS ({len(extracted_strings)} total, showing first 20)", extracted_strings[:20])

# --- Main Application Class ---

class FileXray:
    """The main user interface and controller for the FileXray tool."""

    def __init__(self):
        self.processor = FileProcessor()

    def print_banner(self):
        """Prints the application banner with 3D ASCII art and credit."""
        # Large ASCII art banner for FileXray (impressive, CLI-friendly)
        ascii_art = [
            rf"{Colors.BLUE}{Colors.BOLD}  ███████████  ███  ████           █████ █████                                {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD} ░░███░░░░░░█ ░░░  ░░███          ░░███ ░░███                                 {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}  ░███   █ ░  ████  ░███   ██████  ░░███ ███   ████████   ██████   █████ ████ {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}  ░███████   ░░███  ░███  ███░░███  ░░█████   ░░███░░███ ░░░░░███ ░░███ ░███  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}  ░███░░░█    ░███  ░███ ░███████    ███░███   ░███ ░░░   ███████  ░███ ░███  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}  ░███  ░     ░███  ░███ ░███░░░    ███ ░░███  ░███      ███░░███  ░███ ░███  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}  █████       █████ █████░░██████  █████ █████ █████    ░░████████ ░░███████  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD} ░░░░░       ░░░░░ ░░░░░  ░░░░░░  ░░░░░ ░░░░░ ░░░░░      ░░░░░░░░   ░░░░░███  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}                                                                    ███ ░███  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}                                                                    ░░██████  {Colors.END}",
            rf"{Colors.BLUE}{Colors.BOLD}                                                                     ░░░░░░   {Colors.END}",
            rf"{Colors.CYAN}{Colors.BOLD}=============================================================={Colors.END}",
            rf"{Colors.MAGENTA}{Colors.BOLD}          Advanced Multimedia Forensic Analysis Tool{Colors.END}",
            rf"{Colors.CYAN}{Colors.BOLD}=============================================================={Colors.END}",
        ]

        for line in ascii_art:
            print(line)

        # Print Author and Contact details
        print(f"{Colors.YELLOW}Author: Voltsparx    Contact: voltsparx@gmail.com{Colors.END}")


    def show_supported_formats(self):
        """Displays all supported file formats and analysis types."""
        print(f"\n{Colors.BLUE}{Colors.BOLD}--- Supported File Analysis Types ---{Colors.END}")
        print(f"{Colors.CYAN}{'Type':<20}{'Extensions/Signature':<40}{'Analysis Method'}{Colors.END}")
        print("-" * 80)
        
        # Display magic number primary types
        for sig, ftype in MAGIC_NUMBERS.items():
            sig_str = binascii.hexlify(sig).decode('utf-8')[:10] + "..."
            print(f"{Colors.WHITE}{ftype:<20}{sig_str:<40}{'Magic Number Check'}{Colors.END}")
            
        # Display extension fallbacks
        for extensions, ftype in EXTENSION_MAPPING.items():
            ext_str = ", ".join(extensions)[:37] + ("..." if len(", ".join(extensions)) > 37 else "")
            print(f"{Colors.WHITE}{ftype:<20}{ext_str:<40}{'Extension Check'}{Colors.END}")

    def show_module_status(self):
        """Displays the status of optional Python dependencies."""
        print(f"\n{Colors.BLUE}{Colors.BOLD}--- Optional Module Status ---{Colors.END}")
        for module, status in modules_status.items():
            if status is True:
                status_color = Colors.GREEN
                status_text = "INSTALLED"
            elif status is False:
                status_color = Colors.RED
                status_text = "MISSING"
            else:
                status_color = Colors.YELLOW
                status_text = "ERROR"
            
            print(f"  {Colors.CYAN}{module:<20}:{Colors.END} {status_color}{status_text}{Colors.END}")
        print(f"\n{Colors.YELLOW}[i] Missing modules (e.g., PIL) limit specific analyses (e.g., image dimensions).{Colors.END}")

    def process_file(self, file_path):
        """Performs a full analysis on a single file."""
        file_path = Path(file_path).resolve()
        
        if not file_path.exists():
            print(f"{Colors.RED}[-] Error: File not found at {file_path}{Colors.END}")
            return
            
        print(f"\n{Colors.GREEN}{Colors.BOLD}===================================================={Colors.END}")
        print(f"{Colors.GREEN}[+] Analyzing File: {file_path.name}{Colors.END}")
        print(f"{Colors.GREEN}[+] Full Path: {file_path}{Colors.END}")
        print(f"{Colors.GREEN}===================================================={Colors.END}")

        # 1. Basic File Information
        stats = file_path.stat()
        file_size = stats.st_size
        last_modified = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        
        basic_info = {
            'Size (Bytes)': f"{file_size:,}",
            'Last Modified': last_modified,
            'Permissions': oct(stats.st_mode)[-3:],
            'File Extension': file_path.suffix.lower() if file_path.suffix else 'N/A'
        }
        self.processor.print_result_section("BASIC FILE INFORMATION", basic_info)

        # 2. File Identification
        identified_type = self.processor.identify_file_type(file_path)
        self.processor.print_result_section("FILE TYPE IDENTIFICATION", 
            f"Identified Type: {Colors.MAGENTA}{identified_type}{Colors.END}"
        )

        # 3. Cryptographic and Statistical Analysis
        crypto_stats = {
            'SHA256 Hash': self.processor.calculate_hash(file_path, 'sha256'),
            'MD5 Hash': self.processor.calculate_hash(file_path, 'md5'),
            'Entropy (bits)': self.processor.calculate_entropy(file_path)
        }
        self.processor.print_result_section("CRYPTOGRAPHIC & STATISTICAL ANALYSIS", crypto_stats)

        # 4. File-Type Specific Processing
        self.processor.process_file_analysis(file_path, identified_type)

    def process_directory(self, dir_path, recursive=False):
        """Recursively scans a directory and analyzes all contained files."""
        dir_path = Path(dir_path).resolve()
        
        if not dir_path.is_dir():
            print(f"{Colors.RED}[-] Error: Directory not found at {dir_path}{Colors.END}")
            return

        print(f"\n{Colors.GREEN}{Colors.BOLD}===================================================={Colors.END}")
        print(f"{Colors.GREEN}[+] Directory Scan: {dir_path.name}{Colors.END}")
        print(f"{Colors.GREEN}[+] Recursive: {'Yes' if recursive else 'No'}{Colors.END}")
        print(f"{Colors.GREEN}===================================================={Colors.END}")
        
        file_count = 0
        
        for root, _, files in os.walk(dir_path):
            for filename in files:
                file_path = Path(root) / filename
                self.process_file(file_path)
                file_count += 1
                
            if not recursive:
                break # Stop after the top directory if not recursive
                
        if file_count == 0:
            print(f"{Colors.YELLOW}[i] No files found in directory {dir_path}{Colors.END}")

    def run(self):
        """The main application loop for the command-line interface."""
        self.print_banner()
        
        while True:
            print(f"\n{Colors.WHITE}{Colors.BOLD}--- Main Menu ---{Colors.END}")
            print(f"{Colors.GREEN}1.{Colors.END} Analyze Single File")
            print(f"{Colors.GREEN}2.{Colors.END} Analyze Directory")
            print(f"{Colors.GREEN}3.{Colors.END} Show Supported Formats")
            print(f"{Colors.GREEN}4.{Colors.END} Show Module Status")
            print(f"{Colors.GREEN}5.{Colors.END} Exit")
            
            choice = input(f"{Colors.MAGENTA}[fxr]:>> {Colors.END}").strip()
            
            if choice == '1':
                file_path = input(f"{Colors.CYAN}[+] Enter file path: {Colors.END}").strip()
                if file_path:
                    try:
                        self.process_file(file_path)
                    except Exception as e:
                        print(f"{Colors.RED}[-] An error during file analysis: {str(e)}{Colors.END}")
                        logging.error(f"File analysis failure: {e}")
                else:
                    print(f"{Colors.RED}[-] No file path provided{Colors.END}")
            elif choice == '2':
                dir_path = input(f"{Colors.CYAN}[+] Enter directory path: {Colors.END}").strip()
                rec = input(f"{Colors.YELLOW}[?] Recursive scan? (y/n): {Colors.END}").strip().lower()
                try:
                    self.process_directory(dir_path, recursive=(rec == 'y'))
                except Exception as e:
                    print(f"{Colors.RED}[-] An error during directory analysis: {str(e)}{Colors.END}")
                    logging.error(f"Directory analysis failure: {e}")
            elif choice == '3':
                self.show_supported_formats()
            elif choice == '4':
                self.show_module_status()
            elif choice == '5':
                print(f"{Colors.GREEN}[+] Thank you for using FileXray!{Colors.END}")
                break
            else:
                print(f"{Colors.RED}[-] Invalid choice. Please select 1-5.{Colors.END}")
                
            input(f"\n{Colors.YELLOW}[*] Press Enter to continue...{Colors.END}")

def main():
    try:
        parser = argparse.ArgumentParser(prog='filexray', description='FileXray - Advanced Multimedia Forensic Analysis Tool')
        parser.add_argument('-f', '--file', help='Analyze a single file')
        parser.add_argument('-d', '--directory', help='Analyze a directory')
        parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan directories')
        parser.add_argument('--show-modules', action='store_true', help='Show optional module status and exit')
        parser.add_argument('--list-formats', action='store_true', help='List supported formats and exit')
        args = parser.parse_args()

        tool = FileXray()

        # Non-interactive modes
        if args.show_modules:
            tool.show_module_status()
            return

        if args.list_formats:
            tool.show_supported_formats()
            return

        if args.file:
            tool.process_file(args.file)
            return

        if args.directory:
            tool.process_directory(args.directory, recursive=args.recursive)
            return

        # Default to interactive
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operation cancelled by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] A critical error occurred: {str(e)}{Colors.END}")
        logging.critical(f"Critical application error: {e}", exc_info=True)

if __name__ == "__main__":
    main()
