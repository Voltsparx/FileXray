#!/usr/bin/env python3
"""
FileXray - Advanced Multimedia Forensic Analysis Tool
Author: Voltsparx
Contact: voltsparx@gmail.com
Version: 3.5
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

# Setup logging
logging.basicConfig(filename='filexray.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

modules_status = {}

def try_import(module_name, import_statement):
    try:
        exec(import_statement, globals())
        modules_status[module_name] = True
        return True
    except ImportError:
        modules_status[module_name] = False
        return False

PIL_AVAILABLE = try_import('PIL', 'from PIL import Image, ImageFilter, ImageOps, ImageCms, ImagePalette; from PIL.ExifTags import TAGS, GPSTAGS')
CV2_AVAILABLE = try_import('OpenCV', 'import cv2; import numpy as np')
PDF_AVAILABLE = try_import('PDF', 'import PyPDF2; import pdfplumber')
AUDIO_AVAILABLE = try_import('Audio', 'from pydub import AudioSegment; import mutagen')
GEODATA_AVAILABLE = try_import('Geolocation', 'from geopy.geocoders import Nominatim')
OLE_AVAILABLE = try_import('OLE', 'import olefile')
BS4_AVAILABLE = try_import('BeautifulSoup', 'from bs4 import BeautifulSoup')
YARA_AVAILABLE = try_import('YARA', 'import yara')
TESSERACT_AVAILABLE = try_import('Tesseract', 'import pytesseract')
EXIFREAD_AVAILABLE = try_import('ExifRead', 'import exifread')
HACHOIR_AVAILABLE = try_import('Hachoir', 'import hachoir.parser; import hachoir.metadata; import hachoir.core')
FONTTOOLS_AVAILABLE = try_import('FontTools', 'import fontTools.ttLib')
OPENPYXL_AVAILABLE = try_import('OpenPyXL', 'import openpyxl')
DOCX_AVAILABLE = try_import('Docx', 'import docx')
PPTX_AVAILABLE = try_import('Pptx', 'import pptx')
WINREG_AVAILABLE = try_import('WinReg', 'import winreg')
PARAMIKO_AVAILABLE = try_import('Paramiko', 'import paramiko')

class FileXray:
    def __init__(self):
        self.author = "Voltsparx"
        self.contact = "voltsparx@gmail.com"
        self.tool_name = "FileXray"
        self.version = "3.5"
        self.repository = "https://github.com/voltsparx/FileXray"
        self.output_base = "fxr_extractions"
        self.directories = {
            'images': 'images',
            'videos': 'videos', 
            'documents': 'documents',
            'audio': 'audio',
            'archives': 'archives',
            'executables': 'executables',
            'scripts': 'scripts',
            'database': 'database',
            'emails': 'emails',
            'fonts': 'fonts',
            'reports': 'reports'
        }
        self.supported_formats = {
            'images': ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp', '.webp', '.heic', '.gif', '.ico', '.psd', '.svg', '.raw', '.cr2', '.nef'],
            'videos': ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.3gp', '.mpeg', '.mpg'],
            'documents': ['.pdf', '.docx', '.doc', '.txt', '.rtf', '.odt', '.pages', '.xlsx', '.xls', '.csv', '.pptx', '.ppt', '.odp'],
            'audio': ['.mp3', '.wav', '.flac', '.m4a', '.aac', '.ogg', '.wma', '.aiff'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'],
            'executables': ['.exe', '.dll', '.msi', '.bin', '.app', '.deb', '.rpm'],
            'scripts': ['.py', '.js', '.html', '.css', '.php', '.java', '.cpp', '.c', '.h', '.sh', '.bat', '.ps1'],
            'database': ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb'],
            'emails': ['.eml', '.msg', '.pst'],
            'fonts': ['.ttf', '.otf', '.woff', '.woff2'],
            'system': ['.reg', '.log', '.cfg', '.ini', '.conf', '.xml', '.json', '.yaml', '.yml']
        }

    def show_banner(self):
        banner = f"""
{Colors.BLUE}{Colors.BOLD}
   ______ _ _      __   __                     
  |  ____(_) |     \ \ / /                     
  | |__   _| | ___  \ V /___  _   _ _ __ ___  
  |  __| | | |/ _ \  > < _  \| | | | '_ ` _ \ 
  | |    | | |  __/ / . \ (_) | |_| | | | | | |
  |_|    |_|_|\___|/_/ \_\___/ \__,_|_| |_| |_|
{Colors.END}
{Colors.CYAN}{Colors.BOLD}FileXray - Advanced Multimedia Forensic & OSINT Tool{Colors.END}
{Colors.YELLOW}Version: {self.version} | Author: {self.author} | Contact: {self.contact}{Colors.END}
{Colors.MAGENTA}System: {platform.system()} {platform.release()} | Python: {platform.python_version()}{Colors.END}
{Colors.GREEN}Repository: {self.repository}{Colors.END}
"""
        print(banner)
        self.show_module_status()

    def show_module_status(self):
        print(f"{Colors.CYAN}{Colors.BOLD}[*] Module Status:{Colors.END}")
        print(f"{Colors.WHITE}{'='*60}{Colors.END}")
        for module, status in modules_status.items():
            status_color = Colors.GREEN if status else Colors.RED
            status_text = "LOADED" if status else "MISSING"
            print(f"{Colors.WHITE}[{status_color}{'✓' if status else '✗'}{Colors.WHITE}] {module:<15} : {status_color}{status_text}{Colors.END}")
        print(f"{Colors.WHITE}{'='*60}{Colors.END}\n")

    def create_output_structure(self):
        for dir_type, dir_name in self.directories.items():
            dir_path = os.path.join(self.output_base, dir_name)
            try:
                os.makedirs(dir_path, exist_ok=True)
                if not os.access(dir_path, os.W_OK):
                    print(f"{Colors.RED}[!] Warning: No write permission for '{dir_path}'{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error creating directory '{dir_path}': {e}{Colors.END}")
        print(f"{Colors.GREEN}[+] Output structure ready in '{self.output_base}'{Colors.END}")

    def get_file_type(self, file_path):
        ext = Path(file_path).suffix.lower()
        for file_type, extensions in self.supported_formats.items():
            if ext in extensions:
                return file_type
        return 'unknown'

    def calculate_hashes(self, file_path):
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            hashes = {
                'MD5': hashlib.md5(content).hexdigest(),
                'SHA1': hashlib.sha1(content).hexdigest(),
                'SHA256': hashlib.sha256(content).hexdigest(),
                'SHA512': hashlib.sha512(content).hexdigest(),
                'File Size': f"{os.path.getsize(file_path)} bytes",
                'BLAKE2b': hashlib.blake2b(content).hexdigest()
            }
        except Exception as e:
            hashes['Error'] = f"Hash calculation failed: {str(e)}"
        return hashes

    def extract_file_signature(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(20)
                return {
                    'Hex Signature': header.hex().upper(),
                    'ASCII Representation': ''.join([chr(b) if 32 <= b <= 126 else '.' for b in header]),
                    'File Header': str(header)
                }
        except Exception as e:
            return {"Error": f"Signature extraction failed: {str(e)}"}

    def extract_hidden_data(self, file_path):
        hidden_data = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            hidden_strings = self.extract_hidden_strings(content)
            if hidden_strings:
                hidden_data['Hidden Strings'] = hidden_strings
            base64_data = self.extract_base64(content)
            if base64_data:
                hidden_data['Base64 Encoded Data'] = base64_data
            urls = self.extract_urls(content)
            if urls:
                hidden_data['Hidden URLs'] = urls
            emails = self.extract_emails(content)
            if emails:
                hidden_data['Email Addresses'] = emails
            ips = self.extract_ips(content)
            if ips:
                hidden_data['IP Addresses'] = ips
            credit_cards = self.extract_credit_cards(content)
            if credit_cards:
                hidden_data['Credit Card Patterns'] = credit_cards
            private_keys = self.extract_private_keys(content)
            if private_keys:
                hidden_data['Private Keys'] = private_keys
        except Exception as e:
            hidden_data['Error'] = f"Hidden data extraction failed: {str(e)}"
        return hidden_data

    def extract_hidden_strings(self, content):
        try:
            pattern = b'[\\x20-\\x7E]{4,}'
            strings = re.findall(pattern, content)
            return [s.decode('utf-8', errors='ignore') for s in strings[:50]]
        except:
            return None

    def extract_base64(self, content):
        try:
            pattern = b'[A-Za-z0-9+/]{20,}={0,2}'
            base64_matches = re.findall(pattern, content)
            decoded_data = []
            for match in base64_matches[:10]:
                try:
                    decoded = base64.b64decode(match)
                    if len(decoded) > 0:
                        decoded_data.append({
                            'Encoded': match.decode('utf-8', errors='ignore'),
                            'Decoded': decoded[:100]
                        })
                except:
                    continue
            return decoded_data if decoded_data else None
        except:
            return None

    def extract_urls(self, content):
        try:
            text_content = content.decode('utf-8', errors='ignore')
            pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(pattern, text_content)
            return list(set(urls))[:20]
        except:
            return None

    def extract_emails(self, content):
        try:
            text_content = content.decode('utf-8', errors='ignore')
            pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(pattern, text_content)
            return list(set(emails))[:10]
        except:
            return None

    def extract_ips(self, content):
        try:
            text_content = content.decode('utf-8', errors='ignore')
            pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(pattern, text_content)
            return list(set(ips))[:10]
        except:
            return None

    def extract_credit_cards(self, content):
        try:
            text_content = content.decode('utf-8', errors='ignore')
            pattern = r'\b(?:\d[ -]*?){13,16}\b'
            potential_cards = re.findall(pattern, text_content)
            return potential_cards[:5]
        except:
            return None

    def extract_private_keys(self, content):
        try:
            text_content = content.decode('utf-8', errors='ignore')
            patterns = [
                r'-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END RSA PRIVATE KEY-----',
                r'-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END EC PRIVATE KEY-----'
            ]
            keys = []
            for pattern in patterns:
                matches = re.findall(pattern, text_content)
                keys.extend(matches)
            return keys[:3]
        except:
            return None

    def extract_image_data(self, image_path):
        if not PIL_AVAILABLE:
            return {"Error": "PIL/Pillow not installed"}
        try:
            with Image.open(image_path) as img:
                file_info = {
                    'Filename': os.path.basename(image_path),
                    'File Path': os.path.abspath(image_path),
                    'File Size': f"{os.path.getsize(image_path)} bytes",
                    'Format': img.format,
                    'Dimensions': f"{img.width} x {img.height}",
                    'Color Mode': img.mode,
                    'Color Palette': img.palette if hasattr(img, 'palette') else 'None'
                }
                exif_data = self.extract_exif_data(img)
                gps_data = self.extract_gps_data(exif_data)
                thumbnail_data = self.analyze_thumbnails(img)
                forensics_data = self.image_forensics_analysis(img, image_path)
                hash_data = self.calculate_hashes(image_path)
                signature_data = self.extract_file_signature(image_path)
                hidden_data = self.extract_hidden_data(image_path)
                ocr_data = self.extract_ocr_text(image_path)
                return {
                    'File Information': file_info,
                    'EXIF Metadata': exif_data,
                    'GPS Data': gps_data,
                    'Thumbnail Analysis': thumbnail_data,
                    'Image Forensics': forensics_data,
                    'Hash Values': hash_data,
                    'File Signature': signature_data,
                    'Hidden Data': hidden_data,
                    'OCR Text': ocr_data,
                    'OSINT Links': self.generate_osint_links(image_path, hash_data, gps_data)
                }
        except Exception as e:
            return {"Error": f"Image processing failed: {str(e)}"}

    def extract_exif_data(self, img):
        exif_data = {}
        try:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                for tag_id, value in img._getexif().items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == "GPSInfo":
                        gps_data = {}
                        for gps_tag_id in value:
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_data[gps_tag] = value[gps_tag_id]
                        exif_data[tag] = gps_data
                    else:
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='ignore')
                            except:
                                value = str(value)
                        exif_data[tag] = value
        except Exception as e:
            exif_data["Error"] = f"EXIF extraction failed: {str(e)}"
        return exif_data

    def extract_gps_data(self, exif_data):
        gps_info = {}
        try:
            if "GPSInfo" in exif_data:
                gps_data = exif_data["GPSInfo"]
                gps_coords = self.convert_gps_coordinates(gps_data)
                if gps_coords:
                    gps_info['Coordinates'] = gps_coords
                gps_info['Raw GPS Data'] = gps_data
                if 'Coordinates' in gps_info:
                    coords = gps_info['Coordinates']
                    if 'Latitude' in coords and 'Longitude' in coords:
                        lat, lon = coords['Latitude'], coords['Longitude']
                        gps_info['Map Links'] = {
                            'Google Maps': f"https://maps.google.com/?q={lat},{lon}",
                            'OpenStreetMap': f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}",
                            'Google Earth': f"https://earth.google.com/web/@{lat},{lon}",
                        }
                        address = self.reverse_geocode(lat, lon)
                        if address:
                            gps_info['Approximate Location'] = address
        except Exception as e:
            gps_info['Error'] = f"GPS processing failed: {str(e)}"
        return gps_info

    def convert_gps_coordinates(self, gps_info):
        try:
            gps_latitude = gps_info.get('GPSLatitude')
            gps_latitude_ref = gps_info.get('GPSLatitudeRef', 'N')
            gps_longitude = gps_info.get('GPSLongitude')
            gps_longitude_ref = gps_info.get('GPSLongitudeRef', 'E')
            if gps_latitude and gps_longitude:
                def convert_to_degrees(value):
                    if isinstance(value, tuple) and len(value) == 3:
                        d, m, s = value
                        return d + (m / 60.0) + (s / 3600.0)
                    return value
                lat = convert_to_degrees(gps_latitude)
                lon = convert_to_degrees(gps_longitude)
                if gps_latitude_ref == 'S':
                    lat = -lat
                if gps_longitude_ref == 'W':
                    lon = -lon
                return {
                    "Latitude": round(lat, 6),
                    "Longitude": round(lon, 6),
                    "Latitude Reference": gps_latitude_ref,
                    "Longitude Reference": gps_longitude_ref,
                    "DMS Format": f"{abs(lat)}° {gps_latitude_ref}, {abs(lon)}° {gps_longitude_ref}"
                }
        except Exception as e:
            return f"Coordinate conversion error: {str(e)}"
        return None

    def reverse_geocode(self, lat, lon):
        if not GEODATA_AVAILABLE:
            return None
        try:
            geolocator = Nominatim(user_agent="filexray_tool")
            location = geolocator.reverse(f"{lat}, {lon}", exactly_one=True)
            return location.address if location else None
        except:
            return None

    def analyze_thumbnails(self, img):
        thumbnail_data = {}
        try:
            if hasattr(img, 'thumbnail'):
                thumbnail_data['Has Thumbnail'] = True
                thumbnail_data['Thumbnail Size'] = img.thumbnail.size if img.thumbnail else 'None'
            else:
                thumbnail_data['Has Thumbnail'] = False
        except Exception as e:
            thumbnail_data['Error'] = f"Thumbnail analysis failed: {str(e)}"
        return thumbnail_data

    def image_forensics_analysis(self, img, image_path):
        forensics = {}
        try:
            forensics['Format Consistency'] = self.check_format_consistency(image_path)
            forensics['File Signature'] = self.check_file_signature(image_path)
            if img.mode in ['L', 'RGB', 'RGBA']:
                stats = img.getextrema()
                forensics['Pixel Range'] = stats
        except Exception as e:
            forensics['Error'] = f"Forensics analysis failed: {str(e)}"
        return forensics

    def check_format_consistency(self, file_path):
        try:
            with Image.open(file_path) as img:
                actual_format = img.format
                extension = Path(file_path).suffix.upper()[1:]
                return f"Extension: {extension}, Actual: {actual_format} - {'MATCH' if extension == actual_format else 'MISMATCH'}"
        except:
            return "Format check failed"

    def check_file_signature(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return f"File signature: {header.hex().upper()}"
        except:
            return "Signature check failed"

    def extract_ocr_text(self, image_path):
        if not TESSERACT_AVAILABLE:
            return {"Status": "Tesseract not available"}
        try:
            text = pytesseract.image_to_string(Image.open(image_path))
            if text.strip():
                return {
                    'Status': 'Text found',
                    'Extracted Text': text.strip()[:1000]
                }
            else:
                return {'Status': 'No text found'}
        except Exception as e:
            return {'Status': f'OCR failed: {str(e)}'}

    def extract_video_data(self, video_path):
        video_data = {}
        try:
            video_data['File Information'] = {
                'Filename': os.path.basename(video_path),
                'File Size': f"{os.path.getsize(video_path)} bytes",
                'Format': Path(video_path).suffix.upper()[1:]
            }
            if CV2_AVAILABLE:
                cap = cv2.VideoCapture(video_path)
                if cap.isOpened():
                    video_data['Video Properties'] = {
                        'Width': int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                        'Height': int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
                        'FPS': cap.get(cv2.CAP_PROP_FPS),
                        'Frame Count': int(cap.get(cv2.CAP_PROP_FRAME_COUNT)),
                        'Duration (seconds)': int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) / cap.get(cv2.CAP_PROP_FPS) if cap.get(cv2.CAP_PROP_FPS) > 0 else 0,
                        'Codec': self.get_video_codec(cap)
                    }
                    ret, frame = cap.read()
                    if ret:
                        frame_info = self.analyze_video_frame(frame)
                        video_data['First Frame Analysis'] = frame_info
                    cap.release()
            video_data['Hash Values'] = self.calculate_hashes(video_path)
            video_data['File Signature'] = self.extract_file_signature(video_path)
            video_data['Hidden Data'] = self.extract_hidden_data(video_path)
            return video_data
        except Exception as e:
            return {"Error": f"Video processing failed: {str(e)}"}

    def get_video_codec(self, cap):
        try:
            fourcc = int(cap.get(cv2.CAP_PROP_FOURCC))
            codec = "".join([chr((fourcc >> 8 * i) & 0xFF) for i in range(4)])
            return codec
        except:
            return "Unknown"

    def analyze_video_frame(self, frame):
        try:
            return {
                'Frame Dimensions': f"{frame.shape[1]} x {frame.shape[0]}",
                'Color Channels': frame.shape[2] if len(frame.shape) > 2 else 1,
                'Frame Type': 'Color' if len(frame.shape) > 2 else 'Grayscale'
            }
        except:
            return {"Error": "Frame analysis failed"}

    def extract_pdf_data(self, pdf_path):
        pdf_data = {}
        try:
            pdf_data['File Information'] = {
                'Filename': os.path.basename(pdf_path),
                'File Size': f"{os.path.getsize(pdf_path)} bytes",
                'Format': 'PDF'
            }
            if PDF_AVAILABLE:
                with open(pdf_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    pdf_data['PDF Metadata'] = {
                        'Pages': len(pdf_reader.pages),
                        'Encrypted': pdf_reader.is_encrypted,
                        'PDF Version': pdf_reader.pdf_header
                    }
                    if pdf_reader.metadata:
                        pdf_data['Document Metadata'] = dict(pdf_reader.metadata)
                with pdfplumber.open(pdf_path) as pdf:
                    if len(pdf.pages) > 0:
                        first_page = pdf.pages[0]
                        text = first_page.extract_text()
                        if text:
                            pdf_data['Text Content'] = {
                                'First Page Sample': text[:1000] + "..." if len(text) > 1000 else text,
                                'Total Pages with Text': sum(1 for page in pdf.pages if page.extract_text().strip())
                            }
            pdf_data['Hash Values'] = self.calculate_hashes(pdf_path)
            pdf_data['File Signature'] = self.extract_file_signature(pdf_path)
            pdf_data['Hidden Data'] = self.extract_hidden_data(pdf_path)
            return pdf_data
        except Exception as e:
            return {"Error": f"PDF processing failed: {str(e)}"}

    def extract_audio_data(self, audio_path):
        audio_data = {}
        try:
            audio_data['File Information'] = {
                'Filename': os.path.basename(audio_path),
                'File Size': f"{os.path.getsize(audio_path)} bytes",
                'Format': Path(audio_path).suffix.upper()[1:]
            }
            if AUDIO_AVAILABLE:
                audio_file = mutagen.File(audio_path)
                if audio_file:
                    audio_data['Audio Metadata'] = dict(audio_file)
                    audio_data['Audio Properties'] = {
                        'Duration': f"{audio_file.info.length:.2f} seconds" if hasattr(audio_file.info, 'length') else 'Unknown',
                        'Bitrate': f"{audio_file.info.bitrate} bps" if hasattr(audio_file.info, 'bitrate') else 'Unknown',
                        'Sample Rate': f"{audio_file.info.sample_rate} Hz" if hasattr(audio_file.info, 'sample_rate') else 'Unknown'
                    }
            audio_data['Hash Values'] = self.calculate_hashes(audio_path)
            audio_data['File Signature'] = self.extract_file_signature(audio_path)
            audio_data['Hidden Data'] = self.extract_hidden_data(audio_path)
            return audio_data
        except Exception as e:
            return {"Error": f"Audio processing failed: {str(e)}"}

    def extract_archive_data(self, archive_path):
        archive_data = {}
        try:
            archive_data['File Information'] = {
                'Filename': os.path.basename(archive_path),
                'File Size': f"{os.path.getsize(archive_path)} bytes",
                'Format': Path(archive_path).suffix.upper()[1:]
            }
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    archive_data['Archive Type'] = 'ZIP'
                    archive_data['Files in Archive'] = zip_ref.namelist()
                    archive_data['Comment'] = zip_ref.comment.decode('utf-8', errors='ignore') if zip_ref.comment else 'None'
            elif tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, 'r') as tar_ref:
                    archive_data['Archive Type'] = 'TAR'
                    archive_data['Files in Archive'] = tar_ref.getnames()
            archive_data['Hash Values'] = self.calculate_hashes(archive_path)
            archive_data['File Signature'] = self.extract_file_signature(archive_path)
            archive_data['Hidden Data'] = self.extract_hidden_data(archive_path)
            return archive_data
        except Exception as e:
            return {"Error": f"Archive processing failed: {str(e)}"}

    def extract_document_data(self, doc_path):
        doc_data = {}
        try:
            doc_data['File Information'] = {
                'Filename': os.path.basename(doc_path),
                'File Size': f"{os.path.getsize(doc_path)} bytes",
                'Format': Path(doc_path).suffix.upper()[1:]
            }
            if doc_path.lower().endswith('.pdf'):
                pdf_info = self.extract_pdf_data(doc_path)
                doc_data.update(pdf_info)
            elif doc_path.lower().endswith('.txt'):
                text_data = self.analyze_text_file(doc_path)
                doc_data['Text Analysis'] = text_data
            elif doc_path.lower().endswith(('.docx', '.doc')) and DOCX_AVAILABLE:
                docx_data = self.analyze_docx_file(doc_path)
                doc_data['Document Analysis'] = docx_data
            elif doc_path.lower().endswith(('.xlsx', '.xls')) and OPENPYXL_AVAILABLE:
                excel_data = self.analyze_excel_file(doc_path)
                doc_data['Spreadsheet Analysis'] = excel_data
            doc_data['Hash Values'] = self.calculate_hashes(doc_path)
            doc_data['File Signature'] = self.extract_file_signature(doc_path)
            doc_data['Hidden Data'] = self.extract_hidden_data(doc_path)
            return doc_data
        except Exception as e:
            return {"Error": f"Document processing failed: {str(e)}"}

    def analyze_text_file(self, text_path):
        try:
            with open(text_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return {
                    'Character Count': len(content),
                    'Line Count': len(content.splitlines()),
                    'Word Count': len(content.split()),
                    'Content Sample': content[:1000] + "..." if len(content) > 1000 else content,
                    'Encoding': 'UTF-8'
                }
        except Exception as e:
            return {"Error": f"Text analysis failed: {str(e)}"}

    def analyze_docx_file(self, docx_path):
        try:
            doc = docx.Document(docx_path)
            text_content = "\n".join([paragraph.text for paragraph in doc.paragraphs])
            return {
                'Paragraph Count': len(doc.paragraphs),
                'Character Count': len(text_content),
                'Word Count': len(text_content.split()),
                'Content Sample': text_content[:1000] + "..." if len(text_content) > 1000 else text_content,
                'Core Properties': {
                    'Title': doc.core_properties.title,
                    'Author': doc.core_properties.author,
                    'Created': str(doc.core_properties.created),
                    'Modified': str(doc.core_properties.modified)
                }
            }
        except Exception as e:
            return {"Error": f"DOCX analysis failed: {str(e)}"}

    def analyze_excel_file(self, excel_path):
        try:
            workbook = openpyxl.load_workbook(excel_path)
            sheet_info = {}
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                sheet_info[sheet_name] = {
                    'Rows': sheet.max_row,
                    'Columns': sheet.max_column,
                    'Used Cells': sheet.max_row * sheet.max_column
                }
            return {
                'Sheets': workbook.sheetnames,
                'Sheet Details': sheet_info,
                'Properties': {
                    'Creator': workbook.properties.creator,
                    'Created': str(workbook.properties.created),
                    'Modified': str(workbook.properties.modified)
                }
            }
        except Exception as e:
            return {"Error": f"Excel analysis failed: {str(e)}"}

    def generate_osint_links(self, file_path, hash_data, gps_data):
        links = {}
        try:
            if 'MD5' in hash_data:
                links['Hash Searches'] = {
                    'VirusTotal': f"https://www.virustotal.com/gui/file/{hash_data['MD5']}",
                    'Hybrid Analysis': f"https://www.hybrid-analysis.com/search?query={hash_data['MD5']}",
                    'MalwareBazaar': f"https://bazaar.abuse.ch/browse.php?search=md5:{hash_data['MD5']}"
                }
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.webp')):
                links['Reverse Image Search'] = {
                    'Google Images': "https://images.google.com/",
                    'Yandex Images': "https://yandex.com/images/",
                    'TinEye': "https://tineye.com/"
                }
            if gps_data and 'Coordinates' in gps_data:
                coords = gps_data['Coordinates']
                if 'Latitude' in coords and 'Longitude' in coords:
                    lat, lon = coords['Latitude'], coords['Longitude']
                    links['Location Intelligence'] = {
                        'Google Earth': f"https://earth.google.com/web/@{lat},{lon}",
                        'Wikimapia': f"http://wikimapia.org/#lang=en&lat={lat}&lon={lon}",
                        'FlightRadar24': f"https://www.flightradar24.com/{lat},{lon}"
                    }
        except Exception as e:
            links['Error'] = f"OSINT link generation failed: {str(e)}"
        return links

    def print_analysis_results(self, analysis_data, filename, file_type):
        print(f"\n{Colors.BLUE}{'='*100}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}📊 FILEXRAY ANALYSIS: {filename.upper()} ({file_type.upper()}){Colors.END}")
        print(f"{Colors.BLUE}{'='*100}{Colors.END}")
        for category, data in analysis_data.items():
            if category == 'Error':
                print(f"\n{Colors.RED}[!] ERROR: {data}{Colors.END}")
                continue
            print(f"\n{Colors.GREEN}┌── {category.replace('_', ' ').title()} {Colors.END}")
            print(f"{Colors.GREEN}└{'─'*98}{Colors.END}")
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        print(f"    {Colors.YELLOW}├─ {key}:{Colors.END}")
                        for sub_key, sub_value in value.items():
                            if isinstance(sub_value, dict):
                                print(f"    {Colors.YELLOW}│   ├─ {sub_key}:{Colors.END}")
                                for sub_sub_key, sub_sub_value in sub_value.items():
                                    print(f"    {Colors.WHITE}│   │   ├─ {sub_sub_key}: {sub_sub_value}{Colors.END}")
                            else:
                                print(f"    {Colors.WHITE}│   ├─ {sub_key}: {sub_value}{Colors.END}")
                    else:
                        print(f"    {Colors.WHITE}├─ {key}: {value}{Colors.END}")
            else:
                print(f"    {Colors.WHITE}{data}{Colors.END}")
        print(f"\n{Colors.BLUE}{'='*100}{Colors.END}")
        print(f"{Colors.GREEN}[+] ANALYSIS COMPLETE - Data saved to organized output structure{Colors.END}")
        print(f"{Colors.BLUE}{'='*100}{Colors.END}")

    def save_analysis_results(self, analysis_data, file_path, file_type):
        try:
            output_dir = os.path.join(self.output_base, self.directories[file_type])
            filename = Path(file_path).stem
            output_path = os.path.join(output_dir, f"{filename}_analysis.json")
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, indent=4, ensure_ascii=False)
            text_output_path = os.path.join(output_dir, f"{filename}_report.txt")
            with open(text_output_path, 'w', encoding='utf-8') as f:
                f.write(f"FileXray Advanced Analysis Report\n")
                f.write(f"{'='*60}\n")
                f.write(f"Tool: {self.tool_name}\n")
                f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target File: {os.path.basename(file_path)}\n")
                f.write(f"File Type: {file_type}\n")
                f.write(f"{'='*60}\n\n")
                for category, data in analysis_data.items():
                    f.write(f"{category.upper()}\n")
                    f.write(f"{'-'*len(category)}\n")
                    self._write_formatted_data(f, data, 0)
                    f.write("\n")
            print(f"{Colors.GREEN}[+] Analysis saved to:{Colors.END}")
            print(f"    {Colors.CYAN}JSON: {output_path}{Colors.END}")
            print(f"    {Colors.CYAN}Text: {text_output_path}{Colors.END}")
            return output_path
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving analysis: {str(e)}{Colors.END}")
            return None

    def _write_formatted_data(self, file, data, indent_level):
        indent = "  " * indent_level
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    file.write(f"{indent}{key}:\n")
                    self._write_formatted_data(file, value, indent_level + 1)
                elif isinstance(value, list):
                    file.write(f"{indent}{key}:\n")
                    for item in value:
                        file.write(f"{indent}  - {item}\n")
                else:
                    file.write(f"{indent}{key}: {value}\n")
        else:
            file.write(f"{indent}{data}\n")

    def process_file(self, file_path):
        if not os.path.exists(file_path):
            print(f"{Colors.RED}[-] Error: File '{file_path}' not found!{Colors.END}")
            return
        file_type = self.get_file_type(file_path)
        filename = os.path.basename(file_path)
        print(f"\n{Colors.CYAN}[*] Processing {file_type}: {filename}{Colors.END}")
        if file_type == 'images':
            analysis_data = self.extract_image_data(file_path)
        elif file_type == 'videos':
            analysis_data = self.extract_video_data(file_path)
        elif file_type == 'documents':
            analysis_data = self.extract_document_data(file_path)
        elif file_type == 'audio':
            analysis_data = self.extract_audio_data(file_path)
        elif file_type == 'archives':
            analysis_data = self.extract_archive_data(file_path)
        else:
            analysis_data = self.generic_file_analysis(file_path)
        self.print_analysis_results(analysis_data, filename, file_type)
        self.save_analysis_results(analysis_data, file_path, file_type)

    def generic_file_analysis(self, file_path):
        return {
            'File Information': {
                'Filename': os.path.basename(file_path),
                'File Path': os.path.abspath(file_path),
                'File Size': f"{os.path.getsize(file_path)} bytes",
                'Format': Path(file_path).suffix.upper()[1:],
                'File Type': 'Unknown/Unsupported'
            },
            'Hash Values': self.calculate_hashes(file_path),
            'File Signature': self.extract_file_signature(file_path),
            'Hidden Data': self.extract_hidden_data(file_path)
        }

    def process_directory(self, directory_path, recursive=True):
        if not os.path.exists(directory_path):
            print(f"{Colors.RED}[-] Error: Directory '{directory_path}' not found!{Colors.END}")
            return
        supported_files = []
        for file_type, extensions in self.supported_formats.items():
            for ext in extensions:
                if recursive:
                    supported_files.extend(Path(directory_path).rglob(f"*{ext}"))
                    supported_files.extend(Path(directory_path).rglob(f"*{ext.upper()}"))
                else:
                    supported_files.extend(Path(directory_path).glob(f"*{ext}"))
                    supported_files.extend(Path(directory_path).glob(f"*{ext.upper()}"))
        if not supported_files:
            print(f"{Colors.YELLOW}[-] No supported files found in '{directory_path}'{Colors.END}")
            return
        print(f"{Colors.GREEN}[+] Found {len(supported_files)} supported files to process{Colors.END}")
        summary = []
        for idx, file_path in enumerate(supported_files, 1):
            print(f"{Colors.CYAN}[{idx}/{len(supported_files)}] Processing: {file_path}{Colors.END}")
            self.process_file(str(file_path))
            summary.append(str(file_path))
            print()
        print(f"{Colors.GREEN}[+] Batch analysis complete!{Colors.END}")
        print(f"{Colors.YELLOW}Summary:{Colors.END}")
        for f in summary:
            print(f"  {Colors.WHITE}{f}{Colors.END}")

    def show_main_menu(self):
        print(f"\n{Colors.BLUE}{Colors.BOLD}FileXray Main Menu{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")
        print(f"{Colors.WHITE}[1] Analyze Single File{Colors.END}")
        print(f"{Colors.WHITE}[2] Analyze Directory{Colors.END}")
        print(f"{Colors.WHITE}[3] Show Supported Formats{Colors.END}")
        print(f"{Colors.WHITE}[4] Module Information{Colors.END}")
        print(f"{Colors.WHITE}[5] Exit{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")

    def show_supported_formats(self):
        print(f"\n{Colors.BLUE}{Colors.BOLD}Supported File Formats{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        for file_type, extensions in self.supported_formats.items():
            print(f"{Colors.GREEN}{file_type.title():<12}: {Colors.WHITE}{', '.join(extensions)}{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")

    def run(self):
        self.show_banner()
        self.create_output_structure()
        while True:
            self.show_main_menu()
            choice = input(f"{Colors.MAGENTA}[fxr]:>> {Colors.END}").strip()
            if choice == '1':
                file_path = input(f"{Colors.CYAN}[+] Enter file path: {Colors.END}").strip()
                if file_path:
                    self.process_file(file_path)
                else:
                    print(f"{Colors.RED}[-] No file path provided{Colors.END}")
            elif choice == '2':
                dir_path = input(f"{Colors.CYAN}[+] Enter directory path: {Colors.END}").strip()
                rec = input(f"{Colors.YELLOW}[?] Recursive scan? (y/n): {Colors.END}").strip().lower()
                self.process_directory(dir_path, recursive=(rec == 'y'))
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
        tool = FileXray()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operation cancelled by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] An error occurred: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()