# FileXray 🔍

![FileXray Banner](https://via.placeholder.com/1200x400/0080FF/FFFFFF?text=FileXray+Multimedia+Forensic+Analysis+Tool)

**FileXray** is a powerful, comprehensive multimedia forensic analysis tool designed for OSINT investigations, digital forensics, and security analysis. It extracts hidden data, metadata, and forensic artifacts from over **50+ file formats** with an intuitive, colorized interface.

---

## 🌟 Features

### 🔍 **Multi-Format Support**
|---------------------------------------------------------------------------------------------------|
|          Category          |                                            Supported Formats                                                     |
|---------------------|-----------------------------------------------------------------------------|
|       **Images**        |    JPEG, PNG, TIFF, BMP, WEBP, HEIC, GIF, ICO, PSD, SVG, RAW (CR2, NEF)   |
|        **Videos**        |        MP4, AVI, MOV, MKV, WMV, FLV, WEBM, M4V, 3GP, MPEG, MPG              |
|    **Documents**    | PDF, DOCX, DOC, TXT, RTF, ODT, PAGES, XLSX, XLS, CSV, PPTX, PPT, ODP | 
|         **Audio**         |                       MP3, WAV, FLAC, M4A, AAC, OGG, WMA, AIFF                             |
|      **Archives**       |                                   ZIP, RAR, 7Z, TAR, GZ, BZ2, XZ                                          |
|    **Executables**   |                               EXE, DLL, MSI, BIN, APP, DEB, RPM                                       |
|        **Scripts**        |               PY, JS, HTML, CSS, PHP, JAVA, CPP, C, H, SH, BAT, PS1                     |
|      **Database**      |                             DB, SQLITE, SQLITE3, MDB, ACCDB                                        |
|        **Emails**         |                                            EML, MSG, PST                                                           |
|         **Fonts**          |                                    TTF, OTF, WOFF, WOFF2                                                    |
|       **System**         |                REG, LOG, CFG, INI, CONF, XML, JSON, YAML, YML                          |
|---------------------------------------------------------------------------------------------------|

### 🕵️ **Analysis Capabilities**
- **EXIF & Metadata Extraction** - Comprehensive metadata from images, documents, and multimedia files
- **Hidden Data Discovery** - Strings, URLs, emails, IP addresses, base64 content, credit card patterns, private keys
- **GPS & Geolocation** - Coordinate extraction, reverse geocoding, and map service links
- **File Forensics** - Hash verification, signature analysis, manipulation detection
- **OCR Text Extraction** - Text extraction from images and scanned documents using Tesseract
- **OSINT Integration** - VirusTotal lookups, reverse image search, geolocation services
- **Thumbnail Analysis** - Embedded thumbnail extraction and analysis
- **Multiple Hash Types** - MD5, SHA1, SHA256, SHA512, BLAKE2b

### 💻 **User-Friendly Interface**
- **Colorized Terminal** - Beautiful blue-themed interface with clear color coding
- **Menu-Driven Navigation** - Simple number-based selection system
- **Batch Processing** - Analyze single files or entire directories
- **Real-time Progress** - Clear status updates and progress indicators
- **Custom Prompt** - `[fxr]:>>` command prompt for FileXray

### 📊 **Comprehensive Reporting**
- **JSON Output** - Structured data for programmatic analysis
- **Text Reports** - Human-readable summaries with detailed information
- **Organized Output** - Separate directories for each file type
- **Timestamps** - All reports include analysis date and time

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.8** or higher
- **pip** (Python package manager)
- **4GB RAM** minimum, 8GB recommended
- **1GB** free storage space

### Installation

#### Method 1: Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/voltsparx/fFileXraygit
cd FileXray

# Install dependencies
pip install -r requirements.txt

# Run FileXray
python filexXay.py