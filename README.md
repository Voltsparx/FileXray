
# FileXray 🔎

FileXray is an open-source multimedia forensic analysis tool focused on extracting metadata, hidden artifacts, and forensic indicators from a wide range of file types. It is intended for OSINT, digital forensics triage, and security analysis.

## Features
- File-type identification (magic numbers + extensions)
- Hashing (MD5, SHA256) and entropy calculation
- EXIF and metadata extraction (via ExifTool when available)
- Archive inspection (ZIP/TAR/GZ)
- Email parsing (EML)
- String extraction and basic hidden-data detection
- Interactive menu and non-interactive CLI modes

## Quickstart
### Prerequisites
- Python 3.8+
- Recommended (optional) tools: `exiftool` (external binary), `tesseract` (for OCR)

### Install
Clone the repository and install Python deps:

```powershell
git clone https://github.com/voltsparx/FileXray.git
cd FileXray
pip install -r requirements.txt
```

Install optional utilities for enhanced analysis:

```powershell
# ExifTool (Windows example)
# Download ExifTool and add to PATH. On Windows, copy exiftool(-k).exe to exiftool.exe and place in PATH.
```

### Run
Interactive mode (default):

```powershell
python fileXray.py
```

Non-interactive examples:

```powershell
# List supported formats
python fileXray.py --list-formats

# Show optional module status
python fileXray.py --show-modules

# Analyze a single file
python fileXray.py --file "C:\path\to\file.jpg"

# Analyze a directory recursively
python fileXray.py --directory "C:\path\to\folder" --recursive
```

## Packaging / Installable CLI
The project includes a `setup.py` entry point so you can install it and run `filexray` directly if you want:

```powershell
pip install .
filexray --file "C:\path\to\file.jpg"
```

## Development & Contributing
- Follow `CONTRIBUTING.md` for contribution guidelines.
- Run tests (if added) and keep changes small and focused.

## Notes
- Many advanced features depend on optional Python packages and external binaries. See `requirements.txt` and README notes above.
- This project is intended for lawful use only. Do not use it to invade privacy or perform unauthorized scanning.

## License
This project is distributed under the MIT License. See `LICENSE.txt` for details.
