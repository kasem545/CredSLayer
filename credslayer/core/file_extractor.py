# coding: utf-8

"""
File Extraction Module for CredSLayer

This module extracts files (images, documents, binaries) from network captures.
Supports automatic file type detection using magic bytes and MIME types.
"""

import os
import hashlib
from typing import Optional, Tuple
from pathlib import Path

from credslayer.core import logger


# File signatures (magic bytes) for common file types
FILE_SIGNATURES = {
    # Images
    b'\xff\xd8\xff': ('jpg', 'image/jpeg'),
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': ('png', 'image/png'),
    b'\x47\x49\x46\x38\x37\x61': ('gif', 'image/gif'),
    b'\x47\x49\x46\x38\x39\x61': ('gif', 'image/gif'),
    b'\x42\x4d': ('bmp', 'image/bmp'),
    b'\x49\x49\x2a\x00': ('tiff', 'image/tiff'),
    b'\x4d\x4d\x00\x2a': ('tiff', 'image/tiff'),
    b'\x00\x00\x01\x00': ('ico', 'image/x-icon'),

    # Documents
    b'\x25\x50\x44\x46': ('pdf', 'application/pdf'),
    b'\x50\x4b\x03\x04': ('zip', 'application/zip'),  # Also used for DOCX, XLSX, etc.
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': ('doc', 'application/msword'),
    b'\x52\x61\x72\x21\x1a\x07': ('rar', 'application/x-rar-compressed'),
    b'\x1f\x8b': ('gz', 'application/gzip'),
    b'\x37\x7a\xbc\xaf\x27\x1c': ('7z', 'application/x-7z-compressed'),

    # Executables
    b'\x4d\x5a': ('exe', 'application/x-msdownload'),
    b'\x7f\x45\x4c\x46': ('elf', 'application/x-elf'),

    # Archives
    b'\x75\x73\x74\x61\x72': ('tar', 'application/x-tar'),

    # Media
    b'\x49\x44\x33': ('mp3', 'audio/mpeg'),
    b'\xff\xfb': ('mp3', 'audio/mpeg'),
    b'\x00\x00\x00\x20\x66\x74\x79\x70': ('mp4', 'video/mp4'),
    b'\x00\x00\x00\x18\x66\x74\x79\x70': ('mp4', 'video/mp4'),
    b'\x52\x49\x46\x46': ('avi', 'video/x-msvideo'),  # Also WAV

    # Web
    b'\x3c\x21\x44\x4f\x43\x54\x59\x50\x45': ('html', 'text/html'),
    b'\x3c\x68\x74\x6d\x6c': ('html', 'text/html'),
    b'\x3c\x3f\x78\x6d\x6c': ('xml', 'application/xml'),
}

# MIME type to extension mapping (for Content-Type header)
MIME_TO_EXT = {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/bmp': 'bmp',
    'image/tiff': 'tiff',
    'image/webp': 'webp',
    'image/svg+xml': 'svg',
    'image/x-icon': 'ico',
    'application/pdf': 'pdf',
    'application/zip': 'zip',
    'application/x-zip-compressed': 'zip',
    'application/msword': 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
    'application/vnd.ms-excel': 'xls',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/vnd.ms-powerpoint': 'ppt',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    'application/x-rar-compressed': 'rar',
    'application/x-7z-compressed': '7z',
    'application/gzip': 'gz',
    'application/x-tar': 'tar',
    'application/x-msdownload': 'exe',
    'application/x-executable': 'exe',
    'application/x-elf': 'elf',
    'text/html': 'html',
    'text/css': 'css',
    'text/javascript': 'js',
    'application/javascript': 'js',
    'application/json': 'json',
    'application/xml': 'xml',
    'text/xml': 'xml',
    'audio/mpeg': 'mp3',
    'audio/mp3': 'mp3',
    'audio/wav': 'wav',
    'video/mp4': 'mp4',
    'video/mpeg': 'mpeg',
    'video/x-msvideo': 'avi',
    'video/quicktime': 'mov',
}


class FileExtractor:
    """
    Extracts files from network traffic and saves them to disk.
    """

    def __init__(self, output_dir: str = "extracted_files"):
        """
        Initialize the file extractor.

        Parameters
        ----------
        output_dir : str
            Directory where extracted files will be saved
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_files = []
        self.min_file_size = 100  # Minimum file size in bytes
        self.allowed_types = None  # None = all types, or list of extensions

    def detect_file_type(self, data: bytes, mime_type: Optional[str] = None) -> Tuple[str, str]:
        """
        Detect file type from magic bytes or MIME type.

        Parameters
        ----------
        data : bytes
            File data to analyze
        mime_type : str, optional
            MIME type from HTTP header

        Returns
        -------
        Tuple[str, str]
            (extension, mime_type)
        """
        # First try magic bytes
        for signature, (ext, detected_mime) in FILE_SIGNATURES.items():
            if data.startswith(signature):
                return ext, detected_mime

        # Fall back to MIME type from header
        if mime_type:
            mime_lower = mime_type.lower().split(';')[0].strip()
            if mime_lower in MIME_TO_EXT:
                return MIME_TO_EXT[mime_lower], mime_lower

        # Unknown type
        return 'bin', 'application/octet-stream'

    def generate_filename(self, data: bytes, extension: str, url: str = "") -> str:
        """
        Generate a unique filename for the extracted file.

        Parameters
        ----------
        data : bytes
            File data
        extension : str
            File extension
        url : str
            Source URL (optional)

        Returns
        -------
        str
            Generated filename
        """
        # Create hash of the file content
        file_hash = hashlib.sha256(data).hexdigest()[:16]

        # Try to extract a meaningful name from URL
        base_name = "file"
        if url:
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path
                if path and '/' in path:
                    # Get the last part of the path
                    url_filename = path.split('/')[-1]
                    if url_filename and '.' in url_filename:
                        # Remove extension from URL filename
                        base_name = url_filename.rsplit('.', 1)[0]
                    elif url_filename:
                        base_name = url_filename
            except Exception:
                pass

        # Sanitize filename
        base_name = "".join(c for c in base_name if c.isalnum() or c in ('-', '_'))[:50]
        if not base_name:
            base_name = "file"

        # Create filename with hash to ensure uniqueness
        filename = f"{base_name}_{file_hash}.{extension}"
        return filename

    def save_file(self, data: bytes, mime_type: Optional[str] = None, url: str = "",
                  source_ip: str = "", dest_ip: str = "") -> Optional[str]:
        """
        Save extracted file to disk.

        Parameters
        ----------
        data : bytes
            File data to save
        mime_type : str, optional
            MIME type from HTTP header
        url : str, optional
            Source URL
        source_ip : str, optional
            Source IP address
        dest_ip : str, optional
            Destination IP address

        Returns
        -------
        str or None
            Path to saved file, or None if save failed
        """
        # Skip very small files (likely not actual file transfers)
        if len(data) < self.min_file_size:
            return None

        try:
            # Detect file type
            extension, detected_mime = self.detect_file_type(data, mime_type)

            # Check if this file type is allowed
            if self.allowed_types and extension not in self.allowed_types:
                return None

            # Generate filename
            filename = self.generate_filename(data, extension, url)
            filepath = self.output_dir / filename

            # Save file
            with open(filepath, 'wb') as f:
                f.write(data)

            # Create metadata file
            metadata_path = self.output_dir / f"{filename}.metadata.txt"
            with open(metadata_path, 'w') as f:
                f.write(f"Filename: {filename}\n")
                f.write(f"Size: {len(data)} bytes\n")
                f.write(f"Type: {detected_mime}\n")
                f.write(f"Extension: {extension}\n")
                if url:
                    f.write(f"URL: {url}\n")
                if source_ip:
                    f.write(f"Source IP: {source_ip}\n")
                if dest_ip:
                    f.write(f"Destination IP: {dest_ip}\n")
                f.write(f"SHA256: {hashlib.sha256(data).hexdigest()}\n")
                f.write(f"MD5: {hashlib.md5(data).hexdigest()}\n")

            # Track extracted file
            self.extracted_files.append({
                'path': str(filepath),
                'size': len(data),
                'type': detected_mime,
                'extension': extension,
                'url': url,
                'source_ip': source_ip,
                'dest_ip': dest_ip
            })

            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to save file: {e}")
            return None

    def get_summary(self) -> str:
        """
        Get a summary of extracted files.

        Returns
        -------
        str
            Summary text
        """
        if not self.extracted_files:
            return "No files extracted."

        summary = f"\n{'='*60}\n"
        summary += f"File Extraction Summary\n"
        summary += f"{'='*60}\n"
        summary += f"Total files extracted: {len(self.extracted_files)}\n"
        summary += f"Output directory: {self.output_dir}\n\n"

        # Group by type
        by_type = {}
        total_size = 0
        for file_info in self.extracted_files:
            ext = file_info['extension']
            by_type[ext] = by_type.get(ext, 0) + 1
            total_size += file_info['size']

        summary += "Files by type:\n"
        for ext, count in sorted(by_type.items()):
            summary += f"  {ext.upper()}: {count} file(s)\n"

        summary += f"\nTotal size: {total_size:,} bytes ({total_size / 1024:.2f} KB)\n"
        summary += f"{'='*60}\n"

        return summary


# Global instance
_file_extractor: Optional[FileExtractor] = None


def get_file_extractor() -> Optional[FileExtractor]:
    """Get the global file extractor instance."""
    return _file_extractor


def set_file_extractor(extractor: Optional[FileExtractor]):
    """Set the global file extractor instance."""
    global _file_extractor
    _file_extractor = extractor
