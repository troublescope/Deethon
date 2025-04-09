"""
The utils module contains several useful functions that are used within the package.
"""

from __future__ import annotations

import hashlib
import os
from binascii import a2b_hex, b2a_hex
from pathlib import Path
from typing import Iterator, TYPE_CHECKING, Generator, Any, Dict, Optional

from Crypto.Cipher import AES, Blowfish
from mutagen.flac import FLAC, Picture
from mutagen.id3 import ID3, Frames

if TYPE_CHECKING:
    from .types import Track

# Constants
QUALITY_MAP = {
    "FLAC": "9",
    "MP3_320": "3",
    "MP3_256": "5"
}
DEFAULT_QUALITY = "1"
SONGS_DIR = "Songs"
FORBIDDEN_CHARS_MAP = dict((ord(char), None) for char in r'\/*?:"<>|')
AES_KEY = "jo6aey6haid2Teih".encode()
BLOWFISH_IV = a2b_hex("0001020304050607")
XOR_KEY = b"g4el58wc0zvf9na1"


def md5hex(data: bytes | str) -> bytes:
    """
    Calculate MD5 hash and return as hexadecimal bytes.
    
    Args:
        data: Data to hash, either bytes or string
        
    Returns:
        MD5 hash as hexadecimal bytes
    """
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest().encode()


def get_quality(bitrate: str) -> str:
    """
    Get quality code based on bitrate.
    
    Args:
        bitrate: Bitrate string (FLAC, MP3_320, MP3_256, etc.)
        
    Returns:
        Quality code string
    """
    return QUALITY_MAP.get(bitrate, DEFAULT_QUALITY)


def get_file_path(track: Track, ext: str) -> Path:
    """
    Generate a file path using a Track object.

    Args:
        track: A Track object.
        ext: The file extension to be used.

    Returns:
        A Path object containing the track path.
    """
    album_artist = track.album.artist.translate(FORBIDDEN_CHARS_MAP)
    album_title = track.album.title.translate(FORBIDDEN_CHARS_MAP)

    dir_path = Path(SONGS_DIR, album_artist, album_title)
    dir_path.mkdir(parents=True, exist_ok=True)
    
    file_name = f"{track.artist} - {track.title}{ext}"
    return dir_path / file_name.translate(FORBIDDEN_CHARS_MAP)


def get_stream_url(track: Track, quality: str) -> str:
    """
    Get the direct download url for the encrypted track.

    Args:
        track: A Track instance.
        quality: The preferred quality.

    Returns:
        The direct download url.
    """
    # Create the data packet
    data_parts = [track.md5_origin, quality, str(track.id), track.media_version]
    data = b"\xa4".join(part.encode() for part in data_parts)
    
    # Add hash and padding
    data = b"\xa4".join([md5hex(data), data]) + b"\xa4"
    padding = 16 - (len(data) % 16) if len(data) % 16 else 0
    data = data + (b"\x00" * padding)
    
    # Encrypt and format URL
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    hash_value = b2a_hex(cipher.encrypt(data)).decode()
    
    return f"https://e-cdns-proxy-{track.md5_origin[0]}.dzcdn.net/mobile/1/{hash_value}"


def decrypt_file(input_data: Iterator, track_id: int) -> Generator[bytes, Any, None]:
    """
    Decrypt an encrypted track.

    Args:
        input_data: The input stream must have a chunk size of 2048.
        track_id: The id of the track to be decrypted.

    Returns:
        A Generator object containing the decrypted data
    """
    # Generate decryption key
    h = md5hex(str(track_id))
    key = "".join(chr(h[i] ^ h[i + 16] ^ XOR_KEY[i]) for i in range(16))
    
    for seg, data in enumerate(input_data):
        # Only decrypt certain segments
        if seg % 3 == 0 and len(data) == 2048:
            cipher = Blowfish.new(key.encode(), Blowfish.MODE_CBC, BLOWFISH_IV)
            data = cipher.decrypt(data)
        yield data


def tag(file_path: Path, track: Track) -> None:
    """
    Tag the music file at the given file path using the specified Track instance.

    Args:
        file_path: The music file to be tagged
        track: The Track instance to be used for tagging.
    """
    ext = file_path.suffix.lower()

    if ext == ".mp3":
        _tag_mp3(file_path, track)
    elif ext == ".flac":
        _tag_flac(file_path, track)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")


def _tag_mp3(file_path: Path, track: Track) -> None:
    """
    Apply ID3 tags to an MP3 file.
    
    Args:
        file_path: Path to the MP3 file
        track: Track information
    """
    tags = ID3()
    tags.clear()

    # Add basic tags
    tags.add(Frames["TALB"](encoding=3, text=track.album.title))
    tags.add(Frames["TBPM"](encoding=3, text=str(track.bpm)))
    tags.add(Frames["TCON"](encoding=3, text=track.album.genres))
    tags.add(Frames["TCOP"](encoding=3, text=track.copyright))
    tags.add(Frames["TDAT"](encoding=3, text=track.release_date.strftime("%d%m")))
    tags.add(Frames["TIT2"](encoding=3, text=track.title))
    tags.add(Frames["TPE1"](encoding=3, text=track.artist))
    tags.add(Frames["TPE2"](encoding=3, text=track.album.artist))
    tags.add(Frames["TPOS"](encoding=3, text=str(track.disk_number)))
    tags.add(Frames["TPUB"](encoding=3, text=track.album.label))
    tags.add(Frames["TRCK"](encoding=3, text=f"{track.number}/{track.album.total_tracks}"))
    tags.add(Frames["TSRC"](encoding=3, text=track.isrc))
    tags.add(Frames["TYER"](encoding=3, text=str(track.release_date.year)))
    tags.add(Frames["TXXX"](encoding=3, desc="replaygain_track_gain", text=str(track.replaygain_track_gain)))

    # Add lyrics if available
    if track.lyrics:
        tags.add(Frames["USLT"](encoding=3, text=track.lyrics))

    # Add cover art
    tags.add(Frames["APIC"](encoding=3, mime="image/jpeg", type=3, desc="Cover", data=track.album.cover_xl))

    tags.save(file_path, v2_version=3)


def _tag_flac(file_path: Path, track: Track) -> None:
    """
    Apply Vorbis tags to a FLAC file.
    
    Args:
        file_path: Path to the FLAC file
        track: Track information
    """
    tags = FLAC(file_path)
    tags.clear()
    
    # Add basic tags
    tags["album"] = track.album.title
    tags["albumartist"] = track.album.artist
    tags["artist"] = track.artist
    tags["bpm"] = str(track.bpm)
    tags["copyright"] = track.copyright
    tags["date"] = track.release_date.strftime("%Y-%m-%d")
    tags["genre"] = track.album.genres
    tags["isrc"] = track.isrc
    tags["replaygain_track_gain"] = str(track.replaygain_track_gain)
    tags["title"] = track.title
    tags["tracknumber"] = str(track.number)
    tags["year"] = str(track.release_date.year)
    
    # Add lyrics if available
    if track.lyrics:
        tags["lyrics"] = track.lyrics

    # Add cover art
    cover = Picture()
    cover.type = 3
    cover.data = track.album.cover_xl
    cover.width = 1000
    cover.height = 1000
    tags.clear_pictures()
    tags.add_picture(cover)
    
    tags.save(deleteid3=True)