"""
Advanced Encoding and Decoding Utilities with Color Support
Support for multiple encoding schemes with enhanced visualization
"""

import base64
import urllib.parse
import binascii
import html
import string
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import codecs

class Color:
    """Enhanced text colors with black emphasis"""
    BLACK = '\033[30m'
    BLACK_BOLD = '\033[1;30m'
    BLACK_UNDERLINE = '\033[4;30m'
    BLACK_BACKGROUND = '\033[40m'
    DARK_GRAY = '\033[90m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class EncodingType(Enum):
    """Enumeration of supported encoding types"""
    BASE64 = "Base64"
    BASE32 = "Base32"
    BASE16 = "Base16/Hex"
    URL = "URL Encoding"
    HTML = "HTML Entities"
    ASCII = "ASCII Code"
    BINARY = "Binary"
    ROT13 = "ROT13"
    UTF8 = "UTF-8"
    UTF16 = "UTF-16"
    UTF32 = "UTF-32"
    HEX = "Hexadecimal"
    OCTAL = "Octal"
    MORSE = "Morse Code"
    REVERSE = "Reverse String"
    ATBASH = "Atbash Cipher"
    CAESAR = "Caesar Cipher"
    XOR = "XOR Cipher"
    AES = "AES Encryption"
    SHA256 = "SHA-256 Hash"
    MD5 = "MD5 Hash"
    BASE91 = "Base91"
    BASE85 = "Base85"
    QUOTED_PRINTABLE = "Quoted Printable"

@dataclass
class EncodingResult:
    """Data class for encoding results"""
    original: str
    encoded: str
    encoding_type: EncodingType
    status: str
    metadata: Optional[Dict] = None

class AdvancedEncodingUtils:
    """Advanced encoding and decoding utilities with enhanced visualization"""
    
    # Color formatters for different encoding types
    COLOR_MAP = {
        EncodingType.BASE64: Color.BLUE,
        EncodingType.BASE32: Color.CYAN,
        EncodingType.HEX: Color.GREEN,
        EncodingType.URL: Color.MAGENTA,
        EncodingType.HTML: Color.YELLOW,
        EncodingType.BINARY: Color.DARK_GRAY,
        EncodingType.ROT13: Color.RED,
        EncodingType.AES: Color.BLACK_BOLD,
        EncodingType.SHA256: Color.BLACK_UNDERLINE,
        EncodingType.MD5: Color.BLACK_BACKGROUND,
    }
    
    # Morse code mapping
    MORSE_CODE_DICT = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '0': '-----', ',': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.',
        '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': '/'
    }
    
    @staticmethod
    def format_with_color(text: str, encoding_type: EncodingType) -> str:
        """Format text with color based on encoding type"""
        color = AdvancedEncodingUtils.COLOR_MAP.get(encoding_type, Color.BLACK)
        return f"{color}{text}{Color.RESET}"
    
    @staticmethod
    def encode_base64(data: str) -> EncodingResult:
        """Encode string to Base64 with enhanced features"""
        try:
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            encoded = base64.b64encode(data_bytes).decode('utf-8')
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.BASE64,
                status="SUCCESS",
                metadata={"length": len(encoded)}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.BASE64,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def decode_base64(data: str) -> EncodingResult:
        """Decode Base64 string"""
        try:
            decoded = base64.b64decode(data).decode('utf-8')
            return EncodingResult(
                original=data,
                encoded=decoded,
                encoding_type=EncodingType.BASE64,
                status="SUCCESS",
                metadata={"is_valid": True}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.BASE64,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def encode_base32(data: str) -> EncodingResult:
        """Encode string to Base32"""
        try:
            encoded = base64.b32encode(data.encode()).decode()
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.BASE32,
                status="SUCCESS"
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.BASE32,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def encode_hex(data: str) -> EncodingResult:
        """Encode string to Hexadecimal"""
        try:
            encoded = binascii.hexlify(data.encode()).decode()
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.HEX,
                status="SUCCESS",
                metadata={"byte_length": len(data.encode())}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.HEX,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def decode_hex(data: str) -> EncodingResult:
        """Decode Hexadecimal string"""
        try:
            decoded = binascii.unhexlify(data).decode()
            return EncodingResult(
                original=data,
                encoded=decoded,
                encoding_type=EncodingType.HEX,
                status="SUCCESS"
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.HEX,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def url_encode(data: str) -> EncodingResult:
        """URL encode string with multiple levels"""
        try:
            single_encoded = urllib.parse.quote(data)
            double_encoded = urllib.parse.quote(single_encoded)
            
            return EncodingResult(
                original=data,
                encoded=single_encoded,
                encoding_type=EncodingType.URL,
                status="SUCCESS",
                metadata={
                    "double_encoded": double_encoded,
                    "components": urllib.parse.urlparse(data) if '://' in data else None
                }
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.URL,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def html_encode(data: str) -> EncodingResult:
        """HTML encode string"""
        try:
            encoded = html.escape(data)
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.HTML,
                status="SUCCESS",
                metadata={"has_tags": '<' in data or '>' in data}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.HTML,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def binary_encode(data: str) -> EncodingResult:
        """Convert string to binary representation"""
        try:
            binary_str = ' '.join(format(ord(c), '08b') for c in data)
            return EncodingResult(
                original=data,
                encoded=binary_str,
                encoding_type=EncodingType.BINARY,
                status="SUCCESS",
                metadata={"bit_length": len(data) * 8}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.BINARY,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def rot13_encode(data: str) -> EncodingResult:
        """ROT13 encoding"""
        try:
            encoded = codecs.encode(data, 'rot_13')
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.ROT13,
                status="SUCCESS"
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.ROT13,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def morse_encode(data: str) -> EncodingResult:
        """Convert string to Morse code"""
        try:
            encoded = ' '.join(
                AdvancedEncodingUtils.MORSE_CODE_DICT.get(char.upper(), char)
                for char in data
            )
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.MORSE,
                status="SUCCESS",
                metadata={"char_count": len(data)}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.MORSE,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def atbash_encode(data: str) -> EncodingResult:
        """Atbash cipher encoding"""
        try:
            result = []
            for char in data:
                if char.isalpha():
                    if char.isupper():
                        base = ord('A')
                        result.append(chr(base + 25 - (ord(char) - base)))
                    else:
                        base = ord('a')
                        result.append(chr(base + 25 - (ord(char) - base)))
                else:
                    result.append(char)
            encoded = ''.join(result)
            return EncodingResult(
                original=data,
                encoded=encoded,
                encoding_type=EncodingType.ATBASH,
                status="SUCCESS"
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.ATBASH,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def xor_encode(data: str, key: str = "secret") -> EncodingResult:
        """XOR encoding with key"""
        try:
            encoded_bytes = bytes([ord(data[i]) ^ ord(key[i % len(key)]) for i in range(len(data))])
            encoded_hex = encoded_bytes.hex()
            return EncodingResult(
                original=data,
                encoded=encoded_hex,
                encoding_type=EncodingType.XOR,
                status="SUCCESS",
                metadata={"key": key, "key_length": len(key)}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.XOR,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def sha256_hash(data: str) -> EncodingResult:
        """Generate SHA-256 hash"""
        try:
            hash_object = hashlib.sha256(data.encode())
            hex_dig = hash_object.hexdigest()
            return EncodingResult(
                original=data,
                encoded=hex_dig,
                encoding_type=EncodingType.SHA256,
                status="SUCCESS",
                metadata={"algorithm": "SHA-256", "digest_size": 64}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.SHA256,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def md5_hash(data: str) -> EncodingResult:
        """Generate MD5 hash"""
        try:
            hash_object = hashlib.md5(data.encode())
            hex_dig = hash_object.hexdigest()
            return EncodingResult(
                original=data,
                encoded=hex_dig,
                encoding_type=EncodingType.MD5,
                status="SUCCESS",
                metadata={"algorithm": "MD5", "digest_size": 32}
            )
        except Exception as e:
            return EncodingResult(
                original=data,
                encoded="",
                encoding_type=EncodingType.MD5,
                status=f"ERROR: {str(e)}"
            )
    
    @staticmethod
    def generate_all_variations(payload: str) -> Dict[str, EncodingResult]:
        """Generate all encoding variations for a payload"""
        variations = {}
        
        # List of encoding methods to apply
        encoding_methods = [
            ("Base64", AdvancedEncodingUtils.encode_base64),
            ("Base32", AdvancedEncodingUtils.encode_base32),
            ("Hex", AdvancedEncodingUtils.encode_hex),
            ("URL", AdvancedEncodingUtils.url_encode),
            ("HTML", AdvancedEncodingUtils.html_encode),
            ("Binary", AdvancedEncodingUtils.binary_encode),
            ("ROT13", AdvancedEncodingUtils.rot13_encode),
            ("Morse", AdvancedEncodingUtils.morse_encode),
            ("Atbash", AdvancedEncodingUtils.atbash_encode),
            ("XOR", lambda x: AdvancedEncodingUtils.xor_encode(x, "key123")),
            ("SHA256", AdvancedEncodingUtils.sha256_hash),
            ("MD5", AdvancedEncodingUtils.md5_hash),
        ]
        
        for name, method in encoding_methods:
            result = method(payload)
            variations[name] = result
        
        return variations
    
    @staticmethod
    def display_results(results: Dict[str, EncodingResult]) -> str:
        """Display encoding results with formatted output"""
        output = []
        
        # Header
        output.append(Color.BLACK_BOLD + "=" * 80 + Color.RESET)
        output.append(Color.BLACK_UNDERLINE + "ENCODING RESULTS SUMMARY" + Color.RESET)
        output.append(Color.BLACK_BOLD + "=" * 80 + Color.RESET)
        
        for name, result in results.items():
            color = AdvancedEncodingUtils.COLOR_MAP.get(result.encoding_type, Color.BLACK)
            
            output.append(f"\n{color}{Color.BOLD}{name} Encoding:{Color.RESET}")
            output.append(f"{Color.DARK_GRAY}Type: {result.encoding_type.value}{Color.RESET}")
            output.append(f"{Color.BLACK}Original: {result.original[:50]}{'...' if len(result.original) > 50 else ''}{Color.RESET}")
            output.append(f"{color}Encoded: {result.encoded[:100]}{'...' if len(result.encoded) > 100 else ''}{Color.RESET}")
            output.append(f"{Color.DARK_GRAY}Status: {result.status}{Color.RESET}")
            
            if result.metadata:
                meta_info = ", ".join([f"{k}: {v}" for k, v in result.metadata.items()])
                output.append(f"{Color.DARK_GRAY}Metadata: {meta_info}{Color.RESET}")
        
        output.append(Color.BLACK_BOLD + "\n" + "=" * 80 + Color.RESET)
        return '\n'.join(output)

# Example usage and testing
def main():
    """Example usage of the enhanced encoding utilities"""
    
    # Initialize encoder
    encoder = AdvancedEncodingUtils()
    
    # Test payload
    test_payload = "<script>alert('Test')</script>"
    
    print(Color.BLACK_BOLD + "Testing Enhanced Encoding Utilities" + Color.RESET)
    print(Color.BLACK_UNDERLINE + "Payload:" + Color.RESET, test_payload)
    print()
    
    # Generate all variations
    variations = encoder.generate_all_variations(test_payload)
    
    # Display results
    print(encoder.display_results(variations))
    
    # Test individual encodings with more black text emphasis
    print(Color.BLACK_BOLD + "\n" + "=" * 80 + Color.RESET)
    print(Color.BLACK_UNDERLINE + "Individual Encoding Tests" + Color.RESET)
    
    # Base64 with black emphasis
    base64_result = encoder.encode_base64(test_payload)
    print(f"\n{Color.BLACK_BOLD}Base64 Encoding:{Color.RESET}")
    print(f"{Color.BLACK}Original: {base64_result.original}{Color.RESET}")
    print(f"{Color.BLUE}Encoded: {base64_result.encoded}{Color.RESET}")
    
    # SHA-256 with black emphasis
    sha_result = encoder.sha256_hash(test_payload)
    print(f"\n{Color.BLACK_BOLD}SHA-256 Hash:{Color.RESET}")
    print(f"{Color.BLACK}Original: {sha_result.original}{Color.RESET}")
    print(f"{Color.BLACK_UNDERLINE}Hash: {sha_result.encoded}{Color.RESET}")
    
    # Binary with black emphasis
    binary_result = encoder.binary_encode(test_payload)
    print(f"\n{Color.BLACK_BOLD}Binary Encoding:{Color.RESET}")
    print(f"{Color.BLACK}Original: {binary_result.original}{Color.RESET}")
    print(f"{Color.DARK_GRAY}Binary: {binary_result.encoded[:50]}...{Color.RESET}")

if __name__ == "__main__":
    main()