"""
Encoding and decoding utilities
"""

import base64
import urllib.parse
import binascii
from colorama import Fore

class EncodingUtils:
    @staticmethod
    def encode_base64(data):
        """Encode data to Base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_base64(data):
        """Decode Base64 data"""
        try:
            return base64.b64decode(data).decode('utf-8')
        except:
            return None
    
    @staticmethod
    def url_encode(data):
        """URL encode data"""
        return urllib.parse.quote(data)
    
    @staticmethod
    def url_decode(data):
        """URL decode data"""
        return urllib.parse.unquote(data)
    
    @staticmethod
    def html_encode(data):
        """HTML encode data"""
        return data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    @staticmethod
    def hex_encode(data):
        """Hex encode data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return binascii.hexlify(data).decode('utf-8')
    
    @staticmethod
    def hex_decode(data):
        """Hex decode data"""
        try:
            return binascii.unhexlify(data).decode('utf-8')
        except:
            return None
    
    @staticmethod
    def generate_payload_variations(payload):
        """Generate various encoded versions of a payload"""
        variations = {
            'original': payload,
            'url_encoded': urllib.parse.quote(payload),
            'double_url_encoded': urllib.parse.quote(urllib.parse.quote(payload)),
            'base64': base64.b64encode(payload.encode()).decode() if isinstance(payload, str) else '',
            'html_encoded': payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;'),
            'hex': EncodingUtils.hex_encode(payload) if isinstance(payload, str) else ''
        }
        return variations