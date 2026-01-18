import base64
import binascii
import urllib.parse

def encode_payload(payload, encoding_type):
    """Encode payload using various encodings"""
    encodings = {
        'base64': lambda p: base64.b64encode(p.encode()).decode(),
        'hex': lambda p: binascii.hexlify(p.encode()).decode(),
        'url': lambda p: urllib.parse.quote(p),
        'double_url': lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        'html': lambda p: ''.join(f'&#{ord(c)};' for c in p),
        'unicode': lambda p: ''.join(f'\\u{ord(c):04x}' for c in p),
        'utf7': lambda p: '+ADw-' + base64.b64encode(p.encode('utf-7')).decode() + '-',
        'rot13': lambda p: p.translate(
            str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            )
        )
    }
    
    if encoding_type in encodings:
        return encodings[encoding_type](payload)
    return payload

def decode_response(response, encoding_type):
    """Decode response based on encoding type"""
    decodings = {
        'base64': lambda r: base64.b64decode(r).decode(errors='ignore'),
        'hex': lambda r: binascii.unhexlify(r).decode(errors='ignore'),
        'url': lambda r: urllib.parse.unquote(r),
        'html': lambda r: ''.join(chr(int(c[2:-1])) for c in r.split('&#')[1:]),
    }
    
    if encoding_type in decodings:
        try:
            return decodings[encoding_type](response)
        except:
            return response
    return response