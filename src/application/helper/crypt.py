import zlib
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

def obscure(data: bytes) -> bytes:
    return b64e(zlib.compress(data, 9)).decode()

def unobscure(obscured: bytes) -> bytes:
    try:
        return zlib.decompress(b64d(obscured)).decode()
    except Exception:
        return False

