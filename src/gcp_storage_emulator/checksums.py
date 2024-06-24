import hashlib
from base64 import b64encode

import google_crc32c

from gcp_storage_emulator.exceptions import Conflict


MD5_CHECKSUM_ERROR = 'Provided MD5 hash "{}" doesn\'t match calculated MD5 hash "{}".'
CRC32C_CHECKSUM_ERROR = 'Provided CRC32C "{}" doesn\'t match calculated CRC32C "{}".'


def _crc32c(content):
    if isinstance(content, str):
        content = content.encode()
    val = google_crc32c.Checksum(content)
    return b64encode(val.digest()).decode("ascii")


def _md5(content):
    if isinstance(content, str):
        content = content.encode()
    return b64encode(hashlib.md5(content).digest()).decode("ascii")


def checksums(content, file_obj):
    crc32c_hash = _crc32c(content)
    obj_crc32c = file_obj.get("crc32c")
    md5_hash = _md5(content)
    obj_md5 = file_obj.get("md5Hash")
    if not obj_crc32c:
        file_obj["crc32c"] = crc32c_hash
    else:
        if obj_crc32c != crc32c_hash:
            raise Conflict(CRC32C_CHECKSUM_ERROR.format(obj_crc32c, crc32c_hash))
    if not obj_md5:
        file_obj["md5Hash"] = md5_hash
    else:
        if obj_md5 != md5_hash:
            raise Conflict(MD5_CHECKSUM_ERROR.format(obj_md5, md5_hash))
    if not file_obj.get("etag"):
        file_obj["etag"] = md5_hash
    return file_obj
