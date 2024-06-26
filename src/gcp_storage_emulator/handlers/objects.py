import hashlib
import json
import logging
import math
import re
import secrets
import string
import textwrap
import time
import urllib.parse
from base64 import b64encode
from copy import deepcopy
from datetime import datetime, timezone
from enum import IntEnum
from http import HTTPStatus

import google_crc32c

from gcp_storage_emulator.exceptions import Conflict, NotFound
from gcp_storage_emulator.checksums import checksums

logger = logging.getLogger("api.object")

_WRITABLE_FIELDS = (
    "cacheControl",
    "contentDisposition",
    "contentEncoding",
    "contentLanguage",
    "contentType",
    "crc32c",
    "customTime",
    "md5Hash",
    "metadata",
    "storageClass",
)

_HASH_HEADER = "X-Goog-Hash"

BAD_REQUEST = {
    "error": {
        "errors": [{"domain": "global", "reason": "invalid", "message": None}],
        "code": 400,
        "message": None,
    }
}

NOT_FOUND = {
    "error": {
        "errors": [{"domain": "global", "reason": "notFound", "message": None}],
        "code": 404,
        "message": None,
    }
}


class GoogleHTTPStatus(IntEnum):
    def __new__(cls, value, phrase, description=""):
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.phrase = phrase
        obj.description = description
        return obj

    RESUME_INCOMPLETE = 308, "Resume Incomplete"


def _handle_conflict(response, err):
    msg = str(err)
    response.status = HTTPStatus.BAD_REQUEST
    resp = deepcopy(BAD_REQUEST)
    resp["error"]["message"] = msg
    resp["error"]["errors"][0]["message"] = msg
    response.json(resp)


def _patch_object(obj, metadata):
    if metadata:
        obj["metageneration"] = str(int(obj["metageneration"]) + 1)
        for key in _WRITABLE_FIELDS:
            val = metadata.get(key)
            if val is not None:
                if key == "customTime" and obj.get(key) and obj.get(key) > val:
                    continue
                obj[key] = val
    return obj


def _make_object_resource(
    base_url, bucket_name, object_name, content_type, content_length, metadata=None
):
    time_id = math.floor(time.time())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    obj = {
        "kind": "storage#object",
        "id": "{}/{}/{}".format(bucket_name, object_name, time_id),
        "selfLink": "/storage/v1/b/{}/o/{}".format(bucket_name, object_name),
        "name": object_name,
        "bucket": bucket_name,
        "generation": str(time_id),
        "metageneration": "1",
        "contentType": content_type,
        "timeCreated": now,
        "updated": now,
        "storageClass": "STANDARD",
        "timeStorageClassUpdated": now,
        "size": content_length,
        "md5Hash": None,
        "mediaLink": "{}/download/storage/v1/b/{}/o/{}?generation={}&alt=media".format(
            base_url,
            bucket_name,
            object_name,
            time_id,
        ),
        "crc32c": None,
        "etag": None,
    }
    obj = _patch_object(obj, metadata)
    return obj


def _content_type_from_request(request, default=None):
    if "contentEncoding" in request.query:
        return request.query["contentEncoding"][0]
    return default


def _media_upload(request, response, storage):
    object_id = request.query["name"][0]
    content_type = _content_type_from_request(
        request, request.get_header("content-type")
    )
    obj = _make_object_resource(
        request.base_url,
        request.params["bucket_name"],
        object_id,
        content_type,
        str(len(request.data)),
    )
    obj = checksums(request.data, obj)
    storage.create_file(
        request.params["bucket_name"],
        object_id,
        request.data,
        obj,
    )

    response.json(obj)


def _multipart_upload(request, response, storage):
    object_id = request.data["meta"].get("name")
    # Overrides the object metadata's name value, if any.
    if "name" in request.query:
        object_id = request.query["name"][0]
    content_type = _content_type_from_request(request, request.data["content-type"])
    obj = _make_object_resource(
        request.base_url,
        request.params["bucket_name"],
        object_id,
        content_type,
        str(len(request.data["content"])),
        request.data["meta"],
    )
    obj = checksums(request.data["content"], obj)
    storage.create_file(
        request.params["bucket_name"],
        object_id,
        request.data["content"],
        obj,
    )

    response.json(obj)


def _create_resumable_upload(request, response, storage):
    # Workaround for libraries using POST method when they should be using PUT.
    if "upload_id" in request.query:
        return upload_partial(request, response, storage)
    if request.data:
        object_id = request.data.get("name")
    # Overrides the object metadata's name value, if any.
    if "name" in request.query:
        object_id = request.query["name"][0]
    content_type = _content_type_from_request(
        request, request.get_header("x-upload-content-type", "application/octet-stream")
    )
    content_length = request.get_header("x-upload-content-length", None)
    obj = _make_object_resource(
        request.base_url,
        request.params["bucket_name"],
        object_id,
        content_type,
        content_length,
    )
    id = storage.create_resumable_upload(
        request.params["bucket_name"],
        object_id,
        obj,
    )
    encoded_id = urllib.parse.urlencode(
        {
            "upload_id": id,
        }
    )
    response["Location"] = request.full_url + "&{}".format(encoded_id)


def _delete(storage, bucket_name, object_id):
    try:
        storage.delete_file(bucket_name, object_id)
        return True
    except NotFound:
        return False


def _patch(storage, bucket_name, object_id, metadata):
    try:
        obj = storage.get_file_obj(bucket_name, object_id)
        obj = _patch_object(obj, metadata)
        storage.patch_object(bucket_name, object_id, obj)
        return obj
    except NotFound:
        logger.error(
            "Could not patch {}/{}: with {}".format(bucket_name, object_id, metadata)
        )
        return None


def _extract_host_bucket(host):
    return re.match(r"^(?P<bucket_name>[^.]+)\.", host).group("bucket_name")


# https://cloud.google.com/storage/docs/xml-api/post-object-multipart
def _xml_initiate_upload(request, response, storage, *args, **kwargs):
    bucket_name = _extract_host_bucket(request.host)
    object_id = request.path.lstrip("/")
    content_type = request.headers.get("content-type")

    # Collect custom metadata
    # https://cloud.google.com/storage/docs/metadata#custom-metadata
    metadata = {}
    for key, value in request.headers.items():
        match = re.match(r"x-goog-meta-(?P<metadata_key>.+)", key.lower())
        if match:
            metadata_key = match.group("metadata_key")
            metadata[metadata_key] = value

    file_obj = _make_object_resource(
        request.base_url, bucket_name, object_id, content_type, 0
    ) | {"metadata": metadata}

    try:
        upload_id = storage.create_xml_multipart_upload(
            bucket_name, object_id, file_obj
        )

        xml = """
        <?xml version='1.0' encoding='UTF-8'?>
        <InitiateMultipartUploadResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>
            <Bucket>{}</Bucket>
            <Key>{}</Key>
            <UploadId>{}</UploadId>
        </InitiateMultipartUploadResult>
        """.format(
            bucket_name, object_id, upload_id
        )
        response.xml(textwrap.dedent(xml))
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND


# https://cloud.google.com/storage/docs/xml-api/post-object-complete
def _xml_complete_upload(request, response, storage, *args, **kwargs):
    bucket_name = _extract_host_bucket(request.host)
    object_id = request.path.lstrip("/")
    upload_id = request.query.get("uploadId")[0]

    try:
        storage.complete_multipart_upload(upload_id)

        # NOTE the constant etag below - we don't actually calculate it
        xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Location>http://{}/{}</Location>
            <Bucket>{}</Bucket>
            <Key>{}</Key>
            <ETag>"7fc8f92280ac3c975f300cb64412c16f-9"</ETag>
        </CompleteMultipartUploadResult>
        """.format(
            request.host, object_id, bucket_name, object_id
        )
        response.xml(textwrap.dedent(xml))
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND


## https://cloud.google.com/storage/docs/xml-api/post-object-multipart
def xml_multipart_upload(request, response, storage, *args, **kwargs):
    if request.query.get("uploads") is not None:
        return _xml_initiate_upload(request, response, storage, *args, **kwargs)

    if request.query.get("uploadId") is not None:
        return _xml_complete_upload(request, response, storage, *args, **kwargs)

    # Only know how to handle multipart uploads at the moment, not resumable ones
    response.status = HTTPStatus.BAD_REQUEST


# https://cloud.google.com/storage/docs/xml-api/put-object-multipart
def xml_part_upload(request, response, storage, *args, **kwargs):
    if request.query.get("uploadId") is None or request.query.get("partNumber") is None:
        response.status = HTTPStatus.BAD_REQUEST
        return

    upload_id = request.query.get("uploadId")[0]
    part_number = int(request.query.get("partNumber")[0], 10)
    try:
        storage.add_to_multipart_upload(upload_id, part_number, request.data)
        # We don't actually do anything with the tag, but return it for compatibility
        response["ETag"] = f'"{hashlib.md5(request.data).hexdigest()}"'
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND


def xml_upload(request, response, storage, *args, **kwargs):
    content_type = request.get_header("Content-Type", "application/octet-stream")
    obj = _make_object_resource(
        request.base_url,
        request.params["bucket_name"],
        request.params["object_id"],
        content_type,
        str(len(request.data)),
    )
    try:
        obj = checksums(request.data, obj)
        storage.create_file(
            request.params["bucket_name"],
            request.params["object_id"],
            request.data,
            obj,
        )

    except NotFound:
        response.status = HTTPStatus.NOT_FOUND


def insert(request, response, storage, *args, **kwargs):
    uploadType = request.query.get("uploadType")

    if not uploadType or len(uploadType) == 0:
        response.status = HTTPStatus.BAD_REQUEST
        return

    uploadType = uploadType[0]

    try:
        if uploadType == "media":
            return _media_upload(request, response, storage)

        if uploadType == "resumable":
            return _create_resumable_upload(request, response, storage)

        if uploadType == "multipart":
            return _multipart_upload(request, response, storage)
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
    except Conflict as err:
        _handle_conflict(response, err)


def upload_partial(request, response, storage, *args, **kwargs):
    """https://cloud.google.com/storage/docs/performing-resumable-uploads"""
    upload_id = request.query.get("upload_id")[0]
    regex = r"^\s*bytes (?P<start>[0-9]+)-(?P<end>[0-9]+)/(?P<total_size>[0-9]+)$"
    pattern = re.compile(regex)
    content_range = request.get_header("Content-Range", "")
    match = pattern.fullmatch(content_range)
    try:
        obj = storage.get_resumable_file_obj(upload_id)
        if match:
            m_dict = match.groupdict()
            total_size = int(m_dict["total_size"])
            data = storage.add_to_resumable_upload(upload_id, request.data, total_size)
            if data is None:
                response.status = GoogleHTTPStatus.RESUME_INCOMPLETE
                response["Range"] = "bytes=0-{}".format(m_dict["end"])
                return
        else:
            data = request.data or b""

        obj = checksums(data, obj)
        obj["size"] = str(len(data))
        storage.create_file(obj["bucket"], obj["name"], data, obj, upload_id)
        response.json(obj)
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
    except Conflict as err:
        _handle_conflict(response, err)


def get(request, response, storage, *args, **kwargs):
    if request.query.get("alt") and request.query.get("alt")[0] == "media":
        return download(request, response, storage)
    try:
        obj = storage.get_file_obj(
            request.params["bucket_name"], request.params["object_id"]
        )
        response.json(obj)
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND


def ls(request, response, storage, *args, **kwargs):
    bucket_name = request.params["bucket_name"]
    prefix = request.query.get("prefix")[0] if request.query.get("prefix") else None
    delimiter = (
        request.query.get("delimiter")[0] if request.query.get("delimiter") else None
    )
    try:
        files, prefixes = storage.get_file_list(bucket_name, prefix, delimiter)
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
    else:
        response.json({"kind": "storage#object", "prefixes": prefixes, "items": files})


def copy(request, response, storage, *args, **kwargs):
    try:
        obj = storage.get_file_obj(
            request.params["bucket_name"], request.params["object_id"]
        )
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
        return

    dest_obj = _make_object_resource(
        request.base_url,
        request.params["dest_bucket_name"],
        request.params["dest_object_id"],
        obj["contentType"],
        obj["size"],
        obj,
    )

    file = storage.get_file(request.params["bucket_name"], request.params["object_id"])
    try:
        dest_obj = checksums(file, dest_obj)
        storage.create_file(
            request.params["dest_bucket_name"],
            request.params["dest_object_id"],
            file,
            dest_obj,
        )
        response.json(dest_obj)
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
    except Conflict as err:
        _handle_conflict(response, err)


def rewrite(request, response, storage, *args, **kwargs):
    try:
        obj = storage.get_file_obj(
            request.params["bucket_name"], request.params["object_id"]
        )
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
        return

    dest_obj = _make_object_resource(
        request.base_url,
        request.params["dest_bucket_name"],
        request.params["dest_object_id"],
        obj["contentType"],
        obj["size"],
        obj,
    )

    file = storage.get_file(request.params["bucket_name"], request.params["object_id"])
    try:
        dest_obj = checksums(file, dest_obj)
        storage.create_file(
            request.params["dest_bucket_name"],
            request.params["dest_object_id"],
            file,
            dest_obj,
        )
        response.json(
            {
                "resource": dest_obj,
                "written": dest_obj["size"],
                "size": dest_obj["size"],
                "done": True,
            }
        )
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
    except Conflict as err:
        _handle_conflict(response, err)


def compose(request, response, storage, *args, **kwargs):
    content_type = None
    dest_file = b""
    try:
        dest_properties = request.data["destination"]
        for src_obj in request.data["sourceObjects"]:
            if content_type is None:
                temp = storage.get_file_obj(
                    request.params["bucket_name"], src_obj["name"]
                )
                content_type = temp["contentType"]
            dest_file += storage.get_file(
                request.params["bucket_name"], src_obj["name"]
            )

    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
        return

    dest_obj = _make_object_resource(
        request.base_url,
        request.params["bucket_name"],
        request.params["object_id"],
        content_type,
        len(dest_file),
        dest_properties,
    )

    try:
        dest_obj = checksums(dest_file, dest_obj)
        storage.create_file(
            request.params["bucket_name"],
            request.params["object_id"],
            dest_file,
            dest_obj,
        )
        response.json(dest_obj)
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND
    except Conflict as err:
        _handle_conflict(response, err)


def download(request, response, storage, *args, **kwargs):
    try:
        file = storage.get_file(
            request.params["bucket_name"], request.params["object_id"]
        )
        obj = storage.get_file_obj(
            request.params["bucket_name"], request.params["object_id"]
        )
        range = request.get_header("range", None)
        if range:
            regex = r"^\s*bytes=(?P<start>[0-9]+)-(?P<end>[0-9]*)$"
            pattern = re.compile(regex)
            match = pattern.fullmatch(range)
            if match:
                end = orig_len = len(file)
                m_dict = match.groupdict()
                start = int(m_dict["start"])
                if m_dict["end"]:
                    end = min(orig_len, int(m_dict["end"]) + 1)
                file = file[start:end]
                end -= 1
                response["Content-Range"] = "bytes {}-{}/{}".format(
                    start, end, orig_len
                )
                response.status = HTTPStatus.PARTIAL_CONTENT
        else:
            hash_header = "crc32c={},md5={}".format(obj["crc32c"], obj["md5Hash"])
            response[_HASH_HEADER] = hash_header

        response.write_file(file, content_type=obj.get("contentType"))
    except NotFound:
        response.status = HTTPStatus.NOT_FOUND


def delete(request, response, storage, *args, **kwargs):
    if not _delete(storage, request.params["bucket_name"], request.params["object_id"]):
        response.status = HTTPStatus.NOT_FOUND


def patch(request, response, storage, *args, **kwargs):
    obj = _patch(
        storage,
        request.params["bucket_name"],
        request.params["object_id"],
        request.data,
    )
    if obj:
        response.json(obj)
    else:
        response.status = HTTPStatus.NOT_FOUND


def batch(request, response, storage, *args, **kwargs):
    boundary = "batch_" + "".join(
        secrets.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        for _ in range(32)
    )
    response["Content-Type"] = "multipart/mixed; boundary={}".format(boundary)
    for item in request.data:
        resp_data = None
        response.write("--{}\r\nContent-Type: application/http\r\n".format(boundary))
        method = item.get("method")
        bucket_name = item.get("bucket_name")
        object_id = item.get("object_id")
        meta = item.get("meta")
        if method == "PATCH":
            resp_data = _patch(storage, bucket_name, object_id, meta)
            if resp_data:
                response.write("HTTP/1.1 200 OK\r\n")
                response.write("Content-Type: application/json; charset=UTF-8\r\n")
                response.write(json.dumps(resp_data))
                response.write("\r\n\r\n")
        if method == "DELETE":
            if object_id:
                resp_data = _delete(storage, bucket_name, object_id)
            else:
                try:
                    storage.delete_bucket(bucket_name)
                    resp_data = True
                except (Conflict, NotFound):
                    pass
            if resp_data:
                response.write("HTTP/1.1 204 No Content\r\n")
                response.write("Content-Type: application/json; charset=UTF-8\r\n")
        if not resp_data:
            msg = "No such object: {}/{}".format(bucket_name, object_id)
            resp_data = deepcopy(NOT_FOUND)
            resp_data["error"]["message"] = msg
            resp_data["error"]["errors"][0]["message"] = msg
            response.write("HTTP/1.1 404 Not Found\r\n")
            response.write("Content-Type: application/json; charset=UTF-8\r\n\r\n")
            response.write(json.dumps(resp_data))
            response.write("\r\n\r\n")

    response.write("--{}--".format(boundary))


def options(request, response, storage, *args, **kwargs):
    response["Content-Type"] = "text/html; charset=UTF-8"
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "*"
    response["Access-Control-Allow-Headers"] = "*"
    response.write("HTTP/1.1 200 OK\r\n")
