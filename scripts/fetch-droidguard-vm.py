#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography"]
# ///
"""Download the DroidGuard VM payload used by NetworkHandleProxyFactory.

This posts the same protobuf request as
play-services-droidguard/core/.../NetworkHandleProxyFactory.fetchFromServer
to the androidantiabuse create endpoint, checks the SHA256withRSA signature
with the key in SignatureVerifier, and writes response.content to the.apk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
import zipfile
from base64 import b64decode
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

SERVER_URL = (
    "https://www.googleapis.com/androidantiabuse/v1/x/create"
    "?alt=PROTO&key=AIzaSyBofcZsgLSS7BOnBjZPEkk4rYwzOIz-lTI"
)
PUBLIC_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxW77dCKJ8mhEIfXXdeidi7/"
    "7LMNM/fzwI+wj1Ed8xIKgTYWCnekRko3JxQb4Cv/gEL5hEA8e9lFs3V67VUL6hCo1Fxys"
    "Xj7Q8n3Kp7hARDkbiZ0mdk8bSanqrPAXTPx6pEL2ZOzfFCHEtJdhz5Ozp2C4XTKF1SBv/"
    "YbpsqSUJwdhG7ZPGjyCMRloMww6ITpGdVQ8lChklkCek0WPbz2UrY5RC1qIJKmmcB6KNxx"
    "E776Dn6QoYbhN5jPeVBp7lDD3UxjfVzTxKKDAome6fUVBop3dpcLM6rq3+nNT2YArgqTD1"
    "qtsVM9vHlcLaAYaPg82vtIN80iDUseMlVHgK+nf6wIDAQAB"
)
# play-services-droidguard/core defaultConfig. The body uses VERSION_CODE as-is.
# User-Agent uses VersionUtil.versionCode, which adds the build-type offset.
LIBRARY_VERSION_NAME = "20.47.14"
LIBRARY_VERSION_CODE = 204714000
DEFAULT_PROXY = "http://127.0.0.1:7891"

# Same table and index rule as VersionUtil.BUILD_MAP / getVersionOffset.
# A dpi whose index is 0 is treated as unknown there (`takeIf { it > 0 }`).
BUILD_MAP = [
    ("00", [("03", ["00", "02", "04", "06", "08"]), ("07", ["00"])]),
    (
        "02",
        [
            ("03", ["00", "04", "06", "08"]),
            ("04", ["00", "06", "08"]),
            ("07", ["00"]),
            ("08", ["00"]),
        ],
    ),
    (
        "04",
        [
            ("03", ["00", "04", "06", "08"]),
            ("04", ["00", "06", "08"]),
            ("07", ["00"]),
            ("08", ["00"]),
        ],
    ),
    (
        "10",
        [
            ("03", ["00", "04", "06", "08"]),
            ("04", ["00", "06", "08"]),
            ("07", ["00"]),
            ("08", ["00"]),
        ],
    ),
    (
        "12",
        [
            ("03", ["00", "04", "06", "08"]),
            ("04", ["00", "06", "08"]),
            ("07", ["00"]),
            ("08", ["00"]),
        ],
    ),
    (
        "15",
        [
            ("03", ["00", "04", "06", "08"]),
            ("04", ["00", "06", "08"]),
            ("07", ["00"]),
            ("08", ["00"]),
        ],
    ),
    (
        "19",
        [("03", ["00", "08"]), ("04", ["00", "08"]), ("07", ["00"]), ("08", ["00"])],
    ),
]


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def fail(message: str, code: int) -> None:
    log(message)
    raise SystemExit(code)


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def key(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def proto_bytes(field: int, payload: bytes) -> bytes:
    return key(field, 2) + varint(len(payload)) + payload


def proto_string(field: int, text: str) -> bytes:
    return proto_bytes(field, text.encode())


def proto_bool(field: int, value: bool) -> bytes:
    return key(field, 0) + varint(1 if value else 0)


def proto_int(field: int, value: int) -> bytes:
    return key(field, 0) + varint(value)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            fail("truncated protobuf varint", 3)
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def decode_message(data: bytes) -> dict[int, list[bytes | int]]:
    fields: dict[int, list[bytes | int]] = {}
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            value, offset = read_varint(data, offset)
            fields.setdefault(field, []).append(value)
        elif wire == 2:
            length, offset = read_varint(data, offset)
            fields.setdefault(field, []).append(data[offset : offset + length])
            offset += length
        else:
            fail(f"unsupported protobuf wire type {wire} on field {field}", 3)
    return fields


def first_bytes(fields: dict[int, list[bytes | int]], number: int) -> bytes | None:
    values = fields.get(number) or []
    if not values:
        return None
    value = values[0]
    if not isinstance(value, bytes):
        fail(f"field {number} is not length-delimited", 3)
    return value


def first_int(fields: dict[int, list[bytes | int]], number: int) -> int | None:
    values = fields.get(number) or []
    if not values:
        return None
    value = values[0]
    if not isinstance(value, int):
        fail(f"field {number} is not a varint", 3)
    return value


def sdk_code(sdk: int) -> str:
    return {
        31: "19",
        30: "15",
        29: "12",
        28: "10",
        23: "04",
        24: "04",
        25: "04",
        26: "04",
        27: "04",
        21: "02",
        22: "02",
    }.get(sdk, "00")


def abi_code(abi: str) -> str:
    return {
        "x86_64": "08",
        "x86": "07",
        "arm64-v8a": "04",
        "arm": "03",
        "armeabi": "03",
        "armeabi-v7a": "03",
    }.get(abi, "00")


def dpi_code(dpi: int) -> str:
    return {160: "02", 240: "04", 320: "06", 480: "08"}.get(dpi, "00")


def version_offset(build_type: str) -> int | None:
    v1, v2, v3 = build_type[0:2], build_type[2:4], build_type[4:6]
    i1 = next((index for index, item in enumerate(BUILD_MAP) if item[0] == v1), None)
    if i1 is None:
        return None
    archs = BUILD_MAP[i1][1]
    i2 = next((index for index, item in enumerate(archs) if item[0] == v2), None)
    if i2 is None:
        return None
    i3 = archs[i2][1].index(v3) if v3 in archs[i2][1] else None
    if i3 is None or i3 <= 0:
        return None
    o1 = sum(len(dpi) for _, groups in BUILD_MAP[:i1] for _, dpi in groups)
    o2 = sum(len(dpi) for _, dpi in archs[:i2])
    return o1 + o2 + i3


def build_type(sdk: int, abi: str, dpi: int) -> str:
    typed = f"{sdk_code(sdk)}{abi_code(abi)}{dpi_code(dpi)}"
    if version_offset(typed) is not None:
        return typed
    nodpi = f"{sdk_code(sdk)}{abi_code(abi)}00"
    if version_offset(nodpi) is not None:
        return nodpi
    return typed


def device_info(args: argparse.Namespace) -> list[tuple[str, str]]:
    abi2 = ""
    supported = args.abi if args.abi != "arm64-v8a" else "arm64-v8a,armeabi-v7a,armeabi"
    return [
        ("BOARD", args.board),
        ("BOOTLOADER", args.bootloader),
        ("BRAND", args.brand),
        ("CPU_ABI", args.abi),
        ("CPU_ABI2", abi2),
        ("SUPPORTED_ABIS", supported),
        ("DEVICE", args.device),
        ("DISPLAY", args.display),
        ("FINGERPRINT", args.fingerprint),
        ("HARDWARE", args.hardware),
        ("HOST", args.host),
        ("ID", args.build_id),
        ("MANUFACTURER", args.manufacturer),
        ("MODEL", args.model),
        ("PRODUCT", args.product),
        ("RADIO", args.radio),
        ("SERIAL", args.serial),
        ("TAGS", "release-keys"),
        ("TIME", args.build_time),
        ("TYPE", "user"),
        ("USER", "android"),
        ("VERSION.CODENAME", "REL"),
        ("VERSION.INCREMENTAL", args.incremental),
        ("VERSION.RELEASE", args.release),
        ("VERSION.SDK", args.release),
        ("VERSION.SDK_INT", str(args.sdk)),
    ]


def encode_request(
    args: argparse.Namespace, version_name: str, version_code: int
) -> bytes:
    usage = proto_string(1, args.flow) + proto_string(2, args.package)
    body = proto_bytes(1, usage)
    for key_name, value in device_info(args):
        pair = proto_string(1, key_name) + proto_string(2, value)
        body += proto_bytes(2, pair)
    body += proto_string(3, version_name)
    body += proto_bool(6, False)
    body += proto_bool(7, False)
    body += proto_bool(8, True)
    body += proto_int(13, version_code)
    body += proto_string(14, args.os_arch)
    return body


def verify(data: bytes, signature: bytes) -> None:
    key = load_der_public_key(b64decode(PUBLIC_KEY))
    key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())


def opener(proxy: str | None) -> urllib.request.OpenerDirector:
    if proxy is None:
        return urllib.request.build_opener()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Download a DroidGuard VM the.apk from androidantiabuse."
    )
    argument_parser.add_argument(
        "--flow",
        default="full",
        help="Usage.flow. The VM download path uses full (default: full)",
    )
    argument_parser.add_argument(
        "--version-name",
        help="Override versionName. Default is VersionUtil.versionString for --sdk/--abi/--dpi",
    )
    argument_parser.add_argument(
        "--version-code",
        type=int,
        help="Override the versionCode field. Default is the droidguard library versionCode, without the User-Agent offset",
    )
    argument_parser.add_argument(
        "--package", default="com.google.android.gms", help="Usage.packageName"
    )
    argument_parser.add_argument(
        "--sdk",
        type=int,
        default=31,
        help="Build.VERSION.SDK_INT used to pick the VM build type",
    )
    argument_parser.add_argument("--abi", default="arm64-v8a", help="Build.CPU_ABI")
    argument_parser.add_argument(
        "--dpi", type=int, default=480, help="densityDpi used by VersionUtil"
    )
    argument_parser.add_argument(
        "--os-arch", default="aarch64", help="Request.arch, Java os.arch on device"
    )
    argument_parser.add_argument("--brand", default="google")
    argument_parser.add_argument("--manufacturer", default="Google")
    argument_parser.add_argument("--model", default="Pixel 6")
    argument_parser.add_argument("--device", default="oriole")
    argument_parser.add_argument("--product", default="oriole")
    argument_parser.add_argument("--board", default="oriole")
    argument_parser.add_argument("--hardware", default="oriole")
    argument_parser.add_argument("--bootloader", default="unknown")
    argument_parser.add_argument("--display", default="SP1A.210812.016")
    argument_parser.add_argument("--build-id", default="SP1A.210812.016")
    argument_parser.add_argument("--incremental", default="7679548")
    argument_parser.add_argument("--release", default="12")
    argument_parser.add_argument("--build-time", default="1631088000000")
    argument_parser.add_argument("--host", default="abfarm")
    argument_parser.add_argument("--radio", default="unknown")
    argument_parser.add_argument("--serial", default="unknown")
    argument_parser.add_argument(
        "--fingerprint",
        default="google/oriole/oriole:12/SP1A.210812.016/7679548:user/release-keys",
    )
    argument_parser.add_argument(
        "--output-dir", type=Path, default=Path("cache/droidguard")
    )
    argument_parser.add_argument("--proxy", default=DEFAULT_PROXY)
    argument_parser.add_argument("--no-proxy", action="store_true")
    argument_parser.add_argument("--force", action="store_true")
    return argument_parser


def main() -> None:
    args = parser().parse_args()
    typed = build_type(args.sdk, args.abi, args.dpi)
    offset = version_offset(typed) or 0
    version_name = args.version_name or f"{LIBRARY_VERSION_NAME} ({typed}-{{{{cl}}}})"
    version_code = (
        args.version_code if args.version_code is not None else LIBRARY_VERSION_CODE
    )
    user_agent_code = version_code + (0 if args.version_code is not None else offset)
    request = encode_request(args, version_name, version_code)
    log(
        f"request flow={args.flow} version_name={version_name} "
        f"version_code={version_code} user_agent=DroidGuard/{user_agent_code} "
        f"device_build_type={typed} bytes={len(request)}"
    )
    http = opener(None if args.no_proxy else args.proxy)
    req = urllib.request.Request(
        SERVER_URL,
        data=request,
        headers={
            "Content-Type": "application/x-protobuf",
            "User-Agent": f"DroidGuard/{user_agent_code}",
        },
        method="POST",
    )
    try:
        with http.open(req, timeout=120) as response:
            payload = response.read()
            log(f"response status={response.status} bytes={len(payload)}")
    except urllib.error.HTTPError as error:
        body = error.read(500)
        fail(f"http {error.code} body={body!r}", 2)
    except urllib.error.URLError as error:
        fail(f"request failed: {error.reason}", 2)

    signed = decode_message(payload)
    data = first_bytes(signed, 1)
    signature = first_bytes(signed, 2)
    if data is None or signature is None:
        fail("signed response is missing data or signature", 3)
    try:
        verify(data, signature)
    except InvalidSignature as error:
        fail(f"signature rejected: {error}", 3)
    log("signature ok")
    message = decode_message(data)
    content = first_bytes(message, 5)
    checksum = first_bytes(message, 3)
    if content is None or checksum is None:
        vm_url = first_bytes(message, 2)
        fail(
            f"response has no inline vm content vm_url={vm_url!r} fields={sorted(message)}",
            3,
        )
    vm_key = checksum.hex()
    destination = args.output_dir / vm_key
    destination.mkdir(parents=True, exist_ok=True)
    apk_path = destination / "the.apk"
    bytecode = first_bytes(message, 1) or b""
    extra = first_bytes(message, 9) or b""
    (destination / "bytecode").write_bytes(bytecode)
    (destination / "extra").write_bytes(extra)
    if apk_path.exists() and not args.force:
        log(f"cache hit {apk_path}")
    else:
        apk_path.write_bytes(content)
    libraries: list[str] = []
    if zipfile.is_zipfile(apk_path):
        with zipfile.ZipFile(apk_path) as archive:
            libraries = [name for name in archive.namelist() if name.endswith(".so")]
            for name in libraries:
                target = destination / Path(name).name
                target.write_bytes(archive.read(name))
    record = {
        "vm_key": vm_key,
        "flow": args.flow,
        "package": args.package,
        "device_build_type": typed,
        "version_code": version_code,
        "user_agent_code": user_agent_code,
        "version_name": version_name,
        "apk": str(apk_path),
        "apk_sha256": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
        "apk_bytes": apk_path.stat().st_size,
        "expiry_time_secs": first_int(message, 4),
        "libraries": libraries,
    }
    (destination / "the.json").write_text(json.dumps(record, indent=2) + "\n")
    json.dump(record, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
