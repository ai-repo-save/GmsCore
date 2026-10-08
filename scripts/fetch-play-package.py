#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# ///
"""Download a Google Play package XAPK/APK from the public APKCombo variant page.

Google Play itself requires an account. This script uses the APKCombo page that
lists the same versioned split packages, then follows its short-lived redirect
to the file host. Output is a local cache file plus one JSON object on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
DEFAULT_PROXY = "http://127.0.0.1:7891"
SITE = "https://apkcombo.com"

# APKCombo prints "Android 12L+" / "Android 10+" / "Android 7.0+".
_API_BY_RELEASE = {
    "7.0": 24,
    "7.1": 25,
    "8.0": 26,
    "8.1": 27,
    "9": 28,
    "10": 29,
    "11": 30,
    "12": 31,
    "12L": 32,
    "13": 33,
    "14": 34,
    "15": 35,
    "16": 36,
}

_ARCH = re.compile(r"<code>([^<]*)</code>")
_VARIANT_LINK = re.compile(r'<a href="(?P<href>/r2\?u=[^"]+)" class="variant"')
_FIELD = {
    "vername": re.compile(r'<span class="vername">([^<]+)</span>'),
    "vercode": re.compile(r'<span class="vercode">\((\d+)\)</span>'),
    "kind": re.compile(r'<span class="type-[^"]+">([^<]+)</span>'),
    "size": re.compile(r'<span class="spec ltr">\s*([^<]+)</span>'),
    "sdk": re.compile(r"Android\s+([0-9]+(?:\.[0-9]+)?L?)\+"),
    "dpi": re.compile(r'<span class="spec"><svg class="icon"><use xlink:href="#ic-dpi"></use></svg>\s*([^<]+)</span>'),
}
_VERSION = re.compile(r"(\d+\.\d+\.\d+)")
_SLUG = re.compile(r'href="/([a-z0-9][a-z0-9-]*)/([^"/]+)/"')


@dataclass
class Variant:
    version_name: str
    version_code: int
    build_label: str
    arch: str
    kind: str
    size_label: str
    min_sdk_label: str
    min_sdk: int | None
    dpi: str
    download_path: str


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def fail(message: str, code: int) -> None:
    log(message)
    raise SystemExit(code)


def build_opener(proxy: str | None) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def fetch_text(opener: urllib.request.OpenerDirector, url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en"})
    try:
        with opener.open(request, timeout=60) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as error:
        fail(f"http {error.code} for {url}", 2)
    except urllib.error.URLError as error:
        fail(f"request failed for {url}: {error.reason}", 2)
    raise AssertionError


def find_slug(opener: urllib.request.OpenerDirector, package: str) -> str:
    html = fetch_text(opener, f"{SITE}/search?q={urllib.parse.quote(package)}")
    slugs = [slug for slug, found in _SLUG.findall(html) if found == package and len(slug) > 2]
    if not slugs:
        fail(f"no APKCombo page for package {package}", 3)
    return slugs[0]


def parse_variants(html: str) -> list[Variant]:
    variants: list[Variant] = []
    seen: set[int] = set()
    for match in _VARIANT_LINK.finditer(html):
        arch_matches = list(_ARCH.finditer(html, 0, match.start()))
        arch = arch_matches[-1].group(1).strip() if arch_matches else ""
        window = html[match.end() : match.end() + 2500]
        vername = _FIELD["vername"].search(window)
        vercode = _FIELD["vercode"].search(window)
        kind = _FIELD["kind"].search(window)
        if not (vername and vercode and kind):
            continue
        code = int(vercode.group(1))
        if code in seen:
            continue
        seen.add(code)
        version_match = _VERSION.search(vername.group(1))
        sdk_match = _FIELD["sdk"].search(window)
        size_match = _FIELD["size"].search(window)
        dpi_match = _FIELD["dpi"].search(window)
        release = sdk_match.group(1) if sdk_match else ""
        label_match = re.search(r"\(([^)]+)\)\s*$", vername.group(1).strip())
        variants.append(
            Variant(
                version_name=version_match.group(1) if version_match else "",
                version_code=code,
                build_label=label_match.group(1) if label_match else "",
                arch=arch,
                kind=kind.group(1).strip(),
                size_label=(size_match.group(1).strip() if size_match else ""),
                min_sdk_label=(f"Android {release}+" if release else ""),
                min_sdk=_API_BY_RELEASE.get(release),
                dpi=(dpi_match.group(1).strip() if dpi_match else ""),
                download_path=html_unescape(match.group("href")),
            )
        )
    return variants


def html_unescape(value: str) -> str:
    return (
        value.replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
    )


def select_variant(variants: list[Variant], version: str | None, version_code: int | None, min_sdk: int | None) -> Variant:
    chosen = variants
    if version:
        chosen = [item for item in chosen if item.version_name == version]
    if version_code is not None:
        chosen = [item for item in chosen if item.version_code == version_code]
    if min_sdk is not None:
        eligible = [item for item in chosen if item.min_sdk is not None and item.min_sdk <= min_sdk]
        if not eligible:
            fail(f"no variant with minSdk <= {min_sdk}", 3)
        eligible.sort(key=lambda item: item.min_sdk or 0, reverse=True)
        return eligible[0]
    if not chosen:
        fail("no matching variant", 3)
    chosen.sort(key=lambda item: (item.min_sdk or 0, item.version_code), reverse=True)
    return chosen[0]


def download(opener: urllib.request.OpenerDirector, url: str, destination: Path) -> tuple[int, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    try:
        with opener.open(request, timeout=120) as response, temporary.open("wb") as output:
            total = response.headers.get("Content-Length")
            log(f"downloading {destination.name} content-length={total or 'unknown'}")
            next_report = 8 * 1024 * 1024
            while True:
                chunk = response.read(1024 * 256)
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
                if size >= next_report:
                    log(f"received {size // (1024 * 1024)} MiB")
                    next_report += 8 * 1024 * 1024
    except urllib.error.HTTPError as error:
        temporary.unlink(missing_ok=True)
        fail(f"http {error.code} while downloading", 2)
    except urllib.error.URLError as error:
        temporary.unlink(missing_ok=True)
        fail(f"download failed: {error.reason}", 2)
    temporary.replace(destination)
    return size, digest.hexdigest()


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Download a Play package APK or XAPK listed on APKCombo."
    )
    argument_parser.add_argument("--package", required=True, help="Android application id, such as com.google.android.gms")
    argument_parser.add_argument("--version", help="Exact versionName to select, such as 26.37.65")
    argument_parser.add_argument("--version-code", type=int, help="Exact versionCode to select")
    argument_parser.add_argument(
        "--min-sdk",
        type=int,
        help="Highest listed variant whose minSdk is less than or equal to this value. "
        "Omit to take the highest minSdk on the latest page.",
    )
    argument_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("cache/play-packages"),
        help="Directory for the downloaded file and its .json sidecar (default: cache/play-packages)",
    )
    argument_parser.add_argument(
        "--proxy",
        default=DEFAULT_PROXY,
        help=f"HTTP proxy for the overseas host (default: {DEFAULT_PROXY})",
    )
    argument_parser.add_argument("--no-proxy", action="store_true", help="Do not use a proxy")
    argument_parser.add_argument("--list", action="store_true", help="Print matching variants as JSON and do not download")
    argument_parser.add_argument("--force", action="store_true", help="Download again even when the cache file exists")
    return argument_parser


def main() -> None:
    args = parser().parse_args()
    proxy = None if args.no_proxy else args.proxy
    opener = build_opener(proxy)
    slug = find_slug(opener, args.package)
    page = f"{SITE}/{slug}/{args.package}/download/apk"
    if args.version:
        page = f"{SITE}/{slug}/{args.package}/download/phone-{urllib.parse.quote(args.version)}-apk"
    log(f"reading {page}")
    variants = parse_variants(fetch_text(opener, page))
    if args.version:
        variants = [item for item in variants if item.version_name == args.version]
    if not variants:
        fail(f"no variants parsed from {page}", 3)
    if args.list and args.version_code is None and args.min_sdk is None:
        json.dump([asdict(item) for item in variants], sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return
    selected = select_variant(variants, args.version, args.version_code, args.min_sdk)
    suffix = ".xapk" if selected.kind.upper() == "XAPK" else ".apk"
    filename = f"{args.package}-{selected.version_name}-{selected.version_code}{suffix}"
    destination = args.output_dir / filename
    sidecar = destination.with_suffix(destination.suffix + ".json")
    if destination.exists() and sidecar.exists() and not args.force:
        log(f"cache hit {destination}")
        sys.stdout.write(sidecar.read_text())
        if not sidecar.read_text().endswith("\n"):
            sys.stdout.write("\n")
        return
    size, sha256 = download(opener, SITE + selected.download_path, destination)
    record = {
        "package": args.package,
        "slug": slug,
        "source_page": page,
        **asdict(selected),
        "path": str(destination),
        "bytes": size,
        "sha256": sha256,
    }
    record.pop("download_path", None)
    text = json.dumps(record, ensure_ascii=False, indent=2) + "\n"
    sidecar.write_text(text)
    log(f"wrote {destination} sha256={sha256}")
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
