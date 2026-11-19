#!/usr/bin/env python3
"""Build the synthetic evidence file for the fictional Harbor Lab demo case.

SYNTHETIC DATA ONLY. The file is a small binary blob that imitates a slice of a disk image
from the fictional workstation WS01. It contains harmless embedded files (a PNG, a PDF and
a ZIP archive), a text log of fictional activity and a UTF-16LE PowerShell command line whose
encoded part decodes to a harmless message. Nothing in it is executable or malicious.

Random filler bytes come from a fixed seed, and the ZIP archive is stored without compression,
so the output is byte-for-byte reproducible on any machine.

Outputs (in --out-dir):
    ws01_triage_synthetic.bin          the evidence file
    ws01_triage_synthetic.bin.sha256   its SHA-256 in `sha256sum` format
    evidence_layout.json               ground truth: what is stored at which offset
"""

import argparse
import base64
import hashlib
import io
import json
import random
import zipfile
from pathlib import Path

SEED = 20260314
BLOCK = 512  # every embedded object starts on a 512-byte boundary, like on a disk
EVIDENCE_NAME = "ws01_triage_synthetic.bin"

# A standard 1x1 pixel PNG image.
PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

ATTACKER_IP = "203.0.113.45"  # RFC 5737 documentation address
ENCODED_PAYLOAD = base64.b64encode('Write-Output "synthetic training event - harmless"'.encode("utf-16-le")).decode("ascii")

ARTIFACT_LOG = f"""== SYNTHETIC ARTIFACT LOG (training data, not from a real system) ==
host=WS01 user=HARBOR\\jdoe
[2026-03-14T11:29:47Z] DOC_OPENED   C:\\Users\\jdoe\\Downloads\\Invoice_March.docm
[2026-03-14T11:30:14Z] PROC_START   WINWORD.EXE -> cmd.exe -> powershell.exe
[2026-03-14T11:30:16Z] NET_CONNECT  powershell.exe 10.10.10.20 -> {ATTACKER_IP}:443
[2026-03-14T11:30:17Z] FILE_CREATED C:\\Users\\jdoe\\AppData\\Local\\Temp\\harbor_update.js
[2026-03-14T11:30:20Z] PROC_START   wscript.exe C:\\Users\\jdoe\\AppData\\Local\\Temp\\harbor_update.js
[2026-03-14T11:31:20Z] NET_CONNECT  wscript.exe 10.10.10.20 -> {ATTACKER_IP}:443 (repeats about every 60 seconds)
[2026-03-14T11:36:40Z] PROC_START   wscript.exe -> whoami.exe, ipconfig.exe, net.exe
== END OF SYNTHETIC ARTIFACT LOG ==
"""

JS_FILE = f"""// SYNTHETIC SAMPLE - harmless text, not a real script.
// It exists only so that a file-carving tool has something to find.
// Fictional staging address used in the Harbor Lab scenario:
// http://{ATTACKER_IP}/stage2
var synthetic = true;
"""

NOTES_FILE = """SYNTHETIC TRAINING FILE - harmless.
Harbor Lab fictional case. Fictional contact: billing@invoices-harbor.test
"""


def make_pdf():
    """A tiny PDF with a correct cross-reference table."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Contents 4 0 R /Resources << >> >>",
    ]
    stream = b"% SYNTHETIC invoice placeholder - harmless"
    objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref_at = out.tell()
    out.write(b"xref\n0 %d\n" % (len(objects) + 1))
    out.write(b"0000000000 65535 f \n")
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref_at))
    return out.getvalue()


def make_zip():
    """A ZIP archive with fixed timestamps and no compression, so it is reproducible."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, text in (("notes.txt", NOTES_FILE), ("harbor_update.js", JS_FILE)):
            info = zipfile.ZipInfo(name, date_time=(2026, 3, 14, 11, 30, 17))
            info.external_attr = 0o644 << 16
            archive.writestr(info, text)
    return buffer.getvalue()


def filler(rng, length):
    return rng.getrandbits(8 * length).to_bytes(length, "little")


def build():
    rng = random.Random(SEED)
    blob = bytearray(b"HARBOR-SYNTH-001\x00\x00\x00\x00")
    layout = []

    def add(name, kind, data, note):
        # Pad to the next block boundary with random filler, then append the object.
        padding = (-len(blob)) % BLOCK
        blob.extend(filler(rng, padding))
        layout.append({"name": name, "type": kind, "offset": len(blob), "length": len(data), "note": note})
        blob.extend(data)

    def add_filler(length):
        padding = (-len(blob)) % BLOCK
        blob.extend(filler(rng, padding + length))

    add_filler(4096)
    add("artifact_log.txt", "ASCII text", ARTIFACT_LOG.encode("ascii"), "Fictional activity log with UTC timestamps")
    add_filler(6144)
    add("invoice_icon.png", "PNG image", PNG_BYTES, "Harmless 1x1 image; carving target")
    add_filler(5120)
    add("invoice_placeholder.pdf", "PDF document", make_pdf(), "Tiny PDF; carving target")
    add_filler(7168)
    add("download_bundle.zip", "ZIP archive", make_zip(), "Contains notes.txt and harbor_update.js (both harmless text)")
    add_filler(4096)
    command = (f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {ENCODED_PAYLOAD}").encode("utf-16-le")
    add("powershell_command_utf16le.bin", "UTF-16LE text", command,
        "Command line as Windows stores it; the encoded part decodes to a harmless message")
    add_filler(3072)
    add("footer.txt", "ASCII text", b"END-OF-SYNTHETIC-EVIDENCE\n", "Marks the end of the file")
    blob.extend(filler(rng, (-len(blob)) % BLOCK))
    return bytes(blob), layout


def main():
    parser = argparse.ArgumentParser(description="Build the synthetic Harbor Lab evidence file.")
    parser.add_argument("--out-dir", default="evidence", help="directory to write to (default: evidence)")
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    blob, layout = build()
    digest = hashlib.sha256(blob).hexdigest()
    (out_dir / EVIDENCE_NAME).write_bytes(blob)
    (out_dir / f"{EVIDENCE_NAME}.sha256").write_text(f"{digest}  {EVIDENCE_NAME}\n", encoding="utf-8")
    with (out_dir / "evidence_layout.json").open("w", encoding="utf-8", newline="\n") as handle:
        json.dump({"file": EVIDENCE_NAME, "size_bytes": len(blob), "sha256": digest, "synthetic": True, "objects": layout},
                  handle, indent=2)
        handle.write("\n")
    print(f"wrote {out_dir / EVIDENCE_NAME} ({len(blob)} bytes)")
    print(f"sha256 {digest}")


if __name__ == "__main__":
    main()
