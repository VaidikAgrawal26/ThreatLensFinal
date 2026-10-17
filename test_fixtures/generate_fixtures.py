"""Generate inert ThreatLens static-analysis fixtures (not malware).

The PE canary has no executable-image flag, no entry point, no imports, and no
code. Its only suspicious-looking content is inert API-name text in .rdata.
"""
from pathlib import Path
import struct

OUT = Path(__file__).resolve().parent
MARKERS = b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"


def build_inert_pe() -> bytes:
    pe_offset = 0x80
    file_alignment = 0x200
    section_alignment = 0x1000
    section_data = (
        b"THREATLENS STATIC TEST FIXTURE - INERT TEXT ONLY\x00"
        + MARKERS
        + b"No code, imports, process actions, persistence, or network activity.\x00"
    )
    raw_size = (len(section_data) + file_alignment - 1) // file_alignment * file_alignment
    section_data = section_data.ljust(raw_size, b"\x00")

    # DOS header: MZ signature and e_lfanew. Remaining fields are zero-filled.
    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0, 0x5A4D)
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    # PE32+ optional header. EntryPoint=0 and NumberOfRvaAndSizes=16.
    optional = bytearray()
    optional += struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0, 0, raw_size, 0, 0, 0x1000, 0x140000000,
        section_alignment, file_alignment,
        6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0,
        3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional += bytes(16 * 8)  # Empty data directories; notably no imports.
    assert len(optional) == 240, len(optional)

    # Deliberately omit IMAGE_FILE_EXECUTABLE_IMAGE (0x0002).
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0020)
    section = struct.pack(
        "<8sIIIIIIHHI", b".rdata\x00\x00", len(section_data), 0x1000,
        raw_size, 0x200, 0, 0, 0, 0, 0x40000040,
    )
    headers = bytearray(0x200)
    headers[:len(dos)] = dos
    cursor = pe_offset
    headers[cursor:cursor + 4] = b"PE\x00\x00"
    cursor += 4
    headers[cursor:cursor + len(coff)] = coff
    cursor += len(coff)
    headers[cursor:cursor + len(optional)] = optional
    cursor += len(optional)
    headers[cursor:cursor + len(section)] = section
    return bytes(headers) + section_data


def main() -> None:
    (OUT / "threatlens_yara_trigger_demo.dat").write_bytes(
        b"THREATLENS STATIC TEST FIXTURE - inert text, not malware.\n" + MARKERS
    )
    (OUT / "threatlens_clean_demo.dat").write_bytes(
        b"THREATLENS CLEAN TEST FIXTURE - inert text with no demo-rule markers.\n"
    )
    (OUT / "threatlens_inert_pe_canary.exe").write_bytes(build_inert_pe())
    print("Generated three inert static-analysis fixtures in:", OUT)
    print("Do not execute the .exe canary; it is only for upload/parser testing.")


if __name__ == "__main__":
    main()
