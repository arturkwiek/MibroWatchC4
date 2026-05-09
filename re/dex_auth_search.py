"""
Search all DEX files for the auth key algorithm.
Finds string references to "deviceKeyBytes", "AES/ECB/PKCS5Padding",
"getAuthCodeVersion1/2" in method bytecode and disassembles context.
"""

import struct
import sys
import os

TARGET_STRINGS = {
    "deviceKey",
    "deviceKeyBytes",
    "AES/ECB/PKCS5Padding",
    "getAuthCodeVersion1",
    "getAuthCodeVersion2",
    "authKey",
    "authCode",
    "authVersion",
    "authSecret",
}

DEX_DIR = "mibro_apk"


def parse_dex(data: bytes) -> dict:
    """Parse DEX header and return useful sections."""
    # DEX header: magic(8) + checksum(4) + SHA1(20) + file_size(4) + header_size(4)
    # + endian_tag(4) + link_size(4) + link_off(4) + map_off(4)
    # + string_ids_size(4) + string_ids_off(4)
    # + type_ids_size(4) + type_ids_off(4)
    # + proto_ids_size(4) + proto_ids_off(4)
    # + field_ids_size(4) + field_ids_off(4)
    # + method_ids_size(4) + method_ids_off(4)
    # + class_defs_size(4) + class_defs_off(4)
    # + data_size(4) + data_off(4)
    if len(data) < 112:
        return {}

    magic = data[:8]
    if not (magic[:4] == b"dex\n" or magic[:3] == b"dex"):
        return {}

    (
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        field_ids_size, field_ids_off,
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
        data_size, data_off,
    ) = struct.unpack_from("<14I", data, 56)

    return {
        "data": data,
        "string_ids_size": string_ids_size,
        "string_ids_off": string_ids_off,
        "type_ids_size": type_ids_size,
        "type_ids_off": type_ids_off,
        "method_ids_size": method_ids_size,
        "method_ids_off": method_ids_off,
        "class_defs_size": class_defs_size,
        "class_defs_off": class_defs_off,
    }


def get_string(data: bytes, string_ids_off: int, idx: int) -> str:
    """Get string by index from DEX string table."""
    off = struct.unpack_from("<I", data, string_ids_off + idx * 4)[0]
    # ULEB128 length
    length = 0
    shift = 0
    pos = off
    while True:
        b = data[pos]
        pos += 1
        length |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return data[pos:pos + length].decode("utf-8", errors="replace")


def find_string_ids(dex: dict) -> dict:
    """Find indices of target strings."""
    data = dex["data"]
    size = dex["string_ids_size"]
    off = dex["string_ids_off"]
    found = {}
    for i in range(size):
        try:
            s = get_string(data, off, i)
            if s in TARGET_STRINGS:
                found[s] = i
                if len(found) == len(TARGET_STRINGS):
                    break
        except Exception:
            pass
    return found


def get_method_name(dex: dict, method_idx: int) -> str:
    data = dex["data"]
    method_ids_off = dex["method_ids_off"]
    # method_id_item: class_idx(2) + proto_idx(2) + name_idx(4)
    entry_off = method_ids_off + method_idx * 8
    if entry_off + 8 > len(data):
        return f"method_{method_idx}"
    class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, entry_off)
    try:
        return get_string(data, dex["string_ids_off"], name_idx)
    except Exception:
        return f"method_{method_idx}"


def get_type_name(dex: dict, type_idx: int) -> str:
    data = dex["data"]
    type_ids_off = dex["type_ids_off"]
    entry_off = type_ids_off + type_idx * 4
    if entry_off + 4 > len(data):
        return f"type_{type_idx}"
    name_idx = struct.unpack_from("<I", data, entry_off)[0]
    try:
        return get_string(data, dex["string_ids_off"], name_idx)
    except Exception:
        return f"type_{type_idx}"


def disasm_around(code_bytes: bytes, pos: int, window: int = 80) -> str:
    """Very rough disassembly of DEX bytecode bytes around a position."""
    start = max(0, pos - window)
    end = min(len(code_bytes), pos + window)
    chunk = code_bytes[start:end]
    lines = []
    i = 0
    while i < len(chunk):
        op = chunk[i]
        abs_pos = start + i
        if op == 0x1A:  # const-string
            if i + 3 < len(chunk):
                vAA = chunk[i + 1]
                idx = struct.unpack_from("<H", chunk, i + 2)[0]
                lines.append(f"  [{abs_pos:06x}] const-string v{vAA}, string@{idx}")
                i += 4
                continue
        elif op == 0x1B:  # const-string/jumbo
            if i + 5 < len(chunk):
                vAA = chunk[i + 1]
                idx = struct.unpack_from("<I", chunk, i + 2)[0]
                lines.append(f"  [{abs_pos:06x}] const-string/jumbo v{vAA}, string@{idx}")
                i += 6
                continue
        elif op == 0x71:  # invoke-virtual
            if i + 5 < len(chunk):
                meth_idx = struct.unpack_from("<H", chunk, i + 2)[0]
                lines.append(f"  [{abs_pos:06x}] invoke-virtual method@{meth_idx}")
                i += 6
                continue
        elif op == 0x70:  # invoke-direct
            if i + 5 < len(chunk):
                meth_idx = struct.unpack_from("<H", chunk, i + 2)[0]
                lines.append(f"  [{abs_pos:06x}] invoke-direct method@{meth_idx}")
                i += 6
                continue
        elif op == 0x6e:  # invoke-virtual/range
            if i + 5 < len(chunk):
                meth_idx = struct.unpack_from("<H", chunk, i + 2)[0]
                lines.append(f"  [{abs_pos:06x}] invoke-virtual/range method@{meth_idx}")
                i += 6
                continue
        elif op == 0x74:  # invoke-virtual/range  (alt opcode)
            if i + 5 < len(chunk):
                meth_idx = struct.unpack_from("<H", chunk, i + 2)[0]
                lines.append(f"  [{abs_pos:06x}] invoke-virtual/range method@{meth_idx}")
                i += 6
                continue
        elif op == 0x0E:  # return-void
            lines.append(f"  [{abs_pos:06x}] return-void")
            i += 2
            continue
        elif op == 0x11:  # return-object
            lines.append(f"  [{abs_pos:06x}] return-object v{chunk[i+1] if i+1<len(chunk) else '?'}")
            i += 2
            continue
        else:
            lines.append(f"  [{abs_pos:06x}] op={op:02x} ...")
            i += 2
            continue
        i += 2
    return "\n".join(lines)


def search_code_for_string_refs(data: bytes, string_ids: dict) -> list:
    """
    Scan all code units in DEX for const-string/const-string-jumbo instructions
    referencing our target strings. Return (file_offset, instruction, string_name, string_idx).
    """
    results = []
    idx_to_name = {v: k for k, v in string_ids.items()}

    # Scan entire file for 0x1A (const-string) followed by any register + LE16 string idx
    i = 0
    while i < len(data) - 3:
        op = data[i]
        if op == 0x1A:
            idx = struct.unpack_from("<H", data, i + 2)[0]
            if idx in idx_to_name:
                results.append((i, "const-string", idx_to_name[idx], idx))
        elif op == 0x1B:
            if i + 5 < len(data):
                idx = struct.unpack_from("<I", data, i + 2)[0]
                if idx in idx_to_name:
                    results.append((i, "const-string/jumbo", idx_to_name[idx], idx))
        i += 1

    return results


def find_code_item_containing(data: bytes, dex: dict, offset: int):
    """
    Scan class_def_items to find which method's code_item contains `offset`.
    Returns (class_name, method_name) or None.
    """
    class_defs_off = dex["class_defs_off"]
    class_defs_size = dex["class_defs_size"]

    for ci in range(class_defs_size):
        cdef_off = class_defs_off + ci * 32
        if cdef_off + 32 > len(data):
            break
        (class_idx, access_flags, superclass_idx, interfaces_off,
         source_file_idx, annotations_off, class_data_off, static_values_off
         ) = struct.unpack_from("<8I", data, cdef_off)

        if class_data_off == 0:
            continue

        try:
            # Parse class_data_item
            pos = class_data_off
            def uleb(pos):
                val = 0
                shift = 0
                while True:
                    b = data[pos]; pos += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                return val, pos

            static_fields_size, pos = uleb(pos)
            instance_fields_size, pos = uleb(pos)
            direct_methods_size, pos = uleb(pos)
            virtual_methods_size, pos = uleb(pos)

            # Skip fields
            for _ in range(static_fields_size + instance_fields_size):
                _, pos = uleb(pos)
                _, pos = uleb(pos)

            method_idx_diff = 0
            for methods_section in [direct_methods_size, virtual_methods_size]:
                for _ in range(methods_section):
                    diff, pos = uleb(pos)
                    method_idx_diff += diff
                    _, pos = uleb(pos)  # access_flags
                    code_off, pos = uleb(pos)

                    if code_off == 0:
                        continue

                    # code_item: registers_size(2) + ins_size(2) + outs_size(2) + tries_size(2) + debug_info_off(4) + insns_size(4)
                    if code_off + 16 > len(data):
                        continue
                    insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
                    code_start = code_off + 16
                    code_end = code_start + insns_size * 2

                    if code_start <= offset < code_end:
                        class_name = get_type_name(dex, class_idx)
                        method_name = get_method_name(dex, method_idx_diff)
                        return class_name, method_name, code_start, code_end
        except Exception:
            continue

    return None


def analyze_dex_file(dex_path: str):
    print(f"\n{'='*60}")
    print(f"Analyzing: {dex_path}")
    print('='*60)

    with open(dex_path, "rb") as f:
        data = f.read()

    dex = parse_dex(data)
    if not dex:
        print("  Not a valid DEX file")
        return

    print(f"  Strings: {dex['string_ids_size']}, Methods: {dex['method_ids_size']}")

    # Find target string indices
    string_ids = find_string_ids(dex)
    if not string_ids:
        print("  No target strings found")
        return

    print(f"  Found target strings:")
    for name, idx in sorted(string_ids.items(), key=lambda x: x[1]):
        print(f"    [{idx:6d}] {name!r}")

    # Search bytecode for references
    refs = search_code_for_string_refs(data, string_ids)
    if not refs:
        print("  No bytecode references found")
        return

    print(f"\n  Found {len(refs)} bytecode references:")
    seen_methods = set()
    for (file_off, instr, sname, sidx) in refs:
        result = find_code_item_containing(data, dex, file_off)
        if result:
            class_name, method_name, code_start, code_end = result
            key = (class_name, method_name)
            print(f"\n  @{file_off:08x}: {instr} {sname!r}")
            print(f"    In: {class_name}.{method_name}")
            if key not in seen_methods:
                seen_methods.add(key)
                # Dump interesting bytecode from the method
                code_bytes = data[code_start:code_end]
                rel_off = file_off - code_start
                print(f"    Code range [{code_start:08x}..{code_end:08x}] ({code_end-code_start} bytes)")
                print(f"    Context disassembly:")
                # Find all const-string refs in this method
                j = 0
                while j < len(code_bytes):
                    op = code_bytes[j]
                    if op == 0x1A:
                        if j + 3 < len(code_bytes):
                            reg = code_bytes[j+1]
                            idx2 = struct.unpack_from("<H", code_bytes, j+2)[0]
                            name2 = string_ids.get(idx2, None)
                            if name2:
                                print(f"      [{code_start+j:08x}] const-string v{reg}, [{idx2}] {name2!r}")
                            j += 4; continue
                    elif op == 0x1B:
                        if j + 5 < len(code_bytes):
                            reg = code_bytes[j+1]
                            idx2 = struct.unpack_from("<I", code_bytes, j+2)[0]
                            name2 = string_ids.get(idx2, None)
                            if name2:
                                print(f"      [{code_start+j:08x}] const-string/jumbo v{reg}, [{idx2}] {name2!r}")
                            j += 6; continue
                    elif op == 0x70:  # invoke-direct
                        if j + 5 < len(code_bytes):
                            midx = struct.unpack_from("<H", code_bytes, j+2)[0]
                            mname = get_method_name(dex, midx)
                            print(f"      [{code_start+j:08x}] invoke-direct [{midx}] {mname}")
                        j += 6; continue
                    elif op == 0x71:  # invoke-virtual
                        if j + 5 < len(code_bytes):
                            midx = struct.unpack_from("<H", code_bytes, j+2)[0]
                            mname = get_method_name(dex, midx)
                            print(f"      [{code_start+j:08x}] invoke-virtual [{midx}] {mname}")
                        j += 6; continue
                    elif op == 0x6e:  # invoke-virtual/range
                        if j + 5 < len(code_bytes):
                            midx = struct.unpack_from("<H", code_bytes, j+2)[0]
                            mname = get_method_name(dex, midx)
                            print(f"      [{code_start+j:08x}] invoke-virtual/range [{midx}] {mname}")
                        j += 6; continue
                    elif op == 0x74:  # invoke-virtual/range
                        if j + 5 < len(code_bytes):
                            midx = struct.unpack_from("<H", code_bytes, j+2)[0]
                            mname = get_method_name(dex, midx)
                            print(f"      [{code_start+j:08x}] invoke-virtual/range [{midx}] {mname}")
                        j += 6; continue
                    elif op in (0x6f, 0x76, 0x77, 0x78):  # more invoke variants
                        if j + 5 < len(code_bytes):
                            midx = struct.unpack_from("<H", code_bytes, j+2)[0]
                            mname = get_method_name(dex, midx)
                            print(f"      [{code_start+j:08x}] invoke-X op={op:02x} [{midx}] {mname}")
                        j += 6; continue
                    j += 1
        else:
            print(f"  @{file_off:08x}: {instr} {sname!r}  (method not found)")


if __name__ == "__main__":
    dex_files = [
        os.path.join(DEX_DIR, f)
        for f in sorted(os.listdir(DEX_DIR))
        if f.endswith(".dex")
    ]
    for dex_path in dex_files:
        analyze_dex_file(dex_path)
