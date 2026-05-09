"""
Find getAuthCodeVersion1/2 as method names in DEX,
then disassemble the method body to find the auth algorithm.
"""

import struct
import sys

DEX_FILE = "mibro_apk/classes3.dex"

TARGET_METHOD_NAMES = {
    "getAuthCodeVersion1",
    "getAuthCodeVersion2",
}

TARGET_FIELD_NAMES = {
    "deviceKey",
    "deviceKeyBytes",
}


def read_uleb128(data, pos):
    val = 0
    shift = 0
    while True:
        b = data[pos]; pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, pos


def get_string(data, string_ids_off, idx):
    off = struct.unpack_from("<I", data, string_ids_off + idx * 4)[0]
    length, pos = read_uleb128(data, off)
    return data[pos:pos + length].decode("utf-8", errors="replace")


def parse_header(data):
    (string_ids_size, string_ids_off,
     type_ids_size, type_ids_off,
     proto_ids_size, proto_ids_off,
     field_ids_size, field_ids_off,
     method_ids_size, method_ids_off,
     class_defs_size, class_defs_off,
     data_size, data_off) = struct.unpack_from("<14I", data, 56)
    return {
        "data": data,
        "string_ids_size": string_ids_size, "string_ids_off": string_ids_off,
        "type_ids_size": type_ids_size, "type_ids_off": type_ids_off,
        "method_ids_size": method_ids_size, "method_ids_off": method_ids_off,
        "field_ids_size": field_ids_size, "field_ids_off": field_ids_off,
        "class_defs_size": class_defs_size, "class_defs_off": class_defs_off,
    }


def find_string_indices(dex, targets):
    data, soff, ssize = dex["data"], dex["string_ids_off"], dex["string_ids_size"]
    result = {}
    for i in range(ssize):
        s = get_string(data, soff, i)
        if s in targets:
            result[s] = i
    return result


def find_method_indices(dex, name_indices):
    """Find all method_id_items where name_idx is in name_indices."""
    data = dex["data"]
    moff = dex["method_ids_off"]
    msize = dex["method_ids_size"]
    soff = dex["string_ids_off"]
    found = []
    for i in range(msize):
        entry_off = moff + i * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, entry_off)
        if name_idx in name_indices.values():
            name = get_string(data, soff, name_idx)
            # get class name
            type_ids_off = dex["type_ids_off"]
            class_name_idx = struct.unpack_from("<I", data, type_ids_off + class_idx * 4)[0]
            class_name = get_string(data, soff, class_name_idx)
            found.append((i, class_idx, class_name, name_idx, name))
    return found


def find_field_indices(dex, name_indices):
    """Find all field_id_items where name_idx is in name_indices."""
    data = dex["data"]
    foff = dex["field_ids_off"]
    fsize = dex["field_ids_size"]
    soff = dex["string_ids_off"]
    type_ids_off = dex["type_ids_off"]
    found = []
    for i in range(fsize):
        entry_off = foff + i * 8
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", data, entry_off)
        if name_idx in name_indices.values():
            name = get_string(data, soff, name_idx)
            class_name_idx = struct.unpack_from("<I", data, type_ids_off + class_idx * 4)[0]
            class_name = get_string(data, soff, class_name_idx)
            found.append((i, class_idx, class_name, name_idx, name))
    return found


def find_and_disasm_method_code(dex, target_method_indices):
    """Scan class_def_items, find the code_item for target method indices."""
    data = dex["data"]
    soff = dex["string_ids_off"]
    type_ids_off = dex["type_ids_off"]
    class_defs_off = dex["class_defs_off"]
    class_defs_size = dex["class_defs_size"]
    target_set = set(target_method_indices)

    for ci in range(class_defs_size):
        cdef_off = class_defs_off + ci * 32
        class_idx = struct.unpack_from("<I", data, cdef_off)[0]
        class_data_off = struct.unpack_from("<I", data, cdef_off + 24)[0]
        if class_data_off == 0:
            continue

        try:
            pos = class_data_off
            static_fields_size, pos = read_uleb128(data, pos)
            instance_fields_size, pos = read_uleb128(data, pos)
            direct_methods_size, pos = read_uleb128(data, pos)
            virtual_methods_size, pos = read_uleb128(data, pos)

            for _ in range(static_fields_size + instance_fields_size):
                _, pos = read_uleb128(data, pos)
                _, pos = read_uleb128(data, pos)

            method_idx_diff = 0
            for section_size in [direct_methods_size, virtual_methods_size]:
                for _ in range(section_size):
                    diff, pos = read_uleb128(data, pos)
                    method_idx_diff += diff
                    access_flags, pos = read_uleb128(data, pos)
                    code_off, pos = read_uleb128(data, pos)

                    if method_idx_diff not in target_set or code_off == 0:
                        continue

                    # Found it! Parse code_item
                    print(f"\n{'='*70}")
                    print(f"Method index: {method_idx_diff}")
                    # Get method name
                    mentry = dex["method_ids_off"] + method_idx_diff * 8
                    _, _, name_idx = struct.unpack_from("<HHI", data, mentry)
                    mname = get_string(data, soff, name_idx)
                    cn_idx = struct.unpack_from("<I", data, type_ids_off + class_idx * 4)[0]
                    cname = get_string(data, soff, cn_idx)
                    print(f"Method: {cname}.{mname}")
                    print(f"Access flags: 0x{access_flags:04x}")

                    regs, ins, outs, tries = struct.unpack_from("<4H", data, code_off)
                    insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
                    insns_off = code_off + 16
                    print(f"Registers: {regs}, insns_size: {insns_size} code-units ({insns_size*2} bytes)")
                    print(f"Code bytes [{insns_off:08x}..{insns_off+insns_size*2:08x}]:")
                    print()

                    # Full disassembly
                    disasm_full(data, dex, insns_off, insns_size * 2)

        except Exception as e:
            continue


def disasm_full(data, dex, start, length):
    soff = dex["string_ids_off"]
    moff = dex["method_ids_off"]
    foff = dex["field_ids_off"]
    type_ids_off = dex["type_ids_off"]

    def gs(idx):
        try: return get_string(data, soff, idx)
        except: return f"str@{idx}"

    def gm(idx):
        try:
            e = moff + idx * 8
            ci, pi, ni = struct.unpack_from("<HHI", data, e)
            return f"{gs(struct.unpack_from('<I', data, type_ids_off + ci * 4)[0])}.{gs(ni)}"
        except: return f"method@{idx}"

    def gf(idx):
        try:
            e = foff + idx * 8
            ci, ti, ni = struct.unpack_from("<HHI", data, e)
            return f"{gs(struct.unpack_from('<I', data, type_ids_off + ci * 4)[0])}.{gs(ni)}"
        except: return f"field@{idx}"

    def gt(idx):
        try:
            ni = struct.unpack_from("<I", data, type_ids_off + idx * 4)[0]
            return gs(ni)
        except: return f"type@{idx}"

    i = 0
    code = data[start:start + length]
    while i < len(code):
        op = code[i]
        abs_off = start + i
        try:
            if op == 0x00:  # nop
                print(f"  [{abs_off:08x}] nop")
                i += 2
            elif op == 0x01:  # move
                print(f"  [{abs_off:08x}] move v{code[i+1]&0xf}, v{(code[i+1]>>4)&0xf}")
                i += 2
            elif op in (0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d):
                print(f"  [{abs_off:08x}] move-wide/result op={op:02x} v{code[i+1]}")
                i += 2
            elif op == 0x0e:  # return-void
                print(f"  [{abs_off:08x}] return-void")
                i += 2
            elif op == 0x0f:  # return
                print(f"  [{abs_off:08x}] return v{code[i+1]}")
                i += 2
            elif op == 0x10:  # return-wide
                print(f"  [{abs_off:08x}] return-wide v{code[i+1]}")
                i += 2
            elif op == 0x11:  # return-object
                print(f"  [{abs_off:08x}] return-object v{code[i+1]}")
                i += 2
            elif op in (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19):
                if i + 3 < len(code):
                    val = struct.unpack_from("<H", code, i+2)[0]
                    print(f"  [{abs_off:08x}] const op={op:02x} v{code[i+1]}, #{val}")
                i += 4
            elif op == 0x1a:  # const-string
                if i + 3 < len(code):
                    reg = code[i+1]
                    idx = struct.unpack_from("<H", code, i+2)[0]
                    s = gs(idx)
                    print(f"  [{abs_off:08x}] const-string v{reg}, \"{s}\"")
                i += 4
            elif op == 0x1b:  # const-string/jumbo
                if i + 5 < len(code):
                    reg = code[i+1]
                    idx = struct.unpack_from("<I", code, i+2)[0]
                    s = gs(idx)
                    print(f"  [{abs_off:08x}] const-string/jumbo v{reg}, \"{s}\"")
                i += 6
            elif op == 0x1c:  # const-class
                if i + 3 < len(code):
                    reg = code[i+1]
                    idx = struct.unpack_from("<H", code, i+2)[0]
                    print(f"  [{abs_off:08x}] const-class v{reg}, {gt(idx)}")
                i += 4
            elif op in (0x1d, 0x1e):
                print(f"  [{abs_off:08x}] monitor op={op:02x} v{code[i+1]}")
                i += 2
            elif op == 0x1f:  # check-cast
                if i + 3 < len(code):
                    idx = struct.unpack_from("<H", code, i+2)[0]
                    print(f"  [{abs_off:08x}] check-cast v{code[i+1]}, {gt(idx)}")
                i += 4
            elif op == 0x20:  # instance-of
                if i + 3 < len(code):
                    print(f"  [{abs_off:08x}] instance-of v{code[i+1]&0xf}, v{(code[i+1]>>4)&0xf}")
                i += 4
            elif op in (0x21, 0x22):  # array-length, new-instance
                if i + 3 < len(code):
                    idx = struct.unpack_from("<H", code, i+2)[0]
                    label = "array-length" if op == 0x21 else "new-instance"
                    print(f"  [{abs_off:08x}] {label} v{code[i+1]}, {gt(idx)}")
                i += 4
            elif op in (0x23,):  # new-array
                if i + 3 < len(code):
                    idx = struct.unpack_from("<H", code, i+2)[0]
                    print(f"  [{abs_off:08x}] new-array v{code[i+1]&0xf}, v{(code[i+1]>>4)&0xf}, {gt(idx)}")
                i += 4
            elif op in range(0x2d, 0x32):
                print(f"  [{abs_off:08x}] cmp op={op:02x} v{code[i+1]}, v{code[i+2] if i+2<len(code) else '?'}")
                i += 4
            elif op in range(0x32, 0x38):  # if-xx
                if i + 3 < len(code):
                    off = struct.unpack_from("<h", code, i+2)[0]
                    print(f"  [{abs_off:08x}] if op={op:02x} v{code[i+1]&0xf}, v{(code[i+1]>>4)&0xf}, offset={off:+d} → [{abs_off+off*2:08x}]")
                i += 4
            elif op in (0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d):  # if-xxz
                if i + 3 < len(code):
                    off = struct.unpack_from("<h", code, i+2)[0]
                    print(f"  [{abs_off:08x}] ifz op={op:02x} v{code[i+1]}, offset={off:+d} → [{abs_off+off*2:08x}]")
                i += 4
            elif op in range(0x44, 0x52):  # aget/aput
                print(f"  [{abs_off:08x}] array-op op={op:02x}")
                i += 4
            elif op in range(0x52, 0x6e):  # iget/iput/sget/sput
                if i + 3 < len(code):
                    idx = struct.unpack_from("<H", code, i+2)[0]
                    fname = gf(idx)
                    label = {0x52:"iget",0x53:"iget-wide",0x54:"iget-object",0x55:"iget-boolean",
                              0x58:"iput",0x59:"iput-wide",0x5a:"iput-object",
                              0x60:"sget",0x61:"sget-wide",0x62:"sget-object",0x63:"sget-boolean",
                              0x67:"sput",0x68:"sput-wide",0x69:"sput-object",0x6a:"sput-boolean"}.get(op, f"op{op:02x}")
                    print(f"  [{abs_off:08x}] {label} v{code[i+1]&0xf}, {fname}")
                i += 4
            elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72):  # invoke-*
                if i + 5 < len(code):
                    cnt_reg = code[i+1]
                    midx = struct.unpack_from("<H", code, i+2)[0]
                    regs = struct.unpack_from("<H", code, i+4)[0]
                    labels = {0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",0x71:"invoke-static",0x72:"invoke-interface"}
                    print(f"  [{abs_off:08x}] {labels.get(op,f'invoke{op:02x}')} {{{cnt_reg}}}, {gm(midx)}")
                i += 6
            elif op in (0x74, 0x75, 0x76, 0x77, 0x78):  # invoke-*/range
                if i + 5 < len(code):
                    cnt = code[i+1]
                    midx = struct.unpack_from("<H", code, i+2)[0]
                    first_reg = struct.unpack_from("<H", code, i+4)[0]
                    labels = {0x74:"invoke-virtual/range",0x75:"invoke-super/range",0x76:"invoke-direct/range",0x77:"invoke-static/range",0x78:"invoke-interface/range"}
                    print(f"  [{abs_off:08x}] {labels.get(op,f'invoke-range{op:02x}')} v{first_reg}..v{first_reg+cnt-1}, {gm(midx)}")
                i += 6
            elif op in (0x0a, 0x0b, 0x0c):  # move-result*
                print(f"  [{abs_off:08x}] move-result op={op:02x} v{code[i+1]}")
                i += 2
            elif op == 0xa8:  # move-result
                print(f"  [{abs_off:08x}] move-result-object v{code[i+1]}")
                i += 2
            elif op in (0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf):
                print(f"  [{abs_off:08x}] move-result* op={op:02x} v{code[i+1]}")
                i += 2
            else:
                # raw bytes fallback
                raw = code[i:min(i+6, len(code))].hex()
                print(f"  [{abs_off:08x}] ? op={op:02x} [{raw}]")
                i += 2
        except Exception as e:
            print(f"  [{abs_off:08x}] ERROR at i={i}: {e}")
            i += 2


if __name__ == "__main__":
    with open(DEX_FILE, "rb") as f:
        data = f.read()

    dex = parse_header(data)

    print(f"DEX: {DEX_FILE}")
    print(f"Strings: {dex['string_ids_size']}, Methods: {dex['method_ids_size']}")

    all_targets = TARGET_METHOD_NAMES | TARGET_FIELD_NAMES | {"AES/ECB/PKCS5Padding"}
    string_indices = find_string_indices(dex, all_targets)
    print(f"\nString indices found:")
    for name, idx in sorted(string_indices.items(), key=lambda x: x[1]):
        print(f"  [{idx:6d}] {name!r}")

    method_name_indices = {k: v for k, v in string_indices.items() if k in TARGET_METHOD_NAMES}
    field_name_indices = {k: v for k, v in string_indices.items() if k in TARGET_FIELD_NAMES}

    print(f"\nSearching method_ids for {list(method_name_indices.keys())}...")
    method_hits = find_method_indices(dex, method_name_indices)
    for mid, cid, cname, nid, name in method_hits:
        print(f"  method_id[{mid}]: {cname}.{name}")

    print(f"\nSearching field_ids for {list(field_name_indices.keys())}...")
    field_hits = find_field_indices(dex, field_name_indices)
    for fid, cid, cname, nid, name in field_hits:
        print(f"  field_id[{fid}]: {cname}.{name}")

    if method_hits:
        target_method_ids = {mid for mid, *_ in method_hits}
        print(f"\nDisassembling methods: {target_method_ids}")
        find_and_disasm_method_code(dex, target_method_ids)
    else:
        print("\nNo methods found with those names.")
