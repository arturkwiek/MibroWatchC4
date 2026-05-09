"""
Find WkLicenseMgr and WkWeChatNet full class analysis across all DEX files.
"""
import struct, os

DEX_DIR = "mibro_apk"
TARGETS = {
    "Lcom/wakeup/license/WkLicenseMgr;",
    "Lcom/xiaoxun/xunoversea/mibrofit/base/net/WkWeChatNet;",
    "Lcom/xiaoxun/xunoversea/mibrofit/base/net/WkWeChatNet$getAuthCodeVersion2$1;",
    "Lcom/xiaoxun/xunoversea/mibrofit/base/utils/encrypt/AESUtil;",
}


def read_uleb128(data, pos):
    val = 0; shift = 0
    while True:
        b = data[pos]; pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return val, pos


def get_string(data, soff, idx):
    off = struct.unpack_from("<I", data, soff + idx * 4)[0]
    length, pos = read_uleb128(data, off)
    return data[pos:pos+length].decode("utf-8", errors="replace")


def parse_header(data):
    if len(data) < 112: return None
    (ss, so, ts, to, ps, po, fs, fo, ms, mo, cs, co, ds, doff) = struct.unpack_from("<14I", data, 56)
    return {"data":data,"ss":ss,"so":so,"ts":ts,"to":to,"ms":ms,"mo":mo,"fs":fs,"fo":fo,"cs":cs,"co":co}


def find_class_in_dex(dex, target_class_names):
    data, so, to, co, cs = dex["data"], dex["so"], dex["to"], dex["co"], dex["cs"]

    # Build type→string map for targets
    target_type_indices = set()
    for ti in range(dex["ts"]):
        ni = struct.unpack_from("<I", data, to + ti*4)[0]
        s = get_string(data, so, ni)
        if s in target_class_names:
            target_type_indices.add(ti)

    found = {}
    for ci in range(cs):
        coff = co + ci * 32
        class_idx = struct.unpack_from("<I", data, coff)[0]
        if class_idx not in target_type_indices:
            continue

        class_data_off = struct.unpack_from("<I", data, coff + 24)[0]
        cn_idx = struct.unpack_from("<I", data, to + class_idx*4)[0]
        cname = get_string(data, so, cn_idx)

        methods = []
        if class_data_off == 0:
            found[cname] = []
            continue

        try:
            pos = class_data_off
            sfs, pos = read_uleb128(data, pos)
            ifs, pos = read_uleb128(data, pos)
            dms, pos = read_uleb128(data, pos)
            vms, pos = read_uleb128(data, pos)

            for _ in range(sfs + ifs):
                _, pos = read_uleb128(data, pos)
                _, pos = read_uleb128(data, pos)

            midx = 0
            for section in [dms, vms]:
                for _ in range(section):
                    diff, pos = read_uleb128(data, pos)
                    midx += diff
                    af, pos = read_uleb128(data, pos)
                    code_off, pos = read_uleb128(data, pos)

                    entry = dex["mo"] + midx * 8
                    _, _, nidx = struct.unpack_from("<HHI", data, entry)
                    mname = get_string(data, so, nidx)

                    methods.append({
                        "idx": midx,
                        "name": mname,
                        "flags": af,
                        "code_off": code_off,
                    })
        except Exception as e:
            pass

        found[cname] = methods

    return found


def dump_method_bytes(data, code_off, limit=200):
    """Dump raw bytes of a method's code_item for manual analysis."""
    if code_off == 0:
        return "(abstract/native)"
    regs, ins, outs, tries = struct.unpack_from("<4H", data, code_off)
    insns_size = struct.unpack_from("<I", data, code_off+12)[0]
    start = code_off + 16
    end = min(start + insns_size*2, len(data))
    raw = data[start:end]
    hex_lines = []
    for i in range(0, min(len(raw), limit), 16):
        chunk = raw[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"  {start+i:08x}: {hex_part:<47}  {asc_part}")
    return f"regs={regs} insns={insns_size}cu ({insns_size*2}B):\n" + "\n".join(hex_lines)


def extract_strings_from_method(data, dex, code_off):
    """Extract all string constants used in a method."""
    if code_off == 0: return []
    so = dex["so"]
    insns_size = struct.unpack_from("<I", data, code_off+12)[0]
    start = code_off + 16
    code = data[start:start+insns_size*2]
    strings = []
    i = 0
    while i < len(code)-3:
        op = code[i]
        if op == 0x1a:
            idx = struct.unpack_from("<H", code, i+2)[0]
            strings.append(get_string(data, so, idx))
            i += 4; continue
        elif op == 0x1b and i+5 < len(code):
            idx = struct.unpack_from("<I", code, i+2)[0]
            strings.append(get_string(data, so, idx))
            i += 6; continue
        i += 2
    return strings


if __name__ == "__main__":
    for fname in sorted(os.listdir(DEX_DIR)):
        if not fname.endswith(".dex"): continue
        path = os.path.join(DEX_DIR, fname)
        with open(path, "rb") as f:
            data = f.read()
        dex = parse_header(data)
        if not dex: continue

        found = find_class_in_dex(dex, TARGETS)
        if not found: continue

        print(f"\n{'='*70}")
        print(f"FILE: {fname}")
        for cname, methods in found.items():
            print(f"\n  CLASS: {cname}")
            print(f"  Methods ({len(methods)}):")
            for m in methods:
                strings = extract_strings_from_method(data, dex, m["code_off"])
                s_info = f"  strings={strings}" if strings else ""
                print(f"    [{m['idx']:5d}] {m['name']} (flags=0x{m['flags']:04x}, code_off=0x{m['code_off']:08x}){s_info}")
                if m["code_off"]:
                    print("    " + dump_method_bytes(data, m["code_off"], limit=128).replace("\n", "\n    "))
