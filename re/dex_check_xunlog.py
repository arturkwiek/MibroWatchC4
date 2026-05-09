"""Check what XunLogUtil.e does (is it suppressed in release?)"""
import struct, os, sys

DEX_DIR = "mibro_apk"
TARGET_CLASS = "Lcom/xiaoxun/xunoversea/mibrofit/log/XunLogUtil;"


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
    (ss,so,ts,to,ps,po,fs,fo,ms,mo,cs,co,ds,doff) = struct.unpack_from("<14I", data, 56)
    return {"data":data,"ss":ss,"so":so,"ts":ts,"to":to,"ms":ms,"mo":mo,"fs":fs,"fo":fo,"cs":cs,"co":co}


def find_class(dex, target_name):
    data, so, to, co, cs = dex["data"], dex["so"], dex["to"], dex["co"], dex["cs"]
    target_ti = None
    for ti in range(dex["ts"]):
        ni = struct.unpack_from("<I", data, to + ti*4)[0]
        if get_string(data, so, ni) == target_name:
            target_ti = ti; break
    if target_ti is None: return None

    for ci in range(cs):
        coff = co + ci * 32
        if struct.unpack_from("<I", data, coff)[0] != target_ti: continue
        cdo = struct.unpack_from("<I", data, coff + 24)[0]
        if not cdo: return []
        methods = []
        pos = cdo
        try:
            sfs, pos = read_uleb128(data, pos)
            ifs, pos = read_uleb128(data, pos)
            dms, pos = read_uleb128(data, pos)
            vms, pos = read_uleb128(data, pos)
            for _ in range(sfs+ifs):
                _, pos = read_uleb128(data, pos)
                _, pos = read_uleb128(data, pos)
            midx = 0
            for sec in [dms, vms]:
                for _ in range(sec):
                    d, pos = read_uleb128(data, pos)
                    midx += d
                    af, pos = read_uleb128(data, pos)
                    code_off, pos = read_uleb128(data, pos)
                    e = dex["mo"] + midx*8
                    _, _, nidx = struct.unpack_from("<HHI", data, e)
                    mname = get_string(data, so, nidx)
                    methods.append((midx, mname, af, code_off))
        except: pass
        return methods
    return None


def dump_code(data, dex, code_off, max_bytes=256):
    if not code_off: return "(abstract)"
    so = dex["so"]
    insns_size = struct.unpack_from("<I", data, code_off+12)[0]
    start = code_off + 16
    code = data[start:start+insns_size*2]
    out = []
    i = 0
    while i < len(code) and i < max_bytes:
        op = code[i]
        abs_off = start + i
        if op == 0x0e:
            out.append(f"  [{abs_off:08x}] return-void"); i+=2
        elif op == 0x0f:
            out.append(f"  [{abs_off:08x}] return v{code[i+1]}"); i+=2
        elif op == 0x11:
            out.append(f"  [{abs_off:08x}] return-object v{code[i+1]}"); i+=2
        elif op == 0x1a:
            idx = struct.unpack_from("<H", code, i+2)[0]
            s = get_string(data, so, idx)
            out.append(f"  [{abs_off:08x}] const-string v{code[i+1]}, \"{s}\""); i+=4
        elif op == 0x1b:
            idx = struct.unpack_from("<I", code, i+2)[0]
            s = get_string(data, so, idx)
            out.append(f"  [{abs_off:08x}] const-string/jumbo v{code[i+1]}, \"{s}\""); i+=6
        elif op in (0x6e,0x6f,0x70,0x71,0x72):
            if i+5<len(code):
                midx = struct.unpack_from("<H", code, i+2)[0]
                e = dex["mo"] + midx*8
                ci2, pi, nidx = struct.unpack_from("<HHI", data, e)
                cn_idx = struct.unpack_from("<I", data, dex["to"]+ci2*4)[0]
                cname = get_string(data, so, cn_idx)
                mname = get_string(data, so, nidx)
                labels = {0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",0x71:"invoke-static",0x72:"invoke-interface"}
                out.append(f"  [{abs_off:08x}] {labels[op]} {cname}.{mname}"); i+=6
            else: i+=2
        elif op in (0x74,0x75,0x76,0x77,0x78):
            if i+5<len(code):
                midx = struct.unpack_from("<H", code, i+2)[0]
                e = dex["mo"] + midx*8
                ci2, pi, nidx = struct.unpack_from("<HHI", data, e)
                cn_idx = struct.unpack_from("<I", data, dex["to"]+ci2*4)[0]
                cname = get_string(data, so, cn_idx)
                mname = get_string(data, so, nidx)
                labels = {0x74:"invoke-virtual/range",0x75:"invoke-super/range",0x76:"invoke-direct/range",0x77:"invoke-static/range",0x78:"invoke-interface/range"}
                out.append(f"  [{abs_off:08x}] {labels[op]} {cname}.{mname}"); i+=6
            else: i+=2
        elif op in (0x38,0x39,0x3a,0x3b,0x3c,0x3d):
            if i+3<len(code):
                off2 = struct.unpack_from("<h", code, i+2)[0]
                out.append(f"  [{abs_off:08x}] ifz op={op:02x} offset={off2:+d}"); i+=4
            else: i+=2
        elif op in (0x32,0x33,0x34,0x35,0x36,0x37):
            if i+3<len(code):
                off2 = struct.unpack_from("<h", code, i+2)[0]
                out.append(f"  [{abs_off:08x}] if op={op:02x} offset={off2:+d}"); i+=4
            else: i+=2
        elif op in (0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d):
            if i+3<len(code):
                fidx = struct.unpack_from("<H", code, i+2)[0]
                e = dex["fo"] + fidx*8
                ci2, ti2, nidx = struct.unpack_from("<HHI", data, e)
                fname = get_string(data, so, nidx)
                out.append(f"  [{abs_off:08x}] iget/iput field {fname}"); i+=4
            else: i+=2
        elif op in (0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b):
            if i+3<len(code):
                fidx = struct.unpack_from("<H", code, i+2)[0]
                e = dex["fo"] + fidx*8
                ci2, ti2, nidx = struct.unpack_from("<HHI", data, e)
                fname = get_string(data, so, nidx)
                out.append(f"  [{abs_off:08x}] sget/sput field {fname}"); i+=4
            else: i+=2
        elif op == 0x22:
            if i+3<len(code):
                tidx = struct.unpack_from("<H", code, i+2)[0]
                tn_idx = struct.unpack_from("<I", data, dex["to"]+tidx*4)[0]
                tname = get_string(data, so, tn_idx)
                out.append(f"  [{abs_off:08x}] new-instance v{code[i+1]}, {tname}"); i+=4
            else: i+=2
        elif op in (0x0a,0x0b,0x0c):
            out.append(f"  [{abs_off:08x}] move-result* op={op:02x} v{code[i+1]}"); i+=2
        elif op == 0x12:
            out.append(f"  [{abs_off:08x}] const/4 v{code[i+1]&0xf}, #{(code[i+1]>>4)&0xf}"); i+=2
        elif op == 0x13:
            val = struct.unpack_from("<h", code, i+2)[0]
            out.append(f"  [{abs_off:08x}] const/16 v{code[i+1]}, #{val}"); i+=4
        else:
            out.append(f"  [{abs_off:08x}] op={op:02x} [{code[i:min(i+4,len(code))].hex()}]"); i+=2
    return "\n".join(out)


for fname in sorted(os.listdir(DEX_DIR)):
    if not fname.endswith(".dex"): continue
    path = os.path.join(DEX_DIR, fname)
    with open(path, "rb") as f:
        data = f.read()
    dex = parse_header(data)
    if not dex: continue
    methods = find_class(dex, TARGET_CLASS)
    if methods is None: continue

    print(f"\nFOUND in {fname}: {TARGET_CLASS}")
    print(f"Methods ({len(methods)}):")
    for midx, mname, af, code_off in methods:
        print(f"\n  [{midx}] {mname} (flags=0x{af:04x})")
        print(dump_code(data, dex, code_off))
    break
else:
    print("XunLogUtil not found in any DEX")
