import struct

def read_uleb128(data, pos):
    val = 0; shift = 0
    while True:
        b = data[pos]; pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return val, pos

def gs(data, soff, idx):
    off = struct.unpack_from('<I', data, soff + idx*4)[0]
    l, p = read_uleb128(data, off)
    return data[p:p+l].decode('utf-8', errors='replace')

with open('mibro_apk/classes5.dex', 'rb') as f:
    data = f.read()

(ssize,soff,tsize,toff,psize,poff,fsize,foff,msize,moff,csize,coff,dsize,doff) = struct.unpack_from('<14I', data, 56)

target = 'Lcom/wakeup/license/Utils;'
target_ti = next(ti for ti in range(tsize)
                 if gs(data,soff,struct.unpack_from('<I',data,toff+ti*4)[0]) == target)

for ci in range(csize):
    coff2 = coff + ci*32
    if struct.unpack_from('<I', data, coff2)[0] != target_ti: continue
    cdo = struct.unpack_from('<I', data, coff2+24)[0]
    pos = cdo
    sfs, pos = read_uleb128(data, pos)
    ifs, pos = read_uleb128(data, pos)
    dms, pos = read_uleb128(data, pos)
    vms, pos = read_uleb128(data, pos)
    for _ in range(sfs+ifs):
        _, pos = read_uleb128(data, pos)
        _, pos = read_uleb128(data, pos)
    midx = 0
    for sec_name, sec_size in [('D', dms), ('V', vms)]:
        for _ in range(sec_size):
            d2, pos = read_uleb128(data, pos)
            midx += d2
            af, pos = read_uleb128(data, pos)
            code_off, pos = read_uleb128(data, pos)
            e = moff + midx*8
            _, _, nidx = struct.unpack_from('<HHI', data, e)
            mname = gs(data, soff, nidx)
            if code_off == 0:
                print(f'[{sec_name}] {mname} native/abstract')
                continue
            insns_size = struct.unpack_from('<I', data, code_off+12)[0]
            start = code_off + 16
            code = data[start:start+insns_size*2]
            strs = []; calls = []
            i = 0
            while i < len(code)-1:
                op = code[i]
                if op == 0x1a and i+3 < len(code):
                    strs.append(gs(data, soff, struct.unpack_from('<H', code, i+2)[0]))
                    i += 4
                elif op == 0x1b and i+5 < len(code):
                    strs.append(gs(data, soff, struct.unpack_from('<I', code, i+2)[0]))
                    i += 6
                elif op in (0x6e,0x6f,0x70,0x71,0x72,0x74,0x75,0x76,0x77,0x78) and i+5 < len(code):
                    mi = struct.unpack_from('<H', code, i+2)[0]
                    e2 = moff + mi*8
                    ci2, _, ni2 = struct.unpack_from('<HHI', data, e2)
                    cn = gs(data, soff, struct.unpack_from('<I', data, toff+ci2*4)[0])
                    mn = gs(data, soff, ni2)
                    calls.append(mn)
                    i += 6
                else:
                    i += 2
            print(f'[{sec_name}] {mname}')
            if strs:
                print(f'  strings: {strs}')
            if calls:
                print(f'  calls:   {calls}')
    break
