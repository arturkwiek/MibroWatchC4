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

target = 'Lcom/wakeup/license/WkLicenseMgr;'
target_ti = next(ti for ti in range(tsize)
                 if gs(data,soff,struct.unpack_from('<I',data,toff+ti*4)[0]) == target)

for ci in range(csize):
    coff2 = coff + ci*32
    if struct.unpack_from('<I', data, coff2)[0] != target_ti:
        continue
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
            regs = struct.unpack_from('<H', data, code_off)[0]
            insns_size = struct.unpack_from('<I', data, code_off+12)[0]
            start = code_off + 16
            code = data[start:start+insns_size*2]
            print(f'[{sec_name}] {mname} regs={regs} insns={insns_size}')
            i = 0
            while i < len(code)-1:
                op = code[i]; ab = start+i
                if op == 0x0e:
                    print(f'  {ab:08x} return-void'); i+=2
                elif op == 0x0f:
                    print(f'  {ab:08x} return v{code[i+1]}'); i+=2
                elif op == 0x11:
                    print(f'  {ab:08x} return-obj v{code[i+1]}'); i+=2
                elif op == 0x1a:
                    if i+3 < len(code):
                        s = gs(data, soff, struct.unpack_from('<H', code, i+2)[0])
                        print(f'  {ab:08x} const-str v{code[i+1]}, {s!r}')
                    i+=4
                elif op == 0x1b:
                    if i+5 < len(code):
                        s = gs(data, soff, struct.unpack_from('<I', code, i+2)[0])
                        print(f'  {ab:08x} const-str/j v{code[i+1]}, {s!r}')
                    i+=6
                elif op in (0x6e,0x6f,0x70,0x71,0x72):
                    if i+5 < len(code):
                        mi = struct.unpack_from('<H', code, i+2)[0]
                        e2 = moff+mi*8; ci2,_,ni2 = struct.unpack_from('<HHI', data, e2)
                        cn = gs(data, soff, struct.unpack_from('<I', data, toff+ci2*4)[0])
                        mn = gs(data, soff, ni2)
                        ops = {0x6e:'virt',0x6f:'super',0x70:'direct',0x71:'static',0x72:'iface'}
                        print(f'  {ab:08x} invoke-{ops[op]} {cn}.{mn}')
                    i+=6
                elif op in (0x74,0x75,0x76,0x77,0x78):
                    if i+5 < len(code):
                        mi = struct.unpack_from('<H', code, i+2)[0]
                        e2 = moff+mi*8; ci2,_,ni2 = struct.unpack_from('<HHI', data, e2)
                        cn = gs(data, soff, struct.unpack_from('<I', data, toff+ci2*4)[0])
                        mn = gs(data, soff, ni2)
                        ops = {0x74:'virt/r',0x75:'super/r',0x76:'direct/r',0x77:'static/r',0x78:'iface/r'}
                        print(f'  {ab:08x} invoke-{ops[op]} {cn}.{mn}')
                    i+=6
                elif op in (0x52,0x53,0x54,0x55,0x56,0x57):
                    if i+3 < len(code):
                        fi = struct.unpack_from('<H', code, i+2)[0]
                        e2 = foff+fi*8; fc,ft,fn = struct.unpack_from('<HHI', data, e2)
                        fcn = gs(data, soff, struct.unpack_from('<I', data, toff+fc*4)[0])
                        print(f'  {ab:08x} iget {fcn}.{gs(data,soff,fn)}')
                    i+=4
                elif op in (0x58,0x59,0x5a,0x5b,0x5c,0x5d):
                    if i+3 < len(code):
                        fi = struct.unpack_from('<H', code, i+2)[0]
                        e2 = foff+fi*8; fc,ft,fn = struct.unpack_from('<HHI', data, e2)
                        fcn = gs(data, soff, struct.unpack_from('<I', data, toff+fc*4)[0])
                        print(f'  {ab:08x} iput {fcn}.{gs(data,soff,fn)}')
                    i+=4
                elif op in (0x60,0x61,0x62,0x63,0x64,0x65,0x66):
                    if i+3 < len(code):
                        fi = struct.unpack_from('<H', code, i+2)[0]
                        e2 = foff+fi*8; fc,ft,fn = struct.unpack_from('<HHI', data, e2)
                        fcn = gs(data, soff, struct.unpack_from('<I', data, toff+fc*4)[0])
                        print(f'  {ab:08x} sget {fcn}.{gs(data,soff,fn)}')
                    i+=4
                elif op in (0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d):
                    if i+3 < len(code):
                        fi = struct.unpack_from('<H', code, i+2)[0]
                        e2 = foff+fi*8; fc,ft,fn = struct.unpack_from('<HHI', data, e2)
                        fcn = gs(data, soff, struct.unpack_from('<I', data, toff+fc*4)[0])
                        print(f'  {ab:08x} sput {fcn}.{gs(data,soff,fn)}')
                    i+=4
                elif op == 0x22:
                    if i+3 < len(code):
                        ti2 = struct.unpack_from('<H', code, i+2)[0]
                        tn = gs(data, soff, struct.unpack_from('<I', data, toff+ti2*4)[0])
                        print(f'  {ab:08x} new-inst v{code[i+1]}, {tn}')
                    i+=4
                elif op in (0x0a,0x0b,0x0c):
                    print(f'  {ab:08x} move-result* v{code[i+1]}'); i+=2
                elif op == 0x12:
                    print(f'  {ab:08x} const/4 v{code[i+1]&0xf}, #{(code[i+1]>>4)&0xf}'); i+=2
                elif op == 0x13:
                    if i+3 < len(code):
                        val16 = struct.unpack_from('<h', code, i+2)[0]
                        print(f'  {ab:08x} const/16 v{code[i+1]}, #{val16}')
                    i+=4
                elif op in (0x38,0x39,0x3a,0x3b,0x3c,0x3d):
                    if i+3 < len(code):
                        off2 = struct.unpack_from('<h', code, i+2)[0]
                        print(f'  {ab:08x} ifz v{code[i+1]}, +{off2}')
                    i+=4
                elif op in (0x32,0x33,0x34,0x35,0x36,0x37):
                    if i+3 < len(code):
                        off2 = struct.unpack_from('<h', code, i+2)[0]
                        a = code[i+1]
                        print(f'  {ab:08x} if v{a&0xf},v{(a>>4)&0xf}, +{off2}')
                    i+=4
                elif op == 0x1c:
                    if i+3 < len(code):
                        ti2 = struct.unpack_from('<H', code, i+2)[0]
                        tn = gs(data, soff, struct.unpack_from('<I', data, toff+ti2*4)[0])
                        print(f'  {ab:08x} const-class v{code[i+1]}, {tn}')
                    i+=4
                elif op == 0x1f:
                    if i+3 < len(code):
                        ti2 = struct.unpack_from('<H', code, i+2)[0]
                        tn = gs(data, soff, struct.unpack_from('<I', data, toff+ti2*4)[0])
                        print(f'  {ab:08x} check-cast v{code[i+1]}, {tn}')
                    i+=4
                elif op == 0x21:
                    if i+3 < len(code):
                        ti2 = struct.unpack_from('<H', code, i+2)[0]
                        tn = gs(data, soff, struct.unpack_from('<I', data, toff+ti2*4)[0])
                        print(f'  {ab:08x} array-length v{code[i+1]}, {tn}')
                    i+=4
                elif op == 0x23:
                    if i+3 < len(code):
                        ti2 = struct.unpack_from('<H', code, i+2)[0]
                        tn = gs(data, soff, struct.unpack_from('<I', data, toff+ti2*4)[0])
                        print(f'  {ab:08x} new-array v{code[i+1]&0xf}, v{(code[i+1]>>4)&0xf}, {tn}')
                    i+=4
                elif op == 0x44:
                    print(f'  {ab:08x} aget v{code[i+1]&0xf}, v{(code[i+1]>>4)&0xf}'); i+=4
                elif op in (0x46,0x47,0x48,0x49):
                    if i+3 < len(code):
                        print(f'  {ab:08x} aget-op={op:02x} [{code[i:i+4].hex()}]')
                    i+=4
                elif op in (0x4b,0x4c,0x4d,0x4e,0x4f,0x50):
                    if i+3 < len(code):
                        print(f'  {ab:08x} aput-op={op:02x} [{code[i:i+4].hex()}]')
                    i+=4
                elif op == 0x1d:
                    print(f'  {ab:08x} monitor-enter v{code[i+1]}'); i+=2
                elif op == 0x1e:
                    print(f'  {ab:08x} monitor-exit v{code[i+1]}'); i+=2
                else:
                    raw = code[i:min(i+4, len(code))].hex()
                    print(f'  {ab:08x} op={op:02x} [{raw}]')
                    i+=2
    break
