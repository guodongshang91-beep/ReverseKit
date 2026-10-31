# -*- coding: utf-8 -*-
"""完整 DNS 解析：A / CNAME / NS / MX / TXT，用于子域接管判断"""
import sys, socket, struct, random, ipaddress
sys.stdout.reconfigure(encoding="utf-8", errors="ignore")

SERVERS = ["223.5.5.5", "223.6.6.6", "119.29.29.29", "8.8.8.8"]
QT = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}


def dns_query(name, qtype=1, server=None, timeout=6):
    servers = [server] if server else SERVERS
    tid = random.randint(0, 0xFFFF)
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    pkt = hdr + qn + struct.pack(">HH", qtype, 1)
    last = None
    for sv in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(pkt, (sv, 53))
            d, _ = s.recvfrom(8192)
            s.close()
            if struct.unpack(">H", d[:2])[0] != tid:
                continue
            return d
        except Exception as e:
            last = e
            continue
    if last:
        raise last
    raise RuntimeError("no answer")


def parse_name(d, off):
    labels = []
    jumped = False
    orig = off
    guard = 0
    while True:
        guard += 1
        if guard > 64:
            break
        ln = d[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", d[off:off + 2])[0] & 0x3FFF
            if not jumped:
                orig = off + 2
            off = ptr
            jumped = True
            continue
        labels.append(d[off + 1:off + 1 + ln].decode("latin1"))
        off += 1 + ln
    return ".".join(labels), (orig if jumped else off)


def parse(d):
    ancount = struct.unpack(">H", d[6:8])[0]
    nscount = struct.unpack(">H", d[8:10])[0]
    arcount = struct.unpack(">H", d[10:12])[0]
    qdcount = struct.unpack(">H", d[4:6])[0]
    off = 12
    for _ in range(qdcount):
        _, off = parse_name(d, off)
        off += 4
    out = []
    for _ in range(ancount + nscount + arcount):
        name, off = parse_name(d, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", d[off:off + 10])
        off += 10
        rdata = d[off:off + rdlen]
        val = None
        if rtype == 1 and rdlen == 4:
            val = ".".join(str(b) for b in rdata)
        elif rtype == 28 and rdlen == 16:
            val = str(ipaddress.IPv6Address(rdata))
        elif rtype in (5, 2, 12):
            val, _ = parse_name(d, off)
        elif rtype == 15:
            pref = struct.unpack(">H", rdata[:2])[0]
            nm, _ = parse_name(d, off + 2)
            val = "%d %s" % (pref, nm)
        elif rtype == 16:
            val = rdata[1:1 + rdata[0]].decode("latin1") if rdata else ""
        elif rtype == 6:
            mname, o2 = parse_name(d, off)
            rname, _ = parse_name(d, o2)
            val = "%s %s" % (mname, rname)
        else:
            val = rdata.hex()
        out.append((name, rtype, ttl, val))
        off += rdlen
    return out


RT = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}


def full(name):
    res = {}
    for qt, num in QT.items():
        try:
            recs = parse(dns_query(name, num))
            vals = [(RT.get(t, t), v) for (_, t, _, v) in recs if t != 6 or qt == "SOA"]
            vals = [x for x in vals if x[0] in (qt, "SOA") or x[0] in ("CNAME", "NS") and qt in ("A", "AAAA", "NS")]
            if vals:
                res[qt] = sorted(set("%s=%s" % (a, b) for a, b in vals))
        except Exception as e:
            pass
    return res


if __name__ == "__main__":
    hosts = sys.argv[1:]
    if not hosts:
        # 不内置任何真实域名：没有目标就问用户，别偷偷跑别的站点
        print("usage: python dnsx.py <domain> [domain...]")
        print("       python dnsx.py example.com api.example.com")
        sys.exit(2)
    for h in hosts:
        r = full(h)
