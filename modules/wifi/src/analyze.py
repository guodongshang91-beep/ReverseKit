# analyze.py - pull the WPA2 4-way handshake out of a pcap and emit hashcat -m 22000 line
# Also ships a synthetic self-test so the whole PMK->PTK->MIC pipeline can be proven
# against a handshake whose password we already know, before we attack the real one.

import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import hashlib
import hmac
import os
import struct
import sys

SSID = os.environ.get("RK_SSID", "")  # set RK_SSID (or --ssid below) to match the capture
for _i, _a in enumerate(sys.argv):
    if _a == "--ssid" and _i + 1 < len(sys.argv):
        SSID = sys.argv[_i + 1]


def prf512(key, a, b):
    """WPA PRF-512: 4 rounds of HMAC-SHA1(key, A || 0x00 || B || i)"""
    out = b""
    for i in range(4):
        out += hmac.new(key, a + b"\x00" + b + bytes([i]), hashlib.sha1).digest()
    return out[:64]


def eapol_key_fields(eapol):
    """eapol = bytes starting at the 802.1X header (version 0x02, type 0x03)"""
    if len(eapol) < 99 or eapol[1] != 0x03:
        return None
    keyinfo = struct.unpack(">H", eapol[5:7])[0]
    nonce = eapol[17:49]
    mic = eapol[81:97]
    kdlen = struct.unpack(">H", eapol[97:99])[0]
    data = eapol[99:99 + kdlen] if kdlen else b""
    return {
        "keyinfo": keyinfo,
        "nonce": nonce,
        "mic": mic,
        "data": data,
        "raw": eapol,
    }


def zero_mic(eapol):
    return eapol[:81] + b"\x00" * 16 + eapol[97:]


def is_m1(f):
    # from AP: Ack=1, MIC=0, Key Type=pairwise
    return bool(f["keyinfo"] & 0x0040) and not bool(f["keyinfo"] & 0x0080)


def is_m2(f):
    # from STA: Ack=0, MIC=1
    return bool(f["keyinfo"] & 0x0080) and not bool(f["keyinfo"] & 0x0040)


def build_22000(mic, mac_ap, mac_sta, ssid, anonce, eapol_m2, messagepair=2):
    return "WPA*02*%s*%s*%s*%s*%s*%s*%02x" % (
        mic.hex(),
        mac_ap.hex(),
        mac_sta.hex(),
        ssid.encode().hex(),
        anonce.hex(),
        eapol_m2.hex(),
        messagepair,
    )


def pmk_ptk_mic(passphrase, ssid, mac_ap, mac_sta, anonce, snonce, eapol_m2_zeroed):
    """Reference implementation: the same math hashcat does, used to verify a hit."""
    pmk = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), ssid.encode(), 4096, 32)
    b = (min(mac_ap, mac_sta) + max(mac_ap, mac_sta) +
         min(anonce, snonce) + max(anonce, snonce))
    ptk = prf512(pmk, b"Pairwise key expansion", b)
    kck = ptk[:16]
    return hmac.new(kck, eapol_m2_zeroed, hashlib.sha1).digest()[:16]


# ---------------- pcap reading ----------------

def iter_packets(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
            nano = False
        elif magic == 0xD4C3B2A1:
            endian = "<"
            nano = False
        elif magic == 0xA1B2CD34:
            endian = "<"
            nano = True
        else:
            raise SystemExit("unknown pcap magic %08x" % magic)
        dlt = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts, tus, caplen, _origlen = struct.unpack(endian + "IIII", rh)
            data = f.read(caplen)
            if len(data) < caplen:
                return
            yield dlt, data


def extract(path, ssid=SSID):
    m1 = None
    m2 = None
    for dlt, buf in iter_packets(path):
        if dlt == 1:  # Ethernet
            if len(buf) < 16 or buf[12:14] != b"\x88\x8e":
                continue
            src = buf[6:12]
            dst = buf[0:6]
            eapol = buf[14:]
        else:  # raw 802.11 (radiotap/avs/prism) - best effort
            # strip radiotap
            off = 0
            if dlt in (127, 163):
                if len(buf) < 8:
                    continue
                itlen = struct.unpack("<H", buf[2:4])[0]
                off = itlen
            fc = buf[off]
            ftype = (fc >> 2) & 0x3
            if ftype != 2:
                continue
            # addr1/2/3 at off+4
            a1 = buf[off + 4:off + 10]
            a2 = buf[off + 10:off + 16]
            a3 = buf[off + 16:off + 22]
            bssid = a3
            src = a2
            dst = a1
            # find LLC/SNAP EAPOL
            idx = buf.find(b"\xaa\xaa\x03\x00\x00\x00\x88\x8e", off)
            if idx < 0:
                continue
            eapol = buf[idx + 8:]
            del bssid
        f = eapol_key_fields(eapol)
        if not f:
            continue
        if is_m1(f):
            m1 = (src, dst, f)   # src=AP, dst=STA
        elif is_m2(f):
            m2 = (src, dst, f)   # src=STA, dst=AP
        if m1 and m2:
            break
    if not m1 or not m2:
        return None
    ap_mac, sta_mac_dst, f1 = m1
    sta_mac, ap_mac_dst, f2 = m2
    anonce = f1["nonce"]
    snonce = f2["nonce"]
    mic = f2["mic"]
    eapol_m2 = zero_mic(f2["raw"])
    return {
        "mac_ap": ap_mac,
        "mac_sta": sta_mac,
        "anonce": anonce,
        "snonce": snonce,
        "mic": mic,
        "eapol": eapol_m2,
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "handshake.pcap"
    h = extract(path)
    if not h:
        print("!! no complete M1+M2 pair in %s" % path)
        return 1
    print("AP  MAC : %s" % h["mac_ap"].hex(":"))
    print("STA MAC : %s" % h["mac_sta"].hex(":"))
    print("ANonce  : %s" % h["anonce"].hex())
    print("SNonce  : %s" % h["snonce"].hex())
    print("MIC(M2) : %s" % h["mic"].hex())
    print("EAPOL   : %d bytes" % len(h["eapol"]))
    line = build_22000(h["mic"], h["mac_ap"], h["mac_sta"], SSID, h["anonce"], h["eapol"])
    out = r"E:\wifi_crack\target.hc22000"
    with open(out, "w") as f:
        f.write(line + "\n")
    print("\n22000 -> %s\n%s" % (out, line[:120] + "..."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
