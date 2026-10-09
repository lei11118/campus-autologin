#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# ★ 标记 ID : CAMPUS-NET-AUTOLOGIN
# ★ 用途    : 校园网（GiWiFi gportal 等门户）自动认证 —— 开机后自动判断是否需要
#             认证，需要则自动登录；被踢下线自动恢复；支持「无人登录 Windows」的
#             无人值守模式（远程控制场景）。
# ★ 位置    : 本文件所在目录（整个目录可拷贝到任意机器 / 任意路径使用）
# ★ 自启    : Windows 计划任务「GiWiFi-Campus-AutoAuth」，由本程序自建：
#             模式 A（--install-logon）登录后每 5 分钟；
#             模式 B（--install，无人值守）开机即跑 + 每 1 分钟，SYSTEM 身份
# ★ 依赖    : 无（仅 Python 标准库 + Windows DPAPI）
# ★ 说明    : 同目录 README.md / ★标记★-校园网自动认证.md
# ⚠ 注意    : 计划任务里记着本目录的绝对路径。移动/改名后必须在新位置重跑
#             python giwifi_auth.py --install
# =============================================================================
"""
GiWiFi 校园网（gportal）开机自动认证工具  —— 零第三方依赖（仅 Python 标准库 + Windows DPAPI）

工作原理
--------
1. 联网探针：先 GET http://nettest.gwifi.com.cn （GiWiFi 自家探针），
   返回 {"resultCode":0,"data":"\\"\\""} 表示已在线；
   再以 http://connect.rom.miui.com/generate_204 判断是否被门户劫持（非 204 / 302 即需认证）。
2. 需要认证时：GET 门户登录页 /gportal/web/login 拿到服务端下发的隐藏参数
   （nasName / userIp / userMac / ssid / apMac / pid / vlan / sign / iv）。
3. 复刻门户前端的加密逻辑：
   plaintext = jQuery.serialize(#frmLogin)  ->  各字段 encodeURIComponent 后用 & 连接
   cipher    = AES-128-CBC(key='1234567887654321', iv=<页面下发的 16 字符 iv>, ZeroPadding)
   data      = Base64(cipher)
4. POST /gportal/web/authLogin?round=<随机数>  表单体: data=<urlencode(base64)>&iv=<iv>
5. 复核探针；失败则按退避策略重试，连续失败达阈值后进入冷却（默认 30 分钟）并输出醒目告警。

常用命令
--------
python giwifi_auth.py                 # 检查一次，需要认证就认证（计划任务默认调用这个）
python giwifi_auth.py --set-password  # 交互式设置账号/密码（密码用 DPAPI 加密后写入 config.json）
python giwifi_auth.py --status        # 查看当前联网状态与配置
python giwifi_auth.py --watch         # 常驻循环守护（每 interval_min 分钟检查一次）
python giwifi_auth.py --install       # 注册开机自启计划任务
python giwifi_auth.py --uninstall     # 删除计划任务
python giwifi_auth.py --selftest      # AES 实现的 FIPS-197 自检
python giwifi_auth.py --force         # 忽略在线检查，强制走一次认证流程
"""

import argparse
import base64
import ctypes
import ctypes.wintypes
import getpass
import json
import os
import random
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
from datetime import datetime
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent

__version__ = "1.1.0"      # 可移植版：门户地址可自动发现、支持无人值守(SYSTEM)模式

# 控制台输出兜底：即使被重定向到管道/文件，也不会因编码问题崩溃或报错
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass


def _console_decode(data: bytes) -> str:
    """解码 Windows 命令行程序输出。schtasks 等系统自带命令输出的是 OEM/ANSI 编码
    （中文系统为 GBK），如果按 UTF-8 解码就会变成乱码，这里逐个尝试。"""
    for enc in ("mbcs", "gbk", "utf-8"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", "replace")


def run_cmd(args) -> tuple:
    """执行外部命令，返回 (returncode, 已正确解码的输出)"""
    r = subprocess.run(args, capture_output=True)
    return r.returncode, (_console_decode(r.stdout) + _console_decode(r.stderr)).strip()

CONFIG_PATH = APP_DIR / "config.json"
STATE_PATH = APP_DIR / "state.json"
LOG_DIR = APP_DIR / "logs"

TASK_NAME = "GiWiFi-Campus-AutoAuth"
DPAPI_PREFIX = "dpapi:"        # 用户范围 DPAPI（只有当前 Windows 用户能解）
DPAPI_M_PREFIX = "dpapim:"      # 机器范围 DPAPI（本机任意进程/ SYSTEM / 未登录也能解）

# 以 SYSTEM 身份运行的 <Principal> 写法，按优先级逐个尝试。
# 关键：内置服务账号【不能】写 <LogonType>，写 ServiceAccount 会直接被 schtasks 拒绝。
BOOT_PRINCIPALS = [
    ("SID + HighestAvailable（标准写法）",
     "<UserId>S-1-5-18</UserId>\n"
     "      <RunLevel>HighestAvailable</RunLevel>"),
    ("SID 形式，不指定 RunLevel",
     "<UserId>S-1-5-18</UserId>"),
    ("名称形式 NT AUTHORITY\\SYSTEM",
     "<UserId>NT AUTHORITY\\SYSTEM</UserId>\n"
     "      <RunLevel>HighestAvailable</RunLevel>"),
]

DEFAULT_CONFIG = {
    # 门户地址：**留空 = 自动发现**（未认证时 AC 会把你 302 重定向到门户登录页，
    # 程序从中读出真实的门户 IP 与接口路径，所以换机器/换校区无需改配置）。
    # 需要固定写死时填内网地址，例如 "http://10.0.0.1"。
    "portal": "",
    "portal_path": "/gportal/web/login",       # 登录页（gportal 家族默认值）
    "auth_path": "/gportal/web/authLogin",     # 认证接口
    "nettest": "http://nettest.gwifi.com.cn",  # GiWiFi 在线探针（其他厂商不可达时自动降级）
    "probe_204": "http://connect.rom.miui.com/generate_204",  # 通用劫持探针
    "encrypt_key": "1234567887654321",         # 门户前端硬编码的 AES key
    "username": "",
    "password": "",                            # 明文，或 "dpapi:<base64>"（用户）/ "dpapim:<base64>"（机器）密文
    "interval_min": 5,                         # 守护/计划任务检查周期（分钟）
    "max_fail": 3,                             # 连续失败多少次进入冷却
    "cooldown_min": 30,                        # 冷却时长（分钟）
    "startup_wait_s": 60,                      # 开机时等网络就绪的最长等待（秒）
    "verify_before_fail": True,                # 认证接口报错时先用探针复核，避免误判失败/误入冷却
    "timeout_s": 8,
}


# =============================================================================
# 日志
# =============================================================================
def _log_file() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / f"autologin-{datetime.now():%Y%m%d}.log"


def log(msg: str, level: str = "INFO") -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{level}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with open(_log_file(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# =============================================================================
# 纯 Python AES-128-CBC（零依赖，输出与 CryptoJS AES.encrypt + ZeroPadding 一致）
# =============================================================================
def _gmul(a: int, b: int) -> int:
    """GF(2^8) 乘法（模 AES 不可约多项式 0x11B）"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gpow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gmul(r, a)
        a = _gmul(a, a)
        n >>= 1
    return r


def _build_sbox():
    box = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else _gpow(i, 254)
        s = inv
        for sh in (1, 2, 3, 4):
            s ^= ((inv << sh) | (inv >> (8 - sh))) & 0xFF
        box[i] = s ^ 0x63
    return box


SBOX = _build_sbox()
RCON = [0x00] + [_gpow(2, i - 1) for i in range(1, 16)]


def _expand_key(key: bytes):
    assert len(key) == 16, "AES-128 需要 16 字节密钥"
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rcon_i = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= RCON[rcon_i]
            rcon_i += 1
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[r * 4:r * 4 + 4] for b in word) for r in range(11)]


def _encrypt_block(block: bytes, rk) -> bytes:
    st = list(block)
    for i in range(16):
        st[i] ^= rk[0][i]
    for rnd in range(1, 11):
        # SubBytes
        st = [SBOX[x] for x in st]
        # ShiftRows：state 为列主序，索引 = row + 4*col
        st = [st[(i % 4) + 4 * (((i // 4) + (i % 4)) % 4)] for i in range(16)]
        # MixColumns（最后一轮不做）
        if rnd != 10:
            out = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = st[4 * c:4 * c + 4]
                out[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
                out[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
                out[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
                out[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
            st = out
        # AddRoundKey
        st = [st[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(st)


def aes_cbc_zeropad_b64(plaintext: bytes, key: bytes, iv: bytes) -> str:
    """AES-128-CBC + ZeroPadding，返回 Base64（与 CryptoJS 行为一致：
    已对齐时不再补块，未对齐时用 0x00 补齐到块边界）"""
    data = bytearray(plaintext)
    if len(data) % 16:
        data.extend(b"\x00" * (16 - len(data) % 16))
    rk = _expand_key(key)
    prev = bytes(iv)
    out = bytearray()
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        enc = _encrypt_block(block, rk)
        out.extend(enc)
        prev = enc
    return base64.b64encode(bytes(out)).decode("ascii")


def self_test() -> bool:
    """FIPS-197 / NIST SP800-38A 测试向量自检（输出保持纯 ASCII 符号，避免控制台乱码）"""
    ok = True
    sbox_checks = {0x00: 0x63, 0x01: 0x7C, 0x53: 0xED, 0xFF: 0x16}
    for k, v in sbox_checks.items():
        if SBOX[k] != v:
            print(f"  [X] SBOX[{k:#04x}] = {SBOX[k]:#04x}, 期望 {v:#04x}")
            ok = False
    # FIPS-197 C.1 AES-128 单块
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = _encrypt_block(pt, _expand_key(key))
    exp = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    if ct != exp:
        print(f"  [X] 单块加密 {ct.hex()} != {exp.hex()}")
        ok = False
    else:
        print("  [OK] FIPS-197 AES-128 单块向量通过")
    # NIST SP800-38A F.2.1 CBC-AES128
    key2 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv2 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt2 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                        "ae2d8a571e03ac9c9eb76fac45af8e51")
    got = base64.b64decode(aes_cbc_zeropad_b64(pt2, key2, iv2)).hex()
    exp2 = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
    if got != exp2:
        print(f"  [X] CBC {got} != {exp2}")
        ok = False
    else:
        print("  [OK] NIST SP800-38A CBC-AES128 向量通过")
    print("  自检结果:", "全部通过" if ok else "存在失败")
    return ok


# =============================================================================
# Windows DPAPI：用当前用户凭据加密密码（密文只能被同一用户在本机解开）
# =============================================================================
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_encrypt(text: str, machine: bool = False) -> str:
    """用 DPAPI 加密。machine=True 用「机器范围」——SYSTEM 身份 / 无人登录时也能解密，
    这是无人值守（开机自动认证后远程控制）场景必须的。"""
    if os.name != "nt":
        raise RuntimeError("DPAPI 仅 Windows 可用")
    raw = text.encode("utf-8")
    blob_in = _DATA_BLOB(len(raw), ctypes.cast(ctypes.create_string_buffer(raw),
                                               ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    # 0x1 = CRYPTPROTECT_UI_FORBIDDEN（无人值守时绝不弹窗），0x4 = CRYPTPROTECT_LOCAL_MACHINE
    flags = 0x1 | (0x4 if machine else 0)
    if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    prefix = DPAPI_M_PREFIX if machine else DPAPI_PREFIX
    return prefix + base64.b64encode(data).decode("ascii")


def dpapi_decrypt(token: str) -> str:
    machine = token.startswith(DPAPI_M_PREFIX)
    prefix = DPAPI_M_PREFIX if machine else DPAPI_PREFIX
    raw = base64.b64decode(token[len(prefix):])
    blob_in = _DATA_BLOB(len(raw), ctypes.cast(ctypes.create_string_buffer(raw),
                                               ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    flags = 0x1 | (0x4 if machine else 0)
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return data.decode("utf-8")


def password_kind(stored: str) -> str:
    if stored.startswith(DPAPI_M_PREFIX):
        return "机器范围 DPAPI 密文"
    if stored.startswith(DPAPI_PREFIX):
        return "用户范围 DPAPI 密文"
    return "明文（已加文件权限保护）"


def resolve_password(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith(DPAPI_M_PREFIX) or stored.startswith(DPAPI_PREFIX):
        try:
            return dpapi_decrypt(stored)
        except Exception as e:  # 换用户/换机器后解不开
            log(f"密码解密失败（{password_kind(stored)} 与当前身份不匹配）：{e}", "ERROR")
            return ""
    return stored


def lock_config_acl(path: Path) -> bool:
    """把 config.json 权限收紧到「当前用户 + SYSTEM + Administrators」，其余一律拒绝。
    明文保存密码时靠这层保护（普通目录默认权限较宽松，这里就是最后防线）。
    注意：当前用户给的是 (M) 而不是 (R,W) —— Modify 含 Delete，这样
    VSCode 等编辑器/工具做「原子替换保存」时才不会 Permission denied。"""
    user = current_user()
    if not user:
        return False
    rc, out = run_cmd(["icacls", str(path), "/inheritance:r",
                       "/grant:r", f"{user}:(M)",
                       "/grant:r", "*S-1-5-18:(F)",
                       "/grant:r", "*S-1-5-32-544:(F)"])
    if rc != 0:
        log(f"收紧 config.json 权限失败：{out}", "WARN")
        return False
    # 复核：自己还能读回来吗
    try:
        path.read_text(encoding="utf-8")
    except Exception as e:
        log(f"收紧权限后自检读取失败：{e}", "WARN")
        return False
    log("已收紧 config.json 权限（仅 当前用户 / SYSTEM / Administrators 可访问）")
    return True


# =============================================================================
# 配置 / 状态
# =============================================================================
def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception as e:
            log(f"config.json 解析失败，使用默认值：{e}", "WARN")
    else:
        save_config(cfg)
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_state(st: dict) -> None:
    try:
        STATE_PATH.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


# =============================================================================
# HTTP 基础
# =============================================================================
def make_opener() -> urllib.request.OpenerDirector:
    """带 cookie 会话、不走系统代理（门户是内网地址）"""
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
    )


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def http_get(opener, url: str, timeout: int = 8, allow_redirect: bool = True):
    """返回 (status, final_url, body_bytes, redirect_location)"""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "*/*",
        "Cache-Control": "no-cache",
    })
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, resp.geturl(), resp.read(), resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read() if hasattr(e, "read") else b"", e.headers.get("Location")
    except Exception as e:
        raise e


def http_post_form(opener, url: str, fields: dict, timeout: int = 8, referer: str = None):
    body = "&".join(
        f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}"
        for k, v in fields.items()).encode("ascii")
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Origin": "{u.scheme}://{u.netloc}".format(u=urllib.parse.urlparse(url)),
    }
    if referer:
        headers["Referer"] = referer
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        resp = opener.open(req, timeout=timeout)
        try:
            text = resp.read().decode("utf-8", "replace")
        except Exception:
            text = ""
        return resp.status, text
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """让 3xx 不被自动跟随，把 Location 交还给我们（用于发现门户地址）"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get_noredirect(url: str, timeout: int = 8):
    """返回 (status, Location)；3xx 会以 HTTPError 形式抛出后在这里被捕获。"""
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        req = urllib.request.Request(url, headers={
            "User-Agent": UA, "Accept": "*/*", "Cache-Control": "no-cache"})
        r = op.open(req, timeout=timeout)
        return r.status, r.headers.get("Location")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location")
    except Exception:
        return None, None


def _looks_like_portal_host(host: str) -> bool:
    """判断重定向目标像不像校园网门户：内网 IP 字面量，或主机名里带 portal/gwifi/srun 等特征。
    不做这个过滤的话，联网状态下的普通网站跳转（百度→www.baidu.com 之类）会被误当成门户。"""
    if not host:
        return False
    if host.replace(".", "").isdigit():          # 纯 IP 字面量（校园门户基本都长这样）
        return True
    low = host.lower()
    return any(k in low for k in ("portal", "gwifi", "wifi", "srun", "drcom",
                                  "eportal", "ac-", "-ac.", "login"))


def discover_portal(cfg) -> tuple:
    """自动发现门户地址（换机器 / 换校区 / 同为 gportal 的其他学校都可免配置）。

    原理：未认证时请求任意 http 站点，AC 会 302 到门户登录页，Location 里带着
    wlanacname/wlanuserip 以及门户的 IP 与路径。返回 (门户基址, 登录路径, 认证路径, 完整登录URL)。
    """
    for url in (cfg.get("probe_204"), "http://www.baidu.com/",
                "http://connect.rom.miui.com/generate_204",
                "http://www.msftconnecttest.com/connecttest.txt"):
        if not url:
            continue
        code, loc = http_get_noredirect(url, cfg.get("timeout_s", 8))
        if not loc or not loc.lower().startswith("http"):
            continue
        u = urllib.parse.urlparse(loc)
        host = u.hostname or ""
        if host == (urllib.parse.urlparse(url).hostname or ""):   # 同站跳转，不是门户劫持
            continue
        if not _looks_like_portal_host(host):
            continue
        portal = f"{u.scheme}://{u.netloc}"
        path = u.path or "/"
        # gportal 家族：/gportal/web/login -> /gportal/web/authLogin
        auth = (path[:-len("/login")] + "/authLogin") if path.endswith("/login") else ""
        return portal, path, auth, loc
    return None, None, None, None


def resolve_portal(cfg, force_discover: bool = False) -> dict:
    """决定这次运行用哪个门户：config 固定值优先；留空则自动发现并缓存到 state.json。"""
    st = load_state()
    portal = (cfg.get("portal") or "").strip().rstrip("/")
    path = cfg.get("portal_path") or "/gportal/web/login"
    auth = cfg.get("auth_path") or "/gportal/web/authLogin"
    if portal and not force_discover:
        return {"portal": portal, "portal_path": path, "auth_path": auth}
    p, pth, apth, _ = discover_portal(cfg)
    if p:
        st["discovered"] = {"portal": p, "portal_path": pth, "auth_path": apth or auth,
                            "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        save_state(st)
        log(f"自动发现门户成功：{p}{pth}（认证接口 {apth or auth}）")
        return {"portal": p, "portal_path": pth, "auth_path": apth or auth}
    d = st.get("discovered") or {}
    if d.get("portal"):
        log(f"本次自动发现失败，沿用上次结果：{d['portal']}{d.get('portal_path', '')}")
        return {"portal": d["portal"], "portal_path": d.get("portal_path", path),
                "auth_path": d.get("auth_path", auth)}
    return {"portal": portal, "portal_path": path, "auth_path": auth}


def local_ip_toward(target_ip: str) -> str:
    """不实际发包地取到通往门户网卡的本机 IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


# =============================================================================
# 1) 联网状态判定
# =============================================================================
ONLINE, NEED_AUTH, UNKNOWN = "ONLINE", "NEED_AUTH", "UNKNOWN"


def _probe_nettest(cfg) -> tuple:
    """探针 A：GiWiFi 自家。返回 (状态, 说明, 门户URL)"""
    try:
        op = make_opener()
        code, _, body, loc = http_get(op, cfg["nettest"], cfg["timeout_s"])
        if code == 200:
            txt = body.decode("utf-8", "replace").strip()
            try:
                j = json.loads(txt)
                if j.get("resultCode") == 0 and j.get("data") == '""':
                    return ONLINE, f"{cfg['nettest']} -> resultCode=0（已在线）", None
                return NEED_AUTH, f"{cfg['nettest']} -> {txt[:120]}", None
            except Exception:
                if "<html" in txt.lower():
                    return NEED_AUTH, f"{cfg['nettest']} 被门户页面劫持", None
                return NEED_AUTH, f"{cfg['nettest']} 返回非预期内容: {txt[:120]}", None
        if code in (301, 302, 303, 307, 308):
            return NEED_AUTH, f"{cfg['nettest']} -> {code} 重定向到 {loc}", loc
        return NEED_AUTH, f"{cfg['nettest']} -> HTTP {code}", loc
    except Exception as e:
        return UNKNOWN, f"{cfg['nettest']} 不可达（{type(e).__name__}: {e}）", None


def _probe_204(cfg) -> tuple:
    """探针 B：通用 generate_204。返回 (状态, 说明, 门户URL)"""
    try:
        op = make_opener()
        code, _, body, loc = http_get(op, cfg["probe_204"], cfg["timeout_s"])
        if code == 204:
            return ONLINE, f"{cfg['probe_204']} -> 204（已在线）", None
        if code in (301, 302, 303, 307, 308):
            return NEED_AUTH, f"{cfg['probe_204']} -> {code} 重定向到 {loc}", loc
        return NEED_AUTH, f"{cfg['probe_204']} -> HTTP {code}（疑似被劫持）", loc
    except Exception as e:
        return UNKNOWN, f"{cfg['probe_204']} 不可达（{type(e).__name__}: {e}）", None


def check_online(cfg, attempts: int = 3, gap: float = 4.0) -> tuple:
    """返回 (状态, 说明, 门户重定向URL)

    校园网的劫持拦截是**有抖动**的：实测出现过「探针被门户页面劫持，但实际会话仍然有效，
    几秒后一切正常」。所以这里先对主探针重试几次，再用 204 探针交叉验证 ——
    宁可多确认一次，也别把「其实在线」误判成「需要认证」：
    误判会让程序做无谓的登录尝试，连续 3 次就把自己送进冷却，之后真掉线了反而不去认证，
    无人值守场景下这是最致命的失败模式。"""
    last = (UNKNOWN, "未探测", None)
    for i in range(max(1, attempts)):
        st, why, url = _probe_nettest(cfg)
        if st == ONLINE:
            return st, why, url
        last = (st, why, url)
        if i + 1 < attempts:
            time.sleep(gap)
    # 主探针一直说没通 -> 用 204 交叉验证
    st2, why2, url2 = _probe_204(cfg)
    if st2 == ONLINE:
        return ONLINE, f"{why2}（主探针：{last[1][:90]}，以 204 探针为准）", None
    if last[0] == NEED_AUTH or st2 == NEED_AUTH:
        return NEED_AUTH, f"{last[1]}；{why2}", last[2] or url2
    return last[0], f"{last[1]}；{why2}", None


# =============================================================================
# 2) 抓登录页 -> 解析隐藏参数
# =============================================================================
import re

_FORM_RE = re.compile(r"<form[^>]*id=[\"']frmLogin[\"'][^>]*>(.*?)</form>", re.S | re.I)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"([a-zA-Z_][\w:-]*)\s*=\s*[\"']([^\"']*)[\"']")


def parse_login_form(html: str) -> dict:
    """从 #frmLogin 表单里按 DOM 顺序取出所有隐藏字段（值原样保留，含空值）"""
    m = _FORM_RE.search(html)
    if not m:
        raise RuntimeError("登录页里没有找到 id=frmLogin 表单（门户页面结构可能已变更）")
    fields = {}
    order = []
    for tag in _INPUT_RE.findall(m.group(1)):
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(tag)}
        name = attrs.get("name")
        if not name:
            continue
        typ = (attrs.get("type") or "text").lower()
        if typ in ("button", "submit", "image", "file"):
            continue
        if typ in ("checkbox", "radio") and "checked" not in tag.lower():
            continue          # jQuery.serialize() 会跳过未勾选的框
        if name not in fields:
            order.append(name)
        fields[name] = attrs.get("value", "")
    if "iv" not in fields or not fields["iv"]:
        raise RuntimeError("登录页里没有拿到 iv（加密随机向量）")
    return {"fields": fields, "order": order}


def fetch_login_page(cfg, opener, discovered_url=None):
    """按优先级尝试拿到登录页 HTML，返回 (html, url, fields/order)"""
    portal = (cfg.get("portal") or "").rstrip("/")
    if not portal:
        raise RuntimeError("未能确定门户地址：config.json 里 portal 留空时需要能自动发现。"
                           "请确认机器已经接在校园网内（未认证时任意 http 请求会被重定向到门户）。")
    local_ip = local_ip_toward(urllib.parse.urlparse(portal).hostname or "10.0.0.1")
    st = load_state()
    nas = st.get("nasName", "")
    candidates = []
    if discovered_url:
        candidates.append(discovered_url)
    candidates.append(f"{portal}{cfg['portal_path']}")
    if nas and local_ip:
        candidates.append(f"{portal}{cfg['portal_path']}"
                          f"?wlanacname={nas}&wlanuserip={local_ip}")
    last_err = None
    for url in candidates:
        try:
            code, final_url, body, loc = http_get(opener, url, cfg["timeout_s"])
            html = body.decode("utf-8", "replace")
            if code == 200 and "frmLogin" in html:
                parsed = parse_login_form(html)
                log(f"登录页获取成功：{url}（{len(html)} 字节）")
                return html, url, parsed
            last_err = f"{url} -> HTTP {code}, {len(html)} 字节, 无 frmLogin"
        except Exception as e:
            last_err = f"{url} -> {type(e).__name__}: {e}"
        log(f"登录页尝试失败：{last_err}", "WARN")
    raise RuntimeError(f"无法获取门户登录页：{last_err}")


# =============================================================================
# 3) 复刻前端加密 + 提交
# =============================================================================
def js_encode_uri_component(s: str) -> str:
    """等价于 JS encodeURIComponent（jQuery.serialize 用的就是它）"""
    return urllib.parse.quote(str(s), safe="!'()*-._~")


def build_plaintext(parsed: dict, username: str, password: str) -> str:
    fields, order = parsed["fields"], parsed["order"]
    items = []
    for name in order:
        if name == "name":
            value = username
        elif name == "password":
            value = password
        else:
            value = fields[name]
        items.append(f"{js_encode_uri_component(name)}={js_encode_uri_component(value)}")
    return "&".join(items)


def run_identity() -> str:
    """当前进程的运行身份（无人值守排障时看日志用）"""
    rc, who = run_cmd(["whoami"])
    who = (who or "").strip() or "?"
    low = who.lower()
    if low.endswith("\\system") or low == "system":
        return "SYSTEM（服务账号·无需任何人登录）"
    if is_admin():
        return f"{who}（管理员令牌）"
    return who


def do_login(cfg, opener, parsed, login_url) -> tuple:
    """执行一次认证，返回 (成功?, 说明)"""
    username = cfg["username"]
    password = resolve_password(cfg["password"])
    if not username or not password:
        return False, "未配置账号或密码（请先运行 --set-password）"

    idx = parsed["fields"].get("name")
    if idx is not None and not idx:
        pass
    plaintext = build_plaintext(parsed, username, password)
    iv = parsed["fields"]["iv"]
    key = cfg["encrypt_key"].encode("utf-8")
    iv_b = iv.encode("utf-8")
    if len(iv_b) != 16:
        return False, f"iv 长度异常({len(iv_b)})，无法加密"
    cipher_b64 = aes_cbc_zeropad_b64(plaintext.encode("utf-8"), key, iv_b)

    url = f"{cfg['portal'].rstrip('/')}{cfg['auth_path']}?round={random.randint(0, 999)}"
    # 认证上下文写进日志：无人值守排障时能一眼看出「这一轮是谁在跑、密码拿到了没」
    log(f"认证上下文：身份={run_identity()}，账号={username}，"
        f"密码={password_kind(cfg['password'])}（可用长度 {len(password)}），目标={url}")
    code, text = http_post_form(
        opener, url,
        {"data": cipher_b64, "iv": iv},
        cfg["timeout_s"], referer=login_url)

    # 记住了门户的状态参数，下次可直接构造带参数的登录页 URL
    st = load_state()
    st["nasName"] = parsed["fields"].get("nasName", st.get("nasName", ""))
    st["userIp"] = parsed["fields"].get("userIp", st.get("userIp", ""))
    save_state(st)

    if code != 200:
        return False, f"认证接口 HTTP {code}：{text[:200]}"
    try:
        j = json.loads(text)
    except Exception:
        return False, f"认证接口返回非 JSON：{text[:200]}"
    if j.get("status") == 1:
        return True, f"认证成功：{j.get('info', '')}"
    info = j.get("info", "")
    reason = (j.get("data") or {}).get("reasoncode") if isinstance(j.get("data"), dict) else None
    hint = {
        "1": "账号或密码错误",
        "16": "账号不存在",
        "32": "需要重置密码",
        "40": "需先完善个人信息",
        "41": "需要绑定手机号/身份",
    }.get(str(reason), "")
    msg = f"认证被拒绝：status={j.get('status')} reasoncode={reason} info={info}"
    if hint and hint not in info:
        msg += f"（{hint}）"
    return False, msg


# =============================================================================
# 主流程
# =============================================================================
def run_once(cfg, force: bool = False, verbose: bool = True) -> int:
    st = load_state()
    # 一次性强制验证标记：让下一次自动运行（哪怕已在线）也做一次真实认证，
    # 用来在不打扰用户的前提下验证「无人值守链路」端到端可用
    if st.pop("force_verify_once", False):
        save_state(st)
        force = True
        log("检测到一次性验证标记 force_verify_once：本轮强制执行真实认证（用于链路自证）")
    # 冷却：连续失败太多时先别刷（避免把账号刷到要求验证码）
    if not force and st.get("fail_count", 0) >= cfg["max_fail"]:
        last = st.get("last_fail_ts", 0)
        if time.time() - last < cfg["cooldown_min"] * 60:
            left = int((cfg["cooldown_min"] * 60 - (time.time() - last)) // 60) + 1
            log(f"连续失败 {st['fail_count']} 次，冷却中（剩余约 {left} 分钟）。"
                f"请检查 config.json 里的账号密码，或运行 --set-password 重设。", "WARN")
            return 3
        st["fail_count"] = 0

    status, why, discovered = check_online(cfg)
    # 开机瞬间网卡/DHCP 可能还没就绪：探针全不可达时先等一会儿再判
    waited = 0
    while status == UNKNOWN and not force and waited < int(cfg.get("startup_wait_s", 60)):
        log(f"网络尚未就绪，10 秒后重试（已等 {waited}s）：{why}")
        time.sleep(10)
        waited += 10
        status, why, discovered = check_online(cfg)
    if status == ONLINE and not force:
        if verbose:
            log(f"无需认证：{why}")
        return 0
    if status == UNKNOWN and not force:
        log(f"无法判断联网状态：{why}")
        return 2
    log(f"需要认证：{why}" if status == NEED_AUTH else f"强制认证（{why}）")

    # 门户地址：config 固定值优先；留空则自动发现（换机器 / 换校区免配置）
    eff = dict(cfg)
    eff.update(resolve_portal(cfg))

    opener = make_opener()
    try:
        html, login_url, parsed = fetch_login_page(eff, opener, discovered)
    except Exception as e:
        log(f"准备阶段失败：{e}", "ERROR")
        return 2

    ok, msg = do_login(eff, opener, parsed, login_url)
    if not ok:
        log(msg, "ERROR")
        # 接口虽然报错，但探针显示已在线（多设备/别的终端已认证/接口口径差异）：
        # 这种情况不算失败，避免白白进入冷却
        if cfg.get("verify_before_fail", True):
            time.sleep(1.5)
            status3, why3, _ = check_online(cfg)
            if status3 == ONLINE:
                log(f"接口报错但探针显示已在线，判定为无需认证：{why3}")
                st = load_state()
                st["fail_count"] = 0
                save_state(st)
                return 0
        st = load_state()
        st["fail_count"] = st.get("fail_count", 0) + 1
        st["last_fail_ts"] = time.time()
        save_state(st)
        return 1

    log(msg)
    # 复核：认证接口说成功，也要用探针确认真的通了
    time.sleep(1.5)
    status2, why2, _ = check_online(cfg)
    if status2 == ONLINE:
        log(f"复核通过：{why2}")
        st = load_state()
        st.update({"fail_count": 0, "last_ok_ts": time.time(),
                   "last_ok_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        save_state(st)
        return 0
    log(f"认证接口返回成功，但复核仍未通网：{why2}", "WARN")
    st = load_state()
    st["fail_count"] = st.get("fail_count", 0) + 1
    st["last_fail_ts"] = time.time()
    save_state(st)
    return 1


def watch(cfg) -> int:
    log(f"守护模式启动，每 {cfg['interval_min']} 分钟检查一次（Ctrl+C 退出）")
    while True:
        try:
            run_once(cfg)
        except KeyboardInterrupt:
            log("收到中断，退出守护模式")
            return 0
        except Exception as e:
            log(f"本轮异常：{type(e).__name__}: {e}", "ERROR")
        time.sleep(max(1, int(cfg["interval_min"])) * 60)


# =============================================================================
# 计划任务安装 / 卸载
# =============================================================================
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_user() -> str:
    try:
        rc, out = run_cmd(["whoami"])
        return out.strip() if rc == 0 else os.environ.get("USERNAME", "")
    except Exception:
        return os.environ.get("USERNAME", "")


def pythonw_path() -> str:
    """优先 pythonw.exe：无控制台窗口，开机时不会弹黑框"""
    exe = Path(sys.executable)
    pw = exe.with_name("pythonw.exe")
    return str(pw if pw.exists() else exe)


def task_xml(pythonw: str, script: Path, mode: str = "boot", principal: str = None) -> str:
    """mode='boot'  —— 开机即运行，以 SYSTEM 身份，**不需要任何人登录 Windows**
                        （无人值守 / 远程控制必须用这个；注册需要管理员权限）
       mode='logon' —— 用户登录后运行，以当前用户身份（无需管理员权限，但没登录就不工作）

    注意（踩过的坑）：运行内置服务账号(SYSTEM)时**不能**写 <LogonType>ServiceAccount</LogonType>，
    那不是合法的枚举值，schtasks 会报「任务 XML 包含格式不正确或超出范围的值 (26,35):LogonType:ServiceAccount」。
    正确做法是省略 LogonType，只写 UserId=S-1-5-18，由系统推断为服务账号令牌。"""
    user = current_user()
    script = Path(script)          # 允许传 str 或 Path
    if mode == "boot":
        if principal is None:
            principal = BOOT_PRINCIPALS[0][1]
        triggers = """
    <!-- 开机后 30 秒先跑一次（此时网络可能还没就绪，脚本内部会等） -->
    <BootTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Delay>PT30S</Delay>
    </BootTrigger>
    <!-- 之后每分钟检查一次：被校园网踢下线最多 1 分钟自动恢复 -->
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>"""
        desc = ("GiWiFi 校园网自动认证（无人值守）：开机即以 SYSTEM 身份检测并自动登录，"
                "每分钟巡检保持在线，无需任何人登录 Windows。")
    else:
        principal = (f"<UserId>{user}</UserId>\n"
                     "      <LogonType>InteractiveToken</LogonType>\n"
                     "      <RunLevel>LeastPrivilege</RunLevel>")
        triggers = f"""
    <LogonTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <UserId>{user}</UserId>
      <Delay>PT30S</Delay>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>"""
        desc = "GiWiFi 校园网自动认证：登录后检测是否需要认证，需要则自动登录。"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{desc}</Description>
  </RegistrationInfo>
  <Triggers>{triggers}
  </Triggers>
  <Principals>
    <Principal id="Author">
      {principal}
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{pythonw}</Command>
      <Arguments>"{script}" --task</Arguments>
      <WorkingDirectory>{script.parent}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def ask_elevate(extra_args: list) -> bool:
    """弹出 UAC，以管理员身份重新运行本脚本（装「开机即认证」的 SYSTEM 任务必须提权）"""
    if is_admin():
        return True
    exe = str(Path(sys.executable))
    script = str(Path(__file__).resolve())
    params = " ".join([f'"{script}"'] + [f'"{a}"' for a in extra_args])
    print()
    print(">>> 需要管理员权限：马上会弹出 UAC 授权窗口，请点「是」")
    print(f">>> （以管理员身份执行：{Path(exe).name} \"giwifi_auth.py\" {' '.join(extra_args)}）")
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, str(APP_DIR), 1)
    except Exception as e:
        print(f"！提权失败：{e}")
        return False
    if int(rc) <= 32:
        print(f"！提权被取消（错误码 {rc}）。可右键「以管理员身份运行」安装.bat 重试。")
        return False
    return True


def verify_task_run(cfg, timeout: int = 60) -> bool:
    """立即手动触发一次计划任务，确认它真的能跑通（SYSTEM 身份下能否解密密码、
    能否写日志，这一步是无人值守场景最关键的验证）"""
    logf = _log_file()
    before = logf.stat().st_size if logf.exists() else 0
    rc, out = run_cmd(["schtasks", "/Run", "/TN", TASK_NAME])
    if rc != 0:
        print(f"！无法手动触发任务做验证：{out}")
        return False
    print("已触发任务，等待它跑完 ...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(2)
        if logf.exists() and logf.stat().st_size > before:
            time.sleep(1)
            # 注意：before 是「字节」偏移，必须在字节层面切，再去解码
            raw = logf.read_bytes()[before:]
            new = raw.decode("utf-8", "replace").strip()
            print("--- 任务本次实际输出 ---")
            for line in new.splitlines()[-6:]:
                print("   " + line)
            print("---")
            if "认证成功" in new or "无需认证" in new:
                print("验证通过：任务可以自动完成认证流程。")
                return True
            print("任务能运行，但结果需要留意（见上面的日志）。")
            return True
    print(f"！{timeout} 秒内没有新日志，任务可能没跑起来。")
    return False


def ensure_system_access(path: Path) -> bool:
    """确保 SYSTEM 能读写程序目录。

    为什么需要：无人值守模式的任务以 SYSTEM 身份运行本程序。如果包被解压到桌面、下载目录或
    其他 SYSTEM 没有权限的位置，任务会"看起来在跑、但一步都做不了"——这类静默失败最难查。
    安装时（提权窗口里）顺手授权，一劳永逸。注意必须带 /T，因为 (OI)(CI) 只对**新建**子项生效，
    已存在的文件不会自动获得新权限。"""
    rc, out = run_cmd(["icacls", str(path), "/grant", "*S-1-5-18:(OI)(CI)(M)", "/T", "/C", "/Q"])
    if rc == 0:
        log(f"已确保 SYSTEM 可访问程序目录：{path}")
        return True
    log(f"授权 SYSTEM 访问程序目录失败（无人值守可能失败）：{out[:300]}", "WARN")
    return False


def install_task(cfg, mode: str = "boot", verbose: bool = False, verify: bool = True) -> int:
    if mode == "boot" and not is_admin():
        print("「开机即认证（SYSTEM 身份、无需登录 Windows）」需要管理员权限。")
        if not ask_elevate(["--install-boot", "--pause-at-end"]):
            return 1
        return 10    # 已在新窗口（管理员）里继续安装
    xml_path = APP_DIR / "task.xml"
    script = Path(__file__).resolve()
    if mode == "boot":
        print("检查 SYSTEM 对程序目录的访问权限 ...")
        ensure_system_access(APP_DIR)
    # boot 模式：按 BOOT_PRINCIPALS 逐个尝试，某个写法被系统拒绝就自动换下一个
    variants = BOOT_PRINCIPALS if mode == "boot" else [("当前用户", None)]
    registered = False
    for label, principal in variants:
        xml_path.write_text(task_xml(pythonw_path(), script, mode, principal), encoding="utf-16")
        rc, out = run_cmd(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_path), "/F"])
        if verbose:
            print(out[:600])
        if rc == 0:
            print(f"计划任务已注册（身份写法：{label}）")
            log(f"计划任务已注册（mode={mode}, principal={label}）：{TASK_NAME}")
            registered = True
            break
        log(f"计划任务注册失败（{label}）：{out}", "ERROR")
        print(f"！该写法被拒绝（{label}）：{out.strip()[-260:]}")
    if not registered:
        print("！所有身份写法都被拒绝了，请把上面的内容发给我。")
        return 1
    if mode == "boot":
        print("  触发：开机后 30 秒 + 之后每 1 分钟巡检")
        print("  身份：SYSTEM（不需要任何人登录 Windows）")
    else:
        print("  触发：用户登录后 30 秒 + 之后每 5 分钟巡检（需要用户已登录）")
    st = load_state()
    st["task_mode"] = mode
    save_state(st)
    if verify:
        print()
        if not verify_task_run(cfg):
            print("！自动验证没通过，请把上面的输出发给我。")
            return 1
    return 0


def uninstall_task(cfg) -> int:
    rc, out = run_cmd(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    if rc == 0:
        log("计划任务已删除（不再开机自启）")
        print("已删除计划任务，开机不会再自动认证了。")
    else:
        print(out)
    return 0 if rc == 0 else 1


# =============================================================================
# CLI
# =============================================================================
def read_secret(prompt: str) -> str:
    """读取密码。真实控制台下用 getpass（不回显）；管道/脚本等非交互环境下
    退化为普通 input —— 否则 Windows 的 getpass 会去读控制台而直接卡死。"""
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            return getpass.getpass(prompt)
    except Exception:
        pass
    return input(prompt)


def cmd_set_password(cfg, unattended=None) -> int:
    print("== 设置校园网认证账号 ==")
    cur = cfg.get("username", "")
    name = input(f"账号（手机号/学工号，回车保持不变 [{cur}]）：").strip() or cur
    pw = read_secret("密码（输入不回显）：")
    pw2 = read_secret("再输一次：")
    if pw != pw2:
        print("两次输入不一致，已取消。")
        return 1
    if not pw:
        print("密码为空，已取消。")
        return 1

    if unattended is None:
        print()
        print("密码保存方式（决定「没人登录 Windows 时能不能自动认证」）：")
        print("  [1] 明文 + 文件权限锁定 ：最可靠，SYSTEM 身份一定能读到（无人值守推荐）")
        print("  [2] 机器范围 DPAPI 加密 ：加密存储，本机进程（含 SYSTEM）都能解")
        print("  [3] 用户范围 DPAPI 加密 ：最安全，但只有你登录 Windows 后才能用")
        kind = {"1": "plain", "2": "machine", "3": "user"}.get(
            (input("请选择 [1]: ").strip() or "1"), "plain")
    else:
        kind = "plain" if unattended else "user"

    cfg["username"] = name
    if kind == "user":
        try:
            cfg["password"] = dpapi_encrypt(pw, machine=False)
            print("已用「用户范围」DPAPI 加密保存（只有你登录 Windows 后能解密）。")
        except Exception as e:
            kind = "plain"
            cfg["password"] = pw
            print(f"！DPAPI 不可用（{e}），改为明文保存。")
    elif kind == "machine":
        try:
            cfg["password"] = dpapi_encrypt(pw, machine=True)
            print("已用「机器范围」DPAPI 加密保存（本机进程含 SYSTEM 都可解密）。")
        except Exception as e:
            kind = "plain"
            cfg["password"] = pw
            print(f"！DPAPI 不可用（{e}），改为明文保存。")
    else:
        cfg["password"] = pw
        print("已按明文保存（随后锁定文件权限）。")
    save_config(cfg)
    if kind == "plain":
        lock_config_acl(CONFIG_PATH)
    print(f"已写入 {CONFIG_PATH}")
    return 0


def cmd_status(cfg) -> int:
    print(f"配置文件   : {CONFIG_PATH}")
    print(f"日志目录   : {LOG_DIR}")
    if cfg.get("portal"):
        print(f"门户地址   : {cfg['portal']}{cfg.get('portal_path', '')}（config.json 固定）")
    else:
        d = (load_state().get("discovered") or {})
        if d.get("portal"):
            print(f"门户地址   : {d['portal']}{d.get('portal_path', '')}"
                  f"（自动发现于 {d.get('at', '?')}）")
        else:
            print("门户地址   : (留空 = 自动发现，将在检测到需要认证时探测)")
    print(f"账号       : {cfg['username'] or '(未设置)'}")
    pw = cfg.get("password", "")
    print(f"密码       : {'已设置（' + password_kind(pw) + '）' if pw else '(未设置)'}")
    st = load_state()
    if st.get("last_ok_at"):
        print(f"上次成功   : {st['last_ok_at']}")
    if st.get("fail_count"):
        print(f"连续失败   : {st['fail_count']} 次")
    status, why, _ = check_online(cfg)
    print(f"联网状态   : {status} —— {why}")
    rc, _ = run_cmd(["schtasks", "/Query", "/TN", TASK_NAME])
    mode = st.get("task_mode", "")
    mode_txt = {"boot": "开机即认证·SYSTEM 身份·无需登录 Windows",
                "logon": "仅登录后认证·当前用户身份"}.get(mode, "")
    print(f"计划任务   : {'已注册' + ('（' + mode_txt + '）' if mode_txt else '') if rc == 0 else '未注册'}")
    print(f"运行身份   : {run_identity()}")
    return 0


def cmd_setup(cfg) -> int:
    """双击 安装.bat 走的就是这个安装向导（中文界面全部由 Python 打印，避开 bat 乱码问题）"""
    line = "=" * 58
    print(line)
    print("   GiWiFi 校园网自动认证 · 安装向导")
    print("   标记 ID: CAMPUS-NET-AUTOLOGIN")
    print(f"   目录   : {APP_DIR}")
    print(line)
    print()
    print("[1/4] 加密算法自检（FIPS-197 / NIST 测试向量）...")
    if not self_test():
        print("\n！自检失败，已中止安装。")
        return 1

    print()
    print("[2/4] 运行模式")
    print("      [1] 开机即认证（SYSTEM 身份）—— 不需要任何人登录 Windows")
    print("          无人值守 / 远程控制用这个；注册需要一次管理员授权(UAC)")
    print("      [2] 仅登录 Windows 后认证（当前用户身份，不需要管理员）")
    unattended = ((input("      请选择 [1]: ").strip() or "1") != "2")
    print(f"      已选择：{'开机即认证（无人值守）' if unattended else '仅登录后认证'}")

    print()
    print("[3/4] 账号 / 密码")
    if cfg.get("username") and cfg.get("password"):
        print(f"      当前账号：{cfg['username']}，密码：{password_kind(cfg['password'])}")
        if unattended and cfg["password"].startswith(DPAPI_PREFIX) \
                and not cfg["password"].startswith(DPAPI_M_PREFIX):
            print("      ！注意：现在存的是「用户范围」密文，SYSTEM 无人值守时解不开，")
            print("        建议选 y 重设，保存方式选 [1] 明文 或 [2] 机器范围。")
        ans2 = input("      要重新设置账号密码吗？(y/N): ").strip().lower()
        if ans2 == "y":
            if cmd_set_password(cfg, unattended=unattended) != 0:
                return 1
        else:
            print("      保持不变。")
    else:
        print("      还没设置账号密码，现在设置：")
        if cmd_set_password(cfg, unattended=unattended) != 0:
            return 1

    print()
    print("[4/4] 安装自动运行的计划任务 ...")
    rc = install_task(cfg, mode="boot" if unattended else "logon")
    if rc == 10:
        print()
        print(">>> 已交给管理员窗口继续安装，请切到那个窗口看结果（它跑完本窗口可关闭）。")
        return 0

    print()
    print("当前状态：")
    cmd_status(cfg)

    print()
    if rc == 0:
        print(line)
        print("  安装完成！")
        if unattended:
            print("  重启后：一开机就自动认证上网，无需任何人登录 Windows，")
            print("          你可以随时远程连进来；被踢下线 1 分钟内自动重连。")
        else:
            print("  登录 Windows 后会自动认证；若还要「无人登录也能认证」，")
            print("  请以管理员身份重新运行本向导并选 [1]。")
        print("  - 立即验证一次： python giwifi_auth.py --force")
        print("  - 查看日志    ： 同目录 logs\\autologin-YYYYMMDD.log")
        print(line)
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="GiWiFi 校园网开机自动认证（支持无人值守）")
    ap.add_argument("--once", "--task", dest="once", action="store_true", help="检查并按需认证一次（默认行为）")
    ap.add_argument("--watch", action="store_true", help="常驻循环守护")
    ap.add_argument("--force", action="store_true", help="忽略在线检查，强制认证一次")
    ap.add_argument("--status", action="store_true", help="显示状态")
    ap.add_argument("--setup", action="store_true", help="安装向导（安装.bat 调用的就是它）")
    ap.add_argument("--set-password", action="store_true", help="设置账号密码")
    ap.add_argument("--install", "--install-boot", dest="install_boot", action="store_true",
                    help="注册「开机即认证」任务：SYSTEM 身份，无需登录 Windows（需要管理员）")
    ap.add_argument("--install-logon", dest="install_logon", action="store_true",
                    help="注册「仅登录后认证」任务：当前用户身份，无需管理员")
    ap.add_argument("--uninstall", action="store_true", help="删除计划任务")
    ap.add_argument("--selftest", action="store_true", help="AES 自检")
    ap.add_argument("--pause-at-end", dest="pause_at_end", action="store_true",
                    help="结束时等待回车（提权窗口内使用）")
    args = ap.parse_args()

    try:
        if args.selftest:
            rc = 0 if self_test() else 1
        else:
            cfg = load_config()
            if args.setup:
                rc = cmd_setup(cfg)
            elif args.set_password:
                rc = cmd_set_password(cfg)
            elif args.status:
                rc = cmd_status(cfg)
            elif args.install_boot:
                r = install_task(cfg, mode="boot")
                rc = 0 if r in (0, 10) else r
            elif args.install_logon:
                r = install_task(cfg, mode="logon")
                rc = 0 if r in (0, 10) else r
            elif args.uninstall:
                rc = uninstall_task(cfg)
            elif args.watch:
                rc = watch(cfg)
            else:
                rc = run_once(cfg, force=args.force)
    except Exception as e:
        log(f"运行异常：{type(e).__name__}: {e}", "ERROR")
        rc = 1

    if args.pause_at_end:
        try:
            input("\n按回车键关闭此窗口 ...")
        except Exception:
            pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
