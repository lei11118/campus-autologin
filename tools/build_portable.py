#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包可移植版：组装 -> 去隐私 -> 扫描校验 -> 打 zip
用法： python tools/build_portable.py

设计要点
--------
* 隐私词**动态**从本机 config.json / state.json / 系统信息里取，脚本自身不写死任何隐私信息；
* 组装完先做一次全目录**字节级扫描**，命中任何隐私词就拒绝出包（不是"提醒一下"）；
* 只拷贝运行必需文件，logs/ state.json/ task.xml/ __pycache__/ 一律不进包。
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
PKG_NAME = "campus-autologin-portable"
STAGE = DIST / PKG_NAME

# 进包清单：(来源相对路径, 包内相对路径)
# 注：仓库根目录本身就是「可分发内容」，所以源路径就是根目录下的文件。
PAYLOAD = [
    ("giwifi_auth.py", "giwifi_auth.py"),
    ("README.md", "README.md"),
    ("★标记★-校园网自动认证.md", "★标记★-校园网自动认证.md"),
    ("安装.bat", "安装.bat"),
    ("查看状态.bat", "查看状态.bat"),
    ("卸载.bat", "卸载.bat"),
    ("config.example.json", "config.example.json"),
    ("隐私处理说明.txt", "隐私处理说明.txt"),
    ("tests/check_boot_xml.py", "tests/check_boot_xml.py"),
    ("tests/_selfcheck_acl.py", "tests/_selfcheck_acl.py"),
    ("tests/check_discovery.py", "tests/check_discovery.py"),
    ("tests/check_watchdog.py", "tests/check_watchdog.py"),
]


def load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def collect_private_tokens() -> list:
    """从本机现状里提取「必须不能出现在包里」的字符串"""
    toks = []
    cfg = load_json(ROOT / "config.json")
    st = load_json(ROOT / "state.json")

    def add(label, value, minlen=4):
        v = (value or "").strip()
        if v and len(v) >= minlen:
            toks.append((label, v))

    add("账号", cfg.get("username"))
    pw = cfg.get("password", "")
    if pw.startswith(("dpapi:", "dpapim:")):
        add("密码密文", pw, 20)
    else:
        add("密码", pw)          # 明文才扫；只统计命中次数，绝不打印内容

    add("本机内网IP", st.get("userIp"))
    add("AC/设备名", st.get("nasName"))
    portal = (cfg.get("portal") or "").strip()
    if portal:
        add("门户地址", portal)
        host = portal.split("//")[-1].split("/")[0]
        add("门户主机", host)

    try:
        me = subprocess.run(["whoami"], capture_output=True).stdout.decode("mbcs", "replace").strip()
        add("Windows 用户名", me.split("\\")[-1] if me else "")
        add("Windows 域\\用户", me)
    except Exception:
        pass
    try:
        hn = socket.gethostname()
        add("计算机名", hn)
    except Exception:
        pass

    # 本机路径特征：通用模式 + 本机实际路径（动态取，脚本自身不写死作者机器信息）
    frags = ["c:\\users\\", "c:/users/", "\\python3"]
    try:
        frags.append(str(ROOT).lower().replace("/", "\\"))        # 本机项目目录
        frags.append(str(Path.home()).lower().replace("/", "\\"))  # 本机用户目录
    except Exception:
        pass
    for frag in frags:
        add("本机路径片段", frag)
    return toks


def stage_files() -> list:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)
    copied = []
    for src, dst in PAYLOAD:
        s = ROOT / src
        d = STAGE / dst
        if not s.exists():
            print(f"  [X] 缺文件：{src}")
            sys.exit(1)
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(s, d)
        copied.append(dst)
    return copied


def scan(root: Path, tokens: list) -> list:
    hits = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        low = p.read_bytes().lower()
        for label, tok in tokens:
            n = low.count(tok.encode("utf-8").lower())
            if n:
                hits.append((label, str(p.relative_to(root)), n))
    return hits


def check_ascii_bats(root: Path) -> list:
    bad = []
    for p in root.rglob("*.bat"):
        data = p.read_bytes()
        if any(b > 127 for b in data):
            bad.append(str(p.relative_to(root)))
    return bad


def main() -> int:
    print("=" * 64)
    print("  打包 校园网自动认证 · 可移植版")
    print("=" * 64)

    # 0) 版本
    ver = "?"
    for line in (ROOT / "giwifi_auth.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            ver = line.split("=", 1)[1].split("#")[0].strip().strip('"').strip("'")
            break
    print(f"\n版本 : v{ver}")

    # 1) 隐私词
    tokens = collect_private_tokens()
    print("\n[1/5] 本机隐私词（将确保不出现在包内）:")
    for label, tok in tokens:
        shown = f"({len(tok)} 字符，已隐去)"
        print(f"      - {label:<12} {shown}")

    # 2) 组装
    print("\n[2/5] 组装文件 ...")
    copied = stage_files()
    for c in copied:
        print(f"      + {c}")

    # 3) 扫描
    print("\n[3/5] 隐私扫描（字节级，全目录）...")
    hits = scan(STAGE, tokens)
    if hits:
        print("      [X] 发现残留！拒绝出包：")
        for label, path, n in hits:
            print(f"          {path}  <- {label} x{n}")
        return 1
    print("      [OK] 无任何隐私词残留")

    # 4) bat 必须纯 ASCII
    print("\n[4/5] 启动器编码检查（.bat 必须纯 ASCII）...")
    bad = check_ascii_bats(STAGE)
    if bad:
        print(f"      [X] 含非 ASCII 字符：{bad}")
        return 1
    print("      [OK] 全部 .bat 均为纯 ASCII")

    # 5) 打 zip
    print("\n[5/5] 生成 zip ...")
    stamp = datetime.now().strftime("%Y%m%d")
    zip_path = DIST / f"{PKG_NAME}-v{ver}-{stamp}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(STAGE.rglob("*")):
            if p.is_file():
                z.write(p, Path(PKG_NAME) / p.relative_to(STAGE))
    size = zip_path.stat().st_size
    sha = __import__("hashlib").sha256(zip_path.read_bytes()).hexdigest()

    print("\n" + "=" * 64)
    print(f"  完成！")
    print(f"  目录 : {STAGE}")
    print(f"  压缩包: {zip_path}")
    print(f"  大小 : {size/1024:.1f} KB")
    print(f"  SHA256: {sha}")
    print("=" * 64)
    print("\n包内文件：")
    for p in sorted(STAGE.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(STAGE)}  ({p.stat().st_size} B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
