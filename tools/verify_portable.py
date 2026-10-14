#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证打包产物：解压到干净目录 -> 独立隐私复扫 -> 真跑自检/状态/测试
用法： python tools/verify_portable.py
（模拟"拷到另一台机器"：完全不依赖原目录，且用新生成的 config.json 冷启动）
"""
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_portable as B          # 复用隐私词提取与扫描逻辑

PY = sys.executable
WORK = Path(os.environ.get("LOCALAPPDATA", str(ROOT))) / "Temp" / "portable_test"

FAIL = []


def step(title):
    print("\n" + "-" * 62)
    print(f"  {title}")
    print("-" * 62)


def run(args, cwd, expect_zero=True, timeout=180):
    r = subprocess.run([PY] + args, cwd=str(cwd), capture_output=True, timeout=timeout)
    out = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
    print(out if out else "(无输出)")
    if expect_zero and r.returncode != 0:
        FAIL.append(f"{' '.join(args)} -> 退出码 {r.returncode}")
    return r.returncode, out


zips = sorted((ROOT / "dist").glob(f"{B.PKG_NAME}-*.zip"))
if not zips:
    print("找不到 zip，请先运行 build_portable.py")
    sys.exit(1)
z = zips[-1]

step(f"0. 解压 {z.name} 到干净目录")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)
with zipfile.ZipFile(z) as zf:
    zf.extractall(WORK)
PKG = WORK / B.PKG_NAME
print(f"解压目录: {PKG}")
print("解压后内容（应与包内清单一致，且**不含** config.json / state.json / logs/ / task.xml）:")
for p in sorted(PKG.rglob("*")):
    print(f"  {'[D]' if p.is_dir() else '   '} {p.relative_to(PKG)}")

step("1. 独立隐私复扫（重新从本机现状提取隐私词，扫解压后的目录）")
tokens = B.collect_private_tokens()
hits = B.scan(PKG, tokens)
print(f"隐私词数量: {len(tokens)}")
if hits:
    print("[X] 有残留：")
    for label, path, n in hits:
        print(f"    {path} <- {label} x{n}")
    FAIL.append("隐私扫描")
else:
    print("[OK] 解压后的目录里没有任何本机隐私词")

step("2. 冷启动自检（算法）")
run(["giwifi_auth.py", "--selftest"], PKG)

step("3. 冷启动状态（应自动创建 config.json，且账号为空）")
run(["giwifi_auth.py", "--status"], PKG)
cfg_new = PKG / "config.json"
print(f"\n新生成的 config.json 存在: {cfg_new.exists()}")
if cfg_new.exists():
    import json
    c = json.loads(cfg_new.read_text(encoding="utf-8"))
    print(f"  账号字段: {c.get('username')!r}（应为空）")
    print(f"  密码字段: {'空' if not c.get('password') else '**非空(不应出现!)**'}")
    print(f"  portal  : {c.get('portal')!r}（应为空 = 自动发现）")
    if c.get("username") or c.get("password"):
        FAIL.append("包内冷启动出现了账号/密码")

step("4. 运行包内自带测试（验证可移植路径写法）")
run(["tests/check_boot_xml.py"], PKG)
run(["tests/check_discovery.py"], PKG)

step("5. 包内脚本关键常量一致性")
code = (PKG / "giwifi_auth.py").read_text(encoding="utf-8")
for needle, why in [('TASK_NAME = "GiWiFi-Campus-AutoAuth"', "计划任务名"),
                    ('__version__ = "1.1.0"', "版本号"),
                    ('BOOT_PRINCIPALS', "SYSTEM 身份写法备选"),
                    ('def discover_portal', "门户自动发现")]:
    ok = needle in code
    print(f"  [{'OK' if ok else 'X '}] {why}: {needle}")
    if not ok:
        FAIL.append(why)

step("结论")
if FAIL:
    print("！验证未通过：")
    for f in FAIL:
        print(f"   - {f}")
    sys.exit(1)
print("全部通过：这个包可以直接拷到别的机器使用。")
print(f"包位置: {z}")
print("在目标机器上：解压 → 双击 安装.bat → 选模式 → 输账号密码 → UAC 点「是」")

