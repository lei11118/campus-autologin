#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把可移植包做成「自解压 EXE」：
  1) 复用 build_portable 的逻辑重新组装 + 隐私扫描（不通过就拒绝出包）
  2) 打成不含顶层目录的 payload.zip
  3) 用 Windows 自带的 csc.exe 编译 tools/sfx/launcher.cs，并把 payload.zip 作为嵌入资源
  4) 扫描 EXE 字节、再用 /x 实跑解压，逐文件比对 SHA256，最后跑一遍包内自检

用法： python tools/build_sfx.py
无需安装任何第三方工具（csc.exe 是 Windows/.NET 自带的）。
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_portable as B          # 复用：组装 / 隐私词提取 / 扫描

DIST = ROOT / "dist"
BUILD = DIST / "build"
LAUNCHER = ROOT / "tools" / "sfx" / "launcher.cs"

CSC_CANDIDATES = [
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
]
FW_DIRS = [
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319",
]

FAIL = []


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def find_csc() -> str:
    for c in CSC_CANDIDATES:
        if Path(c).exists():
            return c
    return ""


def ref_arg(name: str) -> str:
    """优先给出框架目录里的绝对路径，csc 找得到才稳"""
    for d in FW_DIRS:
        p = Path(d) / name
        if p.exists():
            return str(p)
    return name


def make_payload_zip(stage: Path, out: Path) -> int:
    """把 stage 里的内容打成 zip，**不带顶层目录**（解压即得到包根）"""
    if out.exists():
        out.unlink()
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(stage).as_posix())
                n += 1
    return n


def main() -> int:
    print("=" * 64)
    print("  打包 校园网自动认证 · 自解压 EXE")
    print("=" * 64)

    # 版本
    ver = "?"
    for line in (ROOT / "giwifi_auth.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            ver = line.split("=", 1)[1].split("#")[0].strip().strip('"').strip("'")
            break

    # 1) 组装 + 隐私校验（与可移植包同一套标准）
    print("\n[1/6] 组装并做隐私校验 ...")
    tokens = B.collect_private_tokens()
    B.stage_files()
    hits = B.scan(B.STAGE, tokens)
    if hits:
        print("      [X] 源文件里有隐私残留，拒绝出包：")
        for label, path, n in hits:
            print(f"          {path} <- {label} x{n}")
        return 1
    bad_bat = B.check_ascii_bats(B.STAGE)
    if bad_bat:
        print(f"      [X] .bat 含非 ASCII：{bad_bat}")
        return 1
    print(f"      [OK] 文件已组装，{len(tokens)} 个隐私词 0 命中，.bat 纯 ASCII")

    # 2) payload.zip（不带顶层目录）
    print("\n[2/6] 生成嵌入式载荷 payload.zip ...")
    BUILD.mkdir(parents=True, exist_ok=True)
    payload = BUILD / "payload.zip"
    n = make_payload_zip(B.STAGE, payload)
    print(f"      {payload.name}: {n} 个文件, {payload.stat().st_size/1024:.1f} KB")

    # 3) 编译启动器
    print("\n[3/6] 编译自解压启动器（csc.exe）...")
    csc = find_csc()
    if not csc:
        print("      [X] 找不到 csc.exe（.NET Framework 编译器）")
        return 1
    print(f"      编译器: {csc}")
    exe = DIST / f"campus-autologin-setup-v{ver}.exe"
    if exe.exists():
        exe.unlink()
    cmd = [csc, "/nologo", "/target:exe", "/platform:anycpu", "/optimize+",
           "/out:" + str(exe),
           "/resource:" + str(payload) + ",payload.zip",
           "/reference:" + ref_arg("System.IO.Compression.dll"),
           "/reference:" + ref_arg("System.IO.Compression.FileSystem.dll"),
           str(LAUNCHER)]
    r = subprocess.run(cmd, capture_output=True)
    out = (r.stdout + r.stderr).decode("mbcs", "replace").strip()
    if out:
        print("      " + out.replace("\n", "\n      "))
    if r.returncode != 0 or not exe.exists():
        print("      [X] 编译失败")
        return 1
    print(f"      [OK] 生成 {exe.name}（{exe.stat().st_size/1024:.1f} KB）")

    # 4) 扫描 EXE 字节
    print("\n[4/6] 对 EXE 字节做隐私扫描 ...")
    hits = []
    for target_file in (exe, payload):
        low = target_file.read_bytes().lower()
        for label, tok in tokens:
            c = low.count(tok.encode("utf-8").lower())
            if c:
                hits.append((label, target_file.name, c))
    if hits:
        print("      [X] EXE 里有隐私残留：")
        for label, path, c in hits:
            print(f"          {path} <- {label} x{c}")
        return 1
    print("      [OK] EXE 字节里没有任何隐私词")

    # 5) 实跑 /x 解压并逐文件比对
    print("\n[5/6] 实跑验证：/x 解压到临时目录并逐文件比对 SHA256 ...")
    work = Path(tempfile.gettempdir()) / "sfx_test"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    r = subprocess.run([str(exe), "/x:" + str(work)], capture_output=True)
    print((r.stdout + r.stderr).decode("utf-8", "replace"))
    if r.returncode != 0:
        print("      [X] 解压失败")
        return 1
    src_files = {p.relative_to(B.STAGE).as_posix(): sha256(p)
                 for p in B.STAGE.rglob("*") if p.is_file()}
    got_files = {p.relative_to(work).as_posix(): sha256(p)
                 for p in work.rglob("*") if p.is_file()}
    missing = sorted(set(src_files) - set(got_files))
    extra = sorted(set(got_files) - set(src_files))
    diff = sorted(k for k in set(src_files) & set(got_files) if src_files[k] != got_files[k])
    print(f"      源文件 {len(src_files)} 个 / 解压出 {len(got_files)} 个")
    if missing:
        print(f"      [X] 缺少: {missing}")
    if extra:
        print(f"      [X] 多出: {extra}")
    if diff:
        print(f"      [X] 内容不一致: {diff}")
    if missing or extra or diff:
        return 1
    print("      [OK] 每个文件都与源文件字节一致")

    # 6) 在解压出来的目录里跑自检
    print("\n[6/6] 在解压目录里跑包内自检 ...")
    r = subprocess.run([sys.executable, "giwifi_auth.py", "--selftest"], cwd=str(work),
                       capture_output=True)
    txt = (r.stdout + r.stderr).decode("utf-8", "replace").strip()
    print("      " + txt.replace("\n", "\n      "))
    if r.returncode != 0:
        FAIL.append("自检")
    r = subprocess.run([sys.executable, "tests/check_boot_xml.py"], cwd=str(work), capture_output=True)
    if r.returncode != 0:
        FAIL.append("任务 XML 测试")
    else:
        print("      [OK] 包内任务 XML 测试通过")

    print("\n" + "=" * 64)
    if FAIL:
        print("  ！验证未通过：" + ", ".join(FAIL))
        return 1
    print("  完成！自解压安装包：")
    print(f"  {exe}")
    print(f"  大小: {exe.stat().st_size/1024:.1f} KB")
    print(f"  SHA256: {sha256(exe)}")
    print("=" * 64)
    print("\n目标机器上：双击它 → 自动解压并运行安装向导（解压不需要管理员，")
    print("只有注册开机任务那一步会弹 UAC）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
