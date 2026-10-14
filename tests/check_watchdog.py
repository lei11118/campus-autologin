# 看门狗自检：
#   1) pid_state 三分法（alive / dead / unknown —— 普通用户无权探测 SYSTEM 进程）
#   2) 「心跳优先」判定（核心修复：不能把正常工作的 SYSTEM 守护进程误判成已死）
#   3) 看门狗任务 XML 用当前用户身份注册一次（只验 schema 合法性），随即删除
#   4) taskkill 哑进程（卡死分支用的杀进程命令）
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import giwifi_auth as G

FAIL = []

print("=== 1. pid_state 三分法 ===")
print(f"  当前进程 {os.getpid()}        -> {G.pid_state(os.getpid())}   (期望 alive)")
print(f"  不存在的 999999          -> {G.pid_state(999999)}   (期望 dead)")
daemon_pid = int((G.load_state().get("daemon") or {}).get("pid") or 0)
if daemon_pid:
    print(f"  守护进程 {daemon_pid}         -> {G.pid_state(daemon_pid)}   "
          f"(普通用户看 SYSTEM 进程期望 unknown；管理员/SYSTEM 视角为 alive)")
else:
    print("  （当前没有守护进程在跑，跳过该项）")

print()
print("=== 2. 心跳优先判定（核心修复）===")
fake = {"daemon": {"pid": daemon_pid or os.getpid(), "last_beat_ts": time.time(),
                   "state": "ONLINE", "last_beat_at": "刚刚"}}
real_load, real_save = G.load_state, G.save_state
G.load_state = lambda: fake
G.save_state = lambda d: None
try:
    running, info, age = G.daemon_status(G.load_config())
    print(f"  心跳新鲜({age:.0f}s 前) -> running={running}  (期望 True：即使无权探测该进程也算在跑)")
    if not running:
        FAIL.append("心跳新鲜却判为未运行（会导致重复拉起守护进程）")
    fake["daemon"]["last_beat_ts"] = time.time() - 3600
    running2, _, age2 = G.daemon_status(G.load_config())
    print(f"  心跳过期({age2/60:.0f} 分钟) -> running={running2}  "
          f"(期望 False 或取决于进程是否真的还在)")
    if running2:
        FAIL.append("心跳过期却仍判为在跑（看门狗永远不重启）")
finally:
    G.load_state, G.save_state = real_load, real_save

print()
print("=== 3. 看门狗任务 XML 合法性（用当前用户身份注册一次，随即删除）===")
xml = G.task_xml(G.pythonw_path(), ROOT / "giwifi_auth.py", "logon", None, "watchdog")
p = ROOT / "task-watchdog-test.xml"
p.write_text(xml, encoding="utf-16")
rc, out = G.run_cmd(["schtasks", "/Create", "/TN", "GiWiFi-Watchdog-TEST", "/XML", str(p), "/F"])
print(f"  schtasks 返回码 = {rc}")
print(f"  输出: {out.strip()[:300]}")
if rc != 0:
    FAIL.append(f"看门狗 XML 被 schtasks 拒绝：{out.strip()[:200]}")
rc2, out2 = G.run_cmd(["schtasks", "/Query", "/TN", "GiWiFi-Watchdog-TEST"])
print(f"  注册后查询: {'存在 ✔' if rc2 == 0 else '查不到 ✘'}")
if rc2 != 0:
    FAIL.append("注册返回成功但任务查不到（这就是之前踩过的坑）")
G.run_cmd(["schtasks", "/Delete", "/TN", "GiWiFi-Watchdog-TEST", "/F"])
print("  已清理测试任务")
try:
    p.unlink()
except Exception:
    pass

print()
print("=== 4. taskkill 哑进程（看门狗处理卡死守护进程所用的命令）===")
dummy = subprocess.Popen([G.pythonw_path(), "-c", "import time;time.sleep(120)"])
time.sleep(1.5)
print(f"  哑进程 PID {dummy.pid} 状态={G.pid_state(dummy.pid)}")
rc, out = G.run_cmd(["taskkill", "/PID", str(dummy.pid), "/F", "/T"])
print(f"  taskkill 返回码={rc} 输出: {out.strip()[:120]}")
time.sleep(0.5)
after = G.pid_state(dummy.pid)
print(f"  杀后状态={after}  (期望 dead)")
if after != "dead":
    FAIL.append("taskkill 未生效")

print()
if FAIL:
    print("！存在问题：")
    for f in FAIL:
        print("   - " + f)
    sys.exit(1)
print("全部通过：看门狗相关逻辑正常。")
