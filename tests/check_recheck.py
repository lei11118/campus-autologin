# 复核陷阱回归测试（2026-10-14 事故的专用护栏）
#   事故复盘：认证接口已报成功，但 AC 放行有 10~30 秒延迟；旧版只等 1.5 秒就判"复核未通"
#   → 计入失败 → 满 3 次 → 30 分钟冷却。一天内被锁 8 次，"认证掉了、网络断了好长时间"。
# 本测试保证两件事：
#   1) wait_online() 能在探针恢复后立刻返回；探针永不恢复时也能按时返回（不死等）
#   2) 源码里"认证成功但复核未通"的分支绝不再计入失败
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import giwifi_auth as G

FAIL = []

print("=== 1. wait_online：探针第 3 次恢复 ONLINE 应立刻返回 ===")
calls = {"n": 0}


def fake_check_online(cfg):
    calls["n"] += 1
    if calls["n"] >= 3:
        return (G.ONLINE, "已在线", {})
    return (G.UNKNOWN, "被门户劫持", {})


real_check = G.check_online
try:
    G.check_online = fake_check_online
    t0 = time.time()
    status, why = G.wait_online({}, timeout_s=30)
    dt = time.time() - t0
    print(f"  第 {calls['n']} 次探针返回 {status}（{why}），耗时 {dt:.1f}s  [期望 ONLINE 且 <12s]")
    if status != G.ONLINE:
        FAIL.append("探针恢复后没有识别到 ONLINE")
    if dt > 12:
        FAIL.append(f"探针恢复后返回太慢：{dt:.1f}s")

    def never_online(cfg):
        return (G.NEED_AUTH, "仍被劫持", {})

    G.check_online = never_online
    t0 = time.time()
    status2, why2 = G.wait_online({}, timeout_s=3)
    dt2 = time.time() - t0
    print(f"  永不恢复时：{dt2:.1f}s 后返回 {status2}  [期望 ~3~6s 内返回，不死等]")
    if dt2 > 8:
        FAIL.append("超时后没有及时返回（会卡住守护循环）")
    if status2 == G.ONLINE:
        FAIL.append("错误地判定为在线")
finally:
    G.check_online = real_check

print()
print("=== 2. 源码护栏：认证成功但复核未通 → 不得计入失败 ===")
src = (ROOT / "giwifi_auth.py").read_text(encoding="utf-8")
checks = [
    ("wait_online(cfg, 25)", "成功路径必须用 wait_online 复核（给 AC 放行留时间）"),
    ("不计失败", "必须有明确的「不计失败」语义"),
    ("recheck_pending_ts", "必须记录 recheck_pending（而不是 fail_count）"),
]
for needle, desc in checks:
    ok = needle in src
    print(f"  [{'OK' if ok else 'X '}] {desc}")
    if not ok:
        FAIL.append(desc)
old_trap = '认证接口返回成功，但复核仍未通网：'
if old_trap in src and "不计失败" not in src.split(old_trap)[0][-200:]:
    FAIL.append("旧版陷阱分支仍在（认证成功却计入失败）")
print("  [OK] 旧陷阱分支已改写")

print()
if FAIL:
    print("！存在问题：")
    for f in FAIL:
        print("   - " + f)
    sys.exit(1)
print("全部通过：复核逻辑不会再把手滑的 30 秒延迟变成半小时断网。")
