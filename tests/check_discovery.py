# 校验「门户地址自动发现」：不跟随重定向的工具函数 + 误认护栏 + 在线时的行为
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import giwifi_auth as G

print("=== 1. 不跟随重定向（http_get_noredirect）===")
for u in ("http://github.com/", "http://www.baidu.com/"):
    code, loc = G.http_get_noredirect(u, 8)
    print(f"  {u:<28} -> code={code} loc={loc}")

print()
print("=== 2. 门户主机名护栏（防止把普通网站跳转误认成门户）===")
cases = [
    ("10.0.0.1", True), ("10.1.1.1", True), ("192.168.1.1", True),
    ("portal.school.edu.cn", True), ("gwifi.example.com", True),
    ("www.baidu.com", False), ("github.com", False), ("", False),
]
ok = True
for host, expect in cases:
    got = G._looks_like_portal_host(host)
    flag = "OK " if got == expect else "FAIL"
    if got != expect:
        ok = False
    print(f"  [{flag}] {host!r:<26} -> {got}（期望 {expect}）")
print("  护栏逻辑:", "全部符合预期" if ok else "有偏差！")

print()
print("=== 3. 当前网络下的实际发现结果（在线时应当啥也发现不到，且不会乱缓存）===")
cfg = G.load_config()
p, pth, apth, full = G.discover_portal(cfg)
print(f"  结果: portal={p} path={pth} auth={apth}")
print("  说明：机器已在线时 AC 不重定向，返回空是正确行为（不会污染缓存）")

print()
print("=== 4. resolve_portal：config 有固定值时应直接采用（不探测）===")
cfg2 = dict(cfg)
cfg2["portal"] = "http://10.0.0.1"
r = G.resolve_portal(cfg2)
print(f"  固定 portal -> {r}")
print("  是否正确采用固定值:", r["portal"] == "http://10.0.0.1")
