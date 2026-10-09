# 校验 boot 模式任务 XML：格式 + 关键点（不写非法 LogonType、触发器正确、UTF-16 可被 schtasks 读）
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent      # 项目根目录（可移植写法，不写死绝对路径）
sys.path.insert(0, str(ROOT))
import giwifi_auth as G

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
PYW = str(Path(sys.executable).with_name("pythonw.exe"))
SCRIPT = str(ROOT / "giwifi_auth.py")

print("=== 逐个身份写法检查 ===")
for label, principal in G.BOOT_PRINCIPALS:
    xml = G.task_xml(PYW, SCRIPT, "boot", principal)
    root = ET.fromstring(xml)                      # 格式检查
    p = root.find(".//t:Principal", NS)
    children = [c.tag.split('}')[1] for c in p]
    print(f"  [{label}]")
    print(f"      XML 格式: OK    Principal 子元素: {children}")
    assert "LogonType" not in children, "内置服务账号不能写 LogonType！"
    assert "UserId" in children
print("  全部写法均不含非法 LogonType ✔")

print()
print("=== 默认（首选）写法生成的完整 XML ===")
xml = G.task_xml(PYW, SCRIPT, "boot")
for i, line in enumerate(xml.splitlines(), 1):
    if 20 <= i <= 32:
        print(f"  {i:>2}| {line}")

print()
print("=== 落盘编码检查（schtasks /XML 要求 Unicode）===")
p = G.APP_DIR / "task.xml"
p.write_text(xml, encoding="utf-16")
raw = p.read_bytes()
print(f"  文件头字节: {raw[:4].hex()}  （fffe 或 feff = 带 BOM 的 UTF-16）")
print(f"  能被 ElementTree 读回: {ET.fromstring(p.read_text(encoding='utf-16')).tag.split('}')[1]}")

print()
print("=== 当前 config 里的密码状态 ===")
cfg = G.load_config()
print("  账号:", cfg["username"])
print("  密码:", G.password_kind(cfg["password"]) if cfg["password"] else "(未设置)")
if cfg["password"]:
    print("  能解出长度:", len(G.resolve_password(cfg["password"])), "字符")
