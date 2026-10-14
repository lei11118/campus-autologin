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
FAIL = []


def check(xml, kind, expect):
    root = ET.fromstring(xml)                                   # 格式检查
    p = root.find(".//t:Principal", NS)
    children = [c.tag.split('}')[1] for c in p]
    args = root.find(".//t:Actions/t:Exec/t:Arguments", NS).text
    limit = root.find(".//t:Settings/t:ExecutionTimeLimit", NS).text
    trigs = [t.tag.split('}')[1] for t in root.findall(".//t:Triggers/*", NS)]
    restart = root.find(".//t:Settings/t:RestartOnFailure", NS) is not None
    uid = (p.find("t:UserId", NS).text or "")
    is_service = ("S-1-5-18" in uid) or uid.upper().endswith("\\SYSTEM")
    has_logontype = "LogonType" in children
    print(f"  [{kind}]")
    print(f"      Principal={children}  身份={uid}  触发器={trigs}")
    print(f"      Arguments={args}")
    print(f"      ExecutionTimeLimit={limit}  RestartOnFailure={restart}")
    # 关键规则：内置服务账号(SYSTEM) 绝不能写 LogonType；普通用户任务则必须有
    if is_service and has_logontype:
        FAIL.append(f"{kind}: 服务账号出现了非法 LogonType（schtasks 会拒绝整个 XML）")
    if (not is_service) and (not has_logontype):
        FAIL.append(f"{kind}: 普通用户任务缺少 LogonType")
    if expect["args"] not in args:
        FAIL.append(f"{kind}: 动作参数不含 {expect['args']}")
    if limit != expect["limit"]:
        FAIL.append(f"{kind}: ExecutionTimeLimit={limit}，期望 {expect['limit']}")
    if expect["restart"] != restart:
        FAIL.append(f"{kind}: RestartOnFailure={restart}，期望 {expect['restart']}")
    for t in expect["triggers"]:
        if t not in trigs:
            FAIL.append(f"{kind}: 缺少触发器 {t}")


print("=== 逐种任务形态检查（三种 kind × 身份写法）===")
for label, principal in G.BOOT_PRINCIPALS:
    xml = G.task_xml(PYW, SCRIPT, "boot", principal, "daemon")
    assert "LogonType" not in xml, "内置服务账号不能写 LogonType！"
print("  三种身份写法均不含非法 LogonType ✔")
print()

check(G.task_xml(PYW, SCRIPT, "boot", kind="daemon"),
      "daemon", {"args": "--daemon", "limit": "PT0S", "restart": True,
                 "triggers": ["BootTrigger"]})
check(G.task_xml(PYW, SCRIPT, "boot", kind="watchdog"),
      "watchdog", {"args": "--ensure-running", "limit": "PT5M", "restart": False,
                   "triggers": ["TimeTrigger"]})
check(G.task_xml(PYW, SCRIPT, "boot", kind="once"),
      "once", {"args": "--task", "limit": "PT10M", "restart": False,
               "triggers": ["BootTrigger", "TimeTrigger"]})
check(G.task_xml(PYW, SCRIPT, "logon", kind="once"),
      "logon-once", {"args": "--task", "limit": "PT10M", "restart": False,
                     "triggers": ["LogonTrigger"]})

print()
print("=== 落盘编码检查（schtasks /XML 要求 Unicode）===")
p = G.APP_DIR / "task-daemon.xml"
p.write_text(G.task_xml(PYW, SCRIPT, "boot", kind="daemon"), encoding="utf-16")
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

print()
if FAIL:
    print("！存在问题：")
    for f in FAIL:
        print("   - " + f)
    sys.exit(1)
print("全部通过：三种任务形态的 XML 都符合预期。")
