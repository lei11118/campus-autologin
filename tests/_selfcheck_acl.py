# 验证：DPAPI blob 作用域标志 + config.json 权限锁定（无人值守的两块基石）
import base64
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # 项目根目录（可移植）
import giwifi_auth as G


def blob_flags(token: str) -> int:
    """解析 DPAPI blob 头里的 dwFlags（偏移 0x28），4 = CRYPTPROTECT_LOCAL_MACHINE"""
    raw = base64.b64decode(token.split(":", 1)[1])
    return struct.unpack_from("<I", raw, 0x28)[0]


print("=== DPAPI 作用域标志（blob 内自述，解密时系统据此选密钥）===")
m = G.dpapi_encrypt("secret", machine=True)
u = G.dpapi_encrypt("secret", machine=False)
print(f"  机器范围 blob dwFlags = 0x{blob_flags(m):X}  (期望含 0x4 LOCAL_MACHINE)")
print(f"  用户范围 blob dwFlags = 0x{blob_flags(u):X}  (期望 0x0)")
print("  机器范围往返:", G.dpapi_decrypt(m) == "secret")
print("  用户范围往返:", G.dpapi_decrypt(u) == "secret")
print("  说明：解密时 Windows 按 blob 内记录的作用域自动选密钥，无需也不该由调用方指定；")
print("       因此 SYSTEM 能否解开取决于『加密时是否用了机器范围』——本工具正是这么存的。")

print()
print("=== config.json 权限锁定测试（明文保存密码时的保护层）===")
before = G.CONFIG_PATH.read_text(encoding="utf-8")
print("  锁定前 ACL:")
rc, out = G.run_cmd(["icacls", str(G.CONFIG_PATH)])
for line in out.splitlines()[:6]:
    print("   ", line.strip())
ok = G.lock_config_acl(G.CONFIG_PATH)
print("  lock_config_acl 返回:", ok)
rc, out = G.run_cmd(["icacls", str(G.CONFIG_PATH)])
print("  锁定后 ACL:")
for line in out.splitlines()[:8]:
    print("   ", line.strip())
after = G.CONFIG_PATH.read_text(encoding="utf-8")
print("  锁定后仍可读且内容未变:", after == before)
