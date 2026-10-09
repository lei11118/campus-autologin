# 校园网自动认证（可移植版）

> 📦 **下载**：到 [Releases](https://github.com/lei11118/campus-autologin/releases/latest) 下载 `campus-autologin-setup-v1.1.0.exe`（一键安装）或便携 zip。
>
> 💡 如果你拿到的是 **`campus-autologin-setup-v1.1.0.exe`（自解压安装包）**：直接双击它，
> 它会自动解压到 `%LOCALAPPDATA%\campus-autologin` 并立刻启动下面的安装向导
> （解压不需要管理员；只有注册开机任务那一步会弹 UAC）。
> 本文档描述的是**解压之后**的目录用法。

开机后自动判断校园网是否需要认证，需要就自动登录；被踢下线自动恢复。
**支持「无人登录 Windows」的无人值守模式**，适合把机器放在宿舍/机房，靠远程控制随时连回来。

- **零第三方依赖**：纯 Python 标准库 + Windows DPAPI（不需要 pip install 任何东西）
- **零配置迁移**：整个目录拷到别的机器就能用；门户地址会自动发现，不用手填内网 IP
- **版本**：v1.1.0（可移植版） · 标记 ID `CAMPUS-NET-AUTOLOGIN`

> 已在 GiWiFi「校园助手」gportal 门户（`/gportal/web/login` + `authLogin`）上实机验证：
> 字节级复刻前端加密、SYSTEM 身份下完成真实认证、掉线 1 秒自动重连。
> 其他厂商（深澜 Srun / 锐捷 ePortal / Drcom）门户结构不同，需按第五节适配。

---

## 一、准备工作

1. 装了 **Python 3**（3.8+ 都行）。没有的话去 https://www.python.org/downloads/ 装，
   安装时记得勾选 **Add python.exe to PATH**。
2. 把这整个文件夹拷到目标机器上**任意位置**（例如 `D:\tools\campus-autologin\`，
   路径不要放回收站/临时目录里）。
3. 目标机器要能连到校园网（有线/无线都行，但**无线需要该 SSID 已设置自动连接**）。

## 二、安装（双击一个文件）

**双击 `安装.bat`**，按提示输入：

| 提示 | 输入 |
|---|---|
| `[1/4]` 算法自检 | 等它出 `[OK]` |
| `[2/4]` 运行模式 | **回车** = 开机即认证（无人值守，推荐）；输入 `2` = 仅登录后认证 |
| `[3/4]` 账号/密码 | 输校园网账号 → 输密码（不回显）×2 → 保存方式**回车**（推荐默认） |
| `[4/4]` 安装任务 | 若弹出 **UAC 窗口点「是」**；之后它会自动跑一次验证并打印结果 |

看到下面这几行就算成功：

```
计划任务已注册（身份写法：SID + HighestAvailable（标准写法））
认证成功：认证成功，稍后跳转
复核通过：...（已在线）
```

## 三、两种运行模式

| | 模式 B `[1]`（默认，无人值守） | 模式 A `[2]` |
|---|---|---|
| 运行身份 | **SYSTEM** | 当前登录用户 |
| 触发时机 | **开机后 30 秒** + 之后**每 1 分钟** | 用户登录后 30 秒 + 每 5 分钟 |
| 需要人登录 Windows 吗 | **不需要** ✅ | 需要 |
| 需要管理员 | 需要（一次性 UAC） | 不需要 |
| 适合 | 远程控制 / 无人值守 | 自己天天在机器前 |

> 关键区别：模式 A 的任务**在没人登录时根本不会触发**。所以做远程控制一定选模式 B。

**密码保存方式**（模式 B 必看）：

| 选项 | 说明 | 无人值守可用？ |
|---|---|---|
| **[1] 明文 + 文件权限锁定**（默认） | 最可靠；文件权限收紧到「你 + SYSTEM + Administrators」 | ✅ |
| [2] 机器范围 DPAPI 加密 | 加密存储，本机进程（含 SYSTEM）都能解 | ✅ |
| [3] 用户范围 DPAPI 加密 | 最安全，但**只有你登录 Windows 后**才解得开 | ❌ 无人值守别选 |

## 四、常用命令

双击下面这些 bat，或自己开命令行：

| 操作 | 双击 | 命令行 |
|---|---|---|
| 安装/修改配置 | `安装.bat` | `python giwifi_auth.py --setup` |
| 看状态 | `查看状态.bat` | `python giwifi_auth.py --status` |
| 立刻认证一次（验证密码对不对） | — | `python giwifi_auth.py --force` |
| 改账号密码 | — | `python giwifi_auth.py --set-password` |
| 装/更新开机任务（无人值守） | — | `python giwifi_auth.py --install` |
| 装/更新任务（仅登录后） | — | `python giwifi_auth.py --install-logon` |
| 关掉自启 | `卸载.bat` | `python giwifi_auth.py --uninstall` |
| 算法自检 | — | `python giwifi_auth.py --selftest` |

退出码：`0` 已在线/成功 · `1` 认证被拒（看日志里的 `info`/`reasoncode`） ·
`2` 无法判断/准备失败 · `3` 连续失败冷却中。

## 五、换到别的学校 / 别的门户怎么办

**门户地址不用配**：未认证时随便访问一个 http 站点，认证设备(AC)会把你 302 到门户登录页，
程序从中自动读出门户 IP、登录页路径、认证接口路径（只在目标像内网 IP 或含 portal/wifi/srun
等特征时才采纳，避免被普通网站跳转骗到）。想固定写死就在 `config.json` 里填 `portal`。

**如果对方不是 GiWiFi gportal 家族**（例如深澜 Srun、锐捷 ePortal、Drcom），认证接口与加密方式不同，
需要按对方门户页面改三处：

1. `portal_path` / `auth_path`：登录页与认证接口路径；
2. `encrypt_key` + `encrypt_mode`：门户前端 JS 里 `CryptoJS.AES.encrypt(...)` 的 key / iv / mode / padding
   （本工具实现的是 `AES-128-CBC + ZeroPadding`，iv 由页面下发）；
3. 若是完全不同的接口形态（比如锐捷的 `InterFace.do?method=login`），改 `do_login()` 里的请求构造。

排查方法：浏览器打开门户页 → F12 → Network，点一次登录，看那条 XHR 的 URL 和 Form Data；
再看页面 JS 里怎么加密这些参数的。

## 六、工作原理（GiWiFi gportal 家族）

```
判断是否需要认证
  GET http://nettest.gwifi.com.cn  -> {"resultCode":0,"data":"\"\""}   => 已在线
  GET http://connect.rom.miui.com/generate_204 -> 204                 => 已在线
  被 302 到门户 / 探针不通                                            => 需要认证 / 无法判断

认证
  1. GET 门户登录页 -> 解析服务端下发的隐藏参数(iv/sign/nasName/userIp/pid...)
  2. 明文 = 表单字段按 jQuery.serialize() 拼串（encodeURIComponent + "&"）
     密文 = AES-128-CBC(key=门户前端硬编码, iv=页面下发, ZeroPadding) -> Base64
  3. POST /gportal/web/authLogin?round=<随机数>   体: data=<Base64>&iv=<iv>
  4. 成功判据 status==1，随后再用探针复核一次
  5. 失败退避：连续 3 次失败进入 30 分钟冷却（避免账号被刷到要验证码）
```

内置的可靠性设计：

- 探针**重试 3 次 + 交叉验证**后再判定"需要认证"，避免瞬时抖动误判 →
  误判会白白消耗失败次数，连续 3 次就进冷却，真掉线时反而不认证（无人值守最致命的失败模式）
- 开机时若网络还没就绪，最多等 60 秒再判断
- 认证接口报错但探针显示已在线 → 判定为无需认证（多设备/已在别处登录）
- 每次认证都会在日志里打印**运行身份 + 密码来源与可用性**，出问题一条 grep 就能定位

## 七、排障

日志：`logs\autologin-YYYYMMDD.log`（UTF-8，用记事本/VSCode 打开都正常）

| 日志里看到 | 含义 / 处理 |
|---|---|
| `无需认证` | 一切正常 |
| `需要认证` + `认证成功` | 刚自动登录成功 |
| `认证被拒绝：... info=...` | 账号密码错 / 账号不存在（`reasoncode 16`=账号不存在、`40`=需完善个人信息）；用 `--set-password` 重设 |
| `无法判断联网状态` | 不在校园网内 / 网线没插 / DHCP 没拿到地址 |
| `密码解密失败` | 存的是**用户范围** DPAPI 而任务以 SYSTEM 运行 → 重设密码并选 [1] 或 [2] |
| `未配置账号或密码` | 还没跑过 `安装.bat` 的设置步骤 |
| `准备阶段失败：未能确定门户地址` | 不在校园网内（拔网线/换网络了） |

确认计划任务是否在跑：

```bat
schtasks /Query /TN GiWiFi-Campus-AutoAuth /V /FO LIST
```

## 八、无人值守（远程控制）注意事项

- **电源计划里把"睡眠"设为「从不」**，否则机器睡了网络就断，远程连不进来。
- 校园网若限制"同账号在线设备数"，本工具每 1 分钟会自动把本机抢回来。
- 目录被计划任务按**绝对路径**引用：**移动/改名本目录后，必须在新位置重跑一次
  `python giwifi_auth.py --install`**（标记文件里也写了这条）。
- 换 Windows 用户或换机器后，DPAPI 密文解不开（若你选了加密保存）→ 重新 `--set-password`。

## 九、文件说明

| 文件 | 作用 |
|---|---|
| `giwifi_auth.py` | 主程序（唯一必需文件） |
| `安装.bat` / `查看状态.bat` / `卸载.bat` | 双击入口（纯 ASCII，自动找 Python） |
| `config.json` | 账号密码等配置（首次运行自动生成） |
| `config.example.json` | 配置示例（同目录，可参考字段含义） |
| `state.json` | 运行状态（失败计数、缓存的门户信息） |
| `logs\` | 日志目录 |
| `tests\` | 三个自检脚本（算法/加密作用域/门户发现），可随时跑 |
| `★标记★-校园网自动认证.md` | 标记文件（本目录的身份证） |
| `隐私处理说明.txt` | 打包时做了哪些隐私清理 |

**编码约定（改动前必读）**：`*.bat` **只能写 ASCII**（cmd 按系统 ANSI 代码页解析批处理文件，
写中文必乱码），中文界面一律由 Python 打印；`giwifi_auth.py` / `config.json` 用 UTF-8。
自检：`LC_ALL=C grep -c '[^ -~]' 安装.bat` 应为 0。
