// 校园网自动认证 · 自解压安装器（C# 5 / .NET Framework 4.0，由 Windows 自带 csc.exe 编译）
//
// 设计要点：
//   * 载荷(payload.zip)以**嵌入式资源**塞进本 EXE，无需在运行时做字节偏移手术；
//   * 默认解压到 %LOCALAPPDATA%\campus-autologin（用户目录，永远可写，**不需要管理员**），
//     解压完再调用包内的「安装.bat」向导；真正需要提权的是向导里的计划任务注册那一步；
//   * 支持 /d:<目录> 自定义位置、/x[:<目录>] 只解压（排障/自动化用）；
//   * 解压时做路径穿越防护（拒绝 .. 和绝对路径），并且**不覆盖**用户已有的 config.json / state.json；
//   * 所有提示输出走真实控制台（中文显示正常，不碰 Console.OutputEncoding —— 改了反而会乱码）。
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;

class Sfx
{
    const string PAYLOAD = "payload.zip";
    const string APP_FOLDER = "campus-autologin";

    static int Main(string[] args)
    {
        SetupConsole();
        string target = null;
        bool extractOnly = false;

        foreach (string raw in args)
        {
            string a = raw.Trim().Trim('"');
            if (a.Length == 0) continue;
            if (a == "/?" || a == "-h" || a == "--help") { Help(); return 0; }
            if (a.StartsWith("/x", StringComparison.OrdinalIgnoreCase))
            {
                extractOnly = true;
                int i = a.IndexOf(':');
                if (i > 0) target = a.Substring(i + 1);
                continue;
            }
            if (a.StartsWith("/d:", StringComparison.OrdinalIgnoreCase)) { target = a.Substring(3); continue; }
            if (target == null) target = a;      // 容忍直接把目标目录作为第一个参数传进来
        }

        if (target == null || target.Trim().Length == 0)
            target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), APP_FOLDER);

        try { target = Path.GetFullPath(target); }
        catch { Console.WriteLine("  [X] 目标目录不合法: " + target); Pause(); return 2; }

        Console.WriteLine("============================================================");
        Console.WriteLine("  校园网自动认证 · 自解压安装包");
        Console.WriteLine("============================================================");
        Console.WriteLine("  解压到 : " + target);
        Console.WriteLine();

        int count = 0;
        try
        {
            Directory.CreateDirectory(target);
            Stream payload = Assembly.GetExecutingAssembly().GetManifestResourceStream(PAYLOAD);
            if (payload == null) { Console.WriteLine("  [X] 内部载荷缺失，EXE 可能已损坏"); Pause(); return 3; }

            string tmpZip = Path.Combine(Path.GetTempPath(),
                "campus-autologin-" + Guid.NewGuid().ToString("N") + ".zip");
            using (FileStream fs = File.Create(tmpZip)) { payload.CopyTo(fs); }
            payload.Close();

            using (ZipArchive za = ZipFile.OpenRead(tmpZip))
            {
                foreach (ZipArchiveEntry e in za.Entries)
                {
                    string rel = e.FullName.Replace('\\', '/');
                    if (rel.Length == 0) continue;
                    if (rel.IndexOf("..", StringComparison.Ordinal) >= 0) continue;   // 路径穿越防护
                    string dest = Path.Combine(target, rel.Replace('/', Path.DirectorySeparatorChar));
                    if (rel.EndsWith("/") || e.Name.Length == 0) { Directory.CreateDirectory(dest); continue; }
                    string dir = Path.GetDirectoryName(dest);
                    if (dir != null && dir.Length > 0) Directory.CreateDirectory(dir);
                    // 保护用户已有配置：这几个文件只在本包里本来就不存在，若存在说明是用户自己的数据
                    string low = e.Name.ToLowerInvariant();
                    if ((low == "config.json" || low == "state.json") && File.Exists(dest)) continue;
                    e.ExtractToFile(dest, true);
                    count++;
                }
            }
            try { File.Delete(tmpZip); } catch { }
        }
        catch (Exception ex)
        {
            Console.WriteLine("  [X] 解压失败: " + ex.Message);
            Pause();
            return 4;
        }

        Console.WriteLine("  已解压 " + count + " 个文件");

        if (extractOnly)
        {
            Console.WriteLine();
            Console.WriteLine("  (仅解压模式，未运行安装向导)");
            return 0;
        }

        string bat = Path.Combine(target, "安装.bat");
        if (!File.Exists(bat))
        {
            Console.WriteLine("  [X] 未找到安装向导 安装.bat，请手动查看该目录");
            Pause();
            return 5;
        }

        Console.WriteLine();
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine("  接下来运行安装向导：选运行模式 → 输校园网账号密码 → UAC 点「是」");
        Console.WriteLine("  （自解压这一步不需要管理员；只有注册开机任务那一步才弹 UAC）");
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine();

        int rc = 0;
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c \"\"" + bat + "\"\"");
            psi.WorkingDirectory = target;
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            p.WaitForExit();
            rc = p.ExitCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine("  [X] 启动向导失败: " + ex.Message);
            Console.WriteLine("      请手动双击: " + bat);
            Pause();
            return 6;
        }

        Console.WriteLine();
        if (rc == 0)
            Console.WriteLine("  完成！以后要看状态/卸载，双击同目录的 查看状态.bat / 卸载.bat 即可。");
        else
            Console.WriteLine("  向导退出码 " + rc + "（若安装失败，日志见 " + Path.Combine(target, "logs") + "）");
        return rc;
    }

    static void SetupConsole()
    {
        // 输出被重定向（管道/日志）时改用 UTF-8 字节，避免中文在捕获端变成乱码；
        // 真实控制台下保持系统默认代码页（中文 Windows 下 .NET 写出的 cp936 字节显示正常）。
        try { if (Console.IsOutputRedirected) Console.OutputEncoding = System.Text.Encoding.UTF8; }
        catch { }
    }

    static void Pause()
    {
        Console.WriteLine();
        Console.Write("  按回车键退出 ...");
        try { Console.ReadLine(); } catch { }
    }

    static void Help()
    {
        Console.WriteLine("校园网自动认证 · 自解压安装包");
        Console.WriteLine();
        Console.WriteLine("  campus-autologin-setup.exe              解压到 %LOCALAPPDATA%\\" + APP_FOLDER + " 并运行安装向导");
        Console.WriteLine("  campus-autologin-setup.exe /d:<目录>      解压到指定目录并运行安装向导");
        Console.WriteLine("  campus-autologin-setup.exe /x            只解压到默认目录，不运行向导");
        Console.WriteLine("  campus-autologin-setup.exe /x:<目录>      只解压到指定目录，不运行向导");
        Console.WriteLine("  campus-autologin-setup.exe /?            显示本帮助");
        Console.WriteLine();
        Console.WriteLine("  说明：解压不需要管理员权限；只有安装「开机即认证」计划任务那一步会弹 UAC。");
    }
}
