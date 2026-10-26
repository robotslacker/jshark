package com.jshark.parser.env;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

/**
 * 抓包环境预检工具类
 */
public class SnifferEnvChecker {

    /**
     * 运行跨平台预检
     */
    public static void Check()
    {
        if (Platform.isWindows()) {
            checkWindows();
        } else if (Platform.isLinux()) {
            checkLinux();
        } else {
            throw new SnifferEnvCheckerException("Current Platform [" + Platform.getOSType() + "] is not supported.");
        }
    }

    /**
     * Windows 侧检查逻辑
     */
    private static void checkWindows()
    {
        // 1. 检查驱动
        try {
            NativeLibrary.getInstance("wpcap");
        } catch (UnsatisfiedLinkError e)
        {
            throw new SnifferEnvCheckerException("Npcap is not installed. Sniffer need it.");
        }

        // 2. 检查管理员权限
        if (!isWindowsAdmin())
        {
            throw new SnifferEnvCheckerException("App must run with admin privilege.");
        }
    }

    /**
     * Linux 侧检查逻辑
     */
    private static void checkLinux()
    {
        // 1. 检查库文件
        try {
            NativeLibrary.getInstance("pcap");
        } catch (UnsatisfiedLinkError e)
        {
            throw new SnifferEnvCheckerException("libpcap is not installed. Sniffer need it.");
        }

        // 2. 检查权限
        try {
            PcapNetworkInterface nif = Pcaps.findAllDevs().get(0);
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            handle.close();
        }
        catch (PcapNativeException e)
        {
            if (e.getMessage().contains("Permission denied")) {
                throw new SnifferEnvCheckerException("App must run with admin privilege.");
            }
        }
    }

    /**
     * 通过 JNA 调用 Shell32.IsUserAnAdmin 判断当前进程是否以管理员权限运行。
     * 相比执行 "net session" 外部命令，本方式不会产生输出管道，避免在 Windows 命令行下阻塞等待回车。
     */
    private static boolean isWindowsAdmin()
    {
        try {
            Shell32 shell32 = Native.load("shell32", Shell32.class);
            return shell32.IsUserAnAdmin();
        } catch (Throwable t) {
            // 极少数环境下加载 shell32 失败时，保守返回 false 以触发管理员权限提示
            return false;
        }
    }

    /**
     * Shell32 接口映射，仅声明必需的方法。
     */
    private interface Shell32 extends Library {
        boolean IsUserAnAdmin();
    }
}