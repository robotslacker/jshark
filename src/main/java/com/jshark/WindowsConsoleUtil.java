package com.jshark;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

/**
 * Windows 控制台辅助工具。
 *
 * <p>Windows 命令行（cmd）默认开启“快速编辑模式（Quick Edit Mode）”。
 * 一旦用户在控制台窗口内单击或拖选文本，控制台会进入“标记”状态，
 * 任何向 stdout 写入数据的进程都会被阻塞，直到用户按回车或 Esc 退出标记状态。</p>
 *
 * <p>这就表现为：Capture 正常运行过程中“总卡住，需要回车才会继续”。
 * 由于 {@code CliShark} 使用同步的 {@code ConsoleAppender} 输出日志，
 * 主捕获线程会阻塞在日志写入上。通过在启动时关闭快速编辑模式即可从根因上消除该现象。</p>
 */
public final class WindowsConsoleUtil {

    private static final int STD_INPUT_HANDLE = -10;
    private static final int ENABLE_QUICK_EDIT_MODE = 0x0040;
    private static final int ENABLE_EXTENDED_FLAGS = 0x0080;

    private WindowsConsoleUtil() {
    }

    private interface Kernel32 extends Library {
        Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class);

        Pointer GetStdHandle(int nStdHandle);

        boolean GetConsoleMode(Pointer hConsoleHandle, IntByReference lpMode);

        void SetConsoleMode(Pointer hConsoleHandle, int dwMode);
    }

    /**
     * 关闭当前控制台输入句柄的快速编辑模式。
     *
     * <p>仅在 Windows 平台生效；Linux/重定向/无控制台环境下静默忽略。</p>
     */
    public static void disableQuickEditMode() {
        if (!Platform.isWindows()) {
            return;
        }
        try {
            Pointer handle = Kernel32.INSTANCE.GetStdHandle(STD_INPUT_HANDLE);
            if (handle == null || Pointer.nativeValue(handle) == -1L) {
                return;
            }
            IntByReference mode = new IntByReference();
            if (!Kernel32.INSTANCE.GetConsoleMode(handle, mode)) {
                return;
            }
            // 设置 ENABLE_EXTENDED_FLAGS 以确保快速编辑标志是“真实”的，
            // 同时清除 ENABLE_QUICK_EDIT_MODE 位。
            int newMode = (mode.getValue() | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE;
            Kernel32.INSTANCE.SetConsoleMode(handle, newMode);
        } catch (Throwable ignored) {
            // 失败时保持原状，不影响正常抓包
        }
    }
}