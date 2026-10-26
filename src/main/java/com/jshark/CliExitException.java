package com.jshark;

/**
 * CLI 的"退出信号"：参数/启动阶段只抛出它，由各入口的 {@code main} 统一映射成进程退出码。
 *
 * <h3>为什么不是直接 {@code System.exit}</h3>
 * <p>
 * 解析层如果自己退进程，任何直接调用它的测试都会<b>杀掉 forked 测试 JVM</b>——症状是
 * surefire 直接崩溃、看不到失败原因，而不是一条干净的断言失败。因此除 {@code main}
 * （进程边界）之外，业务代码只允许抛这个异常。
 * </p>
 *
 * <p>退出码约定：{@code 0} = 正常结束（{@code --help}/无参数/后台副本已拉起），
 * 非 0 = 参数或启动失败。</p>
 */
public class CliExitException extends RuntimeException {

    /** 正常退出。 */
    public static final int EXIT_OK = 0;
    /** 参数/用法错误。 */
    public static final int EXIT_USAGE = 1;
    /** 未预期的运行时失败（保留历史退出码 255，便于脚本区分"用法错误"与"内部错误"）。 */
    public static final int EXIT_INTERNAL = 255;

    private final int exitCode;

    /**
     * @param exitCode 期望的进程退出码
     * @param message  可读原因；正常退出可为 null
     * @param cause    根因；可为 null
     */
    public CliExitException(int exitCode, String message, Throwable cause) {
        super(message, cause);
        this.exitCode = exitCode;
    }

    /** @return 期望的进程退出码 */
    public int exitCode() {
        return exitCode;
    }
}
