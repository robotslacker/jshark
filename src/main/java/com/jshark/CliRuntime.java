package com.jshark;

import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * CliShark / CliReplay 共用的"进程级"支撑：{@code --daemon}（转后台运行）与 {@code --logfile}（日志落盘）。
 *
 * <h3>为什么单独抽一层</h3>
 * <p>
 * 这两个选项都必须在"解析完参数、开始干活"之前生效，而且两个 CLI 必须行为一致：
 * </p>
 * <ul>
 *   <li>{@code --logfile} 决定日志写到哪里，而<b>参数校验阶段</b>的告警、
 *       {@code --help} 之后的启动横幅也应该落到同一个目标，所以要在日志系统初始化
 *       之前先用 {@link #scanLogTarget(String[])} 把取值预读出来；</li>
 *   <li>{@code --daemon} 要求父进程<b>只负责 fork</b>：拉起子进程后立刻退出，
 *       子进程用同样的参数（但把 {@code --daemon} 换成 {@code false}）在前台真正干活。
 *       写在这里就不会出现"两个入口各写一份、各自跑偏"。</li>
 * </ul>
 *
 * <p>参考实现是 slackerdb dbserver 的 {@code Main} + {@code OSUtil.launchDaemon}。
 * 与它有两处刻意的差别，都是踩过的坑：</p>
 * <ol>
 *   <li><b>Windows 上显式给出 {@code start} 的标题参数。</b>
 *       {@code cmd /c start} 会把第一个带引号的参数当成窗口标题，而 java 可执行文件路径
 *       （{@code C:\Program Files\...\java.exe}）几乎总是带空格、必然被加引号：
 *       {@code start /B "C:\Program Files\...\java.exe" -jar app.jar} 会被解释成
 *       "标题 = java 路径，命令 = -jar"，直接失败。写一个空标题 {@code ""} 占位即可。</li>
 *   <li><b>Linux 上对参数做 shell 转义。</b>
 *       {@code --filter "udp port 3000"} 这类带空格的取值如果直接拼进 {@code sh -c} 的字符串，
 *       会被 shell 拆成多个参数，后台进程收到的过滤器是错的（而且是静默出错）。</li>
 * </ol>
 */
public final class CliRuntime {

    /** 转后台运行开关；取值 {@code true}/{@code false}，裸写 {@code --daemon} 等价于 true。 */
    public static final String DAEMON_OPTION = "--daemon";
    /** 日志输出目标；默认控制台，支持逗号分隔的 {@code CONSOLE} 与文件路径。 */
    public static final String LOGFILE_OPTION = "--logfile";

    private CliRuntime() {
    }

    /**
     * 从原始命令行里预读 {@code --logfile} 的取值（返回 null 表示未指定，用控制台）。
     *
     * <p>只做"取值搬运"，不做合法性判断：未知选项、缺取值、非法取值这些仍然由各自的
     * {@code parseArguments} 统一报错，避免出现两套互相矛盾的参数校验。</p>
     *
     * @param args 原始命令行参数
     * @return 日志目标规格（原样返回，逗号分隔由 {@link CliLogging} 解释）；未指定返回 null
     */
    public static String scanLogTarget(String[] args) {
        String target = null;
        if (args == null) {
            return null;
        }
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                continue;
            }
            String name = arg;
            String value = null;
            int eq = arg.indexOf('=');
            if (eq > 0) {
                name = arg.substring(0, eq);
                value = arg.substring(eq + 1);
            }
            if (DAEMON_OPTION.equals(name)) {
                // 只是把 --daemon 的取值跳过，避免它被误当成别的选项的取值
                if (value == null && i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    i++;
                }
            } else if (LOGFILE_OPTION.equals(name)) {
                if (value == null && i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    value = args[++i];
                }
                if (value != null && !value.trim().isEmpty()) {
                    target = value.trim();
                }
            }
        }
        return target;
    }

    /**
     * 判断一个布尔开关是否"显式开启"（支持 {@code --flag}、{@code --flag=false}、{@code --flag false}）。
     *
     * <p>与 {@link #hasOption(String[], String)} 的区别：后者只看"有没有出现"，用于
     * {@code --control stdio} 这种带值的模式开关；本方法用于 {@code --ui}/{@code --daemon}/
     * {@code --inspect} 这类布尔开关，因此 {@code --ui=false} 必须真的不启动界面。</p>
     *
     * @param args   原始命令行
     * @param option 选项名（含前导 {@code --}）
     * @return true 表示显式开启；未出现或显式 false 返回 false
     */
    public static boolean isEnabled(String[] args, String option) {
        if (args == null) {
            return false;
        }
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals(option)) {
                // 可选值写法：--daemon false / --ui true
                if (i + 1 < args.length && isBooleanLiteral(args[i + 1])) {
                    return Boolean.parseBoolean(args[i + 1]);
                }
                return true;
            }
            if (arg.startsWith(option + "=")) {
                String value = arg.substring(option.length() + 1).trim();
                return value.isEmpty() || Boolean.parseBoolean(value);
            }
        }
        return false;
    }

    private static boolean isBooleanLiteral(String value) {
        return "true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value);
    }

    /**
     * 判断命令行里是否出现某个开关（支持 {@code --opt} 与 {@code --opt=value}）。
     *
     * <p>用于在正式解析之前做"模式预扫描"（{@code --ui}/{@code --control}/{@code --daemon}）：
     * 这些开关必须在日志初始化和环境检查之前就知道。</p>
     *
     * @param args   原始命令行；null 视为没有
     * @param option 选项名（含前导 {@code --}）
     * @return true 表示出现了该开关
     */
    public static boolean hasOption(String[] args, String option) {
        if (args == null) {
            return false;
        }
        for (String arg : args) {
            if (arg.equals(option) || arg.startsWith(option + "=")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 解析 {@code --daemon} 的取值。
     *
     * @param value 取值；null/空白表示"裸写 --daemon"，按 true 处理
     * @return 是否转后台
     * @throws IllegalArgumentException 取值既不是 true 也不是 false
     */
    public static boolean parseDaemonFlag(String value) {
        return parseBooleanFlag(DAEMON_OPTION, value);
    }

    /**
     * 解析"可选取值"的布尔开关：裸写选项等价于 true，也接受显式 true/false。
     *
     * @param optionName 选项名（只用于错误信息，例如 {@code --enable_additioninfo}）
     * @param value      取值；null/空白表示裸写选项，按 true 处理
     * @return 开关值
     * @throws IllegalArgumentException 取值既不是 true 也不是 false
     */
    public static boolean parseBooleanFlag(String optionName, String value) {
        if (value == null || value.trim().isEmpty()) {
            return true;
        }
        String v = value.trim();
        if (v.equalsIgnoreCase("true")) {
            return true;
        }
        if (v.equalsIgnoreCase("false")) {
            return false;
        }
        throw new IllegalArgumentException(optionName + " must be true or false (got: " + value + ")");
    }

    /**
     * 如果请求了后台运行，就把自己重新拉起一个后台副本并让调用方退出。
     *
     * @param anchor       用于推断当前 jar 的主类（{@code CliShark.class} / {@code CliReplay.class}）
     * @param originalArgs 原始命令行参数（子进程会原样继承，但 {@code --daemon} 被替换成 false）
     * @param logTarget    预读到的日志目标；仅用于提示
     * @param logger       用于在"日志已落盘"时把启动信息也写进日志；可为 null
     * @return true 表示后台副本已启动；false 表示当前是开发模式（非 jar 启动）无法转后台，调用方应继续前台运行
     * @throws IOException 启动后台进程失败
     */
    public static boolean startInBackground(Class<?> anchor, String[] originalArgs,
                                            String logTarget, Logger logger) throws IOException {
        List<String> command = buildDaemonCommand(anchor, originalArgs);
        if (command == null) {
            if (logger != null) {
                logger.warn("[JShark] {} is not supported in dev mode (not started from a jar); "
                        + "running in the foreground.", DAEMON_OPTION);
            }
            return false;
        }

        ProcessBuilder builder = new ProcessBuilder(command);
        // 子进程挂在启动它的控制台上：不指定 --logfile 时至少还能看见输出（而不是写进一个没人读的管道）
        builder.redirectInput(ProcessBuilder.Redirect.INHERIT);
        builder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
        builder.redirectError(ProcessBuilder.Redirect.INHERIT);
        Process process = builder.start();
        try {
            process.getInputStream().close();
        } catch (IOException ignored) {
            // 关闭读端失败不影响后台进程运行
        }

        String logDesc = (logTarget == null || logTarget.isBlank()) ? CliLogging.CONSOLE_TARGET : logTarget;
        String jarPath = resolveJarPath(anchor);
        // 直接打到启动终端：日志可能已经只写文件了（--logfile），但"父进程已退出"这件事用户必须看得见
        System.out.println("[JShark] Daemon started in background (jar: " + jarPath + ", log: " + logDesc + ").");
        if (logTarget == null || logTarget.isBlank()) {
            System.out.println("[JShark] Warning: " + LOGFILE_OPTION + " was not given; "
                    + "background output stays on this console and may be lost when it closes.");
        }
        if (logger != null && logTarget != null && !logTarget.isBlank()) {
            logger.info("[JShark] Daemon started in background (jar: {}, log: {})", jarPath, logDesc);
        }
        return true;
    }

    /**
     * 构造后台子进程的完整命令行；开发模式（不是从 jar 启动）返回 null。
     *
     * @throws IOException 无法确定可用的 shell（仅 POSIX 路径）
     */
    static List<String> buildDaemonCommand(Class<?> anchor, String[] originalArgs) throws IOException {
        return buildDaemonCommand(resolveJarPath(anchor), originalArgs);
    }

    /**
     * 命令行拼装本体：与"当前进程是否从 jar 启动"解耦，便于单测直接喂一个假 jar 路径。
     *
     * @param jarPath 可执行 jar 的路径；null 表示开发模式（无法转后台）
     */
    static List<String> buildDaemonCommand(String jarPath, String[] originalArgs) throws IOException {
        if (jarPath == null) {
            return null;
        }

        String javaExe = Path.of(System.getProperty("java.home"), "bin",
                isWindows() ? "java.exe" : "java").toString();

        List<String> foreground = new ArrayList<>();
        foreground.add(javaExe);
        foreground.add("-jar");
        foreground.add(jarPath);
        foreground.addAll(stripDaemonOption(originalArgs));
        // 子进程绝不能再带 --daemon true，否则会无限 fork 下去
        foreground.add(DAEMON_OPTION);
        foreground.add("false");

        List<String> command = new ArrayList<>();
        if (isWindows()) {
            command.add("cmd");
            command.add("/c");
            command.add("start");
            command.add("\"\"");   // 占住 start 的 title 位置，见类注释
            command.add("/B");
            command.addAll(foreground);
            return command;
        }

        String shell = System.getenv("SHELL");
        if (shell == null || shell.isBlank()) {
            shell = new File("/bin/sh").exists() ? "/bin/sh" : null;
        }
        if (shell == null) {
            throw new IOException("Cannot start daemon: no usable shell (SHELL is unset and /bin/sh is missing).");
        }
        StringBuilder line = new StringBuilder("nohup");
        for (String part : foreground) {
            line.append(' ').append(shellQuote(part));
        }
        line.append(" >/dev/null 2>&1 &");
        command.add(shell);
        command.add("-c");
        command.add(line.toString());
        return command;
    }

    /**
     * 去掉命令行里的 {@code --daemon}（含 {@code --daemon=x} 与 {@code --daemon x} 两种写法）。
     */
    static List<String> stripDaemonOption(String[] args) {
        List<String> kept = new ArrayList<>();
        if (args == null) {
            return kept;
        }
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals(DAEMON_OPTION)) {
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    i++;   // 同时丢掉取值
                }
                continue;
            }
            if (arg.startsWith(DAEMON_OPTION + "=")) {
                continue;
            }
            kept.add(arg);
        }
        return kept;
    }

    /**
     * 推断当前进程是从哪个 jar 启动的。
     *
     * <p>可执行 jar 的类来自 jar 内部，不同打包/加载方式给出的 CodeSource 形态并不一样，
     * 这里把见过的几种都归一化掉（顺序很重要：先砍掉"jar 内部条目"部分，再剥协议前缀）：</p>
     * <ul>
     *   <li>Spring Boot 3.2+：{@code jar:nested:/path/app.jar/!BOOT-INF/classes/!/}</li>
     *   <li>Spring Boot 3.2 之前：{@code jar:file:/path/app.jar!/BOOT-INF/classes!/}</li>
     *   <li>普通类路径：{@code file:/path/app.jar}</li>
     * </ul>
     *
     * @return jar 的规范路径；开发模式（从 classes 目录启动、或路径不是 jar）返回 null
     */
    static String resolveJarPath(Class<?> anchor) {
        try {
            java.security.CodeSource source = anchor.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) {
                return null;
            }
            String path = URLDecoder.decode(source.getLocation().getPath(), StandardCharsets.UTF_8);

            // 砍掉 "!/xxx"（Boot < 3.2）或 "/!xxx"（Boot >= 3.2 nested 形式）之后的部分
            int cut = path.indexOf("/!");
            if (cut < 0) {
                cut = path.indexOf("!/");
            }
            if (cut >= 0) {
                path = path.substring(0, cut);
            }

            // 逐层剥掉协议前缀：jar:nested:file: ...
            boolean stripped = true;
            while (stripped) {
                stripped = false;
                for (String prefix : new String[]{"jar:", "nested:", "zip:", "wsjar:", "file:"}) {
                    if (path.regionMatches(true, 0, prefix, 0, prefix.length())) {
                        path = path.substring(prefix.length());
                        stripped = true;
                        break;
                    }
                }
            }

            // Windows 盘符前多出来的斜杠：/C:/x/app.jar -> C:/x/app.jar
            if (path.matches("^/[A-Za-z]:[/\\\\].*")) {
                path = path.substring(1);
            }
            if (!path.toLowerCase().endsWith(".jar")) {
                return null;
            }
            File jar = new File(path);
            return jar.isFile() ? jar.getCanonicalPath() : null;
        } catch (Exception e) {
            return null;
        }
    }

    static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    /** POSIX shell 单引号转义：{@code it's} -> {@code 'it'\''s'}。 */
    static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}
