package com.jshark;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.jshark.forwarder.ForwarderFactory;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * UDP/TCP 转发器主入口。
 *
 * <p>模式：{@code bridge}（UDP 组播 ⇄ TCP peers）。{@code --ui} 启动图形界面
 * （子进程 + stdio），{@code --control stdio} 是 UI 使用的内部协议入口（不出现在帮助里）。</p>
 */
public class CliForwarder {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CliForwarder.class);

    // 打印帮助信息
    public static void showUsage() {
        System.out.println("Usage: java -jar jshark-1.0.0-udpforwarder.jar [--parameter <parameter value>]");
        System.out.println("Parameters:");
        System.out.println("    --help                     print this message.");
        System.out.println("    --ui                       launch the forwarder console (GUI).");
        System.out.println("  bridge parameters :");
        System.out.println("    --udpaddr                   (required) Local udp multicast address:port, ex 224.3.0.0:3000.");
        System.out.println("    --udpif                     (required) Local multicast interface subnet, ex 192.168.1.0/24.");
        System.out.println("    --peer                      (required) Remote peer address:port, ex 10.10.1.100:3001.");
        System.out.println("                                Can be specified multiple times for multi-peer.");
        System.out.println("    --port                      Local tcp listen port, ex 3001. Required unless --ttou false.");
        System.out.println("    --utot                      Enable UDP->TCP forwarding (default true).");
        System.out.println("    --ttou                      Enable TCP->UDP forwarding (default true).");
        System.out.println("                                At least one of --utot / --ttou must be true.");
        System.out.println();
        System.out.println("Example:");
        System.out.println("java -jar jshark-1.0.0-udpforwarder.jar --udpaddr 224.3.0.0:3000 --udpif 11.8.15.0/24 --port 3000 --peer 21.125.249.161:3001");
        System.out.println("java -jar jshark-1.0.0-udpforwarder.jar --udpaddr 224.3.0.0:3000 --udpif 21.125.249.0/24 --port 3000 --peer 11.8.15.1:3001");
    }

    public static void main(String[] args) {
        // 关闭 Windows 控制台“快速编辑模式”，避免转发器日志输出阻塞
        WindowsConsoleUtil.disableQuickEditMode();

        if (args.length == 0) {
            showUsage();
            System.exit(CliExitException.EXIT_OK);
        }

        // 与另两个入口一致：--help/-h 先处理，不依赖参数解析是否成功
        if (CliRuntime.hasOption(args, "--help") || java.util.Arrays.asList(args).contains("-h")) {
            showUsage();
            System.exit(CliExitException.EXIT_OK);
        }

        // --ui 是前台 GUI：本身不转发，真正的转发在 --control stdio 子进程里。
        if (CliRuntime.isEnabled(args, "--ui")) {
            if (CliRuntime.hasOption(args, "--control")) {
                System.err.println("Error: --ui cannot be combined with --control.");
                System.exit(CliExitException.EXIT_USAGE);
            }
            configureLogging(true);
            try {
                ForwarderUi.launch(args);
            } catch (CliExitException e) {
                System.err.println("Error: " + e.getMessage());
                System.exit(e.exitCode());
            }
            return;
        }

        // 解析失败（裸值没有选项名、-h 之类）也要给出 usage，而不是抛栈
        Map<String, String> options;
        try {
            options = parseOptions(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            showUsage();
            System.exit(CliExitException.EXIT_USAGE);
            return;
        }
        boolean control = options.containsKey("control");
        configureLogging(control);

        try {
            if (control) {
                if (!"stdio".equalsIgnoreCase(String.valueOf(options.get("control")))) {
                    throw new IllegalArgumentException("Unsupported --control mode: " + options.get("control")
                            + " (expected 'stdio').");
                }
                ForwarderControl.run(options);
                return;
            }

            ForwarderFactory.Built built = ForwarderFactory.create(options, logger);
            logger.info("[SERVER] Forwarder starting (PID:{})...", ProcessHandle.current().pid());
            logger.info("[SERVER] Forwarder will start with [{}] mode ...", built.mode().toUpperCase());

            // Ctrl+C / SIGTERM：让 Netty 优雅关闭，避免端口与线程一直挂着。
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("[SERVER] Received shutdown signal, stopping forwarder...");
                try {
                    built.source().stop();
                } catch (Throwable t) {
                    logger.warn("[SERVER] stop failed: {}", t.toString());
                }
            }, "ShutdownHook"));

            built.source().run();   // 阻塞到 stop()/内部关闭
            logger.info("[SERVER] Forwarder stopped gracefully.");
        } catch (IllegalArgumentException e) {
            logger.error("[SERVER] Forwarder start fail: {}", e.getMessage());
            showUsage();
            System.exit(CliExitException.EXIT_USAGE);
        } catch (Exception e) {
            logger.error("[SERVER] Forwarder error:", e);
            System.exit(CliExitException.EXIT_INTERNAL);
        }
    }

    /** 解析 {@code --name value} / {@code --name=value} / 裸 {@code --flag}（值为 null）。 */
    static Map<String, String> parseOptions(String[] args) {
        Map<String, String> options = new HashMap<>();
        String paramName = null;
        for (String arg : args) {
            if (arg.startsWith("--")) {
                int eq = arg.indexOf('=');
                if (eq > 2) {
                    putOption(options, arg.substring(2, eq), arg.substring(eq + 1));
                    paramName = null;
                } else {
                    paramName = arg.substring(2);
                }
            } else {
                if (paramName == null) {
                    throw new IllegalArgumentException("Option name missed for value: " + arg);
                }
                putOption(options, paramName, arg);
                paramName = null;
            }
        }
        if (paramName != null) {
            putOption(options, paramName, null);
        }
        return options;
    }

    /** 转发器实际认识的选项（{@code --peerN} 由正则单独放行）。 */
    private static final java.util.Set<String> KNOWN_OPTIONS = java.util.Set.of(
            "help", "ui", "udpaddr", "udpif", "peer", "port", "utot", "ttou", "control");

    private static void putOption(Map<String, String> options, String name, String value) {
        String key = name.toLowerCase(java.util.Locale.ROOT);
        if (!KNOWN_OPTIONS.contains(key) && !key.matches("peer\\d+")) {
            // 以前未知选项被静默忽略，拼错 --udpif 只会表现为"缺 --udpif"，非常误导
            throw new IllegalArgumentException("Unknown option: --" + key);
        }
        // --peer 可重复；Map 只能存一个，后出现的转成 peer1..peerN
        if (options.containsKey(key) && "peer".equals(key)) {
            int n = 1;
            while (options.containsKey("peer" + n)) {
                n++;
            }
            options.put("peer" + n, value);
        } else {
            options.put(key, value);
        }
    }

    /**
     * 配置 logback：控制通道/GUI 子进程的 stdout 是协议，日志必须走 stderr。
     *
     * <p>格式、pcap4j/Netty 的静音统一由 {@link CliLogging} 负责，这里只补 Netty 这一条
     * （转发器不用 pcap4j，但共用日志初始化可以保证三个入口的时间戳格式一致）。</p>
     */
    static void configureLogging(boolean stderr) {
        CliLogging.configure(null, stderr);
        ((Logger) LoggerFactory.getLogger("io.netty")).setLevel(Level.OFF);
    }
}
