package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.parser.DbReplayTool;
import com.jshark.parser.FrameRewriter;
import com.jshark.parser.NeighborResolver;
import com.jshark.parser.PcapReplayTool;
import com.jshark.parser.ReplayControl;
import com.jshark.parser.ReplayModeResolver;
import com.jshark.parser.SourceInspector;
import com.jshark.parser.SplitUtil;
import com.jshark.parser.StartupSelfCheck;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JShark - Packet Replay Tool
 * CLI/GUI interface for packet replay functionality
 * Usage:
 *   CLI mode (default):  CliReplay --db packets.db [options]
 *   GUI mode:            CliReplay --ui [--db packets.db]
 */
public class CliReplay implements ControlServer.Host {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CliReplay.class);
    
    // DB Replay options
    private String replayDbFile;
    private String replayPcapFile;
    private Double replaySpeed = 1.0;
    // 天文（绝对捕获）时间：--start/--end，epoch 毫秒
    private Long replayStartTime;
    private Long replayEndTime;
    private String replaySourceIp;
    private String replayDestinationIp;
    private Integer replaySourcePort;
    private Integer replayDestinationPort;
    private String replayIpProtocol;
    private String replayApplicationProtocol;
    private String replayExpressionFilter;
    
    // Replay target mapping options (IP/端口映射，支持 SrcIP:SrcPort-DestIP:DestPort 格式)
    private String replayTargetMapping;

    // 帧级注入参数
    private String injectInterface;
    private String dstMac;
    /** 默认重放模式：payload（与 PCAP 路径、UI 保持一致）。 */
    private String replayMode = "payload";
    /**
     * 是否显式给出过 --replayMode。
     * <p>
     * 未显式给出时（{@code replayModeExplicit == false}）一律走默认 payload，即使给了
     * {@code --injectInterface} 也被忽略并告警；显式 --replayMode=frame 却没有 inject 则直接报错，
     * 不再静默降级（与 PCAP 路径一致）。
     * </p>
     */
    private boolean replayModeExplicit = false;

    /** 是否执行启动前只读检查（--inspect），检查完即退出 */
    private boolean inspect = false;

    /** 是否运行 stdio 控制模式（--control stdio），主要供 UI 子进程使用 */
    private boolean controlMode = false;

    /** 控制/进度通道；控制模式下由 ControlServer 持有 */
    private ReplayControl replayControl;

    /** 当前工具实例，供控制模式 stop 使用（frame 路径仍读 stopRequested） */
    private volatile DbReplayTool currentDbTool;
    private volatile PcapReplayTool currentPcapTool;

    /** 当前会话的 shutdown hook；seek 重开段时先移除旧的，避免累积。 */
    private volatile Thread shutdownHook;

    /** pcap seek 重开段的起点（epoch ms）；null 表示从头开始。 */
    private volatile Long pcapStartMs;

    /**
     * 会话级注入自检结果：整个会话只跑一次，seek 重开段复用。
     *
     * <p>自检会真实发一帧探测包；原来每段都跑，等于每次拖动进度条都往网卡多打一帧。</p>
     */
    private boolean startupCheckDone;
    private StartupSelfCheck.Result startupCheck;

    /** 是否转后台运行（--daemon）；后台副本由父进程拉起，父进程随后立即退出 */
    private boolean daemon = false;
    /** 日志目标（--logfile）：逗号分隔的 CONSOLE 或文件路径；null 表示只输出到控制台 */
    private String logFile;
    
    // Option definitions
    private static final Map<String, OptionInfo> OPTIONS = CliArgs.stableOptions();
    
    static {
        // DB Replay options
        OPTIONS.put("--db", new OptionInfo("replayDbFile", true, "Replay packets from database file"));
        OPTIONS.put("--pcap", new OptionInfo("replayPcapFile", true, "Replay packets directly from a PCAP file (no database needed)"));
        OPTIONS.put("--speed", new OptionInfo("replaySpeed", true, "Replay speed multiplier (default: 1.0). "
                + "This is an UPPER BOUND, not a promise: adaptive speed is always ON, so the replay slows "
                + "itself down (AIMD, floor 0.1x) when the sender cannot keep up, keeping packet spacing "
                + "faithful instead of squeezing it. There is no fixed-speed mode."));
        OPTIONS.put("--start", new OptionInfo("replayStartTime", true,
                "Start capture time as an absolute wall-clock timestamp (format: yyyy-MM-dd HH:mm:ss, "
                        + "e.g., 2026-08-21 08:10:00). Replays only packets captured at or after this time. "
                        + "For time-split databases, volumes outside the window are skipped by file name."));
        OPTIONS.put("--end", new OptionInfo("replayEndTime", true,
                "End capture time as an absolute wall-clock timestamp (format: yyyy-MM-dd HH:mm:ss, "
                        + "e.g., 2026-08-21 08:35:00). Replays only packets captured at or before this time."));
        OPTIONS.put("--sourceIp", new OptionInfo("replaySourceIp", true, "Filter by source IP address"));
        OPTIONS.put("--destinationIp", new OptionInfo("replayDestinationIp", true, "Filter by destination IP address"));
        OPTIONS.put("--sourcePort", new OptionInfo("replaySourcePort", true, "Filter by source port"));
        OPTIONS.put("--destinationPort", new OptionInfo("replayDestinationPort", true, "Filter by destination port"));
        OPTIONS.put("--ipProtocol", new OptionInfo("replayIpProtocol", true, "Filter by IP protocol (e.g., TCP, UDP, ICMP)"));
        OPTIONS.put("--applicationProtocol", new OptionInfo("replayApplicationProtocol", true, "Filter by application protocol (e.g., HTTP, DNS, DIS)"));
        OPTIONS.put("--exfilter", new OptionInfo("replayExpressionFilter", true,
                """
                        Filter by expression using FilterNinja syntax (e.g., dis.pdu.type=28 && dis.exercise.id=17)
                        The expression matches the database additionalInfo column, which is only populated when
                        the capture was run with --enable_additioninfo=true (a capture-side option). Otherwise
                        additionalInfo is NULL and every packet is filtered out."""));
        OPTIONS.put("--replayTargetMapping", new OptionInfo("replayTargetMapping", true, "Map source IP:Port to target IP:Port. Format: SrcIP:SrcPort-DestIP:DestPort (e.g., 11.0.0.1:5520-192.178.0.1:5530). Supports wildcard * and comma-separated multiple mappings."));
        OPTIONS.put("--replayMode", new OptionInfo("replayMode", true,
                "Replay mode: 'payload' (default) sends only the transport payload via the kernel stack "
                        + "(works across routers, lower fidelity); "
                        + "'frame' injects the original frames verbatim "
                        + "(only destination address/port and checksums are rewritten), "
                        + "and requires --injectInterface; an explicit --replayMode=frame without it is an error. "
                        + "If --replayMode is omitted, the default is payload, and a supplied --injectInterface "
                        + "is ignored with a warning."));
        OPTIONS.put("--injectInterface", new OptionInfo("injectInterface", true,
                "NIC used for frame injection, selected by its IP address (required in 'frame' mode; "
                        + "ignored with a warning in 'payload' mode)"));
        OPTIONS.put("--dstMac", new OptionInfo("dstMac", true,
                "Destination MAC policy for injected frames: 'preserve' (default; keep the original MAC, correct "
                        + "when the collector captures in promiscuous mode), 'auto' (multicast/broadcast by formula, "
                        + "unicast via OS neighbor table then active ARP probe), a single MAC, or 'IP=MAC,IP=MAC'. "
                        + "Note: only applies to frame replay, and is effectively useless for UDP traffic "
                        + "(UDP has no bidirectional session that depends on L2 addressing)."));
        OPTIONS.put("--daemon", new OptionInfo("daemon", true, true,
                """
                        Run in the background (daemon mode): true|false (default: false).
                          The launching process forks a detached copy of itself with the same
                          command-line options (except that --daemon becomes false) and exits
                          immediately, so the replay keeps running after the console closes.
                          Bare --daemon is the same as --daemon true.
                          Requires starting from a jar; in dev/IDE mode (classes) it falls back to
                          running in the foreground with a warning.
                          Combine with --logfile, otherwise the background output only lives on the
                          console that launched it."""));
        OPTIONS.put("--ui", new OptionInfo("ui", false,
                "Launch the Swing replay console (starts a headless replay child process)."));
        OPTIONS.put("--inspect", new OptionInfo("inspect", false, false, true,
                """
                        Read-only pre-start inspection: list DB time-split volumes / the PCAP file,
                          per-file start/end/duration/size, global data range and selected playback range.
                          Outputs NDJSON to stdout, logs to stderr, then exits.
                          Does not start replay, does not require --injectInterface."""));
        OPTIONS.put("--control", new OptionInfo("controlMode", true, true, true,
                "stdio control mode for the UI child process: NDJSON commands on stdin, "
                        + "status/ack/finished on stdout, logs on stderr. Value: stdio (default)."));
        OPTIONS.put("--logfile", new OptionInfo("logFile", true,
                """
                        Write log output to a file instead of the console (default: CONSOLE).
                          The value is a comma-separated target list; each item is either CONSOLE or a
                          file path, e.g. --logfile logs/replay.log or --logfile CONSOLE,logs/replay.log
                          Missing parent directories are created automatically; logs are appended.
                          Recommended together with --daemon: the file is the only place left to look
                          after the launching console is gone."""));
    }
    
    /**
     * Main entry point for packet replay
     */
    public static void main(String[] args) {
        // 关闭 Windows 控制台“快速编辑模式”，避免 CLI 模式下日志输出阻塞
        WindowsConsoleUtil.disableQuickEditMode();

        // --help 时打印帮助并退出
        boolean hasHelp = false;
        for (String arg : args) {
            if ("--help".equals(arg) || "-h".equals(arg)) {
                hasHelp = true;
                break;
            }
        }
        if (hasHelp) {
            CliLogging.configure(CliRuntime.scanLogTarget(args));
            printHelp();
            System.exit(0);
        }

        // 不带任何参数时打印帮助并退出（与 CliShark 一致）
        if (args.length == 0) {
            CliLogging.configure(null);
            printHelp();
            System.exit(0);
        }

        // --ui：启动 Swing console；UI 进程只做 supervisor/客户端，不跑重放引擎。
        if (CliRuntime.isEnabled(args, "--ui")) {
            if (CliRuntime.hasOption(args, "--control") || CliRuntime.isEnabled(args, "--inspect")) {
                System.err.println("Error: --ui cannot be combined with --control/--inspect");
                System.exit(1);
            }
            if (CliRuntime.isEnabled(args, "--daemon")) {
                System.err.println("Error: --ui cannot be combined with --daemon "
                        + "(the UI owns its replay child process)");
                System.exit(1);
            }
            if (java.awt.GraphicsEnvironment.isHeadless()) {
                System.err.println("Error: --ui requires a graphical environment (not headless)");
                System.exit(1);
            }
            CliLogging.configure(CliRuntime.scanLogTarget(args));
            ReplayUi.launch(args);
            return;
        }

        // 始终以 CLI 模式运行（不再支持 GUI 模式）
        runCliMode(args);
    }

    /**
     * 运行CLI模式
     */
    private static void runCliMode(String[] args) {
        // --logfile 必须在日志系统初始化之前读出来：这样连"参数非法"之类的告警
        // 也会落到用户指定的日志文件里，而不是只出现在屏幕上。
        // --inspect/--control 的 stdout 是协议，日志必须走 stderr。
        CliLogging.configure(CliRuntime.scanLogTarget(args),
                CliRuntime.isEnabled(args, "--inspect") || CliRuntime.hasOption(args, "--control"));

        org.slf4j.Logger logger = LoggerFactory.getLogger(CliReplay.class);
        logger.info("[JShark] JShark - Packet Replay Tool (CLI mode)");

        CliReplay cliReplay = new CliReplay();
        try {
            cliReplay.parse(args);
        } catch (CliExitException e) {
            // 进程边界：解析层只抛退出信号，这里统一映射成退出码
            System.exit(e.exitCode());
        }
        System.exit(CliExitException.EXIT_OK);
    }
    
    /**
     * Parse command line arguments
     * @param args command line arguments
     */
    public void parse(String[] args) {
        try {
            parseArguments(args);
            if (inspect && controlMode) {
                throw new IllegalArgumentException("--inspect cannot be used with --control");
            }
            if (inspect) {
                if (daemon) {
                    throw new IllegalArgumentException("--inspect cannot be used with --daemon");
                }
                runInspect();
                return;
            }
            if (controlMode) {
                if (daemon) {
                    throw new IllegalArgumentException("--control cannot be used with --daemon");
                }
                runControlMode();
                return;
            }
            if (enterDaemonModeIfRequested(args)) {
                // 后台副本已经拉起，父进程到此为止（退出码 0）
                throw new CliExitException(CliExitException.EXIT_OK, null, null);
            }
            startReplay();
        } catch (CliExitException e) {
            // --help / 后台副本 / inspect/control 的终态：原样上抛，由 main 决定退出码
            throw e;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid command line arguments: {}", e.getMessage());
            System.err.println("Error: " + e.getMessage());
            System.err.println("Use --help for usage information");
            throw new CliExitException(CliExitException.EXIT_USAGE, e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Failed to parse command line arguments", e);
            System.err.println("Error: Failed to parse command line arguments");
            throw new CliExitException(CliExitException.EXIT_USAGE,
                    "Failed to parse command line arguments", e);
        }
    }
    /**
     * {@code --inspect}：只读检查数据源，向 stdout 输出 NDJSON，随后退出。
     *
     * <p>stdout 只放协议；先保存原始 stdout，再把 {@code System.out} 重定向到 stderr，
     * 防止 pcap4j / 其他代码的意外打印污染协议。</p>
     */
    private void runInspect() {
        PrintStream stdout = System.out;
        System.setOut(System.err);
        PrintStream out = new PrintStream(stdout, true, StandardCharsets.UTF_8);
        String session = UUID.randomUUID().toString();

        try {
            SourceInspector.Options options = new SourceInspector.Options(
                    replayDbFile, replayPcapFile, replayMode, replayModeExplicit,
                    injectInterface != null && !injectInterface.trim().isEmpty(),
                    replayStartTime, replayEndTime);
            JSONObject result = SourceInspector.inspect(options, session, progress -> {
                JSONObject p = new JSONObject();
                p.put("type", "inspect-progress");
                p.put("inspectSession", session);
                p.put("phase", progress.phase());
                p.put("current", progress.current());
                p.put("total", progress.total());
                p.put("bytes", progress.bytes());
                p.put("packets", progress.packets());
                p.put("message", progress.message());
                out.println(JSON.toJSONString(p));
                out.flush();
            });
            out.println(JSON.toJSONString(result));
            out.flush();
        } catch (Exception e) {
            JSONObject error = new JSONObject();
            error.put("type", "inspect-error");
            error.put("inspectSession", session);
            JSONObject detail = new JSONObject();
            detail.put("code", e instanceof IllegalArgumentException ? "INVALID_ARGUMENT" : "INSPECT_FAILED");
            detail.put("message", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            error.put("error", detail);
            out.println(JSON.toJSONString(error));
            out.flush();
            logger.error("Inspect failed", e);
            throw new CliExitException(CliExitException.EXIT_USAGE, e.getMessage(), e);
        }
        throw new CliExitException(CliExitException.EXIT_OK, null, null);
    }
    /**
     * {@code --control stdio}：NDJSON 控制模式。stdout 只放协议，日志走 stderr。
     */
    private void runControlMode() {
        PrintStream stdout = System.out;
        System.setOut(System.err);
        PrintStream out = new PrintStream(stdout, true, StandardCharsets.UTF_8);
        try {
            ControlServer server = new ControlServer(System.in, out, this);
            throw new CliExitException(server.run(), null, null);
        } catch (CliExitException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Control mode failed", e);
            JSONObject error = new JSONObject();
            error.put("type", "terminal");
            error.put("ok", false);
            error.put("state", "FAILED");
            error.put("message", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            JSONObject detail = new JSONObject();
            detail.put("code", "CONTROL_FAILED");
            detail.put("message", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            error.put("error", detail);
            out.println(JSON.toJSONString(error));
            out.flush();
            throw new CliExitException(CliExitException.EXIT_USAGE, e.getMessage(), e);
        }
    }
    // ==================== ControlServer.Host ====================

    @Override
    public ReplayControl control() {
        synchronized (this) {
            if (replayControl == null) {
                replayControl = new ReplayControl(replaySpeed == null ? 1.0 : replaySpeed);
            }
            return replayControl;
        }
    }

    /**
     * “参数被忽略/已回退”类告警：日志与协议 warnings 各记一份，避免 UI 只能靠日志猜。
     *
     * @param message 告警正文
     */
    private void warnIgnored(String message) {
        logger.warn(message);
        control().addWarning("OPTION_IGNORED", message);
    }

    /**
     * 会话级注入自检：整个会话只跑一次，seek 重开段复用结果。
     *
     * <p>自检会真实发一帧探测包；原来每个重开段都跑一次，等于每拖动一次进度条
     * 就往网卡多打一帧，而且拖得越多开销越大。</p>
     *
     * @param nif         注入网卡
     * @param volumeCount 自检日志用的卷数（沿用各调用点原来的取值）
     * @return 自检结果（网卡为 null 时为 null）
     */
    private StartupSelfCheck.Result startupCheck(PcapNetworkInterface nif, int volumeCount) {
        if (!startupCheckDone) {
            startupCheck = StartupSelfCheck.run(nif, -1, volumeCount);
            startupCheckDone = true;
        }
        return startupCheck;
    }

    @Override
    public void start() {
        startReplay();
    }

    @Override
    public void stop() {
        control().requestStop();
        DbReplayTool db = currentDbTool;
        if (db != null) {
            db.stopReplay();
        }
        PcapReplayTool pcap = currentPcapTool;
        if (pcap != null) {
            pcap.stopReplay();
        }
    }

    @Override
    public String requestedMode() {
        return replayMode;
    }

    @Override
    public String effectiveMode() {
        if (replayPcapFile != null && !replayPcapFile.trim().isEmpty()) {
            return "payload".equalsIgnoreCase(replayMode) ? "payload" : "frame";
        }
        boolean hasInject = injectInterface != null && !injectInterface.trim().isEmpty();
        ReplayModeResolver.Decision decision =
                ReplayModeResolver.resolveDb(replayMode, replayModeExplicit, hasInject);
        return decision.mode() == null ? "invalid"
                : decision.mode().name().toLowerCase(java.util.Locale.ROOT);
    }

    @Override
    public String sourceKind() {
        return replayPcapFile != null && !replayPcapFile.trim().isEmpty() ? "pcap" : "db";
    }

    @Override
    public String sourcePath() {
        return "pcap".equals(sourceKind()) ? replayPcapFile : replayDbFile;
    }

    @Override
    public void prepareRestart(long targetMs) {
        control().beginNewSegment(targetMs);
        if ("pcap".equals(sourceKind())) {
            pcapStartMs = targetMs;
        } else {
            replayStartTime = targetMs;
        }
        replaySpeed = control().targetSpeed();
    }

    private void installShutdownHook(Runnable stopAction) {
        removeShutdownHook();
        Thread hook = new Thread(stopAction, "jshark-replay-shutdown");
        shutdownHook = hook;
        Runtime.getRuntime().addShutdownHook(hook);
    }

    private void removeShutdownHook() {
        Thread hook = shutdownHook;
        shutdownHook = null;
        if (hook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (IllegalStateException ignored) {
                // JVM 正在关闭，remove 会抛；忽略
            }
        }
    }

    /**
     * 处理 {@code --daemon}：请求后台运行时拉起后台副本，由它在前台真正重放；
     * 开发模式（非 jar 启动）无法脱离当前进程，给出告警后退化为前台运行。
     *
     * @param args 原始命令行参数，原样传给后台副本（其中 {@code --daemon} 会被替换为 false）
     * @return true 表示后台副本已启动，调用方应立即退出
     */
    private boolean enterDaemonModeIfRequested(String[] args) {
        if (!daemon) {
            return false;
        }
        try {
            return CliRuntime.startInBackground(CliReplay.class, args, logFile, logger);
        } catch (Exception e) {
            logger.error("[JShark] Failed to start daemon process", e);
            throw new IllegalArgumentException("Failed to start daemon process: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parse command line arguments into fields
     */
    private void parseArguments(String[] args) {
        // --help 与历史行为一致：直接打印并退出（main 也做了一次预扫描）
        for (String arg : args) {
            if (arg.equals("--help") || arg.equals("-h")) {
                printHelp();
                throw new CliExitException(CliExitException.EXIT_OK, null, null);
            }
        }
        for (CliArgs.Entry<OptionInfo> entry : CliArgs.parse(args, OPTIONS, name -> {
            if ("--startc".equals(name) || "--endc".equals(name)) {
                String replacement = "--startc".equals(name) ? "--start" : "--end";
                return name + " has been renamed to " + replacement
                        + " (absolute capture time, e.g. 2026-08-21 08:10:00)";
            }
            return null;
        })) {
            OptionInfo info = entry.spec();
            setFieldValue(info.fieldName(), entry.value() == null ? "true" : entry.value());
        }
    }

    
    /**
     * Print help/usage information
     */
    private static void printHelp() {
        System.out.println("JShark - Packet Replay Tool");
        System.out.println();
        System.out.println("Usage: CliReplay [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.printf("  %-28s %s%n", "--help", "Show this help message and exit");
        CliHelp.printOptions(System.out, OPTIONS);
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Replay all packets from database at 2x speed");
        System.out.println("  CliReplay --db packets.db --speed 2.0");
        System.out.println();
        System.out.println("  # Replay packets captured within an absolute wall-clock time window");
        System.out.println("  CliReplay --db packets.db --start \"2026-08-21 08:10:00\" --end \"2026-08-21 08:35:00\"");
        System.out.println();
        System.out.println("  # Same window against a time-split capture (volumes outside the window are skipped by name)");
        System.out.println("  CliReplay --db capture.db --start \"2026-08-21 08:10:00\" --end \"2026-08-21 08:35:00\"");
        System.out.println();
        System.out.println("  # Replay packets filtered by source and destination IP");
        System.out.println("  CliReplay --db packets.db --sourceIp 192.168.1.100 --destinationIp 10.0.0.1");
        System.out.println();
        System.out.println("  # Replay DIS packets with expression filter");
        System.out.println("  CliReplay --db packets.db --exfilter \"dis.pdu.type=28 && dis.exercise.id=17\"");
        System.out.println();
        System.out.println("  # Replay DIS packets filtered by protocol and port");
        System.out.println("  CliReplay --db packets.db --applicationProtocol DIS --sourcePort 3000 --speed 0.5");
        System.out.println();
        System.out.println("  # Replay with target mapping (SrcIP:SrcPort-DestIP:DestPort)");
        System.out.println("  CliReplay --db packets.db --replayTargetMapping \"11.0.0.1:5520-192.178.0.1:5530\"");
        System.out.println();
        System.out.println("  # Replay with wildcard target mapping (send all to 192.168.0.5)");
        System.out.println("  CliReplay --db packets.db --replayTargetMapping \"*:*-192.168.0.5:*\"");
        System.out.println();
        System.out.println("  # Replay with multiple target mappings");
        System.out.println("  CliReplay --db packets.db --replayTargetMapping \"11.0.0.1:5520-192.178.0.1:5530, *:*-192.168.0.5:*\"");
        System.out.println();
        System.out.println("  # Split-mode live delayed replay: rolling-follow is the default for --split volumes");
        System.out.println("  CliReplay --db capture.db --speed 1.0 --replayTargetMapping \"*:*-127.0.0.1:8200\"");
        System.out.println();
        System.out.println("  # Run the replay in the background and keep the log in a file");
        System.out.println("  CliReplay --db capture.db --daemon --logfile logs/replay.log");
        System.out.println();
        System.out.println("  # Launch the Swing replay console");
        System.out.println("  CliReplay --ui --db capture.db");
    }
    
    /**
     * Set field value based on field name and string value
     */
    private void setFieldValue(String fieldName, String value) {
        try {
            switch (fieldName) {
                case "replayDbFile" -> this.replayDbFile = value;
                case "replayPcapFile" -> this.replayPcapFile = value;
                case "replaySpeed" -> this.replaySpeed = Double.parseDouble(value);
                case "replayStartTime" -> this.replayStartTime = parseAbsoluteTime(value);
                case "replayEndTime" -> this.replayEndTime = parseAbsoluteTime(value);
                case "replaySourceIp" -> this.replaySourceIp = value;
                case "replayDestinationIp" -> this.replayDestinationIp = value;
                case "replaySourcePort" -> this.replaySourcePort = parsePort(value, "--sourcePort");
                case "replayDestinationPort" -> this.replayDestinationPort = parsePort(value, "--destinationPort");
                case "replayIpProtocol" -> this.replayIpProtocol = value;
                case "replayApplicationProtocol" -> this.replayApplicationProtocol = value;
                case "replayExpressionFilter" -> this.replayExpressionFilter = value;
                case "replayTargetMapping" -> this.replayTargetMapping = value;
                case "replayMode" -> {
                    this.replayMode = value == null ? null : value.trim();
                    this.replayModeExplicit = true;
                }
                case "injectInterface" -> this.injectInterface = value;
                case "dstMac" -> this.dstMac = value;
                case "ui" -> {
                    // --ui 在 main() 里预扫描并直接启动界面，解析层不需要保存状态
                }
                case "inspect" -> this.inspect = Boolean.parseBoolean(value);
                case "controlMode" -> {
                    String v = value == null ? "true" : value.trim();
                    if (!v.equalsIgnoreCase("true") && !v.equalsIgnoreCase("stdio")) {
                        throw new IllegalArgumentException("--control only supports 'stdio' (got: " + value + ")");
                    }
                    this.controlMode = true;
                }
                case "daemon" -> this.daemon = CliRuntime.parseDaemonFlag(value);
                case "logFile" -> {
                    if (value == null || value.trim().isEmpty()) {
                        throw new IllegalArgumentException("--logfile requires a file path or CONSOLE (got: " + value + ")");
                    }
                    this.logFile = value.trim();
                }
                default -> throw new IllegalArgumentException("Unknown field: " + fieldName);
            }
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid number format for " + fieldName + ": " + value);
        }
    }
    
    /**
     * 解析端口过滤参数：只接受 1-65535。
     *
     * @param value  原始取值
     * @param option 选项名（只用于错误信息）
     * @return 端口
     * @throws IllegalArgumentException 越界或非数字
     */
    private static int parsePort(String value, String option) {
        int port = Integer.parseInt(value);
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException(option + " must be 1-65535 (got: " + value + ")");
        }
        return port;
    }

    /**
     * 解析天文（绝对捕获）时间字符串为 epoch 毫秒。
     * <p>
     * 支持格式（大小写不敏感，日期与时间之间可用单个空格或 'T' 分隔）：
     * <ul>
     *   <li>{@code yyyy-MM-dd HH:mm:ss}（推荐）</li>
     *   <li>{@code yyyy-MM-dd HH:mm}</li>
     *   <li>{@code yyyyMMddHHmmss}（14 位紧凑形式，与分卷文件名时间戳一致）</li>
     *   <li>{@code yyyy-MM-dd HH:mm:ss.SSS}（含毫秒）</li>
     * </ul>
     * </p>
     *
     * @param timeStr 绝对时间字符串
     * @return epoch 毫秒
     */
    private Long parseAbsoluteTime(String timeStr) {
        return TimeArgs.parse(timeStr);
    }
    /**
     * 校验时间窗口：{@code --start/--end} 都是绝对捕获时间，{@code end} 不得早于 {@code start}。
     *
     * <p>时间窗口对所有数据源（分卷 DB、单卷 DB、PCAP）都可用；分卷模式只是额外多一步
     * “按卷名快速跳过窗口外的卷”，不影响语义。</p>
     *
     * @param startTime --start（epoch 毫秒；null 表示不限）
     * @param endTime   --end（epoch 毫秒；null 表示不限）
     * @throws IllegalArgumentException end 早于 start
     */
    static void validateTimeSelection(Long startTime, Long endTime) {
        TimeArgs.validateWindow(startTime, endTime);
    }

    // DB 重放模式规则见 com.jshark.parser.ReplayModeResolver（与 --inspect 侧共用同一实现）

    /**
     * Start replay with parsed parameters.
     * <p>
     * 数据源二选一：{@code --db}（DuckDB，支持时间分卷自动发现）或 {@code --pcap}（离线 pcap 文件）。
     * 两者共用同一套倍率时序、过滤与目标映射规则。
     * </p>
     */
    void startReplay() {
        // 倍率必须为正数：精确倍率语义下 0/负数无意义
        if (replaySpeed == null || !(replaySpeed > 0) || Double.isNaN(replaySpeed) || Double.isInfinite(replaySpeed)) {
            throw new IllegalArgumentException(
                    "Invalid --speed: must be a positive finite number (e.g. 1.0, 2.0, 0.5), got: " + replaySpeed);
        }

        boolean hasPcap = replayPcapFile != null && !replayPcapFile.trim().isEmpty();
        boolean hasDb = replayDbFile != null && !replayDbFile.trim().isEmpty();
        if (!hasPcap && !hasDb) {
            throw new IllegalArgumentException(
                    "A data source is required: use --db <database_file> or --pcap <pcap_file>.");
        }
        if (hasPcap) {
            if (hasDb) {
                logger.warn("[JShark] Both --db and --pcap were provided; replaying from PCAP (--pcap takes precedence)");
            }
            replayFromPcap();
            return;
        }

        logger.info("Starting DB replay mode...");

        // Validate database file
        if (replayDbFile == null || replayDbFile.trim().isEmpty()) {
            logger.error("Database file is required. Use --db <database_file> to specify a valid database file.");
            throw new IllegalArgumentException("Database file is required. Use --db <database_file> to specify a valid database file.");
        }
        
        // 校验数据库文件（或时间分卷）是否存在且可读。
        // 时间分卷模式下，基准文件可能不存在，仅存在 capture_<start>-<end>.db（或 capture_<start>-capturing.db）分卷文件，
        // 因此使用分卷发现结果进行校验。
        List<String> volumes = SplitUtil.discoverVolumes(replayDbFile);
        // 存在性校验必须同时覆盖"捕获中"(-capturing)的卷：live 跟随时 capture 可能只有 -capturing 分卷，
        // 它们真实存在于磁盘上（虽不可回放，但不应误报"不存在"）。
        List<String> existingCandidates = SplitUtil.discoverAllSplitStyle(replayDbFile);
        if (existingCandidates.isEmpty()) {
            existingCandidates = volumes;
        }
        boolean anyExists = false;
        for (String v : existingCandidates) {
            File volFile = new File(v);
            if (volFile.exists()) {
                if (!volFile.canRead()) {
                    logger.error("Database volume is not readable: {}", v);
                    throw new IllegalArgumentException("Database volume is not readable: " + v);
                }
                anyExists = true;
                break;
            }
        }
        if (!anyExists) {
            logger.error("Database file (or any time-split volume) does not exist: {}", replayDbFile);
            throw new IllegalArgumentException("Database file (or any time-split volume) does not exist: " + replayDbFile);
        }
        if (volumes.size() > 1) {
            logger.info("[JShark] Time-split volumes detected: {}", volumes.size());
        }

        // 时间窗口对所有数据源统一按绝对捕获时间解释；分卷模式只是多一步按卷名快速跳过。
        validateTimeSelection(replayStartTime, replayEndTime);

        logger.info("Database file: {}", replayDbFile);
        logger.info("Speed multiplier: {}", replaySpeed);

        if (replayStartTime != null) {
            logger.info("Start capture time: {}", new java.sql.Timestamp(replayStartTime));
        }
        if (replayEndTime != null) {
            logger.info("End capture time: {}", new java.sql.Timestamp(replayEndTime));
        }
        if (replaySourceIp != null) {
            logger.info("Source IP filter: {}", replaySourceIp);
        }
        if (replayDestinationIp != null) {
            logger.info("Destination IP filter: {}", replayDestinationIp);
        }
        if (replaySourcePort != null) {
            logger.info("Source port filter: {}", replaySourcePort);
        }
        if (replayDestinationPort != null) {
            logger.info("Destination port filter: {}", replayDestinationPort);
        }
        if (replayIpProtocol != null) {
            logger.info("IP protocol filter: {}", replayIpProtocol);
        }
        if (replayApplicationProtocol != null) {
            logger.info("Application protocol filter: {}", replayApplicationProtocol);
        }
        if (replayExpressionFilter != null) {
            logger.info("Expression filter: {}", replayExpressionFilter);
        }
        if (replayTargetMapping != null) {
            logger.info("Target mapping: {}", replayTargetMapping);
        }
        
        // 先解析模式，再创建/启动工具：显式 frame 缺 inject 时直接失败，不要先建好工具再抛错。
        boolean hasInjectInterface = injectInterface != null && !injectInterface.trim().isEmpty();
        ReplayModeResolver.Decision modeDecision =
                ReplayModeResolver.resolveDb(replayMode, replayModeExplicit, hasInjectInterface);
        if (modeDecision.error() != null) {
            throw new IllegalArgumentException(modeDecision.error());
        }
        if (modeDecision.warning() != null) {
            logger.warn(modeDecision.warning());
            // 让 UI 也能看到“被忽略”的原因，而不是只在日志里
            control().addWarning("OPTION_IGNORED", modeDecision.warning());
        }

        // Create and start replay tool
        DbReplayTool replayTool = new DbReplayTool(
            replayDbFile, replaySpeed, replayStartTime, replayEndTime,
            replaySourceIp, replayDestinationIp, replaySourcePort, replayDestinationPort,
            replayIpProtocol, replayApplicationProtocol, replayExpressionFilter,
            replayTargetMapping
        );
        currentDbTool = replayTool;
        replayTool.setControl(control());
        // 自适应降速是唯一模式：--speed 只是上限，工具默认启用自适应，CLI 不再提供关闭入口。

        if (modeDecision.mode() == ReplayModeResolver.Mode.FRAME) {
            // 解析器保证 FRAME 一定有非空 injectInterface。
            String injectIp = injectInterface.trim();
            PcapNetworkInterface nif = StartupSelfCheck.findInterfaceByIp(injectIp);
            if (nif == null) {
                throw new IllegalArgumentException(
                        "No network interface has IP " + injectInterface + ". " + injectInterfaceHint()
                                + " Use --injectInterface=<IP>.");
            }
            FrameRewriter.MacPolicy macPolicy = FrameRewriter.MacPolicy.parse(dstMac);
            java.util.function.Function<String, byte[]> resolver = null;
            if (macPolicy.mode() == FrameRewriter.MacPolicy.Mode.AUTO
                    || macPolicy.mode() == FrameRewriter.MacPolicy.Mode.PER_IP) {
                NeighborResolver neighborResolver =
                        new NeighborResolver(nif, pickInterfaceMac(nif), injectIp, true);
                resolver = neighborResolver::resolve;
            }
            replayTool.enableFrameMode(nif, macPolicy, resolver);
            replayTool.setStartupCheck(startupCheck(nif, 0));
            logger.info("Replay mode: FRAME (injecting original frames via {})", injectIp);
        } else {
            logger.info("Replay mode: PAYLOAD (transport payload via the kernel stack). "
                    + "Add --replayMode=frame --injectInterface=<IP> for frame-level replay.");
        }

        // 处理 CTRL+C；seek 重开段时会被替换，避免 hook 累积
        installShutdownHook(() -> {
            logger.info("[JShark] Got quit signal.........");
            replayTool.stopReplay();
        });

        try {
            replayTool.startReplay();
        } finally {
            currentDbTool = null;
            removeShutdownHook();
        }
    }

    /**
     * 从离线 pcap 文件重放。
     * <p>
     * 与数据库模式共用倍率时序、源/目的 IP 与端口过滤、IP 协议过滤、目标映射等规则。
     * 时间窗（{@code --start/--end}）同样按绝对捕获时间生效；表达式过滤（{@code --exfilter}）
     * 依赖数据库中的 additionalInfo 解析结果，因此在 pcap 模式下不生效并给出提示。
     * </p>
     */
    private void replayFromPcap() {
        logger.info("Starting PCAP replay mode...");

        File pcap = new File(replayPcapFile);
        if (!pcap.isFile()) {
            throw new IllegalArgumentException("PCAP file does not exist: " + replayPcapFile);
        }
        if (!pcap.canRead()) {
            throw new IllegalArgumentException("PCAP file is not readable: " + replayPcapFile);
        }

        validateTimeSelection(replayStartTime, replayEndTime);

        if (replayStartTime != null) {
            logger.info("Start capture time: {}", new java.sql.Timestamp(replayStartTime));
        }
        if (replayEndTime != null) {
            logger.info("End capture time: {}", new java.sql.Timestamp(replayEndTime));
        }
        if (replayExpressionFilter != null) {
            warnIgnored("[JShark] --exfilter is ignored in --pcap mode "
                    + "(additionalInfo is only produced by the database capture path)");
        }
        if (replayApplicationProtocol != null) {
            warnIgnored("[JShark] --applicationProtocol is ignored in --pcap mode "
                    + "(appProtocol is only recorded in the database)");
        }

        logger.info("PCAP file: {}", pcap.getAbsolutePath());
        logger.info("Speed multiplier: {}x", replaySpeed);
        if (replaySourceIp != null) {
            logger.info("Source IP filter: {}", replaySourceIp);
        }
        if (replayDestinationIp != null) {
            logger.info("Destination IP filter: {}", replayDestinationIp);
        }
        if (replaySourcePort != null) {
            logger.info("Source port filter: {}", replaySourcePort);
        }
        if (replayDestinationPort != null) {
            logger.info("Destination port filter: {}", replayDestinationPort);
        }
        if (replayIpProtocol != null) {
            logger.info("IP protocol filter: {}", replayIpProtocol);
        }
        if (replayTargetMapping != null) {
            logger.info("Target mapping: {}", replayTargetMapping);
        }

        PcapReplayTool.Mode mode;
        if ("payload".equalsIgnoreCase(replayMode)) {
            mode = PcapReplayTool.Mode.PAYLOAD;
        } else if ("frame".equalsIgnoreCase(replayMode)) {
            mode = PcapReplayTool.Mode.FRAME;
        } else {
            throw new IllegalArgumentException("Invalid --replayMode: " + replayMode
                    + " (expected 'frame' or 'payload')");
        }

        PcapNetworkInterface injectionNif = null;
        FrameRewriter.MacPolicy macPolicy = FrameRewriter.MacPolicy.parse(dstMac);
        java.util.function.Function<String, byte[]> resolver = null;

        if (mode == PcapReplayTool.Mode.FRAME) {
            if (injectInterface == null || injectInterface.trim().isEmpty()) {
                throw new IllegalArgumentException(
                        "'frame' replay mode requires --injectInterface=<IP of the NIC to inject on>.");
            }
            injectionNif = StartupSelfCheck.findInterfaceByIp(injectInterface.trim());
            if (injectionNif == null) {
                throw new IllegalArgumentException(
                        "No network interface has IP " + injectInterface + ". " + injectInterfaceHint()
                                + " Check the address or use --injectInterface.");
            }

            // 启动自检：权限 / DLT / 注入能力（只打印，不阻断；会话级缓存，seek 不再重跑）
            StartupSelfCheck.Result check = startupCheck(injectionNif, 1);

            // 需要解析单播 MAC 时构造解析器（组播/广播仍走公式，不触发探测）
            if (macPolicy.mode() == FrameRewriter.MacPolicy.Mode.AUTO
                    || macPolicy.mode() == FrameRewriter.MacPolicy.Mode.PER_IP) {
                byte[] localMac = pickInterfaceMac(injectionNif);
                NeighborResolver neighborResolver =
                        new NeighborResolver(injectionNif, localMac, injectInterface.trim(), true);
                resolver = neighborResolver::resolve;
            }
            if (check != null && check.verdict() == StartupSelfCheck.InjectVerdict.FAILED) {
                logger.error("[JShark] Injection self-check failed on this NIC; replay would send nothing. "
                        + "Pick a wired Ethernet adapter with --injectInterface, then retry.");
                String advice = check.advice();
                control().addWarning("INJECTION_FAILED",
                        "Frame injection self-check failed on " + injectionNif.getName()
                                + (check.detail() == null || check.detail().isBlank() ? "" : ": " + check.detail())
                                + (advice == null ? "" : " — " + advice));
            }
            if (check != null) {
                for (String warning : check.warnings()) {
                    control().addWarning("INJECTION_WARNING", warning);
                }
            }
        } else if (injectInterface != null) {
            warnIgnored("[JShark] --injectInterface is ignored in 'payload' replay mode");
        }

        logger.info("Replay mode: {}", mode);
        PcapReplayTool tool = new PcapReplayTool(
                replayPcapFile, replaySpeed, mode,
                replaySourceIp, replayDestinationIp,
                replaySourcePort, replayDestinationPort,
                replayIpProtocol, replayTargetMapping,
                injectionNif, macPolicy, resolver);
        currentPcapTool = tool;
        tool.setControl(control());
        tool.setStartupCheck(startupCheck);
        tool.setStartAtMs(pcapStartMs != null ? pcapStartMs : replayStartTime);
        tool.setEndAtMs(replayEndTime);

        installShutdownHook(() -> {
            logger.info("[JShark] Got quit signal.........");
            tool.stopReplay();
        });

        try {
            tool.startReplay();
        } finally {
            currentPcapTool = null;
            removeShutdownHook();
        }
    }

    /**
     * 找不到注入网卡时的可操作提示：列出 pcap 实际能看到的 IPv4。
     *
     * <p>UI 的网卡下拉来自 Java 的 {@code NetworkInterface}，而帧注入按 pcap/Npcap 的设备列表
     * 解析 IP；两者可能不一致（例如 Npcap 未安装、网卡被 Npcap 排除、或下拉里的 IP 已过期）。
     * 空列表通常意味着 Npcap/libpcap 不可用。</p>
     *
     * @return 单行提示（以空格结尾），可直接拼在错误信息后
     */
    private static String injectInterfaceHint() {
        java.util.List<String> available = StartupSelfCheck.listIpv4Addresses();
        if (available.isEmpty()) {
            return "Npcap/libpcap is unavailable or no IPv4 interface is visible to it; "
                    + "install Npcap with WinPcap API compatibility and run as Administrator.";
        }
        return "Interfaces visible to pcap: " + String.join(", ", available) + ".";
    }

    /**
     * 从网卡地址推断其 MAC（用于主动 ARP 探测的发送方地址）。
     *
     * @param nif 网卡
     * @return 6 字节 MAC；无法推断返回 null
     */
    private byte[] pickInterfaceMac(PcapNetworkInterface nif) {
        try {
            String name = nif.getName();
            int brace = name.lastIndexOf('{');
            String guid = brace >= 0 ? name.substring(brace) : name;
            for (java.net.NetworkInterface ni : java.util.Collections.list(
                    java.net.NetworkInterface.getNetworkInterfaces())) {
                String niName = ni.getName();
                String niDisplay = ni.getDisplayName() == null ? "" : ni.getDisplayName();
                if (niName == null) {
                    continue;
                }
                // Windows 上 pcap 设备名形如 \Device\NPF_{GUID}，而 NetworkInterface 名通常是 {GUID}
                boolean matches = niName.equalsIgnoreCase(guid)
                        || niDisplay.contains(guid.replace("{", "").replace("}", ""))
                        || niName.contains(guid.replace("{", "").replace("}", ""));
                if (matches) {
                    byte[] mac = ni.getHardwareAddress();
                    if (mac != null && mac.length == 6) {
                        return mac;
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("[JShark] Failed to determine interface MAC: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Inner class to store option information
     *
     * @param fieldName     目标字段名
     * @param requiresValue 取值是否必需（false = 纯开关）
     * @param valueOptional 取值可省略（省略时按 "true" 处理，如 {@code --daemon}）
     * @param hidden        是否为隐藏参数（仍可解析但不显示在帮助里）
     * @param description   帮助文本
     */
    private record OptionInfo(String fieldName, boolean requiresValue, boolean valueOptional,
                              boolean hidden, String description)
            implements CliArgs.Spec {
        /** 取值必需的常规选项。 */
        OptionInfo(String fieldName, boolean requiresValue, String description) {
            this(fieldName, requiresValue, false, false, description);
        }

        /** 值可省略的常规选项（如 {@code --daemon}）。 */
        OptionInfo(String fieldName, boolean requiresValue, boolean valueOptional, String description) {
            this(fieldName, requiresValue, valueOptional, false, description);
        }
    }
}