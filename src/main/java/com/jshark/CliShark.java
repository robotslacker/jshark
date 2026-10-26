package com.jshark;

import com.jshark.parser.SplitUtil;
import com.jshark.parser.env.SnifferEnvChecker;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JShark - Java Packet Capture Tool
 * CLI interface for packet capture functionality
 */
public class CliShark {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(CliShark.class);
    
    // Command line options for packet capture
    private String interfaceIP;
    private String filterExpression;
    private Integer packetCount;
    private Integer timeoutSeconds;
    private String pcapOutputFile;
    private String pcapInputFile;
    private String logDb;
    private String exfilter; // 表达式过滤additionalInfo内容
    /**
     * 是否展开 DIS/HTTP/PG 的详细字段并写入数据库 additionalInfo 列。
     * 默认 false：不为了该列解析载荷，数据库该列恒为 NULL（appProtocol/tcpFlags/帧数据不受影响）。
     * 设置 {@code --exfilter} 时会自动变为 true（表达式依赖该列）。
     */
    private boolean enableAdditionInfo = false;
    private long splitIntervalMs; // 时间分卷间隔（毫秒），0 表示不启用
    private boolean promiscuous = false;
    /** 内核抓包缓冲大小（MB）；null 表示用 PacketCapture 的默认值（64MB） */
    private Integer pcapBufferMb;
    /** 是否启用 immediate mode（每包立即唤醒） */
    private boolean immediate = false;
    /** 解析线程数；null 表示用默认值（1 = 单线程原地解析） */
    private Integer parseThreads;
    /** 是否转后台运行（--daemon）；后台副本由父进程拉起，父进程随后立即退出 */
    private boolean daemon = false;
    /** 日志目标（--logfile）：逗号分隔的 CONSOLE 或文件路径；null 表示只输出到控制台 */
    private String logFile;
    /** --ui：启动采集图形界面（在 run() 中预扫描处理，解析层不保留状态） */
    /** --control：内部 stdio 控制通道（由 --ui 拉起的子进程使用）；null 表示普通 CLI 模式 */
    private String controlMode;
    /** 当前采集引擎：控制模式/UI 需要它做 requestStop 与状态快照 */
    private volatile PacketCapture activeCapture;
    /** 抓包线程引用，供 shutdown hook 等待其完成收尾 */
    private Thread captureThreadRef;
    /** 是否已经处理过第一次退出信号；用于忽略重复的 Ctrl+C（见 installSignalGuard） */
    private static final java.util.concurrent.atomic.AtomicBoolean SIGNAL_HANDLED =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private final List<String> multicastGroups = new ArrayList<>();
    
    // Option definitions
    private static final Map<String, OptionInfo> OPTIONS = CliArgs.stableOptions();
    
    static {
        // Define all supported long options (no short options)
        OPTIONS.put("--ip_address", new OptionInfo("interfaceIP", true, "Select network interface according to ip address"));
        OPTIONS.put("--filter", new OptionInfo("filterExpression", true, "BPF filter expression (e.g., 'tcp port 80')"));
        OPTIONS.put("--count", new OptionInfo("packetCount", true, "Stop after capturing specified number of packets"));
        OPTIONS.put("--timeout", new OptionInfo("timeoutSeconds", true, "Stop after specified seconds"));
        OPTIONS.put("--pcapoutput", new OptionInfo("pcapOutputFile", true, "Save captured packets to PCAP file (supports automatic time-based rotation)"));
        OPTIONS.put("--pcapinput", new OptionInfo("pcapInputFile", true, false, true,
                "Read packets from an offline PCAP file instead of a live interface "
                        + "(runs the exact same parsing/storage pipeline; useful for replay-from-archive and for tests) "
                        + "[hidden: not shown in help]"));
        OPTIONS.put("--split", new OptionInfo("split", true, "Time-based volume split interval, applies to both PCAP and logdb. "
                + "Unit is required: m (minutes), h (hours) or d (days); the smallest unit is minute (e.g. 5m, 1h, 1d)."));
        OPTIONS.put("--logdb", new OptionInfo("logDb", true, "Save all messages to a DuckDB database (path required)"));
        OPTIONS.put("--exfilter", new OptionInfo("exfilter", true,
                """
                        Filter additionalInfo content using advanced expressions
                          Supported operators: =, !=, >, <, >=, <=, like (with wildcards * and ?)
                          Logical operators: && (AND), || (OR)
                          Parentheses: () for grouping
                          Examples:
                            dis.pdu.type=28 && dis.exercise.id=17
                            (dis.pdu.type=28 || dis.pdu.type=1) && dis.exercise.id!=0
                            dis.pdu.type>20 && dis.pdu.type<30
                            dis.entity.name like "*tank*"
                        Only matching packets are stored; unmatched packets are dropped (they are
                        counted and reported on exit). Setting --exfilter automatically enables
                        --enable_additioninfo, so the matched rows keep their protocol details for
                        later queries and replay-side --exfilter."""));
        OPTIONS.put("--enable_additioninfo", new OptionInfo("enableAdditionInfo", true, true,
                """
                        Expand DIS/HTTP/PG details into the database additionalInfo column: true|false
                        (default: false; bare --enable_additioninfo means true).
                          false - do NOT parse the payload for that column and leave it NULL.
                                  appProtocol/tcpFlags/frameData/rawData are still recorded, so capture
                                  and replay behave exactly the same; only the detailed protocol JSON is
                                  missing. This is the fast path for high-rate captures.
                          true  - parse and store DIS/HTTP/PG details (the previous behaviour).
                        Note: setting --exfilter enables this automatically, because the expression is
                        evaluated against those details."""));
        OPTIONS.put("--promiscuous", new OptionInfo("promiscuous", false, "Enable promiscuous mode"));
        OPTIONS.put("--pcap-buffer", new OptionInfo("pcapBufferMb", true,
                "Kernel capture buffer size in MB (default 64). This is the only buffer that can absorb "
                        + "bursts; the platform default (~2MB on Npcap) drops packets silently under load."));
        OPTIONS.put("--immediate", new OptionInfo("immediate", false,
                "Enable pcap immediate mode (wake up on every packet). Lower latency, higher CPU per packet. "
                        + "Default: off (disabled)."));
        OPTIONS.put("--parse-threads", new OptionInfo("parseThreads", true,
                """
                        Number of parser threads (default 1 = parse inline on the capture thread).
                          >1 offloads packet parsing/DIS decoding to N workers, which is where most of the
                          per-packet CPU goes. Stateful work (TCP flow reassembly, IP fragment reassembly)
                          is pinned to a shard by flow, so results stay identical to single-threaded mode;
                          stateless packets (UDP/DIS) are spread round-robin for real parallelism.
                          Note: the DB sink is a separate single thread and can become the new bottleneck.
                          Capped at 4 x CPU cores (at least 4); a larger value is clamped with a warning.
                          Also note: in parallel mode the ingestSeq/ID column may contain gaps
                          (packets buffered for fragment reassembly also consume a number) and rows are
                          no longer inserted in capture order - query with ORDER BY ingestSeq."""));
        OPTIONS.put("--multicast", new OptionInfo("multicastGroups", true,
                "Join multicast group IP before capture (repeatable), e.g. --multicast 224.3.0.0"
                        + " enables the NIC to receive multicast DIS traffic on this group"));
        OPTIONS.put("--daemon", new OptionInfo("daemon", true, true,
                """
                        Run in the background (daemon mode): true|false (default: false).
                          The launching process forks a detached copy of itself with the same
                          command-line options (except that --daemon becomes false) and exits
                          immediately, so the capture keeps running after the console closes.
                          Bare --daemon is the same as --daemon true.
                          Requires starting from a jar; in dev/IDE mode (classes) it falls back to
                          running in the foreground with a warning.
                          Combine with --logfile, otherwise the background output only lives on the
                          console that launched it."""));
        OPTIONS.put("--logfile", new OptionInfo("logFile", true,
                """
                        Write log output to a file instead of the console (default: CONSOLE).
                          The value is a comma-separated target list; each item is either CONSOLE or a
                          file path, e.g. --logfile logs/capture.log or --logfile CONSOLE,logs/capture.log
                          Missing parent directories are created automatically; logs are appended.
                          Recommended together with --daemon: the file is the only place left to look
                          after the launching console is gone."""));
        OPTIONS.put("--ui", new OptionInfo("ui", false,
                "Launch the capture console (GUI) instead of running headless; "
                        + "the GUI starts the real capture in a child process."));
        // 内部参数：UI 子进程的 stdio 协议，不出现在 --help
        OPTIONS.put("--control", new OptionInfo("control", true, false, true,
                "Internal stdio control channel used by --ui (hidden)"));
    }

    /**
     * Main entry point for packet capture
     */
    public static void main(String[] args) {
        // 关闭 Windows 控制台“快速编辑模式”，防止用户在控制台内点击/拖选文本时
        // 阻塞 stdout 写入，导致 capture 过程“卡住、需要回车才能继续”。
        WindowsConsoleUtil.disableQuickEditMode();

        try {
            run(args);
        } catch (CliExitException e) {
            // 进程边界：只有这里决定退出码。
            // 解析层（parse）不再自己 System.exit —— 那样会让直接调用它的测试在参数回归时
            // 杀掉 forked 测试 JVM（surefire 崩），而不是让用例干净地失败。
            System.exit(e.exitCode());
        }
    }

    /**
     * 真正的启动流程。参数解析只抛 {@link CliExitException}，不在这里退进程。
     */
    static void run(String[] args) {
        if (args.length == 0) {
            printHelp();
            throw new CliExitException(CliExitException.EXIT_OK, null, null);
        }

        // --help/-h 是纯查询：不检查 Npcap/管理员权限，也不解析业务参数
        if (CliRuntime.hasOption(args, "--help") || java.util.Arrays.asList(args).contains("-h")) {
            CliLogging.configure(CliRuntime.scanLogTarget(args), CliRuntime.hasOption(args, "--control"));
            printHelp();
            throw new CliExitException(CliExitException.EXIT_OK, null, null);
        }

        // --ui 是前台 GUI：本身不打开网卡、不做环境检查；真正的采集由它拉起
        // 子进程（--control stdio）完成。父进程需要管理员权限，否则子进程会报错。
        if (CliRuntime.isEnabled(args, "--ui")) {
            if (CliRuntime.hasOption(args, "--control") || CliRuntime.isEnabled(args, "--daemon")) {
                System.err.println("Error: --ui cannot be combined with --control/--daemon");
                throw new CliExitException(CliExitException.EXIT_USAGE, "--ui cannot be combined with --control/--daemon", null);
            }
            CaptureUi.launch(args);
            return;
        }

        // --control 的 stdout 是协议，日志必须走 stderr（与重放端的 --control 一致）。
        boolean stdioControl = CliRuntime.hasOption(args, "--control");
        // --logfile 必须在日志系统初始化之前读出来：这样连"参数非法"之类的告警
        // 也会落到用户指定的日志文件里，而不是只出现在屏幕上。
        CliLogging.configure(CliRuntime.scanLogTarget(args), stdioControl);

        // First check if environment is ready
        logger.info("[JShark] JShark - Java Packet Capture Tool");

        // Process command line arguments. 环境预检（Npcap/管理员）只在真正在线抓包时做：
        // --help 已在上面提前返回，离线 --pcapinput 也不需要管理员权限。
        CliShark cliShark = new CliShark();
        cliShark.parse(args);
        if (cliShark.controlMode != null) {
            if (!"stdio".equalsIgnoreCase(cliShark.controlMode)) {
                throw new CliExitException(CliExitException.EXIT_USAGE,
                        "Unsupported --control mode: " + cliShark.controlMode + " (expected 'stdio')", null);
            }
            CaptureControl.run(cliShark);
            return;
        }
        // 请求后台运行时，父进程只负责拉起后台副本，抓包由后台副本完成
        cliShark.enterDaemonModeIfRequested(args);
        cliShark.startCapture();
    }

    /**
     * 请求停止当前采集（供 {@code --control stdio} 使用；任意线程可调用）。
     *
     * @return true 表示本次调用是首个停止请求
     */
    public boolean requestStop() {
        PacketCapture capture = activeCapture;
        return capture != null && capture.requestStop();
    }

    /** @return 当前采集状态快照；尚未开始时为 null */
    public PacketCapture.Snapshot captureSnapshot() {
        PacketCapture capture = activeCapture;
        return capture != null ? capture.snapshot() : null;
    }

    /**
     * 处理 {@code --daemon}：请求后台运行时，拉起后台副本后本进程立即退出（退出码 0），
     * 真正的抓包工作由后台副本完成；开发模式（非 jar 启动）无法脱离当前进程，
     * 给出告警后退化为前台运行。
     *
     * @param args 原始命令行参数，原样传给后台副本（其中 {@code --daemon} 会被替换为 false）
     */
    private void enterDaemonModeIfRequested(String[] args) {
        if (!daemon) {
            return;
        }
        try {
            if (!CliRuntime.startInBackground(CliShark.class, args, logFile, logger)) {
                return;   // 开发模式：继续在当前进程前台抓包
            }
        } catch (Exception e) {
            logger.error("[JShark] Failed to start daemon process", e);
            throw new CliExitException(CliExitException.EXIT_USAGE, "Failed to start daemon process", e);
        }
        // 正常退出：抓包已经交给后台副本
        throw new CliExitException(CliExitException.EXIT_OK, null, null);
    }
    
    /**
     * Parse command line arguments
     * @param args command line arguments
     */
    public void parse(String[] args) {
        try {
            parseArguments(args);
        } catch (CliExitException e) {
            // --help / 无参数等"正常退出信号"：原样上抛，由 main 决定退出码。
            // 不能落到下面的 catch (Exception)：那会把退出码 0 改成 1。
            throw e;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid command line arguments: {}", e.getMessage());
            System.err.println("Error: " + e.getMessage());
            System.err.println("Use --help for usage information");
            throw new CliExitException(CliExitException.EXIT_USAGE, e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Failed to parse command line arguments", e);
            System.err.println("Error: Failed to parse command line arguments");
            throw new CliExitException(CliExitException.EXIT_USAGE, "Failed to parse command line arguments", e);
        }
    }

    /**
     * Parse command line arguments into fields
     */
    private void parseArguments(String[] args) {
        // --help 是纯查询：先处理，不要求参数表里其它内容合法
        for (String arg : args) {
            if (arg.equals("--help") || arg.equals("-h")) {
                printHelp();
                // 退出码 0：正常退出。上抛给 main，绝不在这里退进程
                throw new CliExitException(CliExitException.EXIT_OK, null, null);
            }
        }
        for (CliArgs.Entry<OptionInfo> entry : CliArgs.parse(args, OPTIONS)) {
            OptionInfo info = entry.spec();
            if (info.requiresValue()) {
                setFieldValue(info.fieldName(), entry.value());
            } else {
                // 纯开关也接受显式 =false（否则 --promiscuous=false 会被静默当成 true）
                boolean enabled = entry.value() == null
                        || CliRuntime.parseBooleanFlag(entry.name(), entry.value());
                setBooleanField(info.fieldName(), enabled);
            }
        }
        // --exfilter 的表达式匹配 additionalInfo 里的协议字段，因此它隐含要求该列落库：
        // 只写 --exfilter 时自动开启 --enable_additioninfo（显式 =false 也一样）。
        if (exfilter != null && !exfilter.isEmpty() && !enableAdditionInfo) {
            logger.info("[JShark] --exfilter is set: enabling --enable_additioninfo automatically");
            enableAdditionInfo = true;
        }
    }

    
    /**
     * Print help/usage information
     */
    private static void printHelp() {
        System.out.println("JShark - Java Packet Capture Tool");
        System.out.println();
        System.out.println("Usage: CliShark [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.printf("  %-28s %s%n", "--help", "Show this help message and exit");
        CliHelp.printOptions(System.out, OPTIONS);
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Capture DIS traffic on specific interface, and save data into file.");
        System.out.println("  CliShark --ip_address 192.168.1.100 --filter \"udp port 3000\" --logdb dis_capture.db");
        System.out.println();
        System.out.println("  # Capture HTTP traffic on specific interface");
        System.out.println("  CliShark --ip_address 192.168.1.100 --filter \"tcp port 80\" --count 100");
        System.out.println();
        System.out.println("  # Save captured packets to PCAP file");
        System.out.println("  CliShark --ip_address 192.168.1.100 --pcapoutput capture.pcap");
        System.out.println();
        System.out.println("  # Capture DIS packets and log to database with expression filter");
        System.out.println("  CliShark --ip_address 192.168.1.100 --logdb dis_capture.db --exfilter \"dis.pdu.type=28 && dis.exercise.id=17\"");
        System.out.println();
        System.out.println("  # Capture DIS packets with timeout and promiscuous mode");
        System.out.println("  CliShark --ip_address 192.168.1.100 --filter \"udp port 3000\" --timeout 60 --promiscuous --logdb dis_capture.db");
        System.out.println();
        System.out.println("  # Capture multicast DIS traffic (join group before capture)");
        System.out.println("  CliShark --ip_address 11.8.8.33 --multicast 224.3.0.0 --filter \"udp port 3001\" --logdb dis_capture.db");
        System.out.println();
        System.out.println("  # Keep only packets that match an expression (unmatched packets are counted and reported)");
        System.out.println("  CliShark --logdb dis.db --exfilter \"dis.pdu.type=28\"");
        System.out.println();
        System.out.println("  # Persist DIS/HTTP/PG details so expression queries and replay-side --exfilter work later");
        System.out.println("  CliShark --ip_address 192.168.1.100 --filter \"udp port 3000\" --enable_additioninfo=true --logdb dis_detail.db");
        System.out.println();
        System.out.println("  # Run the capture in the background and keep the log in a file");
        System.out.println("  CliShark --ip_address 192.168.1.100 --logdb dis_capture.db --daemon --logfile logs/capture.log");
    }
    
    /**
     * Set field value based on field name and string value
     */
    private void setFieldValue(String fieldName, String value) {
        try {
            switch (fieldName) {
                case "interfaceIP" -> this.interfaceIP = value;
                case "filterExpression" -> this.filterExpression = value;
                case "packetCount" -> {
                    int n = Integer.parseInt(value);
                    if (n < 0) {
                        throw new IllegalArgumentException("--count must be >= 0 (got: " + value + ")");
                    }
                    this.packetCount = n;
                }
                case "timeoutSeconds" -> {
                    int n = Integer.parseInt(value);
                    if (n < 0) {
                        throw new IllegalArgumentException("--timeout must be >= 0 seconds (got: " + value + ")");
                    }
                    this.timeoutSeconds = n;
                }
                case "pcapOutputFile" -> this.pcapOutputFile = value;
                case "pcapInputFile" -> this.pcapInputFile = value;
                case "split" -> this.splitIntervalMs = SplitUtil.parseSplit(value);
                case "logDb" -> this.logDb = value;
                case "exfilter" -> this.exfilter = value;
                case "enableAdditionInfo" -> this.enableAdditionInfo =
                        CliRuntime.parseBooleanFlag("--enable_additioninfo", value);
                case "multicastGroups" -> { if (value != null && !value.trim().isEmpty()) this.multicastGroups.add(value.trim()); }
                case "pcapBufferMb" -> {
                    int mb = Integer.parseInt(value);
                    if (mb <= 0) {
                        throw new IllegalArgumentException("--pcap-buffer must be a positive number of MB (got: " + value + ")");
                    }
                    this.pcapBufferMb = mb;
                }
                case "parseThreads" -> {
                    int n = Integer.parseInt(value);
                    if (n <= 0) {
                        throw new IllegalArgumentException("--parse-threads must be a positive integer (got: " + value + ")");
                    }
                    this.parseThreads = n;
                }
                case "daemon" -> this.daemon = CliRuntime.parseDaemonFlag(value);
                case "control" -> this.controlMode = value == null ? null : value.trim();
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
     * Set boolean field value
     */
    private void setBooleanField(String fieldName, boolean enabled) {
        switch (fieldName) {
            case "promiscuous" -> this.promiscuous = enabled;
            case "immediate" -> this.immediate = enabled;
            // --ui 在 run() 里预扫描后直接启动界面，解析层不需要保存状态
            case "ui" -> { }
            default -> throw new IllegalArgumentException("Unknown boolean field: " + fieldName);
        }
    }
    
    /**
     * 启动采集（阻塞直到采集结束）。
     *
     * <p>包级可见性：{@code --ui} 通过 {@code --control stdio} 子进程调用本方法；
     * 普通 CLI 直接调用。无论哪种方式，都可以通过 {@link #requestStop()} 停止。</p>
     */
    void startCapture() {
        PacketCapture packetCapture = new PacketCapture();
        activeCapture = packetCapture;

        // 接管 SIGINT/SIGTERM：第一次信号走正常收尾，重复信号直接忽略。
        // 否则"手抖按两次 Ctrl+C"会在 checkpoint 做到一半时把进程打断——
        // 那正是 "-capturing" + 未合并 .wal 最常见的成因之一。
        installSignalGuard();

        // 添加Shutdown Hook, 处理 CTRL+C / SIGTERM 信号
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("[JShark] Got quit signal.........");
            // hook 线程只请求停止并等待抓包线程收尾，绝不直接关闭 pcap 句柄/数据库：
            // 抓包线程可能阻塞在原生 pcap_next_ex 并持有读锁，从别的线程 close 会死锁。
            if (packetCapture.requestStop()) {
                try {
                    Thread captureThread = captureThreadRef;
                    if (captureThread != null) {
                        // 等"整段收尾预算 + 1s 余量"：抓包线程在这段时间里完成
                        // drain → manifest → FORCE CHECKPOINT → close → rename（见 finishCapture）。
                        captureThread.join(PacketCapture.SHUTDOWN_BUDGET_MS + 1_000L);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                if (!packetCapture.isFinished()) {
                    // 兜底：抓包线程自己卡住了（卡在磁盘 IO / 解析 worker / checkpoint 本身）。
                    // 此时唯一还能救回最后一卷的就是这条路径——把 CHECKPOINT + 更名做完，
                    // 否则磁盘上留下的是 "-capturing" 加一个未合并的 .wal。
                    logger.warn("[JShark] Capture thread did not finish within {}ms; "
                                    + "forcing the last volume to checkpoint and rename",
                            PacketCapture.SHUTDOWN_BUDGET_MS);
                    packetCapture.forceFinalizeLastVolume();
                }
            }
        }, "jshark-shutdown"));

        // 按照IP地址，选择需要捕获的网卡
        packetCapture.setInterfaceIP(interfaceIP);

        // 设置过滤器
        packetCapture.setFilterExpression(filterExpression);

        packetCapture.setPacketCount(packetCount);
        packetCapture.setTimeoutSeconds(timeoutSeconds);

        // 保存PCAP文件
        packetCapture.setOutputFile(pcapOutputFile);
        packetCapture.setSplit(splitIntervalMs);

        // 保存文件到数据库
        packetCapture.setLogDb(logDb);
        // additionalInfo 详细字段展开 / 落盘开关（默认关闭，数据库该列恒为 NULL）
        packetCapture.setEnableAdditionalInfo(enableAdditionInfo);
        logger.info("[JShark] additionalInfo column: {} (--enable_additioninfo={})",
                enableAdditionInfo ? "ENABLED" : "DISABLED (always NULL)", enableAdditionInfo);
        packetCapture.setExfilter(exfilter);
        packetCapture.setPromiscuous(promiscuous);
        packetCapture.setMulticastGroups(multicastGroups);

        // 内核抓包缓冲与 immediate mode（仅在线模式生效；离线 pcapinput 不涉及）
        if (pcapBufferMb != null) {
            packetCapture.setPcapBufferBytes(pcapBufferMb * 1024 * 1024);
        }
        packetCapture.setImmediateMode(immediate);

        // 解析并行化（默认 1 = 单线程原地解析，行为与历史一致）
        if (parseThreads != null) {
            packetCapture.setParseThreads(parseThreads);
        }

        // Start capture（记录抓包线程，供 shutdown hook 等待其收尾）
        captureThreadRef = Thread.currentThread();
        try {
            if (pcapInputFile != null && !pcapInputFile.isEmpty()) {
                // 离线模式：从 pcap 文件读取，走完全相同的解析/IP 重组/TCP 重组/入库/输出流程。
                // 离线模式下 --filter（BPF）不生效，由 pcap 内容本身决定。
                if (filterExpression != null && !filterExpression.isEmpty()) {
                    logger.warn("[JShark] --filter is ignored in --pcapinput mode (BPF filters need a live handle)");
                }
                // 这两个选项只作用于在线句柄的打开参数，离线模式下静默忽略会让人以为调过了
                if (pcapBufferMb != null) {
                    logger.warn("[JShark] --pcap-buffer is ignored in --pcapinput mode "
                            + "(offline handles have no kernel capture buffer)");
                }
                if (immediate) {
                    logger.warn("[JShark] --immediate is ignored in --pcapinput mode "
                            + "(offline handles are driven by file timestamps)");
                }
                packetCapture.startCaptureFromFile(pcapInputFile);
            } else {
                // 只有在线抓包才需要 Npcap + 管理员权限；离线读取由 pcap4j 直接处理文件
                SnifferEnvChecker.Check();
                logger.info("[JShark] Checking system environment.........[OK]");
                packetCapture.startCapture();
            }
        } catch (Exception e) {
            // 同样只上抛：退出码由 main 统一决定（保持"本类只有 main 会退进程"的规则）
            logger.error("Packet capture failed", e);
            throw new CliExitException(CliExitException.EXIT_USAGE, "Packet capture failed", e);
        }
    }

    /**
     * 接管 SIGINT / SIGTERM：第一次信号交给正常收尾，之后的重复信号一律忽略。
     *
     * <p>为什么需要：停机的关键动作（FORCE CHECKPOINT → close → 更名）只有一次机会。
     * 操作员看到进程没立刻退出、再按一次 Ctrl+C 是常态，而第二次退出请求会让 JVM
     * 在收尾中途中止——磁盘上留下的就是 {@code -capturing} 加一个未合并的 {@code .wal}。
     * 这里把重复信号变成一条 WARN，收尾可以安心把预算用完。</p>
     *
     * <p>平台不支持某个信号（例如 Windows 没有 SIGTERM）时静默回落到 JVM 默认处理，
     * 不影响原先的 shutdown hook 路径。</p>
     */
    private static void installSignalGuard() {
        for (String name : new String[] {"INT", "TERM"}) {
            try {
                sun.misc.Signal.handle(new sun.misc.Signal(name), signal -> {
                    if (!SIGNAL_HANDLED.compareAndSet(false, true)) {
                        logger.warn("[JShark] Shutdown already in progress; ignoring repeated {} signal "
                                + "(waiting for the last volume to be checkpointed and renamed)", signal.getName());
                        return;
                    }
                    logger.info("[JShark] Got {} signal, shutting down...", signal.getName());
                    System.exit(130);   // 交由 shutdown hook 走统一收尾
                });
            } catch (Throwable t) {
                logger.debug("[JShark] Cannot install {} handler, falling back to the JVM default: {}",
                        name, t.toString());
            }
        }
    }

    /**
     * Inner class to store option information
     *
     * @param fieldName     目标字段名
     * @param requiresValue 取值是否必需（false = 纯开关）
     * @param valueOptional 取值可省略（省略时按 "true" 处理，如 {@code --daemon}）
     * @param hidden        是否为隐藏参数（true = 仍可解析但不显示在帮助里）
     * @param description   帮助文本
     */
    private record OptionInfo(String fieldName, boolean requiresValue, boolean valueOptional, boolean hidden, String description)
            implements CliArgs.Spec {
        /** 取值必需的常规选项。 */
        OptionInfo(String fieldName, boolean requiresValue, String description) {
            this(fieldName, requiresValue, false, false, description);
        }

        /** 值可省略的常规选项（如 {@code --daemon}） */
        OptionInfo(String fieldName, boolean requiresValue, boolean valueOptional, String description) {
            this(fieldName, requiresValue, valueOptional, false, description);
        }
    }
}