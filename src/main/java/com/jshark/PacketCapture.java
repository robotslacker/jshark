package com.jshark;

import com.jshark.parser.CaptureKind;
import com.jshark.parser.PacketDBEventHandler;
import com.jshark.parser.PacketParser;
import com.jshark.parser.PacketLogger;
import com.jshark.parser.SplitUtil;
import com.jshark.parser.ProtocolParser;
import com.jshark.parser.IpDefrag;
import com.jshark.parser.MessageFramer;
import com.jshark.parser.TcpFlowReassembler;
import com.jshark.parser.ThroughputMeter;
import com.jshark.parser.VolumeManifest;
import com.jshark.parser.VolumeWindows;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Main packet capture engine
 */
public class PacketCapture {
    private static final Logger logger = LoggerFactory.getLogger(PacketCapture.class);
    private Connection logDbConn = null;

    // Configuration
    private String interfaceIP;
    private String filterExpression;
    private Integer packetCount;
    private Integer timeoutSeconds;
    private String outputFile;
    private String logDb;
    private AtomicLong logDBSequence = new AtomicLong(0L);

    // 时间分卷间隔（毫秒），0 表示不分卷（同时作用于 PCAP 与 logdb）
    private long splitIntervalMs = 0;
    // logdb 分卷基础名（去掉扩展名）
    private String logDbBase = null;
    // logdb 扩展名（含点，如 ".db"；无扩展名时为空串）
    private String logDbExt = "";
    // 当前实际写入的 logdb 文件路径
    private String currentLogDbPath = null;
    // 已开启的 logdb 卷序号（从 1 开始；未启用 logdb 时保持 0）
    private int logDbVolumeSeq = 0;

    // ========== 时间窗口（PCAP 与 logdb 共用的唯一时钟） ==========

    /** 时间窗管理器；未启用 --split 时为 null（单文件模式） */
    private VolumeWindows windows;

    // ========== 停机丢弃计数（写入 manifest 与运行报告，绝不静默丢弃） ==========

    /** 停机信号之后才产生的记录数（按"停机后立即停止采集"的语义丢弃） */
    private volatile long droppedAfterSignal = 0;

    /** 停机瞬间正在处理、尚未形成完整记录的包数（并行解析后由多个分片线程更新，故用原子量） */
    private final java.util.concurrent.atomic.AtomicLong droppedInFlight =
            new java.util.concurrent.atomic.AtomicLong();
    /**
     * 因缺少端口信息而被跳过的 TCP/UDP 包数。
     * <p>
     * 这类包的传输层头没能解析出端口（通常是 snaplen 截断，或分片组未补齐），
     * 无法定位到端口。早期实现这里只打一行 debug 日志——等于**静默丢掉这些包的内容**。
     * 现在如实计数、首次出现时告警，并在退出与 manifest 里汇报。
     * （并行解析后由多个分片线程更新，故用原子量。）
     * </p>
     */
    private final java.util.concurrent.atomic.AtomicLong droppedNoPort =
            new java.util.concurrent.atomic.AtomicLong();
    /**
     * 解析 worker 提交/屏障/停机时因队列长时间打满而被丢弃的包数。
     * <p>
     * 早期这里用的是无超时的 {@code put}：一旦某个 worker 卡住且其队列已满，抓包线程会在
     * 卷边界或停机处<b>永久挂死</b>（Ctrl+C 也只置停止标志，解不开）。现在改为限时提交，
     * 超时就丢弃这一包并计数——宁可少录一个包并留下记录，也不能让整条采集挂死。
     * </p>
     */
    private final java.util.concurrent.atomic.AtomicLong droppedParseStall =
            new java.util.concurrent.atomic.AtomicLong();
    /** 解析任务抛异常（已被 worker 隔离、不会杀进程）而丢失的包数 */
    private final java.util.concurrent.atomic.AtomicLong failedParseTasks =
            new java.util.concurrent.atomic.AtomicLong();
    /**
     * 轮转/停机屏障未能等到分片排空的<b>事件次数</b>（不是包数）。
     * <p>
     * 刻意在名字里带 {@code Events}：一次该事件可能牵涉成千上万个包，把它们当包数读会
     * 严重低估计丢包规模。真正受影响的包由 {@code droppedAfterVolumeClose} /
     * {@code droppedAtShutdownBudget} 按包计数。
     * </p>
     */
    private final java.util.concurrent.atomic.AtomicLong parseBarrierTimeoutEvents =
            new java.util.concurrent.atomic.AtomicLong();
    /** 执行抓包循环的线程；用于校验"只允许抓包线程收尾"（见 finishCapture） */
    private volatile Thread captureLoopThread = null;
    /**
     * 最近一次停机对账的残差（{@code queued - accounted}），0 表示账目闭合。
     * <p>只用于自检与回归测试：正常运行时结论在日志里，测试需要一个可直接断言的数值，
     * 否则"账目是否闭合"只能靠人去读日志（也就等于没人看）。</p>
     */
    private volatile long accountingResidual = 0;
    /** 停机时是否已发出停止信号（用于区分"边界轮转"与"停机收尾"） */
    private volatile boolean stopRequested = false;
    // ========== 停机预算 ==========
    //
    // 历史故障（本方案要修的）：shutdown hook 只等固定 30s 就返回，JVM 随即 halt；
    // 而最后一卷的收尾是"提交给守护线程池后无限等"，队列上限又是 10 万条 ——
    // drain 一旦超过 30s，守护线程被就地杀死，文件永远停在 "-capturing" 且 .wal 未合并。
    //
    // 现在的模型：整段收尾限定在一个固定预算里，并给 "FORCE CHECKPOINT + close + rename"
    // 预留一段尾巴。无论队列里还剩多少包，最后一卷一定收得干净；没写完的包如实计数、
    // 写进 manifest（绝不静默丢）。

    /** 停机收尾总预算（毫秒）：从收到停止信号起，到进程允许退出为止 */
    public static final long SHUTDOWN_BUDGET_MS = 6_000L;
    /** 预算中预留给尾部动作（FORCE CHECKPOINT + close + rename）的时间（毫秒） */
    private static final long SHUTDOWN_TAIL_RESERVE_MS = 1_500L;
    /** 首次停机请求时刻（{@link System#nanoTime()}）；0 表示尚未收到停止信号 */
    private volatile long shutdownStartNanos = 0;
    /** 停机时刻（逻辑时钟，与窗口 startMs 同源）：用于生成最后一卷的 end */
    private volatile long stopAtMs = 0;
    /** {@link #finishCapture()} 是否已完整跑完（供 shutdown hook 判断要不要接管收尾） */
    private volatile boolean finished = false;

    // ========== 切卷异步收尾（"每文件一个写库线程"） ==========
    //
    // 历史问题：finalizeVolume 在抓包线程上同步执行 drainSnapshot + flushAndCloseLogDb +
    // FORCE CHECKPOINT + close + rename。队列里积压越多，分卷边界/停机这一下就卡得越久，
    // 期间抓包线程被完全阻塞（数据进不了采集 -> 出不了队 -> 丢包）。
    // 现在的模型：分卷边界一到，抓包线程<b>只</b>把旧卷的 handler/连接/路径摘离，立即开新卷；
    // 旧卷的"排空 -> 落库 -> 写 manifest -> CHECKPOINT -> 更名 -> 关连接"全部交给后台写库线程
    // （每卷一个）异步慢慢完成；退出时再统一 join，保证"慢慢写完再退出"。

    /** 卷收尾后台执行器：每个关闭的旧卷跑一个线程（cached pool 按需起线程，与"每文件一线程"一致） */
    private final java.util.concurrent.ExecutorService volumeCloseExecutor =
            java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "jshark-volume-closer");
                t.setDaemon(true);
                return t;
            });

    /** 已提交的卷收尾任务句柄；仅供抓包线程访问（finalizeVolume / finishCapture 都在抓包线程） */
    private final java.util.List<java.util.concurrent.Future<Long>> volumeCloseFutures =
            new java.util.ArrayList<>();

    /** 正在收尾中的卷（seq -> job）；供兜底路径接管"还没做完的尾部动作" */
    private final java.util.Map<Long, VolumeCloseJob> inFlightVolumes =
            new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * 一卷的收尾工作单。
     * <p>
     * 把"哪一卷、哪条连接、哪个文件、结束时间是多少"固化成一个对象，而不是让收尾代码去读
     * {@code PacketCapture} 上那些会被下一个卷改写的字段 —— 异步收尾与兜底接管都靠它。
     * </p>
     * <p>
     * {@code tailLock + tailDone} 让"FORCE CHECKPOINT → close → rename"这段尾部动作
     * <b>幂等</b>：正常收尾线程与兜底线程谁先拿到锁谁做，另一个直接返回，
     * 不会出现"一个线程在 close、另一个在 checkpoint"的致命并发。
     * </p>
     */
    private static final class VolumeCloseJob {
        final long seq;
        final long startMs;
        /** 窗口网格边界（仅 boundary 收尾使用） */
        final long windowEndMs;
        /** 实际用于命名的结束时间；shutdown 收尾时会改写成"按下 CTRL+C 的时刻" */
        volatile long endMs;
        final boolean complete;
        final String closedReason;
        final Connection conn;
        final String path;
        final PacketDBEventHandler handler;
        final long droppedAfterSignalSnapshot;
        final java.util.concurrent.locks.ReentrantLock tailLock = new java.util.concurrent.locks.ReentrantLock();
        volatile boolean tailDone = false;

        VolumeCloseJob(long seq, long startMs, long windowEndMs, boolean complete, String closedReason,
                       Connection conn, String path, PacketDBEventHandler handler, long droppedAfterSignalSnapshot) {
            this.seq = seq;
            this.startMs = startMs;
            this.windowEndMs = windowEndMs;
            this.endMs = windowEndMs;
            this.complete = complete;
            this.closedReason = closedReason;
            this.conn = conn;
            this.path = path;
            this.handler = handler;
            this.droppedAfterSignalSnapshot = droppedAfterSignalSnapshot;
        }
    }

    // 定时进度日志输出间隔（毫秒）
    private static final long PROGRESS_INTERVAL_MS = 5000L;

    /**
     * 吞吐量统计打印间隔（毫秒）：每 20 秒打印一次"过去这一段"的平均流量 MB/s。
     * <p>
     * 与 {@link #PROGRESS_INTERVAL_MS}（5 秒的进度心跳）分开：进度是"还活着"的信号，
     * 20 秒这条是"实际处理了多少流量"，用于判断是否已经跟不上到达速率。
     * </p>
     */
    private static final long RATE_REPORT_INTERVAL_MS = 20_000L;

    // logdb 数据库建表语句（初始化与轮转时复用）
    // 说明：不做历史库迁移——新结构直接用下面的语句创建。
    private static final String CREATE_LOG_SCHEMA_SQL = """
            Create Table IF Not Exists JSharkLog
            (
                ID                  BIGINT primary key,
                timeStamp           timestamp,
                length				int,
                wireLen				int,
                capLen				int,
                sourceMac			text,
                destinationMac		text,
                sourceIp			text,
                destinationIp		text,
                ipProtocol			text,
                sourcePort			int,
                destinationPort		int,
                appProtocol         text,
                tcpFlags			text,
                frameData			BLOB,
                rawData				BLOB,
                captureKind			SMALLINT,
                ingestSeq			BIGINT,
                volumeSeq			int,
                additionalInfo		text
            );
            Create Table IF Not Exists JSharkManifest
            (
                volumeSeq      BIGINT,
                startMs        BIGINT,
                endMs          BIGINT,
                startTime      text,
                endTime        text,
                packetCount    BIGINT,
                completeWindow boolean,
                closedReason   text,
                dropped        text,
                info           text
            );
            """;

    private boolean promiscuous;

    /**
     * 内核抓包缓冲大小，默认 64MB。
     * <p>
     * 采集端不做背压、DB 冲刷又是 5 秒一批，抓包线程遇到 GC 停顿或瞬时突发时，
     * 唯一能吸收突发的就是这层内核缓冲。默认（平台约 2MB）在高流量下远远不够。
     * </p>
     */
    private int pcapBufferBytes = 64 * 1024 * 1024;

    /**
     * immediate mode，默认关闭。开启后每包立即唤醒，延迟最低但 CPU 开销更高。
     */
    private boolean immediateMode = false;

    /**
     * 当前句柄是否为在线网卡句柄。内核统计（pcap_stats）只对在线句柄有意义。
     */
    private volatile boolean liveHandle = false;

    /** 本次采集处理的包数（供停机汇总使用） */
    private volatile int capturedTotal = 0;

    /** 最近一次读取到的内核统计 */
    private volatile long kernelReceived = 0;
    private volatile long kernelCaptured = 0;
    private volatile long kernelDropped = 0;
    private volatile long kernelDroppedByIf = 0;

    // 组播组地址列表（抓包前加入，使服务器能接收对应组播流量，例如 DIS 224.3.0.0:3001）
    private List<String> multicastGroups = new ArrayList<>();

    // 已加入的组播订阅（用于抓包结束后离开）
    private final List<MulticastSocket> multicastSockets = new ArrayList<>();

    // Components
    private final InterfaceManager interfaceManager;
    private final FilterEngine filterEngine;
    private final PacketLogger packetLogger;

    /**
     * 时间源（毫秒）。默认取系统时钟；测试可通过 {@link #setClockForTest} 注入假时钟，
     * 从而在不等待真实时间的前提下驱动分卷轮转（含"一次跨过多个窗口"的路径）。
     */
    private java.util.function.LongSupplier clock = System::currentTimeMillis;

    // Capture state
    private PcapHandle handle;
    private volatile boolean capturing = false;
    private volatile boolean stopped = false;

    /**
     * 一个解析分片独占的、<b>有状态</b>的组件集合。
     * <p>
     * 为什么必须按分片各持一份：{@link IpDefrag}（分片重组表）与
     * {@link TcpFlowReassembler}（按序列号的流缓冲）都是可变状态，多个线程共享会直接损坏数据。
     * 每个分片只由自己的那一个工作线程访问，因此内部无需加锁。
     * </p>
     * <p>
     * {@code firstFragmentMeta} 原本挂在 {@code PacketCapture} 上（抓包线程独占），
     * 并行后必须随分片私有，否则两个线程会互相覆盖首片元数据。
     * </p>
     */
    private static final class ParseContext {
        final PacketParser packetParser = new PacketParser();
        final ProtocolParser protocolParser;
        final TcpFlowReassembler tcpReassembler = new TcpFlowReassembler();
        final IpDefrag ipDefrag = new IpDefrag();
        /** 当前正在重组的 IP 分片数据报的首片元数据（时间戳/线上长度） */
        PacketParser.WireMeta firstFragmentMeta = null;

        ParseContext(boolean enableAdditionalInfo) {
            this.protocolParser = new ProtocolParser(enableAdditionalInfo);
        }
    }

    /**
     * 解析分片数组。长度 1 时即"单线程原地处理"（默认，行为与历史完全一致）；
     * 长度 &gt; 1 时每个分片由一个 {@link ParseWorker} 线程驱动。
     */
    private ParseContext[] parseShards;

    /** 解析工作线程；长度与 {@link #parseShards} 一致。单线程模式下为 null。 */
    private ParseWorker[] parseWorkers;

    /**
     * 解析线程数（1 = 单线程原地解析，默认）。
     * <p>
     * 为什么值得并行：实测单包解析成本（186B 真实 DIS）约 24.9 µs，其中约 6.7 µs 是
     * MAC 字符串格式化、约 8 µs 是 DIS 协议解析，全部压在唯一的抓包线程上；
     * 100Mbps~1Gbps 量级下这一个线程就是吞吐上限。
     * </p>
     */
    private int parseThreads = 1;

    /**
     * 是否展开 DIS/HTTP/PG 的详细字段并写入数据库 {@code additionalInfo} 列。
     * <p>
     * 默认 false（与 CLI {@code --enable_additioninfo} 一致）：不解析这些协议的详细字段，
     * 数据库 additionalInfo 列恒为 NULL，可显著降低高流量下的每包解析开销。
     * appProtocol/tcpFlags/frameData/rawData 等独立列以及重放逻辑都不受影响。
     * </p>
     */
    private volatile boolean enableAdditionalInfo = false;

    /**
     * additionalInfo 过滤表达式（{@code --exfilter}）。
     * <p>过滤依赖协议字段，因此设置该表达式时会自动开启
     * {@code --enable_additioninfo}（这些字段同时会落库）。</p>
     */
    private String exfilter;

    /** 每个解析分片的任务队列容量（包）。队列满时读线程阻塞（背压到内核缓冲），不静默丢弃。 */
    private static final int PARSE_QUEUE_CAPACITY = 1024;

    /**
     * 解析提交/屏障/停机毒丸的最长等待（毫秒）。
     * <p>背压是刻意的，但"等待"必须有上限：worker 卡死时无上限的 {@code put} 会让抓包线程
     * 在卷边界或停机处永久挂死，而 Ctrl+C 只置停止标志、解不开。</p>
     */
    private static final long PARSE_SUBMIT_TIMEOUT_MS = 30_000L;

    /** 抓包吞吐统计（每 20 秒打印"过去这一段"的平均流量） */
    private volatile ThroughputMeter captureMeter;

    /** 无状态包（UDP 非分片等）的轮询分片游标 */
    private final java.util.concurrent.atomic.AtomicInteger roundRobin =
            new java.util.concurrent.atomic.AtomicInteger();

    public PacketCapture() {
        this.interfaceManager = new InterfaceManager();
        this.filterEngine = new FilterEngine();
        this.packetLogger = new PacketLogger();
        this.parseShards = new ParseContext[] {new ParseContext(false)};
    }

    // ========== 采集 UI / 控制通道（stdio）快照 ==========

    /** 运行中已抓取包数（抓包循环内实时累加，供 UI 展示） */
    private final java.util.concurrent.atomic.AtomicLong capturedLive =
            new java.util.concurrent.atomic.AtomicLong();

    /** 当前卷内已抓取包数（仅 PCAP 模式没有逐包入库计数，用这个） */
    private final java.util.concurrent.atomic.AtomicLong volumeCaptured =
            new java.util.concurrent.atomic.AtomicLong();

    /** 已收尾的数据卷（UI 分卷表用；只增不改，读线程安全） */
    private final java.util.concurrent.CopyOnWriteArrayList<VolumeRow> closedVolumes =
            new java.util.concurrent.CopyOnWriteArrayList<>();

    /** 抓包循环起点（纳秒）；0 表示还没开始，用于 UI 的已运行时长 */
    private volatile long captureStartNanos = 0;

    /**
     * 采集 UI 的一个数据卷条目（只读快照）。
     *
     * @param seq     卷序号（单文件模式为 1）
     * @param file    数据文件完整路径（有 logdb 时是 db 文件，否则是 pcap 文件）
     * @param startMs 窗口起点（epoch ms；单文件模式为 0）
     * @param endMs   窗口终点（epoch ms；正在写的卷为 0）
     * @param packets 本卷包数（logdb 用已入库数；仅 PCAP 用已抓取数）
     * @param bytes   文件大小（字节）
     * @param status  {@code capturing} / {@code complete} / {@code partial}
     */
    public record VolumeRow(long seq, String file, long startMs, long endMs,
                            long packets, long bytes, String status) {
    }

    /**
     * 采集状态快照：GUI 与 {@code --control stdio} 子进程共用。
     *
     * @param state          IDLE / RUNNING / STOPPING / FINISHED
     * @param elapsedMs      已运行时长（毫秒）
     * @param captured       已抓取包数
     * @param stored         已入库包数（logdb）
     * @param filtered       被表达式过滤的包数
     * @param dropped        各类丢弃合计（不含 filtered）
     * @param bytes          已抓取帧的字节数
     * @param currentVolume  当前正在写的文件路径（可能为 null）
     * @param volumes        分卷列表（已收尾 + 当前卷）
     */
    public record Snapshot(String state, long elapsedMs, long captured, long stored, long filtered,
                           long dropped, long bytes, String currentVolume,
                           java.util.List<VolumeRow> volumes) {
    }

    /**
     * 采集状态快照（任意线程可调用）。
     *
     * <p>只读 volatile / 原子字段与已完成卷的不可变列表，不加锁、不阻塞抓包线程。
     * 当前卷的包数：logdb 用本卷已入库数，仅 PCAP 用本卷已抓取数。</p>
     *
     * @return 快照
     */
    public Snapshot snapshot() {
        String state;
        if (finished) {
            state = "FINISHED";
        } else if (stopRequested) {
            state = "STOPPING";
        } else if (capturing) {
            state = "RUNNING";
        } else {
            state = "IDLE";
        }
        long elapsedMs = captureStartNanos > 0
                ? (System.nanoTime() - captureStartNanos) / 1_000_000L : 0;
        long stored = packetLogger.committedPacketsTotal();
        long filtered = packetLogger.filteredOut();
        long dropped = packetLogger.droppedQueueFull() + packetLogger.abandonedAtShutdown()
                + packetLogger.droppedAfterVolumeClose() + packetLogger.droppedAfterClose()
                + packetLogger.failedToEnqueue() + packetLogger.failedToCommit()
                + droppedInFlight.get() + droppedNoPort.get() + droppedParseStall.get()
                + failedParseTasks.get() + droppedAfterSignal;
        long bytes = captureMeter != null ? captureMeter.totalBytes() : 0;

        String current = this.logDb != null ? currentLogDbPath : packetLogger.currentPcapPath();
        java.util.List<VolumeRow> rows = new java.util.ArrayList<>(closedVolumes);
        // 正在写的卷只在运行/收尾阶段展示；FINISHED 之后 closedVolumes 已经包含它，避免重复。
        if (current != null && !finished) {
            long packets = this.logDb != null
                    ? packetLogger.committedPackets() : volumeCaptured.get();
            long start = windows != null ? windows.currentStartMs() : 0;
            long seq = windows != null ? windows.currentSeq() : Math.max(1, logDbVolumeSeq);
            rows.add(new VolumeRow(seq, current, start, 0, packets, fileSize(current), "capturing"));
        }
        rows.sort(java.util.Comparator.comparingLong(VolumeRow::seq));
        return new Snapshot(state, elapsedMs, capturedLive.get(), stored, filtered, dropped,
                bytes, current, rows);
    }

    /** 记录一个已收尾的数据卷（重复调用同一卷时覆盖）。 */
    private void recordClosedVolume(long seq, String file, long startMs, long endMs,
                                    long packets, String status) {
        if (file == null || file.isEmpty()) {
            return;
        }
        VolumeRow row = new VolumeRow(seq, file, startMs, endMs, packets, fileSize(file), status);
        for (int i = 0; i < closedVolumes.size(); i++) {
            VolumeRow old = closedVolumes.get(i);
            if (old.seq() == seq && old.file().equals(file)) {
                closedVolumes.set(i, row);
                return;
            }
        }
        closedVolumes.add(row);
    }

    /** 文件大小（字节）；不存在或读取失败返回 0，绝不抛异常。 */
    private static long fileSize(String path) {
        try {
            java.io.File f = new java.io.File(path);
            return f.isFile() ? f.length() : 0;
        } catch (RuntimeException e) {
            return 0;
        }
    }

    /**
     * 解析工作线程：单线程消费自己的有界队列。
     * <p>
     * 为什么不用 ThreadPoolExecutor 的 CallerRunsPolicy：那会把任务退回读线程执行，
     * 而任务持有的是<b>某个分片的可变状态</b>，一旦被另一个线程执行，就会与该分片的工作线程
     * 并发修改同一份 HashMap/TreeMap，直接损坏重组结果。这里改成"限时阻塞提交"，
     * 保证分片状态永远只被它自己的线程访问；队列满时读线程等待（背压到内核缓冲，
     * 由此产生的丢包由 pcap_stats 如实统计），等待超时则丢弃该包并计数——
     * 既不会静默堆积到 OOM，也不会永久挂死。
     * </p>
     */
    private static final class ParseWorker {
        private static final Runnable POISON = () -> { };
        private final ArrayBlockingQueue<Runnable> tasks;
        private final Thread thread;
        private final String name;
        /** 任务抛异常（已隔离）而丢失的包数；由外层的运行报告读取 */
        private final java.util.concurrent.atomic.AtomicLong failedTasks;
        /** 队列长时间打满导致提交/屏障/毒丸失败的次数；由外层的运行报告读取 */
        private final java.util.concurrent.atomic.AtomicLong stalledSubmissions;

        ParseWorker(String name, int capacity,
                    java.util.concurrent.atomic.AtomicLong failedTasks,
                    java.util.concurrent.atomic.AtomicLong stalledSubmissions) {
            this.name = name;
            this.tasks = new ArrayBlockingQueue<>(capacity);
            this.failedTasks = failedTasks;
            this.stalledSubmissions = stalledSubmissions;
            this.thread = new Thread(this::loop, name);
            this.thread.setDaemon(true);
            this.thread.start();
        }

        private void loop() {
            try {
                while (true) {
                    Runnable task = tasks.take();
                    if (task == POISON) {
                        return;
                    }
                    try {
                        task.run();
                    } catch (Throwable t) {
                        // 隔离异常（不能让 worker 死掉、也不能传播到读线程），但必须计数：
                        // 否则"进程不崩、DB 少行"就只能靠 captured/queued 的差额去猜。
                        long n = failedTasks.incrementAndGet();
                        if (n <= 3 || n % 1000 == 0) {
                            logger.error("[JShark] parse worker {} task failed (total failures: {}); "
                                    + "this packet is missing from the output", name, n, t);
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        /**
         * 限时阻塞提交；队列满时等待（背压），但等待有上限。
         *
         * @return true = 已提交；false = 队列在超时内一直满，该包已被丢弃并计数
         */
        boolean submit(Runnable task) throws InterruptedException {
            if (tasks.offer(task, PARSE_SUBMIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                return true;
            }
            long n = stalledSubmissions.incrementAndGet();
            logger.error("[JShark] parse worker {} has been blocked for {}ms with a full queue; dropping this "
                            + "packet (total dropped this way: {}). Investigate the stuck task/worker",
                    name, PARSE_SUBMIT_TIMEOUT_MS, n);
            return false;
        }

        /**
         * 屏障：等待此前提交的任务全部执行完（分卷轮转/停机前使用）。
         *
         * @return true = 已排空；false = 队列满到连屏障都塞不进去，或等待超时
         */
        boolean awaitIdle(long timeoutMs) throws InterruptedException {
            CountDownLatch latch = new CountDownLatch(1);
            if (!tasks.offer(latch::countDown, timeoutMs, TimeUnit.MILLISECONDS)) {
                stalledSubmissions.incrementAndGet();
                logger.error("[JShark] parse worker {} queue is full; the drain barrier could not even be enqueued "
                        + "within {}ms — this shard is stuck, packets still in it will be LOST", name, timeoutMs);
                return false;
            }
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                logger.error("[JShark] parse worker {} did not drain within {}ms; packets still in flight will be "
                        + "LOST and counted as droppedAfterVolumeClose/droppedAtShutdownBudget", name, timeoutMs);
                return false;
            }
            return true;
        }

        void shutdown(long timeoutMs) {
            try {
                // 刻意不用无超时的 put：worker 若卡死且队列已满，停机就会永久挂死。
                if (!tasks.offer(POISON, timeoutMs, TimeUnit.MILLISECONDS)) {
                    stalledSubmissions.incrementAndGet();
                    logger.error("[JShark] parse worker {} queue is full; the poison pill could not be enqueued "
                            + "within {}ms. Leaving it as a daemon thread — it cannot block JVM exit, but this "
                            + "shard's remaining packets are lost", name, timeoutMs);
                    return;
                }
                thread.join(timeoutMs);
                if (thread.isAlive()) {
                    logger.error("[JShark] parse worker {} did not terminate within {}ms (daemon thread; "
                            + "JVM exit is not blocked)", name, timeoutMs);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 设置解析线程数（默认 1）。
     * <p>
     * 上界：{@code max(4, 核数*4)}。每个 worker 都是一条线程 + 一个 1024 深的队列，
     * 没有任何上界时 {@code --parse-threads 100000} 会直接造出 10 万条线程和 10 万个队列
     * （仅队列数组就约 0.8GB），表现为原生线程耗尽/OOM，而不是一条清晰的参数错误。
     * 超过上界时按上界生效并告警，不静默放大。
     * </p>
     *
     * @param parseThreads {@code <=1} 表示单线程原地解析（与历史行为一致）
     */
    public void setParseThreads(int parseThreads) {
        int requested = Math.max(1, parseThreads);
        int cap = maxParseThreads();
        if (requested > cap) {
            logger.warn("[JShark] --parse-threads {} exceeds the supported maximum {} (4 x CPU cores, at least 4); "
                            + "using {} instead", requested, cap, cap);
            requested = cap;
        }
        this.parseThreads = requested;
    }

    /** 解析线程数上界：4 倍核数，至少 4 */
    public static int maxParseThreads() {
        return Math.max(4, Runtime.getRuntime().availableProcessors() * 4);
    }

    /** @return 生效的解析线程数（1 = 单线程原地解析） */
    public int parseThreads() {
        return parseThreads;
    }

    /**
     * 按 {@link #parseThreads} 建立解析分片与工作线程（必须在抓包循环前调用）。
     * <p>
     * 构造过程中若失败（例如线程创建被拒），会先回收已经建好的 worker 再抛出：
     * 早期实现里 {@code parseWorkers} 是在全部建完后才赋值的，中途失败会让已建线程泄漏，
     * 并且循环因为看到 {@code parseWorkers == null} 而<b>无日志地退化成单线程</b>。
     * </p>
     */
    private void initParseShards() {
        int n = Math.max(1, parseThreads);
        ParseContext[] shards = new ParseContext[n];
        for (int i = 0; i < n; i++) {
            shards[i] = new ParseContext(enableAdditionalInfo);
        }
        this.parseShards = shards;
        if (n == 1) {
            this.parseWorkers = null;
            return;
        }
        ParseWorker[] workers = new ParseWorker[n];
        try {
            for (int i = 0; i < n; i++) {
                workers[i] = new ParseWorker("jshark-parse-" + i, PARSE_QUEUE_CAPACITY,
                        failedParseTasks, droppedParseStall);
            }
        } catch (Throwable t) {
            for (ParseWorker w : workers) {
                if (w != null) {
                    w.shutdown(1000L);
                }
            }
            // 明确失败，而不是静默退化为单线程
            throw new IllegalStateException("Failed to start " + n + " parse workers", t);
        }
        this.parseWorkers = workers;
        logger.info("[JShark] Parallel parsing enabled: {} workers x {} packets queue. "
                        + "Stateful work (TCP reassembly, IP defrag) is pinned per flow; "
                        + "stateless packets (UDP etc.) are spread round-robin.", n, PARSE_QUEUE_CAPACITY);
    }

    /** 停机：等所有分片把已提交的包处理完 */
    private void shutdownParseShards() {
        ParseWorker[] workers = this.parseWorkers;
        if (workers == null) {
            return;
        }
        for (ParseWorker w : workers) {
            w.shutdown(PARSE_SUBMIT_TIMEOUT_MS);
        }
        logger.info("[JShark] All parse workers stopped");
    }

    /**
     * 屏障：等待所有分片把已提交的任务处理完。
     *
     * @return true = 所有分片都已排空；false = 至少一个分片超时/卡住（掉队包会被计入
     *         {@code droppedAfterVolumeClose}）
     */
    private boolean awaitParseShardsIdle() {
        ParseWorker[] workers = this.parseWorkers;
        if (workers == null) {
            return true;
        }
        boolean allIdle = true;
        for (ParseWorker w : workers) {
            try {
                if (!w.awaitIdle(PARSE_SUBMIT_TIMEOUT_MS)) {
                    allIdle = false;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        if (!allIdle) {
            parseBarrierTimeoutEvents.incrementAndGet();
        }
        return allIdle;
    }

    /**
     * 选择处理该包的分片。
     * <p>
     * 关键区分：<b>有状态</b>的包（TCP 段、IP 分片）必须按流固定到同一分片，否则
     * TCP 流重组表 / 分片重组表会被拆到不同分片而算出错误结果；<b>无状态</b>的包
     * （UDP 非分片等，正是 DIS 组播的典型形态）用轮询，否则同一条组播流因五元组完全相同
     * 会全部落到同一个分片，并行度退化为 1。
     * </p>
     */
    private int chooseShard(Packet packet) {
        int n = this.parseShards.length;
        if (n == 1) {
            return 0;
        }
        if (requiresFlowAffinity(packet)) {
            return Math.floorMod(flowAffinityHash(packet), n);
        }
        return Math.floorMod(roundRobin.getAndIncrement(), n);
    }

    /** TCP 段与 IP 分片是有状态的，必须按流固定分片 */
    private boolean requiresFlowAffinity(Packet packet) {
        try {
            if (packet.contains(TcpPacket.class)) {
                return true;
            }
            IpV4Packet v4 = packet.get(IpV4Packet.class);
            if (v4 != null) {
                IpV4Packet.IpV4Header h = v4.getHeader();
                return h.getFragmentOffset() != 0 || h.getMoreFragmentFlag();
            }
            // IPv6 可能带扩展头/分片头，判断成本高，一律按流固定（保守且正确）
            return packet.contains(IpV6Packet.class);
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * 流亲和哈希：IPv4 用 (源IP, 目的IP, 协议号)；IPv6 只用 (源IP, 目的IP)。
     * <p>
     * IPv4 刻意<b>不含端口</b>：非首片没有端口信息，若按端口哈希，同一数据报的首片与后续分片
     * 会落到不同分片，分片重组必然失败。同一数据报的所有分片共享 (源,目的,协议)，
     * 同一条 TCP 连接的两个方向也各自共享，因此该键足以保证亲和性。
     * </p>
     * <p>
     * IPv6 不能用固定头里的 {@code nextHeader}：它表示"紧邻的下一个头"，
     * 带扩展头（Hop-by-Hop 0 / Routing 43 / Fragment 44 / Destination 60）的包会得到与该流
     * 其它包不同的值 —— 同一条流被拆到两个分片后，两边各持一份 TCP 重组表，
     * 结果是静默的字节流/窗口错误。IPv6 分片重组本来也不做（IpDefrag 只处理 IPv4），
     * 所以这里按 (源,目的) 固定即可：正确性优先于并行度。
     * </p>
     */
    private int flowAffinityHash(Packet packet) {
        int h = 1;
        try {
            IpV4Packet v4 = packet.get(IpV4Packet.class);
            if (v4 != null) {
                IpV4Packet.IpV4Header hdr = v4.getHeader();
                h = 31 * h + hdr.getSrcAddr().hashCode();
                h = 31 * h + hdr.getDstAddr().hashCode();
                h = 31 * h + hdr.getProtocol().value();
                return h;
            }
            IpV6Packet v6 = packet.get(IpV6Packet.class);
            if (v6 != null) {
                IpV6Packet.IpV6Header hdr = v6.getHeader();
                h = 31 * h + hdr.getSrcAddr().hashCode();
                h = 31 * h + hdr.getDstAddr().hashCode();
                // 刻意不含 nextHeader，见方法注释
                return h;
            }
        } catch (Exception ignored) {
            // 落到下面的兜底
        }
        return 0;
    }

    /** 预留一个单调递增的入库序号（并行模式下由读线程统一分配，保证顺序确定） */
    private long nextLogDBSequence() {
        return this.logDBSequence.incrementAndGet();
    }
    
    /**
     * Start packet capture
     * @throws PcapNativeException if capture fails
     */
    public void startCapture() throws PcapNativeException {
        // Get network interface
        PcapNetworkInterface networkInterface = interfaceManager.getInterface(interfaceIP);
        logger.info("[JShark] Selected interface: {} {}", networkInterface.getName(), networkInterface.getDescription());

        // Configure capture
        int snapshotLength = 65536; // bytes
        int readTimeout = 50; // milliseconds
        PcapNetworkInterface.PromiscuousMode mode = promiscuous ? 
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS : 
            PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;

        int capturedCount;
        try {
            // 加入组播组：让本机网卡接收指定组播流量（例如 DIS 组播 224.3.0.0）
            // 必须在使用 pcap 打开句柄之前完成，确保网卡/交换机已把该组播转发到本机端口。
            try {
                joinMulticastGroups();
            } catch (Exception e) {
                logger.error("[JShark] Failed to join multicast groups: {}", e.getMessage(), e);
            }

            // Open handle
            //
            // 用 PcapHandle.Builder（pcap_create + pcap_set_* + pcap_activate）而不是
            // openLive（pcap_open_live）：只有走 Builder 才能设置内核抓包缓冲大小。
            // 之前没有任何地方设置缓冲 → 走平台默认（Windows/Npcap 约 2MB），
            // 在 100Mbps~1Gbps 量级下仅相当于 20~160ms 的缓冲，一次 GC 停顿就会溢出丢包，
            // 而且丢包发生在内核、jshark 侧完全看不到（见 captureKernelStats）。
            liveHandle = true;
            PcapHandle.Builder handleBuilder = new PcapHandle.Builder(networkInterface.getName())
                    .snaplen(snapshotLength)
                    .promiscuousMode(mode)
                    .timeoutMillis(readTimeout);
            // 与 setPcapBufferBytes 的契约保持一致：<=0 表示"不设置，用平台默认"。
            // 早期这里无条件调用 bufferSize(...)，注释与实现不符（0/负数在部分实现里会直接抛错）。
            if (pcapBufferBytes > 0) {
                handleBuilder.bufferSize(pcapBufferBytes);
            }
            handle = handleBuilder.immediateMode(immediateMode).build();
            logger.info("[JShark] Capture handle opened: snaplen={}, readTimeout={}ms, bufferSize={}MB, immediateMode={}",
                    snapshotLength, readTimeout, pcapBufferBytes / (1024 * 1024), immediateMode);

            // Set filter if specified（BPF 过滤器仅在线模式可用）
            if (filterExpression != null && !filterExpression.isEmpty()) {
                try {
                    filterEngine.compileFilter(handle, filterExpression);
                } catch (Exception e) {
                    throw new PacketCaptureException("Failed to compile filter: {" + filterExpression + "}", e);
                }
            }

            capturedCount = runCaptureLoop(handle);
            capturedTotal = capturedCount;
        } finally {
            // Cleanup
            stopCapture();
        }
        
        logger.info("Capture completed. Captured {} packets.", capturedCount);
    }

    /**
     * 从离线 pcap 文件执行采集（用于回放归档、回归测试与帧级重放的字节比对）。
     * <p>
     * 与 {@link #startCapture()} 走**完全相同的处理路径**（IP 重组、TCP 流重组、协议解析、
     * 完整帧入库、PCAP 输出、时间分卷），区别仅在于数据源为离线文件而非网卡。
     * 离线句柄不支持 BPF 过滤，因此 {@code filterExpression} 在离线模式下不生效。
     * </p>
     * <p>
     * 注意：离线读取速度远快于实时，若配置了 {@code --split}，分卷按**当前墙钟**轮转，
     * 可能一次跨过多个时间边界并补齐空卷；做分卷相关测试时应使用可控时钟或更小的样本。
     * </p>
     *
     * @param pcapFile 离线 pcap 文件路径
     * @throws PacketCaptureException 文件不存在或无法打开
     */
    public void startCaptureFromFile(String pcapFile) {
        java.io.File file = new java.io.File(pcapFile);
        if (!file.isFile()) {
            throw new PacketCaptureException("PCAP file does not exist: " + pcapFile);
        }

        int capturedCount = 0;
        try {
            liveHandle = false; // 离线句柄没有内核统计
            handle = Pcaps.openOffline(file.getAbsolutePath());
            logger.info("[JShark] Offline capture from PCAP file: {}", file.getAbsolutePath());
            capturedCount = runCaptureLoop(handle);
            capturedTotal = capturedCount;
        } catch (PcapNativeException e) {
            throw new PacketCaptureException("Failed to open PCAP file: " + pcapFile, e);
        } finally {
            stopCapture();
        }

        logger.info("Offline capture completed. Captured {} packets.", capturedCount);
    }

    /**
     * 读取内核抓包统计（pcap_stats）并缓存到字段。
     * <p>
     * <b>为什么必须读：</b>内核缓冲溢出导致的丢包在 jshark 侧是<b>完全不可见</b>的 ——
     * 抓包线程只看到"漏进来"的包，看不到被丢掉的包。不读 pcap_stats 就无法区分
     * "线上本来没有这些包"和"包在内核就被丢了"，于是采集不完整这件事会被静默掩盖。
     * </p>
     * <p>
     * 只应在抓包线程调用（避免与 pcap_next_ex 并发访问句柄），并且必须在句柄 close 之前调用。
     * 离线句柄没有该统计，会直接跳过。
     * </p>
     *
     * @return 是否成功读到统计
     */
    private boolean captureKernelStats() {
        if (!liveHandle || handle == null || !handle.isOpen()) {
            return false;
        }
        try {
            org.pcap4j.core.PcapStat st = handle.getStats();
            kernelReceived = st.getNumPacketsReceived();
            kernelCaptured = st.getNumPacketsCaptured();
            kernelDropped = st.getNumPacketsDropped();
            kernelDroppedByIf = st.getNumPacketsDroppedByIf();
            return true;
        } catch (Exception e) {
            logger.debug("[JShark] pcap_stats unavailable: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 进度日志用的内核丢包后缀；离线或读不到时返回空串。
     */
    private String kernelStatsSuffix() {
        if (!captureKernelStats()) {
            return "";
        }
        return String.format(", kernelDropped=%d (byIf=%d)", kernelDropped, kernelDroppedByIf);
    }

    /**
     * 采集主循环（在线/离线共用）。
     * <p>
     * 负责：配置输出目标、按 count/timeout 限制循环、逐包处理并驱动时间分卷轮转。
     * 句柄的打开与关闭由调用方负责。
     * </p>
     *
     * @param pcapHandle 已打开且（在线模式下）已设置过滤器的抓包句柄
     * @return 实际处理的包数
     */
    /**
     * 初始化输出目标（PCAP 与 logdb），在线/离线共用。
     * <p>
     * 启用 {@code --split} 时统一走"时间窗命名"：先建立 {@link VolumeWindows}，
     * 用窗口起点的文件名打开 PCAP；logdb 的连接已由 {@link #setLogDb(String)} 按同一窗口打开。
     * 未启用分卷时保持单文件语义。
     * </p>
     */
    private void prepareOutputs() {
        if (outputFile != null) {
            if (windows != null && windows.isInitialized()) {
                // 时间窗模式：按本窗口命名打开；若此前已被打开（例如 setLogDb 之前）则先关掉
                if (packetLogger.currentPcapPath() == null) {
                    packetLogger.openPcap(windows.pcapFor(windows.currentStartMs()));
                }
            } else {
                packetLogger.setOutputFile(outputFile);
            }
        }
        if (logDb != null) {
            if (logDbConn == null) {
                logger.warn("[JShark] Database connection is null, cannot save to database. "
                        + "Make sure setLogDb() is called before startCapture().");
            } else {
                packetLogger.setLogDb(logDbConn);
            }
        }
    }

    private int runCaptureLoop(PcapHandle pcapHandle) {
        // 配置输出目标。顺序很重要：
        //   1) 先按需建立时间窗（--split 时），确定本窗口应有的文件名；
        //   2) 再按窗口文件名打开输出 —— 否则 PCAP 会先按"基准名"打开，
        //      之后即使切到窗口文件名，也已经在磁盘上留下一个多余的无时间戳文件。
        prepareOutputs();

        // 建立解析分片。parseThreads == 1 时不创建任何线程，处理方式与历史完全一致。
        initParseShards();

        // 吞吐量统计（每 20 秒打印"过去这一段"的平均流量）
        captureMeter = new ThroughputMeter("Capture", RATE_REPORT_INTERVAL_MS);

        // UI / 控制通道的实时计数基线
        captureStartNanos = System.nanoTime();
        volumeCaptured.set(0);

        // Start capture loop
        capturing = true;
        // 记录执行抓包循环的线程：收尾（finishCapture）必须由它调用，见该方法内的校验
        captureLoopThread = Thread.currentThread();
        int capturedCount = 0;

        // Determine capture limit
        int maxPackets = (packetCount != null) ? packetCount : -1; // -1 means unlimited
        int timeoutMs = (timeoutSeconds != null) ? timeoutSeconds * 1000 : -1;
        long startTime = System.currentTimeMillis();
        long lastProgressLogMs = startTime;

        // Capture loop
        try {
            while (capturing) {
            // Check timeout
            if (timeoutMs > 0 && (System.currentTimeMillis() - startTime) >= timeoutMs) {
                logger.info("Capture timeout reached");
                break;
            }

            // Check packet count limit
            if (maxPackets > 0 && capturedCount >= maxPackets) {
                logger.info("Packet count limit reached: {}", maxPackets);
                break;
            }

            // 定时输出抓包进度：即使未配置 logdb、不记录任何包，
            // 也让控制台周期性反馈，避免长时间无输出、看似“卡住”。
            long now = System.currentTimeMillis();
            if (now - lastProgressLogMs >= PROGRESS_INTERVAL_MS) {
                long elapsedSec = (now - startTime) / 1000;
                logger.info("[JShark] Capturing... packets={}, elapsed={}s{}", capturedCount, elapsedSec,
                        kernelStatsSuffix());
                lastProgressLogMs = now;
            }

            // 每 20 秒一条"过去这一段的平均流量"（MB/s + pps），并附内核丢包数，
            // 用于判断采集是否已经跟不上到达速率（丢包时这条会立刻反映出来）。
            //
            // 必须先问 shouldTick()：kernelStatsSuffix() 会调用 pcap_stats（JNA 原生调用 + 对象分配），
            // 而 Java 的实参在调用前求值 —— 写成 tick(kernelStatsSuffix()) 就等于"每个包一次系统调用"，
            // 恰好压在整条链路唯一的读线程上（这也正是本类要优化的瓶颈）。
            if (captureMeter.shouldTick()) {
                captureMeter.tick(kernelStatsSuffix());
            }

            try {
                // 时间窗轮转：必须在处理当前包**之前**检查，
                // 这样跨过边界后的第一个包会落入新卷，而不是留在一个"时间上已经结束"的卷里。
                // 轮转同时作用于 PCAP 与 logdb（两者共用同一个 VolumeWindows），并写出 manifest。
                checkAndRotateLogDb();

                // Get next packet
                Packet packet = pcapHandle.getNextPacketEx();

                // pcap 首部元数据：时间戳取自抓包首部（而非解析时刻），
                // 线上长度用于识别 snaplen 截断（capLen < wireLen）
                PacketParser.WireMeta wireMeta = null;
                if (packet != null) {
                    wireMeta = readWireMeta(pcapHandle, packet);
                }

                if (packet != null) {
                    capturedCount++;
                    capturedLive.incrementAndGet();
                    volumeCaptured.incrementAndGet();

                    // 吞吐统计：按"抓到的帧长"累计，与 pcap 文件实际写入体积同口径
                    captureMeter.addPacket(packet.length());

                    // PCAP 落盘固定在抓包线程：PcapDumper 底层是单个原生 FILE*，非线程安全。
                    // （解析并行化后 processPacket 会跑在多个 worker 上，所以这一步必须留在读线程。）
                    if (outputFile != null) {
                        packetLogger.saveToPcap(packet);
                    }

                    ParseWorker[] workers = this.parseWorkers;
                    if (workers == null) {
                        // 单线程：原地处理，语义与历史完全一致（序号在 processPacket 内现场分配）
                        processPacket(packet, wireMeta, parseShards[0], -1L);
                    } else {
                        // 并行：入库序号由读线程统一分配，保证 ingestSeq 与抓包顺序一致。
                        // 注意（与单线程的唯一差异）：被缓存等待后续分片的包同样会消耗一个序号，
                        // 因此并行模式下 ingestSeq 可能出现"空洞"（序号仍严格单调且唯一，
                        // 下游只依赖单调性：DbReplayTool 按 id 排序、重启时取 max(id) 续号）。
                        // 单线程模式（默认）不预分配序号，行为与历史完全一致，无空洞。
                        // 包按"有状态/无状态"路由到分片（见 chooseShard）。
                        final Packet pkt = packet;
                        final PacketParser.WireMeta meta = wireMeta;
                        final long seq = nextLogDBSequence();
                        final int shard = chooseShard(packet);
                        final ParseContext ctx = parseShards[shard];
                        // 阻塞提交：队列满时等待，形成到内核缓冲的背压，而不是无界堆积
                        workers[shard].submit(() -> processPacket(pkt, meta, ctx, seq));
                    }
                }

            } catch (TimeoutException e) {
                // 无包到达（读取超时）。上面的 checkAndRotateLogDb() 已在每轮开头执行，
                // 因此即使长时间无流量，时间边界到达时依然会切出（空的）分卷文件。
            } catch (java.io.EOFException e) {
                // 离线文件读完
                logger.info("Reached end of offline PCAP file");
                break;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error capturing packet", e);
                break;
            }
            }
        } finally {
            // 停机：等所有分片把已提交的包处理完，保证"抓到的包都走完后端流程"再收尾
            shutdownParseShards();
            // 打印最后一段（不满 20 秒的尾段），否则短时任务看不到任何速率
            if (captureMeter != null) {
                captureMeter.flush(kernelStatsSuffix());
            }
        }

        return capturedCount;
    }
    
    /**
     * 请求停止采集（可由任意线程调用，例如 CTRL+C 的 shutdown hook）。
     *
     * <h3>为什么与"收尾"分开</h3>
     * <p>
     * 抓包循环通常阻塞在原生 {@code pcap_next_ex} 并持有 pcap4j {@code PcapHandle} 的读锁，
     * 而 {@code close()} 需要写锁 —— 从另一个线程直接 close 会死锁。
     * 因此停止信号线程<b>只做</b>三件事：置标志、{@code breakLoop()}、等待抓包线程收尾。
     * 所有文件与数据库的关闭动作都留在抓包线程的 {@link #finishCapture()} 里执行。
     * </p>
     *
     * @return true 表示本次调用是"首个"停止请求
     */
    public boolean requestStop() {
        if (stopRequested) {
            return false;
        }
        stopRequested = true;
        capturing = false;
        // 记下"停机时刻"：既用于计算最后一卷的 end（= 按下 CTRL+C 的时间），
        // 也是整段收尾预算的起点。时钟刻意用可注入的 clock：它与窗口 startMs 同源，
        // 测试里注入假时钟时，文件名才会与窗口时间戳落在同一条时间轴上。
        stopAtMs = clock.getAsLong();
        shutdownStartNanos = System.nanoTime();
        logger.info("[JShark] Stop requested at {}; shutdown budget {}ms (tail reserve {}ms for CHECKPOINT+rename)",
                SplitUtil.formatTimestamp(stopAtMs), SHUTDOWN_BUDGET_MS, SHUTDOWN_TAIL_RESERVE_MS);
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (Exception e) {
                logger.debug("[JShark] breakLoop failed: {}", e.getMessage());
            }
        }
        return true;
    }

    /**
     * Stop packet capture（保留旧入口，语义等价于"请求停止 + 同步收尾"）。
     * <p>
     * 供非 shutdown-hook 场景（例如离线采集结束后的 finally 块）使用。
     * </p>
     */
    public void stopCapture() {
        requestStop();
        finishCapture();
    }

    /**
     * 最近一次停机对账的残差：{@code queued - accounted}。
     * <p>
     * {@code 0} 表示"进入日志器的每一个包都有明确去向"（入库、或落到某条已计数的丢弃渠道）。
     * 非 0 说明存在未被记账的丢失，或某条渠道被重复计数——两种情况都必须修，不能靠人读日志发现。
     * 未启用 logdb 时"不入库"是预期行为，这里恒为 {@code 0}。
     * </p>
     *
     * @return 残差；仅在一次 {@link #finishCapture()} 完成后有意义
     */
    public long accountingResidual() {
        return accountingResidual;
    }

    /**
     * 收尾：把已抓到的数据全部落库、关闭文件、写 manifest、离开组播组。
     * <p>
     * <b>只应由抓包线程调用</b>（抓包循环结束后的 finally 块）。
     * </p>
     */
    public void finishCapture() {
        // 机制而非约定：收尾会 drain/关闭输出并写 manifest，若与仍在运行的解析 worker 并发，
        // 结果就是"包进来了、没人收"的静默丢失。仓库内调用点都在抓包线程，这里把它固定下来。
        Thread loopThread = captureLoopThread;
        if (loopThread != null && Thread.currentThread() != loopThread) {
            throw new IllegalStateException("finishCapture() must be called by the capture loop thread ("
                    + loopThread.getName() + "), but was called from " + Thread.currentThread().getName()
                    + "; use requestStop() from other threads");
        }
        if (stopped) {
            return;
        }
        stopped = true;
        capturing = false;

        // 1) 停机快照：把"此刻已入队"的记录全部落库；快照之外的丢弃并如实计数
        try {
            droppedAfterSignal += packetLogger.drainSnapshot(flushDeadlineMs());
        } catch (Exception e) {
            logger.error("[JShark] Failed to drain the pending queue: {}", e.getMessage(), e);
        }

        // 2) 关闭当前时间窗（若启用分卷）并写 manifest。
        //    停机路径必须**同步**收尾：hook join 的就是本线程，只有在本线程上做完
        //    "drain → manifest → FORCE CHECKPOINT → close → rename"，hook 的等待才真正覆盖到它。
        //    （早期把这一卷交给守护线程池后立即返回，hook 一到 30s 就 halt，守护线程被就地杀死，
        //      磁盘上留下 "-capturing" + 未合并的 .wal —— 这正是本方案要修的现场故障。）
        if (windows != null && windows.isInitialized()) {
            finalizeVolume(windows.currentSeq(), windows.currentStartMs(), windows.currentEndMs(),
                    false, "shutdown", true);
        } else {
            // 单文件模式：没有时间窗，finalizeVolume 不会被调用；这里补记这一卷给 UI。
            String pcapPath = packetLogger.currentPcapPath();
            packetLogger.close(shutdownDeadlineMs());
            if (this.logDb != null) {
                recordClosedVolume(1, currentLogDbPath, 0, 0,
                        packetLogger.committedPacketsTotal(), "complete");
            } else {
                recordClosedVolume(1, pcapPath, 0, 0, capturedLive.get(), "complete");
            }
        }

        // 2a) 等所有卷收尾任务（含上面这一卷）写完再继续：分卷模式下 finalizeVolume 是异步的，
        //     必须等"每文件一个写库线程"把旧卷排空、写 manifest、CHECKPOINT、更名、关连接全部完成，
        //     下面的停机统计（committed 等跨卷总计）才准确、账目才闭合。
        //     等待有上限：整段收尾共用同一个预算，超时就带着"还剩几卷没关完"的日志退出，
        //     而不是无限期挂在 Ctrl+C 之后。
        awaitVolumeCloseTasks();

        // 2b) 停机统计：应用层丢弃 + 内核丢弃，都必须在退出时可见
        //     内核统计必须在句柄关闭（步骤 3）之前读取。
        //
        //     注意用带 Total 的访问器：分卷模式下每卷都是新的 handler，只读"最后一卷"的闩存值
        //     会把前面各卷的丢弃漏掉，也会让 committed 看起来偏小。
        boolean kernelStatsOk = captureKernelStats();
        long queued = packetLogger.totalLogged();
        long committed = packetLogger.committedPacketsTotal();
        long droppedQueueFull = packetLogger.droppedQueueFull();
        long abandoned = packetLogger.abandonedAtShutdown();
        long failedEnqueue = packetLogger.failedToEnqueue();
        long failedCommit = packetLogger.failedToCommit();
        long afterVolumeClose = packetLogger.droppedAfterVolumeClose();
        long afterClose = packetLogger.droppedAfterClose();
        long filteredOut = packetLogger.filteredOut();
        logger.info("[JShark] Capture summary: captured={}, queued={}, committed={}, filteredOut={}",
                capturedTotal, queued, committed, filteredOut);
        logger.info("[JShark] Drop summary (all run totals): droppedQueueFull={}, droppedAtShutdownBudget={}, "
                        + "droppedAfterVolumeClose={}, droppedAfterClose={}, enqueueFailed={}, commitFailed={}, "
                        + "droppedAfterSignal={}, droppedInFlight={}, droppedNoPort={}, droppedParseStall={}, "
                        + "failedParseTasks={}, parseBarrierTimeoutEvents={}",
                droppedQueueFull, abandoned, afterVolumeClose, afterClose, failedEnqueue, failedCommit,
                droppedAfterSignal, droppedInFlight.get(), droppedNoPort.get(),
                droppedParseStall.get(), failedParseTasks.get(), parseBarrierTimeoutEvents.get());

        // 账目恒等式：queued（进入日志器的包）应当等于 committed + 各条丢弃渠道 + 被过滤且未入库的数量。
        // droppedAfterSignal 也要算进来：它是"已入队但在停机快照之外被丢弃"的量（drainSnapshot 的返回值），
        // 这些包同样计入 queued，不加上就会得到假的残差。
        // 注意：droppedParseStall / failedParseTasks 刻意**不**计入这里 —— 它们在 logPacket 之前
        // 就丢了，从未进入 queued，加进来会造出负残差。（parseBarrierTimeoutEvents 是事件数，更不是包数。）
        // 只在启用过 logdb 时才校验：只写 pcap 时不入库是预期行为，不是丢包。
        long accounted = committed + droppedQueueFull + abandoned + afterVolumeClose + afterClose
                + failedEnqueue + failedCommit + filteredOut + droppedAfterSignal;
        long unexplained = queued - accounted;
        // 未启用 logdb 时"不入库"是预期行为，残差没有意义，对外报告为 0
        accountingResidual = packetLogger.isLogDbEnabled() ? unexplained : 0;
        if (packetLogger.isLogDbEnabled() && unexplained != 0) {
            logger.warn("[JShark] Packet accounting does not balance: queued={} but accounted={} "
                            + "(committed={}, queueFull={}, atShutdown={}, afterVolumeClose={}, afterClose={}, "
                            + "enqueueFailed={}, commitFailed={}, filteredOut={}, afterSignal={}); "
                            + "unexplained={}",
                    queued, accounted, committed, droppedQueueFull, abandoned, afterVolumeClose, afterClose,
                    failedEnqueue, failedCommit, filteredOut, droppedAfterSignal, unexplained);
        } else if (!packetLogger.isLogDbEnabled() && queued > 0) {
            logger.info("[JShark] --logdb not configured: {} packets were parsed but not stored in any database",
                    queued);
        }

        if (kernelStatsOk) {
            logger.info("[JShark] Kernel capture stats: received={}, captured={}, dropped={}, droppedByIf={}",
                    kernelReceived, kernelCaptured, kernelDropped, kernelDroppedByIf);
            if (kernelDropped > 0 || kernelDroppedByIf > 0) {
                logger.warn("[JShark] {} packets were dropped in the KERNEL (capture buffer overflow) and {} "
                                + "were dropped by the interface. These never reached jshark and cannot be recovered; "
                                + "raise --pcap-buffer and check the capture thread's CPU/GC pauses",
                        kernelDropped, kernelDroppedByIf);
            }
        }

        // 无端口包的数量与分卷无关，任何模式下都要可见（否则就是静默丢内容）
        if (droppedNoPort.get() > 0) {
            logger.warn("[JShark] {} TCP/UDP packets were not recorded (missing port info): payload not stored and cannot be replayed."
                            + "This usually means the capture was truncated by snaplen, or the datagram's fragment group is incomplete.",
                    droppedNoPort.get());
        }

        // 3) 关闭抓包句柄
        if (handle != null && handle.isOpen()) {
            try {
                handle.close();
            } catch (Exception e) {
                logger.debug("[JShark] Error closing handle: {}", e.getMessage());
            }
        }

        // 使用 closeLogDb() 统一关闭数据库连接
        closeLogDb();

        // 抓包结束，离开已加入的组播组
        leaveMulticastGroups();

        // 最后一步才置完成标志：中途抛异常时保持 false，让 shutdown hook 的兜底路径
        // （forceFinalizeLastVolume）还有机会把最后一卷 checkpoint + 更名。
        finished = true;
        long elapsedMs = shutdownStartNanos == 0 ? 0
                : (System.nanoTime() - shutdownStartNanos) / 1_000_000L;
        logger.info("[JShark] Shutdown finished in {}ms (budget {}ms)", elapsedMs, SHUTDOWN_BUDGET_MS);
    }

    /**
     * @return {@link #finishCapture()} 是否已完整跑完（含最后一卷的 CHECKPOINT + 更名）
     */
    public boolean isFinished() {
        return finished;
    }

    /**
     * 计算"排空队列"可用的截止时间（epoch 毫秒）。
     * <p>
     * 一旦收到停止信号，所有 drain 都只能用"总预算 - 尾部预留"这段时间：
     * 尾部动作（FORCE CHECKPOINT + close + rename）必须始终有钱可花，
     * 否则队列里剩下的包会把预算吃光，最后一卷又变回 {@code -capturing} + 未合并的 {@code .wal}。
     * </p>
     *
     * @return epoch 毫秒；{@link Long#MAX_VALUE} 表示不限（未开始收尾且未配置 flush 超时）
     */
    private long flushDeadlineMs() {
        long remaining = remainingShutdownMs();
        if (remaining == Long.MAX_VALUE) {
            return Long.MAX_VALUE;
        }
        long drainMs = remaining - SHUTDOWN_TAIL_RESERVE_MS;
        return System.currentTimeMillis() + Math.max(0L, drainMs);
    }

    /**
     * @return 停机预算的剩余时间（毫秒）；未开始收尾时返回 {@link Long#MAX_VALUE}
     */
    private long remainingShutdownMs() {
        if (shutdownStartNanos == 0) {
            return Long.MAX_VALUE;
        }
        long elapsedMs = (System.nanoTime() - shutdownStartNanos) / 1_000_000L;
        return SHUTDOWN_BUDGET_MS - elapsedMs;
    }

    /**
     * @return 整段收尾的绝对截止时间（epoch 毫秒）；未开始收尾时返回 {@link Long#MAX_VALUE}（不设上限）
     */
    private long shutdownDeadlineMs() {
        long remaining = remainingShutdownMs();
        if (remaining == Long.MAX_VALUE) {
            return Long.MAX_VALUE;
        }
        return System.currentTimeMillis() + Math.max(0L, remaining);
    }

    /**
     * 计算停机卷的 {@code end}：<b>就是按下 CTRL+C 的时刻</b>。
     * <p>
     * 两个夹取条件都是必要的：
     * </p>
     * <ul>
     *   <li>不能越过本窗口的网格边界 —— 否则文件名会声称覆盖到下一卷的时间段，
     *       回放端按 {@code --start/--end} 求交时会算错；</li>
     *   <li>必须严格大于 {@code startMs} 且向上取整到秒 —— 文件名只有秒级精度，
     *       同秒内起停时若直接截断会得到 {@code start-start}（与"空卷"无法区分）。</li>
     * </ul>
     *
     * @param startMs     本卷窗口起点
     * @param stopAtMs    停机时刻（{@link #requestStop()} 记录）
     * @param windowEndMs 本卷窗口网格边界
     * @return 用于文件名与 manifest 的结束时间（epoch 毫秒，整秒）
     */
    static long computeEndMs(long startMs, long stopAtMs, long windowEndMs) {
        long end = stopAtMs > 0 ? stopAtMs : System.currentTimeMillis();
        if (windowEndMs > startMs && end > windowEndMs) {
            end = windowEndMs;
        }
        end = Math.floorDiv(end + 999L, 1000L) * 1000L;   // 向上取整到秒，保证覆盖停机瞬间
        if (end <= startMs) {
            end = startMs + 1_000L;
        }
        return end;
    }

    /**
     * 设置需要加入的组播组地址列表（例如 "224.3.0.0"）。
     * 会在打开 pcap 抓包句柄之前加入这些组播组，使本机网卡能接收对应组播流量。
     *
     * @param multicastGroups 组播 IP 列表；null 或空表示不加入任何组播组
     */
    public void setMulticastGroups(List<String> multicastGroups) {
        this.multicastGroups = (multicastGroups != null) ? new ArrayList<>(multicastGroups) : new ArrayList<>();
        if (!this.multicastGroups.isEmpty()) {
            logger.info("[JShark] Multicast groups to join: {}", this.multicastGroups);
        }
    }

    /**
     * 在打开 pcap 句柄之前，对目标网卡执行真实的 IP_ADD_MEMBERSHIP 三层组播订阅。
     * <p>
     * 这是关键：单纯在网卡上添加组播 MAC（ip maddr）不会向交换机发出 IGMP report，
     * 交换机的 IGMP snooping 不会把该组播转发到本机端口。通过 MulticastSocket
     * join 会发送真实的 IGMP join，交换机才会把 224.3.0.0 等组播转发到本机，
     * 网卡也才会接收这些帧，之后 libpcap 抓包才可见。
     * </p>
     */
    private void joinMulticastGroups() {
        if (multicastGroups == null || multicastGroups.isEmpty()) {
            return;
        }
        // 绑定到目标网卡的本机 IP，确保订阅从正确接口发出
        String localIp = interfaceIP;
        for (String group : multicastGroups) {
            if (group == null || group.trim().isEmpty()) {
                continue;
            }
            try {
                InetAddress groupAddr = InetAddress.getByName(group.trim());
                if (!groupAddr.isMulticastAddress()) {
                    logger.warn("[JShark] Ignored non-multicast address in --multicast: {}", group);
                    continue;
                }
                MulticastSocket ms = new MulticastSocket(null);
                ms.setReuseAddress(true);
                // 绑定到目标网卡地址（端口任选），使 IGMP join 从这个接口发出
                ms.bind(new InetSocketAddress(localIp, 0));
                NetworkInterface nif = NetworkInterface.getByInetAddress(InetAddress.getByName(localIp));
                if (nif == null) {
                    logger.warn("[JShark] Cannot find network interface for local IP {}, multicast join skipped for {}",
                            localIp, group);
                    ms.close();
                    continue;
                }
                ms.joinGroup(new InetSocketAddress(groupAddr, 0), nif);
                // 订阅成功后句柄保持打开以维持组成员关系
                multicastSockets.add(ms);
                logger.info("[JShark] Joined multicast group {} on interface {} ({})", group, nif.getName(), localIp);
            } catch (Exception e) {
                logger.error("[JShark] Failed to join multicast group {}: {}", group, e.getMessage(), e);
            }
        }
    }

    /**
     * 抓包结束后离开已加入的组播组并关闭订阅 socket。
     */
    private void leaveMulticastGroups() {
        for (MulticastSocket ms : multicastSockets) {
            try {
                ms.close();
            } catch (Exception e) {
                logger.debug("[JShark] Error closing multicast socket: {}", e.getMessage());
            }
        }
        multicastSockets.clear();
    }
    
    /**
     * 读取 pcap 首部元数据（时间戳 + 原始线上长度）。
     * <p>
     * 时间戳必须在此刻读取：pcap4j 的 {@code getTimestamp()} 返回的是"最近一次读取到的那一帧"
     * 的时间，因此要在处理该帧之前立即取。
     * </p>
     *
     * @param handle 抓包句柄
     * @param packet 刚读到的数据包（用于回退取得长度）
     * @return 帧元数据；读取失败时回退为当前时刻与捕获长度
     */
    private PacketParser.WireMeta readWireMeta(PcapHandle handle, Packet packet) {
        Instant headerTs = null;
        int origLen = 0;
        try {
            // pcap4j 的 getTimestamp() 返回最近一次读取到的那一帧的时间戳
            java.sql.Timestamp ts = handle.getTimestamp();
            if (ts != null) {
                headerTs = ts.toInstant();
            }
        } catch (Exception e) {
            logger.debug("Failed to read pcap header timestamp: {}", e.getMessage());
        }
        try {
            // pcap 首部记录的原始长度（> length() 表示被 snaplen 截断）
            Integer orig = handle.getOriginalLength();
            if (orig != null && orig > 0) {
                origLen = orig;
            }
        } catch (Exception e) {
            logger.debug("Failed to read pcap original length: {}", e.getMessage());
        }
        return PacketParser.WireMeta.of(headerTs, origLen);
    }

    /**
     * 处理捕获的数据包
     * <p>
     * 核心处理方法，负责：
     * <ol>
     *   <li>解析原始数据包为 ParsedPacket</li>
     *   <li>对TCP有应用层数据的包进行流重组（分片合并）</li>
     *   <li>协议解析（检测应用层协议并解析详细信息）</li>
     *   <li>根据解析完整性决定是否记录日志和清空缓冲区</li>
     *   <li>保存到PCAP文件（如配置）</li>
     * </ol>
     * </p>
     *
     * <h3>TCP 流重组逻辑：</h3>
     * <p>
     * 对于 TCP 且有应用层数据的包：
     * <ol>
     *   <li>创建流标识 {@link TcpFlowReassembler.StreamKey}（四元组，保留原始方向）</li>
     *   <li>调用 {@link TcpFlowReassembler#offer} 提交该段；
     *       重组器按序列号缓存，**只在连续区间上交付**，有缺口时不越过缺口</li>
     *   <li>返回的 {@code data} 是**整个未消费窗口**（可能含上一段留下的半条消息）</li>
     *   <li>内容列用累计窗口；帧相关字段保持为**触发本行的真实帧**，因此每行都可按帧原样重放</li>
     *   <li>调用 {@link ProtocolParser#parseProtocolDetails} 进行协议解析</li>
     *   <li>用 {@link MessageFramer} 做统一消息切分，算出窗口里有多少字节构成完整消息</li>
     *   <li>记录本行，并只把"完整消息"的字节 {@link TcpFlowReassembler#consume} 掉；
     *       剩余半条消息留在窗口里与后续段拼接</li>
     * </ol>
     * </p>
     *
     * <h3>方向策略：</h3>
     * <p>
     * 每个TCP流有两个方向（客户端→服务器 和 服务器→客户端），
     * 每个方向独立维护窗口，避免双向数据混合。
     * 使用 (srcIp, dstIp, srcPort, dstPort) 保留原始方向。
     * </p>
     *
     * @param packet   原始数据包
     * @param wireMeta pcap 首部元数据（时间戳/线上长度）；null 时回退
     * @param ctx      本包所属解析分片的有状态组件；<b>只允许分片自己的线程访问</b>
     * @param seq      预分配的入库序号；{@code <0} 表示在此处现场分配（单线程模式的原有语义）
     */
    private void processPacket(Packet packet, PacketParser.WireMeta wireMeta, ParseContext ctx, long seq) {
        try {
            // 第零步：IP 分片检测与重组
            // 当 UDP/TCP 报文超过 MTU 时，IP 层会将报文分成多个分片。
            // 只有第一个分片（offset=0）包含传输层头（端口信息），后续分片没有端口信息。
            // 如果不做重组，后续分片解析出的 destinationPort=null，回放时会发送到 Port 0。
            IpDefrag.ReassembledResult defragResult = ctx.ipDefrag.addFragment(packet);
            if (defragResult == null) {
                // 分片已缓存，等待更多分片到达，跳过此包（属于"半截数据"，计入 droppedInFlight）。
                // 记录首片元数据：重组完成时用它作为整条记录的时间戳与线上长度基准
                // （该数据报"真正开始到达"的时刻），保证记录只含线上真实长度且时间单调性可预期。
                if (isFirstFragment(packet)) {
                    ctx.firstFragmentMeta = wireMeta;
                }
                droppedInFlight.incrementAndGet();
                return;
            }

            // IP 分片重组完成时：**先合成完整帧，再解析合成帧**。
            // 原因：首片只带分片数据，pcap4j 无法把它识别为 UDP/TCP（长度字段与分片长度不符），
            // 直接解析首片会得到 sourcePort/destinationPort = null，导致该数据报被当作
            // "无端口的传输层包"丢弃。合成帧头部齐全，解析它即可得到正确的端口、长度与校验和。
            // 时间戳使用最后一个分片的到达时刻（即重组完成时刻），保证记录时间戳单调。
            Packet packetToParse = packet;
            boolean synthesized = false;
            PacketParser.WireMeta synthMeta = null;
            if (defragResult.isReassembled()) {
                SynthesizedFrame synth = synthesizeDefragFrame(defragResult, defragResult.reassembledPayload());
                if (synth.packet() != null) {
                    packetToParse = synth.packet();
                    synthesized = true;
                    // 时间戳取首片到达时刻（该数据报真正开始到达的时间），
                    // 线上长度取重组后数据报的原始长度（首片线上长度 + 后续分片增量），
                    // 这样 length == wireLen 自洽，且不会把"首片帧长"当成整条数据报的长度。
                    Instant ts = (ctx.firstFragmentMeta != null && ctx.firstFragmentMeta.timestamp() != null)
                            ? ctx.firstFragmentMeta.timestamp()
                            : wireMeta.timestamp();
                    synthMeta = PacketParser.WireMeta.of(ts, synth.wireLen());
                    logger.debug("IP fragment reassembled: payload {} bytes -> synthesized frame {} bytes",
                            defragResult.reassembledPayload().length, synth.capLen());
                } else {
                    logger.warn("IP fragment reassembled but frame synthesis failed; the datagram will be dropped");
                }
                // 该分片组已消费完，清除首片元数据，避免被后续分片组误用
                ctx.firstFragmentMeta = null;
            }

            // 第一步：解析原始数据包为 ParsedPacket
            // PacketParser.parse() 负责提取以太网、IP、TCP/UDP各层信息，并保留完整原始帧
            PacketParser.ParsedPacket parsed =
                    ctx.packetParser.parse(packetToParse, seq >= 0 ? seq : this.getLogDBSequence(),
                            synthesized ? synthMeta : wireMeta);

            // 合成帧属于"线上原本不存在、但头部齐全可注入"的帧
            if (synthesized) {
                parsed = parsed.withFrame(parsed.frameData(), parsed.wireLen(), parsed.capLen(),
                        CaptureKind.IP_DEFRAG_SYNTH);
            }


            // 第二步：TCP 流重组（按序列号）
            // 只对 TCP 且有应用层数据的包做重组；纯控制段走下面的分支
            if (parsed.ipProtocol() != null && parsed.ipProtocol().equals(IpNumber.TCP)
                    && parsed.sourcePort() != null && parsed.destinationPort() != null
                    && parsed.rawData() != null && parsed.rawData().length > 0) {

                // 流标识保留原始方向：客户端→服务器 与 服务器→客户端 各自维护窗口，
                // 避免双向数据被拼到一起
                TcpFlowReassembler.StreamKey streamKey = createStreamKey(parsed);

                String tcpFlags = (String) parsed.additionalInfo().get("tcp.flags");
                boolean syn = tcpFlags != null && tcpFlags.contains("S");
                boolean fin = tcpFlags != null && tcpFlags.contains("F");
                boolean rst = tcpFlags != null && tcpFlags.contains("R");

                // 重组必须用 **TCP 序列号**。
                // 注意：ParsedPacket.packetSequence() 是**入库序号（包计数器）**，
                // 不是 TCP 序列号；真正的序列号在 additionalInfo["tcp.seq"] 里。
                // 用错会让重传去重、乱序重排、缺口等待全部失效（退化成按到达顺序拼接）。
                long tcpSeq = tcpSequence(parsed);
                if (tcpSeq < 0) {
                    // 理论上不会发生（TCP 头解析成功就会写入 tcp.seq）。
                    // 真出现时退化为按到达顺序，并留下告警，而不是静默错拼。
                    tcpSeq = parsed.packetSequence() != null ? parsed.packetSequence() : 0L;
                    logger.warn("TCP segment lacks tcp.seq; falling back to arrival order: {}:{} -> {}:{}",
                            parsed.sourceIp(), parsed.sourcePort(),
                            parsed.destinationIp(), parsed.destinationPort());
                }

                // 提交该段。重组器只在"连续区间"上交付：有缺口时缓存数据、不越过缺口，
                // 因此乱序到达不会把字节按到达顺序拼错，重传也不会产生重复字节。
                // 返回的 data 是**整个未消费窗口**（可能含上一段留下的半条消息）。
                TcpFlowReassembler.StreamUpdate update = ctx.tcpReassembler.offer(
                        streamKey, tcpSeq, parsed.rawData(), syn, fin, rst,
                        System.currentTimeMillis());

                if (update.newConnection()) {
                    logger.debug("TCP flow {} detected a new connection; previous session buffer isolated by generation.",
                            streamKey.tuple());
                }

                // 内容视图：窗口连续时用累计窗口（内容审计单位），
                // 存在缺口时退化为"本段自身载荷"（此时窗口不连续，不可作为内容）
                byte[] window = update.data();
                byte[] content = window != null ? window : parsed.rawData();

                Map<String, Object> windowInfo = new HashMap<>(parsed.additionalInfo());
                // 内容是否"是累计出来的"（而非本帧单独一段）。
                // 这决定 ProtocolParser.detectByContent() 要不要扫描协议标签：
                // 累计内容可能从一条消息的中途开始，只认开头会漏识别。
                boolean accumulated = window != null && window.length > parsed.rawData().length;
                if (accumulated || update.waitingForGap()) {
                    windowInfo.put("tcp.has_buffer", "true");
                }
                if (update.waitingForGap()) {
                    // 该段落在缺口之后，内容暂不连续；窗口为空也可能只是"上一批已消费完"
                    // （如重传段），那不是缺口，所以单独用 waitingForGap 判定
                    windowInfo.put("tcp.gap_pending", "true");
                }

                // 帧相关字段（frameData / captureKind）原样保留：本行仍可按帧原样重放。
                // 旧实现把"合并行"写成 frameData=null + TCP_REASSEMBLED，
                // 那些字节就永久不可重放了。
                PacketParser.ParsedPacket packetToLog = parsed.withRawData(content, windowInfo);

                // 第三步：协议解析（仅用于判定完整性；PacketLogger 内部还会解析一次）
                PacketParser.ParsedPacket enhancedPacket =
                        ctx.protocolParser.parseProtocolDetails(packetToLog);
                String appProtocol =
                        (String) enhancedPacket.additionalInfo().get("application.protocol");

                // 第四步：统一消息切分——窗口里有多少字节构成完整消息。
                // 无法可靠判断时返回 0（字节留在窗口里等后续段），
                // 绝不退化回"整窗口都算完整"：那正是消息跨段时丢字节的原因。
                int consumedBytes = completeMessageBytes(enhancedPacket, appProtocol, window);

                Map<String, Object> finalInfo = new HashMap<>(enhancedPacket.additionalInfo());
                finalInfo.put("tcp.window.bytes", String.valueOf(window == null ? 0 : window.length));
                finalInfo.put("tcp.complete_message_bytes", String.valueOf(consumedBytes));
                enhancedPacket = enhancedPacket.withAdditionalInfo(finalInfo);

                // 第五步：记录并消费。
                // **每一帧都要入库**：帧是重放单位，漏掉任何一帧都会让"原样重放"不再成立。
                // 内容列给的是累计窗口，因此一条跨段的完整消息会在它完成的那一行里完整可见。
                packetLogger.logPacket(enhancedPacket, true);

                // 只消费真正构成完整消息的字节，剩下的半条消息留在窗口里与后续段拼接。
                // 这样窗口长度被限制在"当前这一条未完成消息"以内，不会无界增长。
                if (window != null && consumedBytes > 0) {
                    ctx.tcpReassembler.consume(streamKey, consumedBytes);
                    if (consumedBytes < window.length) {
                        logger.debug("TCP flow {} consumed {} bytes of complete messages; kept {} bytes awaiting more segments.",
                                streamKey.tuple(), consumedBytes, window.length - consumedBytes);
                    }
                }
            } else if (parsed.ipProtocol() != null && parsed.ipProtocol().equals(IpNumber.TCP)
                    && parsed.sourcePort() != null && parsed.destinationPort() != null) {
                // TCP包但没有应用层数据（如SYN/SYN-ACK/FIN/RST等控制包）
                // 检查TCP标志位。SYN/FIN/RST 都必须交给重组器：
                //   - SYN 决定本条流的初始序列号（ISN）。不提交 SYN 的话，流的起点只能取
                //     "首个见到的数据段"，于是**乱序先到的那个段会被当成流的起点**，
                //     随后到达的更早的段会被误判为"完全重复"而静默丢弃。
                //   - FIN/RST 结束流，并交出窗口里尚未记录的残留字节。
                // 纯 ACK 只表示确认，不代表连接关闭，不提交。
                String tcpFlags = (String) parsed.additionalInfo().get("tcp.flags");
                boolean syn = tcpFlags != null && tcpFlags.contains("S");
                boolean fin = tcpFlags != null && tcpFlags.contains("F");
                boolean rst = tcpFlags != null && tcpFlags.contains("R");
                boolean isConnectionClose = fin || rst;

                byte[] residual = null;
                if (syn || isConnectionClose) {
                    TcpFlowReassembler.StreamKey streamKey = createStreamKey(parsed);
                    long tcpSeq = tcpSequence(parsed);
                    if (tcpSeq < 0) {
                        tcpSeq = parsed.packetSequence() != null ? parsed.packetSequence() : 0L;
                        logger.warn("TCP control segment lacks tcp.seq; cannot establish flow start: {}:{} -> {}:{}",
                                parsed.sourceIp(), parsed.sourcePort(),
                                parsed.destinationIp(), parsed.destinationPort());
                    }
                    TcpFlowReassembler.StreamUpdate controlUpdate = ctx.tcpReassembler.offer(
                            streamKey, tcpSeq, null, syn, fin, rst, System.currentTimeMillis());
                    residual = controlUpdate.data();
                }

                if (residual != null && residual.length > 0) {
                    // 连接关闭时窗口里还有"尚未凑成完整消息"的残留字节：
                    // 这些字节不会再有机会补齐，必须随本帧一并记录，否则就是静默丢数据。
                    logger.debug("TCP connection closed ({}); {} residual bytes recorded with this frame.",
                            tcpFlags, residual.length);

                    // 只记一行：帧仍用本控制帧，内容换成残留字节。
                    // 拆成两行会让同一个帧被记两次，重放时就会重复注入。
                    Map<String, Object> additionalInfo = new HashMap<>(parsed.additionalInfo());
                    additionalInfo.put("tcp.buffer_flushed", "true");
                    additionalInfo.put("tcp.buffer_flushed_bytes", String.valueOf(residual.length));
                    PacketParser.ParsedPacket bufferPacket =
                            parsed.withRawData(residual, additionalInfo);
                    packetLogger.logPacket(ctx.protocolParser.parseProtocolDetails(bufferPacket), true);
                } else {
                    packetLogger.logPacket(parsed);
                }


            } else {
                // 非TCP或无应用层数据，正常处理
                // 防御：对于 IP 分片（传输层被截断），TCP/UDP 包可能没有端口信息
                // 这些包无法正确重放，跳过记录
                if (parsed.ipProtocol() != null
                        && (parsed.ipProtocol().equals(IpNumber.TCP)
                        || parsed.ipProtocol().equals(IpNumber.UDP))
                        && (parsed.sourcePort() == null || parsed.destinationPort() == null)) {
                    // 传输层头没解析出端口（多为 snaplen 截断 / 分片未补齐）。
                    // 早期实现只打一行 debug 日志，等于静默丢掉这些包的内容；
                    // 现在如实计数，首次出现时给出可见的告警。
                    long noPortCount = droppedNoPort.incrementAndGet();
                    if (noPortCount == 1) {
                        logger.warn("[JShark] TCP/UDP packet without port info cannot be recorded "
                                        + "(truncated or incomplete transport header); further occurrences "
                                        + "are counted and reported at exit: ipProtocol={}, srcPort={}, dstPort={}",
                                parsed.ipProtocol(), parsed.sourcePort(), parsed.destinationPort());
                    } else {
                        logger.debug("Skipping TCP/UDP packet without port info: ipProtocol={}, srcPort={}, dstPort={}",
                                parsed.ipProtocol(), parsed.sourcePort(), parsed.destinationPort());
                    }
                } else {
                    packetLogger.logPacket(parsed);
                }
            }

            // 注意：PCAP 落盘（saveToPcap）已从这里移到**抓包线程**（见 runCaptureLoop）。
            // 原因：PcapDumper 底层是单个 FILE* / 原生句柄，不是线程安全的；
            // 解析并行化后本方法会跑在多个 worker 线程上，必须保证 dumper 只被一个线程使用。

        } catch (Exception e) {
            logger.error("Error processing packet", e);
        }
    }

    /**
     * 判断是否为 IPv4 分片组的首片（offset == 0 且 MF == 1）。
     *
     * @param packet 数据包
     * @return true 表示是首片
     */
    private boolean isFirstFragment(Packet packet) {
        try {
            if (!packet.contains(org.pcap4j.packet.IpV4Packet.class)) {
                return false;
            }
            // 注意：getFragmentOffset() 返回纯偏移值（8 字节为单位，不含标志位），MF 需单独获取
            org.pcap4j.packet.IpV4Packet.IpV4Header h =
                    packet.get(org.pcap4j.packet.IpV4Packet.class).getHeader();
            return h.getFragmentOffset() == 0 && h.getMoreFragmentFlag();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从字节数组按大端读取 16 位无符号整数。
     *
     * @param data   数据
     * @param offset 起始偏移
     * @return 无符号 16 位值
     */
    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /**
     * 从字节数组按大端读取 32 位无符号整数。
     *
     * @param data   数据
     * @param offset 起始偏移
     * @return 以 long 承载的无符号 32 位值
     */
    private static long readUint32(byte[] data, int offset) {
        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    /**
     * 合成帧及其长度信息。
     *
     * @param packet    合成后的完整数据包（可直接用于解析与注入）；null 表示合成失败
     * @param wireLen   原始线上长度
     * @param capLen    实际捕获长度（等于合成帧字节数）
     */
    private record SynthesizedFrame(Packet packet, int wireLen, int capLen) {}

    /**
     * 按 IP 分片重组结果合成一个可注入的完整帧。
     * <p>
     * 做法：把"首片的以太网头"与"新的 IPv4 头（MF=0、offset=0、总长度=重组后长度）"以及
     * 重组后的传输层 payload 拼成完整帧，并重算 IP 头校验和。这样：
     * </p>
     * <ul>
     *   <li>合成帧头部齐全，可被正常解析（首片因长度不符无法被识别为 UDP/TCP）</li>
     *   <li>校验和正确，可被任何协议栈接收（供帧级重放）</li>
     *   <li>长度自洽：{@code capLen} 等于合成帧长度，不再出现"长度与内容不一致"</li>
     *   <li>应用层载荷与线上完全一致（仅分片结构被还原）</li>
     * </ul>
     * <p>
     * 该帧在线上原本不存在，因此记录会标记为 {@link CaptureKind#IP_DEFRAG_SYNTH}，
     * 而原始分片帧仍按原样写入 PCAP 文件。
     * </p>
     *
     * @param defragResult        重组结果（提供首片的原始 Packet）
     * @param reassembledPayload  重组后的传输层 payload（含 TCP/UDP 头）
     * @return 合成结果；无法合成时 {@code packet()} 为 null
     */
    private SynthesizedFrame synthesizeDefragFrame(IpDefrag.ReassembledResult defragResult,
                                                   byte[] reassembledPayload) {
        Packet first = defragResult.firstFragmentPacket();
        if (first == null || reassembledPayload == null || reassembledPayload.length == 0) {
            return new SynthesizedFrame(null, 0, 0);
        }

        try {
            if (!first.contains(org.pcap4j.packet.IpV4Packet.class)) {
                return new SynthesizedFrame(null, 0, 0);
            }

            org.pcap4j.packet.IpV4Packet ip4 = first.get(org.pcap4j.packet.IpV4Packet.class);
            org.pcap4j.packet.IpV4Packet.IpV4Header ipHeader = ip4.getHeader();

            // 传输层 builder：必须使用**类型化** builder（UdpPacket/TcpPacket），
            // 而不是 UnknownPacket —— pcap4j 对 UnknownPacket 载荷不会按 IP 协议号再识别，
            // 导致 contains(UdpPacket.class) 为 false、端口解析不出来。
            // 这里直接复用重组后的传输层字节中的端口字段，其余字节原样保留。
            // 传输层校验和保持原值（重组后内容不变，校验和依然有效）。
            org.pcap4j.packet.Packet.Builder transportBuilder;
            IpNumber proto = ipHeader.getProtocol();
            if (proto.equals(IpNumber.UDP)) {
                if (reassembledPayload.length < 8) {
                    logger.warn("Reassembled UDP payload too short: {} bytes", reassembledPayload.length);
                    return new SynthesizedFrame(null, 0, 0);
                }
                byte[] appPayload = new byte[reassembledPayload.length - 8];
                System.arraycopy(reassembledPayload, 8, appPayload, 0, appPayload.length);
                transportBuilder = new org.pcap4j.packet.UdpPacket.Builder()
                        .srcPort(org.pcap4j.packet.namednumber.UdpPort.getInstance(
                                (short) readUint16(reassembledPayload, 0)))
                        .dstPort(org.pcap4j.packet.namednumber.UdpPort.getInstance(
                                (short) readUint16(reassembledPayload, 2)))
                        .srcAddr(ipHeader.getSrcAddr())
                        .dstAddr(ipHeader.getDstAddr())
                        .correctChecksumAtBuild(false)
                        .correctLengthAtBuild(true)
                        .payloadBuilder(new org.pcap4j.packet.UnknownPacket.Builder().rawData(appPayload));
            } else if (proto.equals(IpNumber.TCP)) {
                if (reassembledPayload.length < 20) {
                    logger.warn("Reassembled TCP payload too short: {} bytes", reassembledPayload.length);
                    return new SynthesizedFrame(null, 0, 0);
                }
                int dataOffset = ((reassembledPayload[12] & 0xF0) >> 4) * 4;
                if (dataOffset < 20 || dataOffset > reassembledPayload.length) {
                    logger.warn("Invalid TCP data offset in reassembled payload: {}", dataOffset);
                    return new SynthesizedFrame(null, 0, 0);
                }
                byte[] appPayload = new byte[reassembledPayload.length - dataOffset];
                System.arraycopy(reassembledPayload, dataOffset, appPayload, 0, appPayload.length);
                transportBuilder = new org.pcap4j.packet.TcpPacket.Builder()
                        .srcPort(org.pcap4j.packet.namednumber.TcpPort.getInstance(
                                (short) readUint16(reassembledPayload, 0)))
                        .dstPort(org.pcap4j.packet.namednumber.TcpPort.getInstance(
                                (short) readUint16(reassembledPayload, 2)))
                        .sequenceNumber((int) readUint32(reassembledPayload, 4))
                        .acknowledgmentNumber((int) readUint32(reassembledPayload, 8))
                        .dataOffset((byte) (dataOffset / 4))
                        .reserved((byte) 0)
                        .urg((reassembledPayload[13] & 0x20) != 0)
                        .ack((reassembledPayload[13] & 0x10) != 0)
                        .psh((reassembledPayload[13] & 0x08) != 0)
                        .rst((reassembledPayload[13] & 0x04) != 0)
                        .syn((reassembledPayload[13] & 0x02) != 0)
                        .fin((reassembledPayload[13] & 0x01) != 0)
                        .window((short) readUint16(reassembledPayload, 14))
                        .srcAddr(ipHeader.getSrcAddr())
                        .dstAddr(ipHeader.getDstAddr())
                        .correctChecksumAtBuild(false)
                        .correctLengthAtBuild(true)
                        .payloadBuilder(new org.pcap4j.packet.UnknownPacket.Builder().rawData(appPayload));
            } else {
                logger.debug("Reassembled IP datagram has non-TCP/UDP protocol {}; no frame synthesized",
                        proto);
                return new SynthesizedFrame(null, 0, 0);
            }

            org.pcap4j.packet.IpV4Packet.Builder ipBuilder = new org.pcap4j.packet.IpV4Packet.Builder();
            ipBuilder.version(ipHeader.getVersion())
                    .ihl(ipHeader.getIhl())
                    .tos(ipHeader.getTos())
                    .totalLength((short) (ipHeader.getIhl() * 4 + reassembledPayload.length))
                    .identification(ipHeader.getIdentification())
                    .reservedFlag(ipHeader.getReservedFlag())
                    .dontFragmentFlag(ipHeader.getDontFragmentFlag())
                    .moreFragmentFlag(false)   // 重组完成：不再是分片
                    .fragmentOffset((short) 0)
                    .ttl(ipHeader.getTtl())
                    .protocol(proto)
                    .srcAddr(ipHeader.getSrcAddr())
                    .dstAddr(ipHeader.getDstAddr())
                    .options(ipHeader.getOptions())
                    .padding(ipHeader.getPadding())
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .paddingAtBuild(false)
                    .payloadBuilder(transportBuilder);

            Packet synthesized;
            if (first.contains(org.pcap4j.packet.EthernetPacket.class)) {
                org.pcap4j.packet.EthernetPacket eth = first.get(org.pcap4j.packet.EthernetPacket.class);
                synthesized = new org.pcap4j.packet.EthernetPacket.Builder()
                        .srcAddr(eth.getHeader().getSrcAddr())
                        .dstAddr(eth.getHeader().getDstAddr())
                        .type(eth.getHeader().getType())
                        .payloadBuilder(ipBuilder)
                        // 重组后必然 >= 最小以太网帧长，无需填充；
                        // 显式给出空 pad（pcap4j 在 paddingAtBuild=false 时要求 pad 非 null）
                        .paddingAtBuild(false)
                        .pad(new byte[0])
                        .build();
            } else {
                synthesized = ipBuilder.build();
            }

            byte[] frameData = synthesized.getRawData();
            // 线上长度：首片的线上长度 + 后续分片带来的增量
            //          = 首片线上长度 + (重组 payload - 首片 IP payload)
            int firstFragmentWireLen = first.length();
            int firstIpPayloadLen = 0;
            try {
                org.pcap4j.packet.Packet ipPayload = ip4.getPayload();
                firstIpPayloadLen = ipPayload != null ? ipPayload.getRawData().length : 0;
            } catch (Exception ignore) {
                // 仅用于估算增量，忽略失败
            }
            int wireLen = firstFragmentWireLen + Math.max(reassembledPayload.length - firstIpPayloadLen, 0);

            return new SynthesizedFrame(synthesized, wireLen, frameData.length);

        } catch (Exception e) {
            logger.warn("Failed to synthesize defragmented frame ({} bytes payload): {}",
                    reassembledPayload.length, e.getMessage());
            return new SynthesizedFrame(null, 0, 0);
        }
    }

    /**
     * 取 TCP 序列号。
     * <p>
     * 真实序列号由 {@link PacketParser} 放在 {@code additionalInfo["tcp.seq"]}，
     * 而 {@code ParsedPacket.packetSequence()} 是入库序号（包计数器）——两者含义完全不同，
     * 混用会让 TCP 重组彻底失效。
     * </p>
     *
     * @param parsed 已解析记录
     * @return TCP 序列号；缺失时返回 -1
     */
    private long tcpSequence(PacketParser.ParsedPacket parsed) {
        Object seq = parsed.additionalInfo().get("tcp.seq");
        if (seq instanceof Number n) {
            return n.longValue();
        }
        return -1L;
    }

    /**
     * 统一的"窗口里有多少字节构成完整消息"判定。
     * <p>
     * 只有确定构成完整消息的字节才允许被 {@code consume()} 消费掉；无法判断时返回 0，
     * 让字节留在重组器窗口里等后续段。**绝不能**退化回
     * {@code consumedBytes = rawData.length}（把整个窗口都当成完整消息）——
     * 那正是消息跨 TCP 段时丢字节的原因。
     * </p>
     *
     * @param enhancedPacket 已完成协议解析的记录
     * @param appProtocol    识别出的应用层协议名
     * @param window         当前连续窗口；无窗口时为 null
     * @return 完整消息占用的字节数；0 表示还凑不出完整消息
     */
    private int completeMessageBytes(PacketParser.ParsedPacket enhancedPacket, String appProtocol,
                                     byte[] window) {
        if (window == null || appProtocol == null || "UNKNOWN".equals(appProtocol)) {
            return 0;
        }
        if ("PG".equals(appProtocol)) {
            // PG 解析器按消息类型算出了实际消耗字节数
            Object consumed = enhancedPacket.additionalInfo().get("pg.consumed_bytes");
            return consumed instanceof Integer i ? Math.max(0, Math.min(i, window.length)) : 0;
        }
        return MessageFramer.completeMessageBytes(appProtocol, window);
    }

    /**
     * 创建 TCP 流标识（保留原始方向）。
     * <p>
     * 每个 TCP 流有两个方向（客户端→服务器 和 服务器→客户端），
     * 每个方向独立维护窗口，避免双向数据混合。
     * 连接代次由 {@link TcpFlowReassembler} 内部维护，这里只需四元组。
     * </p>
     */
    private TcpFlowReassembler.StreamKey createStreamKey(PacketParser.ParsedPacket parsed) {
        return new TcpFlowReassembler.StreamKey(
                parsed.sourceIp(), parsed.destinationIp(),
                parsed.sourcePort(), parsed.destinationPort());
    }

    public void setInterfaceIP(String interfaceIP) {
        this.interfaceIP = interfaceIP;
    }
    
    public void setFilterExpression(String filterExpression) {
        this.filterExpression = filterExpression;
    }
    
    public void setPacketCount(Integer packetCount) {
        this.packetCount = packetCount;
    }
    
    public void setTimeoutSeconds(Integer timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }
    
    public void setOutputFile(String outputFile) {
        if (outputFile != null) {
            logger.info("[JShark] PCAP file will be saved to {}", outputFile);
            this.outputFile = outputFile;
        } else {
            this.outputFile = null;
        }
    }
    
    /**
     * 设置时间分卷间隔（同时作用于 PCAP 与 logdb）。
     * <p>
     * 分卷按时间网格对齐：文件名后缀为该卷起始时间的 YYYYMMDDHH24MISS 时间戳。
     * 未启用（间隔 <= 0）时，输出为单个文件。
     * </p>
     *
     * @param splitIntervalMs 分卷间隔（毫秒）
     */
    public void setSplit(long splitIntervalMs) {
        this.splitIntervalMs = splitIntervalMs;
        if (splitIntervalMs > 0) {
            logger.info("[JShark] Time-based split enabled: {} ms", splitIntervalMs);
        }
        // 只有 PCAP 输出（没有 logdb）时，同样需要时间分卷。
        // 早期实现由 PacketLogger 自己维护一套 pcap 卷时钟，改造后统一由 VolumeWindows 统管，
        // 因此这里必须显式初始化，否则 --pcapoutput + --split 会退化成"总是写同一个文件"。
        ensureWindowsInitialized();
    }

    /**
     * 按需初始化时间窗（PCAP 与 logdb 共用）。
     * <p>
     * 基准路径优先取 logdb；未配置 logdb 时取 PCAP 输出路径。
     * 两者都存在时以 logdb 为基准 —— 文件名分别由 {@link VolumeWindows#fileFor(long)} 与
     * {@link VolumeWindows#pcapFor(long)} 生成，时间戳必然一致。
     * </p>
     */
    private void ensureWindowsInitialized() {
        if (splitIntervalMs <= 0) {
            return;
        }
        String base = (this.logDb != null) ? this.logDb : this.outputFile;
        if (base == null) {
            return;
        }

        // 基准路径可能发生变化，必须重建窗口。
        // CLI 的调用顺序是 setOutputFile → setSplit → setLogDb，因此 setSplit 执行时 logDb 还没设置，
        // 窗口会先按 **PCAP** 路径建好（连扩展名 .pcap 一起）。若不重建：
        //   logdb 会被写成 "xxx_<时间戳>.pcap"（DuckDB 库文件顶着 .pcap 的名字），
        //   而随后按同一路径打开 PCAP 必然失败——那个文件正被 DuckDB 占用。
        // "两者都存在时以 logdb 为基准"是本方法的既定语义，故基准变了就重建。
        if (windows != null && !base.equals(windows.basePath())) {
            logger.info("[JShark] Time window base changed: {} -> {}, rebuilding",
                    windows.basePath(), base);
            windows = null;
            currentLogDbPath = null;
        }
        if (windows != null) {
            return;
        }

        windows = new VolumeWindows(base, splitIntervalMs, clock);
        windows.initialize(clock.getAsLong());
        currentLogDbPath = (this.logDb != null) ? windows.fileFor(windows.currentStartMs()) : null;
        logDbVolumeSeq = 1;
        if (this.logDb != null) {
            packetLogger.resetCommittedCount();
            packetLogger.setVolumeSeq(logDbVolumeSeq);
        }
        logger.info("[JShark] Time window initialized: seq=1, [{} .. {})",
                SplitUtil.formatTimestamp(windows.currentStartMs()),
                SplitUtil.formatTimestamp(windows.currentEndMs()));
    }
    
    public void setPromiscuous(boolean promiscuous) {
        this.promiscuous = promiscuous;
    }

    /**
     * 设置内核抓包缓冲大小（pcap_set_buffer_size）。
     * <p>
     * 该缓冲是"网卡/驱动 -> 用户态"之间的队列。默认值（Windows/Npcap 约 2MB）在高流量下
     * 只相当于几十到一百多毫秒的缓冲，一次 GC 停顿或调度抖动就会导致内核静默丢包。
     * </p>
     *
     * @param pcapBufferBytes 缓冲字节数；{@code <=0} 表示不设置（用平台默认）
     */
    public void setPcapBufferBytes(int pcapBufferBytes) {
        this.pcapBufferBytes = pcapBufferBytes;
    }

    /**
     * 设置是否启用 immediate mode（每到一个包立即唤醒，不再等缓冲填满或超时）。
     * <p>
     * 默认关闭：immediate mode 会显著增加每包的系统调用/唤醒次数，仅在需要极低延迟时开启。
     * </p>
     *
     * @param immediateMode true 表示启用
     */
    public void setImmediateMode(boolean immediateMode) {
        this.immediateMode = immediateMode;
    }

    public void setVerbose(boolean verbose) {
        packetLogger.setVerbose(verbose);
    }

    /**
     * 设置是否展开 DIS/HTTP/PG 详细字段并写入 {@code additionalInfo} 列。
     * <p>
     * false（默认）：不为了该列解析载荷，数据库该列恒为 NULL；appProtocol/tcpFlags、
     * frameData/rawData 以及重放逻辑保持不变。true：恢复完整展开。
     * 设置了 {@code --exfilter} 时该开关恒为 true（表达式依赖这些字段）。
     * </p>
     *
     * @param enableAdditionalInfo true = 展开并落盘 additionalInfo
     */
    public void setEnableAdditionalInfo(boolean enableAdditionalInfo) {
        this.enableAdditionalInfo = enableAdditionalInfo
                || (exfilter != null && !exfilter.isEmpty());
        applyAdditionalInfoMode();
    }

    /**
     * 应用 additionalInfo 开关：解析详细字段与写库列始终一致。
     */
    private void applyAdditionalInfoMode() {
        packetLogger.setEnableAdditionalInfo(enableAdditionalInfo);
        packetLogger.setStoreAdditionalInfo(enableAdditionalInfo);
        if (parseShards != null) {
            for (ParseContext ctx : parseShards) {
                if (ctx != null) {
                    ctx.protocolParser.setEnableAdditionalInfo(enableAdditionalInfo);
                }
            }
        }
    }

    /**
     * 设置附加信息过滤表达式。
     * <p>
     * 表达式匹配的是 additionalInfo 里的协议字段，因此设置表达式会自动开启
     * {@code --enable_additioninfo}：这些字段既用于求值，也会落库供事后查询与重放过滤。
     * </p>
     *
     * @param exfilter 过滤表达式；null 或空串表示不过滤
     */
    public void setExfilter(String exfilter) {
        this.exfilter = exfilter;
        if (exfilter != null && !exfilter.isEmpty()) {
            // 过滤依赖协议字段，同时保留这些字段供事后查询/重放过滤
            this.enableAdditionalInfo = true;
            // 将exfilter传递给packetLogger
            packetLogger.setExfilter(exfilter);
        }
        applyAdditionalInfoMode();
    }

    /**
     * 关闭数据库连接并释放资源。
     * <p>
     * 关闭前先结束可能仍处于打开状态的事务：DuckDB 在连接上有活动事务时会拒绝
     * {@code FORCE CHECKPOINT}（报 "the current transaction has been started for this database"）。
     * 典型触发场景是<b>一个包都没入库</b>——例如 {@code --exfilter} 把所有包都过滤掉了，
     * 于是 {@code PacketDBEventHandler} 从未 commit 过，建表时那条只读查询留下的事务一直挂着。
     * </p>
     * <p>
     * 无论如何都必须真正 {@code close()}：否则连接泄漏，且同进程再次打开同一个库文件会失败
     * （"Can't open a connection to same database file with a different configuration"）。
     * </p>
     */
    private void closeLogDb() {
        Connection conn = logDbConn;
        logDbConn = null;
        if (conn == null) {
            return;
        }
        try {
            if (!conn.isClosed()) {
                try {
                    if (!conn.getAutoCommit()) {
                        conn.rollback();
                    }
                } catch (SQLException e) {
                    logger.debug("[JShark] rollback before close failed: {}", e.getMessage());
                }
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("FORCE CHECKPOINT");
                } catch (SQLException e) {
                    logger.debug("[JShark] FORCE CHECKPOINT failed, closing anyway: {}", e.getMessage());
                }
                logger.info("[JShark] logdb closed (last volume seq={})", logDbVolumeSeq);
            }
        } catch (SQLException e) {
            logger.warn("[JShark] Error closing database connection: {}", e.getMessage());
        } finally {
            try {
                if (!conn.isClosed()) {
                    conn.close();
                }
            } catch (SQLException e) {
                logger.warn("[JShark] Failed to close logdb connection: {}", e.getMessage());
            }
        }
    }

    public void setLogDb(String logDb) throws PacketCaptureException
    {
        if (logDb == null)
        {
            closeLogDb();
            return;
        }

        // 检查是否需要重新连接
        boolean needReconnect = (logDbConn == null);

        if (needReconnect) {
            // 关闭旧连接
            closeLogDb();

            this.logDb = logDb;
            initializeLogDbVolumePath();
            logger.info("[JShark] Will save package into database {} ...", currentLogDbPath);

            try {
                logger.info("[JShark] Starting backup database in local mode with file [{}] ... Press CTRL+C to stop it.", currentLogDbPath);
                String connectURL = "jdbc:duckdb:" + currentLogDbPath;
                logDbConn = DriverManager.getConnection(
                        connectURL, "", "");
                logDbConn.setAutoCommit(false);

                initializeLogDbSchema(logDbConn);

                // 首卷卷序号从 1 开始
                logDbVolumeSeq = 1;
                packetLogger.setVolumeSeq(logDbVolumeSeq);
                packetLogger.setLogDb(logDbConn);
            }
            catch (SQLException sqlException)
            {
                throw new PacketCaptureException("Failed to create log database " + this.logDb + ".", sqlException );
            }
        }
    }

    /**
     * 初始化 logdb 数据库结构并恢复 ID 序号
     * <p>
     * 建表（如不存在），并从已有表读取 MAX(ID) 初始化 {@link #logDBSequence}。
     * 用于首次打开数据库和分卷轮转时初始化新数据库文件。
     * </p>
     *
     * @param conn 已打开的数据库连接
     * @throws SQLException 建表或查询失败
     */
    private void initializeLogDbSchema(Connection conn) throws SQLException {
        try (Statement statement = conn.createStatement()) {
            statement.execute(CREATE_LOG_SCHEMA_SQL);
            conn.commit();

            ResultSet rs = statement.executeQuery("SELECT MAX(ID) FROM JSharkLog");
            if (rs.next()) {
                this.logDBSequence = new AtomicLong(rs.getLong(1));
            } else {
                this.logDBSequence = new AtomicLong(0L);
            }
            rs.close();
            // 连接是 autoCommit=false：上面这条只读查询会开启一个事务，
            // 必须显式结束，否则它会一直挂到关闭时（并让 FORCE CHECKPOINT 失败）
            conn.commit();
        }
    }

    /**
     * 拆分 logdb 基础名与扩展名。
     * <p>
     * 例如 {@code dis_capture.db} 拆分为 {@code dis_capture} 与 {@code .db}；
     * 无扩展名时 {@code logDbExt} 为空串。
     * </p>
     */
    private void resolveLogDbBaseAndExt() {
        String path = this.logDb;
        int dot = path.lastIndexOf('.');
        int slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        if (dot > slash && dot > 0) {
            logDbBase = path.substring(0, dot);
            logDbExt = path.substring(dot);
        } else {
            logDbBase = path;
            logDbExt = "";
        }
    }

    /**
     * 初始化 logdb 写入路径。
     * <p>
     * 时间窗由 {@link VolumeWindows} 统管（见 {@link #ensureWindowsInitialized()}）：
     * 首窗从采集启动时刻开始、结束于其后的第一个自然时间网格边界
     * （如 10:03 启动、间隔 5 分钟 → 首窗 10:03–10:05，之后 10:05–10:10…），
     * 因此窗口边界始终落在整分/整点上，且长时间运行不累积漂移。
     * PCAP 与 logdb 共用同一个 {@code VolumeWindows} 实例，文件名时间戳必然一致。
     * </p>
     */
    private void initializeLogDbVolumePath() {
        resolveLogDbBaseAndExt();
        if (splitIntervalMs > 0) {
            ensureWindowsInitialized();
            if (currentLogDbPath == null) {
                currentLogDbPath = windows.fileFor(windows.currentStartMs());
            }
            // 窗口已建好时，PCAP 输出也切换到同一窗口的文件名
            if (packetLogger.isPcapEnabled() && packetLogger.currentPcapPath() == null) {
                packetLogger.openPcap(windows.pcapFor(windows.currentStartMs()));
            }
        } else {
            currentLogDbPath = this.logDb;
        }
    }

    /**
     * 检查时间窗是否到期并执行轮转；轮转时同时关闭 PCAP 与 logdb 的当前卷，
     * 并写出该窗口的 manifest。
     * <p>
     * 关键点：
     * <ol>
     *   <li>在<b>处理当前包之前</b>调用，保证边界之后的第一个包落入新卷；</li>
     *   <li>一次调用可能关闭多个窗口（跨边界补齐），中间窗口产出空卷；</li>
     *   <li>关闭顺序：抓包线程<b>只</b>摘离旧卷并立即开新卷（异步，不阻塞采集）；
     *       旧卷的"排空 -> 落库 -> 写 manifest -> CHECKPOINT -> 更名 -> 关连接"
     *       由后台写库线程完成，退出时统一 join。</li>
     * </ol>
     * </p>
     */
    private void checkAndRotateLogDb() {
        if (windows == null || !windows.isInitialized()) {
            return;
        }
        VolumeWindows.Advance advance = windows.advance();
        if (!advance.rotated()) {
            return;
        }

        // 并行解析时：轮转意味着要关闭当前卷的 logdb/PCAP，必须先把各分片里已提交的包
        // 全部处理完（屏障），否则 worker 可能还在往"已经关闭的卷"上写，或者这些包
        // 被计入下一个卷。轮转本身是低频事件，屏障代价可以忽略。
        awaitParseShardsIdle();

        for (VolumeWindows.ClosedWindow closed : advance.closed()) {
            // 先关掉 closed **自己**那个窗口：此刻 currentLogDbPath/当前 PCAP 正是它的文件，
            // 所以它写出的 manifest 才会指向自己的数据文件。
            finalizeVolume(closed.volumeSeq(), closed.startMs(), closed.endMs(),
                    closed.complete(), closed.closedReason(), false);
            // 紧接着打开它的**后继**窗口，而不是循环外那个最终窗口。
            // 一次卡顿可能跨过多个边界（advance() 用 while 补齐），中间被跨过的空窗口
            // 也必须各自成卷——否则它们既没有数据文件，manifest 还会指向最终窗口的文件。
            openVolume(closed.volumeSeq() + 1, closed.endMs());
        }
    }

    /**
     * 注入时间源（毫秒）。仅供测试：用于在不等待真实时间的前提下驱动分卷轮转。
     *
     * @param clock 时间源；null 表示恢复为 {@link System#currentTimeMillis()}
     */
    void setClockForTest(java.util.function.LongSupplier clock) {
        this.clock = clock != null ? clock : System::currentTimeMillis;
    }

    /**
     * 关闭当前窗口的 PCAP 与 logdb，写出 manifest。
     *
     * @param seq          卷序号
     * @param startMs      窗口起始时刻
     * @param endMs        窗口结束边界（{@code boundary} 收尾时即为最终文件名里的 end）
     * @param complete     是否完整窗口
     * @param closedReason 关闭原因（{@code boundary} / {@code shutdown}）
     * @param sync         true = 在调用线程上把整卷收完（停机路径，必须在被抓包线程上执行）；
     *                     false = 交给后台写库线程（到点轮转，不能阻塞采集）
     */
    private void finalizeVolume(long seq, long startMs, long endMs, boolean complete,
                                String closedReason, boolean sync) {
        // 先关 PCAP（快速、同步即可，与 DB 无关）。仅 PCAP 模式下它本身就是一卷的数据文件：
        // 关之前记下路径，收尾后按窗口/停机时刻登记给 UI。
        String pcapPath = packetLogger.currentPcapPath();
        packetLogger.closePcap();

        Connection oldConn = logDbConn;
        String oldPath = currentLogDbPath;
        // 摘离旧卷：boundary 交给后台"每文件一个写库线程"；shutdown 在本线程同步做完。
        if (oldConn != null) {
            // 摘下旧 handler（detach：不 latch、不 shutdown，全部留在收尾线程做）
            PacketDBEventHandler oldHandler = packetLogger.detachLogDb();
            // 摘离引用：openVolume 会为下一个卷分配新的 logDbConn/currentLogDbPath，
            // 这里先清空，避免后台 task 与后续 openVolume 互相踩字段。
            this.logDbConn = null;
            this.currentLogDbPath = null;

            VolumeCloseJob job = new VolumeCloseJob(seq, startMs, endMs, complete, closedReason,
                    oldConn, oldPath, oldHandler, droppedAfterSignal);
            inFlightVolumes.put(seq, job);
            logger.info("[JShark] Finalizing volume seq={} ({}), sync={}, path={}",
                    seq, closedReason, sync, oldPath);

            if (sync) {
                // 停机：在被 hook join 的线程上同步收完，hook 的等待才真正覆盖到 CHECKPOINT+rename
                try {
                    droppedAfterSignal += closeVolumeJob(job);
                } catch (Throwable t) {
                    logger.error("[JShark] Volume {} close failed", seq, t);
                } finally {
                    inFlightVolumes.remove(seq, job);
                }
            } else {
                // 轮转：不阻塞采集，旧卷由后台线程慢慢写完
                volumeCloseFutures.add(volumeCloseExecutor.submit(() -> {
                    try {
                        return closeVolumeJob(job);
                    } finally {
                        inFlightVolumes.remove(seq, job);
                    }
                }));
            }
            return;
        }

        // 无 logdb（仅 PCAP）：没有后台收尾，直接登记这一卷（pcap 文件名已经带窗口时间戳）
        if (this.logDb == null) {
            recordClosedVolume(seq, pcapPath, startMs, endMs, volumeCaptured.get(),
                    complete ? "complete" : "partial");
        }
    }

    /**
     * 整卷收尾：排空旧卷队列、闩存计数、写 manifest、CHECKPOINT/close、更名。
     * <p>
     * 由 {@code boundary} 的后台写库线程或 {@code shutdown} 时的抓包线程执行。
     * 全程只触碰 job 里固化的旧 handler / 旧连接 / 旧路径，绝不读任何会被下一个卷改写的字段。
     * </p>
     *
     * @return 本卷在快照之外丢弃（应入 {@code droppedAfterSignal}）的包数
     */
    private long closeVolumeJob(VolumeCloseJob job) {
        long discardedOutsideSnapshot = 0;
        long committedCount = 0;
        try {
            PacketDBEventHandler handler = job.handler;
            if (handler == null) {
                // 理论不可达：父方法只在 oldConn != null 时建 job，而 setLogDb 会建 handler。
                logger.warn("[JShark] Volume {} close skipped: no DB handler (unexpected)", job.seq);
                return 0;
            }

            // 1) 把旧卷队列排空落库。旧卷已摘引、不再有新包，故排空后队列为空。
            //    预算：boundary 时沿用旧语义（flushTimeout<=0 即不限）；shutdown 时受总预算约束。
            discardedOutsideSnapshot = handler.drainSnapshot(flushDeadlineMs());
            committedCount = handler.committedPackets();

            // 2) 先把计数闩存并累计进运行级总计，再 shutdown handler（队列已空，不会遗弃）。
            packetLogger.latchVolumeCountersExternal(handler);
            handler.shutdown(shutdownDeadlineMs());

            // 3) 停机卷的 end = 按下 CTRL+C 的时刻（boundary 卷仍是网格边界）。
            //    必须在写 manifest / 更名之前算好：文件名与 manifest.endMs 必须是同一个值。
            if ("shutdown".equals(job.closedReason)) {
                job.endMs = computeEndMs(job.startMs, stopAtMs, job.windowEndMs);
                logger.info("[JShark] Shutdown volume end = {} (stop requested at {})",
                        SplitUtil.formatTimestamp(job.endMs), SplitUtil.formatTimestamp(stopAtMs));
            }

            // 4) 写 manifest（写入本卷 db 的 JSharkManifest 表，用旧连接）
            writeManifest(job, committedCount, job.droppedAfterSignalSnapshot + discardedOutsideSnapshot);
        } catch (Throwable t) {
            logger.error("[JShark] Volume {} finalize failed", job.seq, t);
        } finally {
            // 5) 无论如何都要把尾部做完：FORCE CHECKPOINT → close → rename。
            //    这是本方案的核心保证：即使排空失败/超时，文件也一定不再是 "-capturing"。
            finishNow(job);
        }
        // 6) 记录已收尾卷（采集 UI 的分卷表）：优先用更名后的最终文件，更名失败则退回原路径。
        String file = job.path;
        if (windows != null) {
            String finalPath = windows.finalFileFor(job.startMs, job.endMs);
            if (finalPath != null && new java.io.File(finalPath).isFile()) {
                file = finalPath;
            }
        }
        recordClosedVolume(job.seq, file, job.startMs, job.endMs, committedCount,
                job.complete ? "complete" : "partial");
        return discardedOutsideSnapshot;
    }

    /**
     * 把本卷的 manifest 写进该卷 db 的 {@code JSharkManifest} 表。
     * <p>必须在 {@code FORCE CHECKPOINT + close} 之前调用（写入的是同一个库文件）。</p>
     */
    private void writeManifest(VolumeCloseJob job, long committedCount, long droppedAfterSnapshot) {
        if (windows == null || job.conn == null) {
            return;
        }
        try {
            VolumeManifest manifest = new VolumeManifest(job.seq, job.startMs, job.endMs);
            manifest.packetCount(committedCount);
            manifest.closed(job.complete, job.closedReason);
            manifest.dropped("afterSnapshot", droppedAfterSnapshot);
            manifest.dropped("inFlight", droppedInFlight.get());
            manifest.dropped("noPort", droppedNoPort.get());
            // 本卷自己的两项：直接读本卷 handler（每卷独立，无跨卷竞态）。
            manifest.dropped("queueAtShutdown", job.handler != null ? job.handler.abandonedAtShutdown() : 0);
            manifest.dropped("queueFull", job.handler != null ? job.handler.droppedQueueFull() : 0);
            // 以下三项是"截至本卷关闭的累计量"（名字里的 Cum 即 cumulative）：
            manifest.dropped("afterVolumeCloseCum", packetLogger.droppedAfterVolumeClose());
            manifest.dropped("enqueueFailedCum", packetLogger.failedToEnqueue());
            manifest.dropped("commitFailedCum", packetLogger.failedToCommit());
            manifest.dropped("parseStallDroppedCum", droppedParseStall.get());
            manifest.dropped("parseTaskFailedCum", failedParseTasks.get());
            manifest.dropped("parseBarrierTimeoutEventsCum", parseBarrierTimeoutEvents.get());
            manifest.dropped("fragTimeout", 0);
            manifest.dropped("streamTimeout", 0);
            manifest.put("splitIntervalMs", splitIntervalMs);
            manifest.put("pcapEnabled", packetLogger.isPcapEnabled());
            manifest.put("logdbEnabled", true);
            manifest.writeToDb(job.conn);
            logger.info("[JShark] Volume finished: seq={}, window=[{} .. {}), packets={}, complete={}, reason={}",
                    job.seq, SplitUtil.formatTimestamp(job.startMs), SplitUtil.formatTimestamp(job.endMs),
                    committedCount, job.complete, job.closedReason);
        } catch (Throwable t) {
            logger.warn("[JShark] Failed to write manifest into volume {}: {}", job.seq, t.getMessage());
        }
    }

    /**
     * 执行尾部动作（幂等）：{@code FORCE CHECKPOINT → close → rename}。
     * <p>
     * 正常收尾与兜底接管都走这里；{@code tailLock + tailDone} 保证只有一个线程真正执行，
     * 不会出现"一边 close 一边 checkpoint"的致命并发。
     * </p>
     */
    private void finishNow(VolumeCloseJob job) {
        job.tailLock.lock();
        try {
            finishTailLocked(job);
        } finally {
            job.tailLock.unlock();
        }
    }

    /**
     * 带超时的尾部动作：拿不到锁（说明正常收尾正在做）就直接放弃，绝不阻塞。
     *
     * @return true 表示本次调用真的完成了 checkpoint+close+rename
     */
    private boolean finishNowQuietly(VolumeCloseJob job, long waitMs) {
        boolean locked;
        try {
            locked = job.tailLock.tryLock(waitMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
        if (!locked) {
            return false;
        }
        try {
            return finishTailLocked(job);
        } finally {
            job.tailLock.unlock();
        }
    }

    private boolean finishTailLocked(VolumeCloseJob job) {
        if (job.tailDone) {
            return false;
        }
        try {
            closeLogDbConn(job.conn, job.seq);
        } finally {
            // 更名必须在 close 之后：Windows 上文件被 DuckDB 占用时无法改名。
            // 失败只记 WARN（文件仍是 -capturing，至少数据与 WAL 都在原地，不会丢）。
            if (job.path != null && windows != null) {
                renameVolumeFile(job.path, job.startMs, job.endMs);
            }
            job.tailDone = true;
        }
        return true;
    }

    /**
     * 兜底收尾：当抓包线程没能在停机预算内跑完 {@link #finishCapture()} 时，由 shutdown hook 调用。
     * <p>
     * 只做"最后一卷"的尾部动作，<b>不</b>排空队列（那是正常收尾的活）：
     * </p>
     * <ol>
     *   <li>当前卷还没被摘离（抓包线程卡在 finalize 之前）→ 接过来直接做完；</li>
     *   <li>已经在收尾中的卷（异步任务卡在 drain/manifest）→ 抢它的尾部锁，把尾部做完；</li>
     *   <li>任何一步拿不到锁/失败都只告警，绝不阻塞进程退出。</li>
     * </ol>
     *
     * @return true 表示至少完成了一卷的 checkpoint+close+rename
     */
    public boolean forceFinalizeLastVolume() {
        if (finished) {
            return false;
        }
        boolean any = false;

        // (a) 当前卷还没被摘离：这里把它接过来
        Connection conn = this.logDbConn;
        if (conn != null) {
            String path = this.currentLogDbPath;
            PacketDBEventHandler handler = packetLogger.detachLogDb();
            this.logDbConn = null;
            this.currentLogDbPath = null;

            boolean hasWindow = windows != null && windows.isInitialized();
            long seq = hasWindow ? windows.currentSeq() : 0;
            long startMs = hasWindow ? windows.currentStartMs() : stopAtMs;
            long windowEndMs = hasWindow ? windows.currentEndMs() : stopAtMs;

            if (handler != null) {
                // 先刹住落库，否则 checkpoint/close 会与正在跑的 appender 并发
                handler.forceClose(300);
                packetLogger.latchVolumeCountersExternal(handler);
            }

            VolumeCloseJob job = new VolumeCloseJob(seq, startMs, windowEndMs, false, "shutdown",
                    conn, path, handler, droppedAfterSignal);
            job.endMs = computeEndMs(startMs, stopAtMs, windowEndMs);
            inFlightVolumes.put(seq, job);
            try {
                if (handler != null) {
                    writeManifest(job, handler.committedPackets(), droppedAfterSignal);
                }
            } catch (Throwable t) {
                logger.warn("[JShark] Forced manifest write failed for volume {}: {}", seq, t.getMessage());
            }
            try {
                any |= finishNowQuietly(job, 500);
            } finally {
                inFlightVolumes.remove(seq, job);
            }
        }

        // (b) 已经在收尾中的卷：抢尾部锁，把还没做的尾部补上
        for (VolumeCloseJob job : new java.util.ArrayList<>(inFlightVolumes.values())) {
            if (job.tailDone) {
                continue;
            }
            if (job.handler != null) {
                job.handler.forceClose(200);
            }
            any |= finishNowQuietly(job, 300);
        }

        if (any) {
            logger.warn("[JShark] Forced finalize of the last volume: CHECKPOINT + close + rename completed "
                    + "by the shutdown hook (the normal shutdown path did not finish in time)");
        } else {
            logger.warn("[JShark] Forced finalize found nothing to do (already finalized, or another thread holds the tail)");
        }
        return any;
    }

    /**
     * 关闭一个（异步任务专属的）logdb 连接：先结束挂起事务 + FORCE CHECKPOINT，再 close。
     * <p>等价于 {@link #closeLogDb()}，但操作的是后台任务捕获的旧连接（不碰 live 字段）。</p>
     */
    private void closeLogDbConn(Connection conn, long seq) {
        if (conn == null) {
            return;
        }
        try {
            if (!conn.isClosed()) {
                try {
                    if (!conn.getAutoCommit()) {
                        conn.rollback();
                    }
                } catch (SQLException e) {
                    logger.debug("[JShark] rollback before close failed (vol {}): {}", seq, e.getMessage());
                }
                try (Statement stmt = conn.createStatement()) {
                    stmt.execute("FORCE CHECKPOINT");
                } catch (SQLException e) {
                    logger.debug("[JShark] FORCE CHECKPOINT failed (vol {}), closing anyway: {}", seq, e.getMessage());
                }
                logger.info("[JShark] logdb closed (last volume seq={})", seq);
            }
        } catch (SQLException e) {
            logger.warn("[JShark] Error closing database connection (vol {}): {}", seq, e.getMessage());
        } finally {
            try {
                if (!conn.isClosed()) {
                    conn.close();
                }
            } catch (SQLException e) {
                logger.warn("[JShark] Failed to close logdb connection (vol {}): {}", seq, e.getMessage());
            }
        }
    }

    /**
     * 等待所有已提交的卷收尾任务完成（若没有任务则立即返回）。
     * <p>
     * 用于停机收尾：必须等所有后台写库线程把旧卷写完、关连接、更名后才打印
     * 停机统计 —— 否则 committed 等跨卷总计会被写库线程的进度低估，账目对不上。
     * </p>
     */
    private void awaitVolumeCloseTasks() {
        // 用整段收尾的 deadline（而不是 drain 的 deadline）：尾部动作已经留过预留，
        // 这里等的是"旧卷的后台收尾"，不能再无上限地等。
        long deadline = shutdownDeadlineMs();
        for (java.util.concurrent.Future<Long> f : volumeCloseFutures) {
            try {
                long discarded;
                if (deadline == Long.MAX_VALUE) {
                    discarded = f.get(); // 未开始收尾且未配置 flush 超时：等全部写完
                } else {
                    long remain = deadline - System.currentTimeMillis();
                    if (remain <= 0) {
                        logger.warn("[JShark] Timed out waiting for volume close task; it may still be writing");
                        break;
                    }
                    discarded = f.get(remain, java.util.concurrent.TimeUnit.MILLISECONDS);
                }
                droppedAfterSignal += discarded;
            } catch (Exception e) {
                logger.error("[JShark] Volume close task failed/interrupted", e);
            }
        }
        volumeCloseFutures.clear();
        volumeCloseExecutor.shutdown();
    }

    /**
     * 把"捕获中"（-capturing）的 logdb 卷文件更名为最终文件名（{@code <start>-<end>}）。
     * <p>与旧版本的 {@code renameLogDbVolume} 等价，但改用传入的旧路径（异步任务不能读
     * {@code currentLogDbPath}——它已被下一个卷改写）。</p>
     *
     * @param fromPath 旧卷的"捕获中"文件路径
     * @param startMs  窗口起始时刻
     * @param endMs    窗口结束边界
     */
    private void renameVolumeFile(String fromPath, long startMs, long endMs) {
        if (windows == null || fromPath == null) {
            return;
        }
        try {
            java.io.File from = new java.io.File(fromPath);
            if (!from.exists()) {
                logger.warn("[JShark] Rename skipped: volume file not found {} (was it never created?)",
                        fromPath);
                return;
            }
            java.io.File to = new java.io.File(windows.finalFileFor(startMs, endMs));
            if (to.exists()) {
                java.nio.file.Files.deleteIfExists(to.toPath());
            }
            java.nio.file.Files.move(from.toPath(), to.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            logger.info("[JShark] Volume {} closed and renamed to {}", from.getName(), to.getName());
        } catch (Exception e) {
            logger.warn("[JShark] Failed to rename volume {} to final name: {}", fromPath, e.getMessage());
        }
    }

    /**
     * 打开新窗口的 PCAP 与 logdb。
     *
     * @param seq     卷序号
     * @param startMs 窗口起始时刻
     */
    private void openVolume(long seq, long startMs) {
        currentLogDbPath = windows.fileFor(startMs);
        volumeCaptured.set(0);
        // PCAP 与 logdb 使用同一个窗口时间戳 —— 这是"两个输出文件集合时间戳一致"的保证
        if (packetLogger.isPcapEnabled()) {
            packetLogger.openPcap(windows.pcapFor(startMs));
        }
        if (this.logDb != null) {
            try {
                String connectURL = "jdbc:duckdb:" + currentLogDbPath;
                logDbConn = DriverManager.getConnection(connectURL, "", "");
                logDbConn.setAutoCommit(false);
                initializeLogDbSchema(logDbConn);
                logDbVolumeSeq = (int) seq;
                // 顺序很重要：setLogDb() 会（在上卷已关闭时）**新建** handler，
                // 而 resetCommittedCount()/setVolumeSeq() 对 null handler 是 no-op。
                // 早期顺序是 reset → setVolumeSeq → setLogDb，于是卷 ≥2 的 volumeSeq 列
                // 全部写成默认值 0（语义是"未启用分卷"），归档数据里就再也认不出卷号。
                packetLogger.setLogDb(logDbConn);
                // 每卷独立计数：manifest 里报的是"该卷内落库的包数"
                packetLogger.resetCommittedCount();
                packetLogger.setVolumeSeq(logDbVolumeSeq);
                logger.info("[JShark] Opened volume seq={} at {}", seq, currentLogDbPath);
            } catch (SQLException e) {
                logger.error("Failed to open volume {}: {}", currentLogDbPath, e.getMessage());
            }
        }
    }

    public long getLogDBSequence()
    {
        return this.logDBSequence.incrementAndGet();
    }
}
