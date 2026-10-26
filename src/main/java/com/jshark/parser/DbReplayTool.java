package com.jshark.parser;

import com.jshark.PacketCaptureException;
import org.duckdb.DuckDBDriver;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import com.alibaba.fastjson2.JSON;

/**
 * DB重放工具 - 读取DuckDB文件并按时间戳重放消息
 * 支持参数：--db &lt;dbfile&gt; --speed &lt;重放倍数&gt; --start &lt;绝对开始时间&gt; --end &lt;绝对结束时间&gt;
 *          --sourceIp &lt;&gt; --destinationIp &lt;&gt; --sourcePort &lt;&gt; --destinationPort &lt;&gt;
 *          --replayTargetMapping &lt;SrcIP:SrcPort-DestIP:DestPort,...&gt;
 */
public class DbReplayTool {
    private static final Logger logger = LoggerFactory.getLogger(DbReplayTool.class);

    private final String dbFile;
    private final double speedMultiplier;
    // --start/--end：天文（绝对捕获）时间，epoch 毫秒，直接作用于 TimeStamp 列。
    private final Long startAtMs;
    private final Long endAtMs;
    // 第一帧的绝对时间戳（从数据库查询得到）
    private Long firstPacketTimestamp;
    // 最后一帧的绝对时间戳（从数据库查询得到）
    private Long lastPacketTimestamp;
    private final String sourceIpFilter;
    private final String destinationIpFilter;
    private final Integer sourcePortFilter;
    private final Integer destinationPortFilter;
    private final String ipProtocolFilter;
    private final String appProtocolFilter;
    private final String expressionFilter;
    
    // 目标映射（支持通配符和逗号分隔多个映射）
    private final TargetMapping targetMapping;

    // ========== 帧级重放（可选，默认关闭以保持向后兼容） ==========

    /** 是否启用帧级重放（把 frameData 原样注入网卡） */
    private boolean frameMode = false;
    /** 帧级重放的注入网卡 */
    private PcapNetworkInterface injectionInterface;
    /** 帧级重放的帧改写器 */
    private FrameRewriter frameRewriter;
    /** 帧级重放：最近一次运行的引擎（用于报告） */
    private FrameReplayEngine lastFrameEngine;
    /** 帧级重放：累计统计结果 */
    private FrameReplayEngine.Result frameResult;
    
    private Connection connection;
    private NettyPacketSender packetSender;
    
    // 统计计数器（周期统计，每次printStats后重置）
    private final AtomicLong periodPackets = new AtomicLong(0);
    private final AtomicLong periodBytes = new AtomicLong(0);
    private final AtomicLong periodSuccess = new AtomicLong(0);
    /** 每 20 秒打印一次"过去这一段"的平均回放流量（MB/s） */
    private final ThroughputMeter rateMeter = new ThroughputMeter("Replay(db)", 20_000L);
    private final AtomicLong periodFailure = new AtomicLong(0);
    /** 周期内单包最大发送延迟（纳秒），打印时换算成毫秒 */
    private final AtomicLong periodMaxDelayNanos = new AtomicLong(0);
    
    // 周期ID范围跟踪（每次printStats后重置）
    private final AtomicLong periodMinId = new AtomicLong(Long.MAX_VALUE);
    private final AtomicLong periodMaxId = new AtomicLong(Long.MIN_VALUE);
    
    // 总ID范围跟踪（不重置，用于最终统计）
    private final AtomicLong totalMinId = new AtomicLong(Long.MAX_VALUE);
    private final AtomicLong totalMaxId = new AtomicLong(Long.MIN_VALUE);
    
    // 定时器
    private ScheduledExecutorService statsTimer;
    
    // 重放完成标志
    private volatile boolean replayCompleted = false;
    
    // 停止重放标志（用于CTRL+C处理）
    private volatile boolean stopRequested = false;

    /** 控制/进度通道：CLI 控制模式与 UI 使用；CLI 普通模式也可以用它只读统计。 */
    private ReplayControl control;

    /** LIVE 分卷跟随时的可用终点刷新器（2s） */
    private LiveEndWatcher liveEndWatcher;

    /**
     * 会话级的注入自检结果：由 CLI 在会话首段算好并注入，seek 重开段直接复用。
     *
     * <p>自检会真实发一帧探测包，每段重跑一次既浪费也会在 seek 时多打一帧。</p>
     */
    private StartupSelfCheck.Result startupCheck;

    // 是否已初始化重放时钟（保证跨分卷发送节奏连续）
    private boolean replayClockStarted = false;

    // ========== 精确倍率重放时钟（跨分卷共享，保证节奏连续） ==========

    /** 重放时钟：严格仿射倍率、绝不提前发送、落后不补睡 */
    private ReplayClock replayClock = null;
    /** 首个被实际重放的包的时间（跨分卷全局，用于计算理想总时长） */
    private ReplayClock.PacketTime firstReplayedPacketTime = null;
    /** 最后一个被实际重放的包的时间（跨分卷全局） */
    private ReplayClock.PacketTime lastReplayedPacketTime = null;
    /** 重放墙钟起点（锚定首个包发送那一刻，纳秒） */
    private long replayStartNano = 0;
    /** 重放墙钟终点（纳秒） */
    private long replayEndNano = 0;
    /** 已累计的实测墙钟耗时（纳秒），分卷模式下按段累加，剔除等待新分卷的空闲期 */
    private long measuredElapsedNanos = 0;

    // ========== 自适应降速（--speed 是上限，不是承诺） ==========

    /** 是否启用自适应降速；false 仅用于测试固定倍率（命令行已不再提供关闭入口） */
    private boolean adaptiveSpeedEnabled = true;

    /**
     * 自适应倍率控制器。与 {@link #replayClock} 同生命周期：跨分卷共享，
     * 因为时间轴本身也是跨分卷共享的。
     */
    private AdaptiveSpeedController speedController = null;

    // ========== 滚动跟随（分卷模式下默认启用） ==========

    // 滚动跟随的轮询间隔（毫秒），用于探测新分卷是否出现
    private long followPollIntervalMs = DEFAULT_FOLLOW_POLL_MS;
    private static final long DEFAULT_FOLLOW_POLL_MS = 2000L;
    
    /**
     * 完整构造函数，支持绝对时间窗口、过滤器与目标映射（SrcIP:SrcPort-DestIP:DestPort格式）。
     *
     * @param dbFile               数据库文件
     * @param speedMultiplier      重放倍率
     * @param startAtMs            开始捕获时间（绝对，epoch 毫秒）；null 表示不限
     * @param endAtMs              结束捕获时间（绝对，epoch 毫秒）；null 表示不限
     * @param sourceIpFilter       源 IP 过滤
     * @param destinationIpFilter  目的 IP 过滤
     * @param sourcePortFilter     源端口过滤
     * @param destinationPortFilter 目的端口过滤
     * @param ipProtocolFilter     IP 协议过滤
     * @param appProtocolFilter    应用协议过滤
     * @param expressionFilter     表达式过滤
     * @param targetMappingStr     目标映射
     */
    public DbReplayTool(String dbFile, double speedMultiplier,
                       Long startAtMs, Long endAtMs,
                       String sourceIpFilter, String destinationIpFilter,
                       Integer sourcePortFilter, Integer destinationPortFilter,
                       String ipProtocolFilter, String appProtocolFilter,
                       String expressionFilter,
                       String targetMappingStr) {
        this.dbFile = dbFile;
        this.speedMultiplier = speedMultiplier;
        this.startAtMs = startAtMs;
        this.endAtMs = endAtMs;
        this.sourceIpFilter = sourceIpFilter;
        this.destinationIpFilter = destinationIpFilter;
        this.sourcePortFilter = sourcePortFilter;
        this.destinationPortFilter = destinationPortFilter;
        this.ipProtocolFilter = ipProtocolFilter;
        this.appProtocolFilter = appProtocolFilter;
        this.expressionFilter = expressionFilter;
        this.control = new ReplayControl(speedMultiplier);
        
        // 解析目标映射
        this.targetMapping = TargetMapping.parse(targetMappingStr);
        
        // 打印映射信息
        List<String> descs = this.targetMapping.getDescriptions();
        for (String desc : descs) {
            logger.info("Target mapping: {}", desc);
        }
    }

    /**
     * 启用帧级重放：把数据库里的 {@code frameData} 原样注入网卡。
     *
     * <p>与载荷模式相比，帧级重放保真度本质不同：源 IP/源端口/seq/ack/TTL/分片结构
     * 都按原值发出，且<b>双方向全部重放</b>，被动采集器看到的内容与直接读原始 pcap 一致。
     * 数据库中无完整帧的记录（TCP 重组体、缓冲区冲刷体）会被跳过并计数。</p>
     *
     * @param injectionInterface 注入网卡
     * @param macPolicy          目的 MAC 策略；null 视为 {@code preserve}
     * @param unicastResolver    单播 MAC 解析器；可为 null
     */
    public void enableFrameMode(PcapNetworkInterface injectionInterface,
                                FrameRewriter.MacPolicy macPolicy,
                                java.util.function.Function<String, byte[]> unicastResolver) {
        this.frameMode = true;
        this.injectionInterface = injectionInterface;
        this.frameRewriter = new FrameRewriter(macPolicy, unicastResolver);
    }

    /**
     * 设置滚动跟随模式的轮询间隔（毫秒）。
     *
     * @param ms 轮询间隔（毫秒），必须大于 0
     */
    public void setFollowPollIntervalMs(long ms) {
        if (ms > 0) {
            this.followPollIntervalMs = ms;
        }
    }

    /**
     * 是否启用自适应降速（默认启用）。
     *
     * <p>启用时 {@code --speed} 是<b>上限</b>：发送方跟不上就自动降速（AIMD，下限 0.1x），
     * 用"慢一点但保持包间隔"换取时序保真。命令行始终启用自适应，已不提供关闭入口；
     * 本方法仅供内部/回归测试固定倍率使用。</p>
     *
     * @param enabled false 表示禁用自适应降速（仅测试）
     */
    public void setAdaptiveSpeedEnabled(boolean enabled) {
        this.adaptiveSpeedEnabled = enabled;
    }

    /**
     * 连接到指定的分卷文件
     *
     * @param file DuckDB 文件路径（单个时间分卷）
     */
    private void connectTo(String file) throws SQLException {
        // 使用只读模式连接DuckDB，防止重放过程中意外修改数据库
        String url = "jdbc:duckdb:" + file;
        java.util.Properties props = new java.util.Properties();
        props.setProperty("duckdb.read_only", "true");
        props.setProperty(DuckDBDriver.JDBC_STREAM_RESULTS, String.valueOf(true));
        connection = DriverManager.getConnection(url, props);
        logger.info("Connected to database: {} (read-only mode)", file);
    }
    
    /**
     * 关闭数据库连接
     */
    private void disconnect() {
        if (connection != null) {
            try {
                connection.close();
                logger.info("Database connection closed");
            } catch (SQLException e) {
                logger.error("Error closing database connection", e);
            }
        }
    }
    
    /**
     * 从ResultSet读取rawData列，支持多种类型
     * 参考AdditionalInfoParser中的实现
     */
    private static byte[] readRawData(ResultSet rs) throws SQLException {
        Object obj = rs.getObject("rawData");
        if (obj == null) {
            return null;
        }
        if (obj instanceof Blob blob) {
            return blob.getBytes(1, (int) blob.length());
        } else if (obj instanceof byte[]) {
            return (byte[]) obj;
        } else {
            // 其他类型尝试转换为字节数组
            logger.warn("Unexpected rawData type: {}, attempting to convert", obj.getClass().getName());
            return obj.toString().getBytes();
        }
    }
    
    /**
     * 开始重放
     */
    public void startReplay() {
        if (frameMode) {
            replayFramesFromDatabase();
            return;
        }
        try {
            // 初始化Netty发送器
            packetSender = new NettyPacketSender();

            // 初始化精确倍率重放时钟：跨分卷共享，整条时间轴由首个被重放的包锚定
            replayClock = new ReplayClock(speedMultiplier, null, null);
            // 自适应降速控制器：目标倍率是用户给的上限，实际倍率由可持续性决定
            speedController = new AdaptiveSpeedController(speedMultiplier, adaptiveSpeedEnabled);
            control.setAdaptive(adaptiveSpeedEnabled);
            control.speedObserved(speedMultiplier, speedMultiplier);
            control.minSpeedObserved(speedMultiplier);
            logger.info("[Adaptive Speed] mode: {}", adaptiveSpeedEnabled
                    ? "adaptive (--speed " + speedMultiplier + "x is an upper bound; floor "
                      + AdaptiveSpeedController.SPEED_FLOOR + "x)"
                    : "exact (internal test switch: fixed " + speedMultiplier + "x, late packets stay late)");

            // 启动统计定时器（每5秒打印一次）
            startStatsTimer();

            // 分卷模式下默认滚动跟随（capture 持续产生新卷时，replay 持续跟随）；
            // 非分卷模式下回放完毕即退出。
            boolean splitMode = SplitUtil.isSplitMode(dbFile);
            control.setLive(false, splitMode);
            control.setWaitingForData(splitMode);
            // 窗口是“整段会话”的属性，而 seek 会重建本工具并再次执行到这里：
            // 起点只能建立一次、终点上限只能收紧（见 ReplayControl#windowStartIfUnset）。
            // 这里只落用户显式给定的边界，数据终点由 replayPacketsDirectly / LiveEndWatcher 补齐。
            if (startAtMs != null) {
                control.windowStartIfUnset(startAtMs);
            }
            if (endAtMs != null) {
                control.limitWindowTo(endAtMs);
                control.setWindowTo(endAtMs);
            }
            if (splitMode) {
                // LIVE：Start 之后每 2s 刷新一次可用终点；暂停时也刷新。
                liveEndWatcher = new LiveEndWatcher(dbFile, control, 2_000L);
                liveEndWatcher.start();
                // 分卷模式：持续发现 capture 新生成的时间分卷并回放，直到停止
                runFollowReplay();
            } else {
                // 非分卷模式：回放单个数据库文件后退出
                List<String> volumes = SplitUtil.discoverVolumes(dbFile);
                for (String volume : volumes) {
                    if (stopRequested) {
                        logger.info("Replay stopped by user before volume: {}", volume);
                        break;
                    }
                    logger.info("[JShark] Replaying volume: {}", volume);
                    connectTo(volume);
                    replayPacketsDirectly();
                    disconnect();
                }
            }

            // 回放完成后，设置完成标志并停止统计定时器
            replayCompleted = true;
            printStats();
            reportTiming();
            
        } catch (SQLException e) {
            logger.error("Database error during replay", e);
            control.reportError(e);
        } finally {
            if (liveEndWatcher != null) {
                liveEndWatcher.stop();
                liveEndWatcher = null;
            }
            // 停止统计定时器
            stopStatsTimer();
            // 关闭Netty发送器（只在finally中执行一次，避免重复日志）
            if (packetSender != null) {
                packetSender.shutdown();
            }
            disconnect();
        }
    }

    /**
     * 累积"已完成的重放段落"的墙钟耗时。
     * <p>
     * 分卷模式（滚动跟随）下，两次回放之间会有等待新分卷的空闲期，
     * 若把空闲期算进耗时，实测倍率会被严重低估。因此每次
     * {@link #replayPacketsDirectly()} 结束时把该段的墙钟耗时累加进来。
     * </p>
     */
    private void accumulateMeasuredElapsed() {
        if (replayEndNano > replayStartNano) {
            measuredElapsedNanos += (replayEndNano - replayStartNano);
        }
        replayStartNano = 0;
        replayEndNano = 0;
    }
    
    /**
     * 停止重放（由CTRL+C处理调用）
     */
    public void stopReplay() {
        logger.info("[JShark] Stopping replay...");
        stopRequested = true;
        control.requestStop();
    }

    /**
     * 注入控制/进度通道（CLI 控制模式/UI）。未注入时使用内部默认实例。
     *
     * @param control 控制通道；null 表示忽略
     */
    public void setControl(ReplayControl control) {
        if (control != null) {
            this.control = control;
        }
    }

    /** @return 当前控制/进度通道 */
    public ReplayControl control() {
        return control;
    }

    /**
     * 注入会话级的注入自检结果（由 CLI 在会话首段算好后复用）。
     *
     * @param check 自检结果；null 表示不启用缓存（工具不会自行补跑，见调用方）
     */
    public void setStartupCheck(StartupSelfCheck.Result check) {
        this.startupCheck = check;
    }

    /**
     * 滚动跟随重放主循环。
     *
     * <p>与一次性模式不同，本方法在读完已发现的分卷后不会退出，而是持续轮询
     * {@link SplitUtil#discoverVolumes} 探测 capture 新生成的时间分卷，并按时间顺序继续回放，
     * 实现“一边抓包一边延时回放”的直播式场景（需配合 {@code --split} 使用）。</p>
     *
     * <p><b>就绪判定（前提是用户配置正确：正确的 --split、正确的 --speed、正确的延时）</b>：</p>
     * <ul>
     *   <li>本循环<b>只回放「不是最新分卷」的卷</b>，即存在一个文件名时间戳更晚的分卷。
     *       这保证该卷已被 capture 轮转关闭（close 前会 FORCE CHECKPOINT），可安全只读；</li>
     *   <li>最新分卷被 capture 持续写入，<b>永远不会</b>被本循环读取——它要等到后续更晚的分卷出现
     *       才被视为已关闭并被回放；</li>
     *   <li>若 capture 已结束、没有更新的分卷出现，则最新卷不会被自动回放，进程持续等待，
     *       由用户 Ctrl+C 结束。程序不会用启发式猜测“该卷是否已关闭”而去读取仍在写入的卷。</li>
     * </ul>
     *
     * <p><b>失败即终止（fail-fast）</b>：在正确的配置下，replay 永远只读已关闭的旧卷，
     * 理论上<b>绝不会</b>与 capture 发生文件锁冲突。若打开某个本应已关闭的分卷时抛出异常
     * （尤其是锁冲突，意味着读到了 capture 仍在写入的卷），说明程序逻辑或用户配置错误——
     * 这属于使用问题，程序直接<b>终止整个重放并报错</b>，而<b>不跳过</b>该卷（跳过会造成数据缺失）。</p>
     */
    private void runFollowReplay() {
        long pollMs = followPollIntervalMs;
        logger.info("[JShark][FOLLOW] Split-mode rolling-follow enabled (default for --split volumes). "
                + "Watching {} for new volumes every {} ms.", dbFile, pollMs);

        // 已完整回放的分卷（绝对路径），避免重复读取
        Set<String> processed = new HashSet<>();

        boolean failed = false;
        boolean anyReplayed = false;
        boolean waitingLogged = false;
        // --end 到达后结束重放（不再继续 follow）
        boolean endReached = false;

        while (!stopRequested && !control.shouldStop() && !control.hasPendingSeek()) {
            List<String> volumes = SplitUtil.discoverVolumes(dbFile);
            boolean live = hasCapturingVolume();
            control.setLive(live, true);
            if (volumes.isEmpty()) {
                control.setWaitingForData(true);
                if (!waitingLogged) {
                    logger.info("[JShark][FOLLOW] No volumes found yet, waiting for capture to produce data...");
                    waitingLogged = true;
                }
                idleSleep(pollMs);
                continue;
            }

            // --start/--end：只回放文件名时间戳（卷窗口起点）落在窗口内的卷。
            // 未设置时 inWindow == volumes（不缩小范围）。
            List<String> inWindow =
                    SplitUtil.selectVolumesInCaptureWindow(volumes, startAtMs, endAtMs);
            if (inWindow.isEmpty()) {
                // end 位于过去、且最早的卷起点已越过 end：之后只会有更晚的卷，
                // 绝无窗口内数据，直接结束（"到了时间就退出"），避免无限等待。
                if (endAtMs != null) {
                    Long oldestTs = SplitUtil.earliestVolumeStart(volumes);
                    if (oldestTs != null && oldestTs > endAtMs) {
                        logger.info("[JShark][FOLLOW] --end reached: the earliest volume start {} "
                                        + "is already past the absolute end {}, stopping replay.",
                                new java.sql.Timestamp(oldestTs),
                                new java.sql.Timestamp(endAtMs));
                        endReached = true;
                        control.markEndReached();
                        stopRequested = true;
                        break;
                    }
                }
                control.setWaitingForData(true);
                if (!waitingLogged) {
                    logger.info("[JShark][FOLLOW] No volume within the --start/--end window "
                            + "is ready yet. Waiting for capture to produce the target time slice...");
                    waitingLogged = true;
                }
                idleSleep(pollMs);
                continue;
            }

            // 最新分卷可能仍在被 capture 写入，绝不会被本循环读取。
            // 只回放“存在更晚分卷、因此已被 capture 关闭”的卷，保证不产生锁冲突。
            String globalNewest = volumes.get(volumes.size() - 1);
            String toReplay = null;
            for (String v : inWindow) {
                if (v.equals(globalNewest)) {
                    // 仍在被写入，跳过（安全起见）
                    continue;
                }
                if (!processed.contains(v)) {
                    toReplay = v;
                    break;
                }
            }

            if (toReplay == null) {
                // 没有已关闭且未处理的分卷（已追平到最新仍在写入的卷），等待新分卷出现
                control.setWaitingForData(true);
                if (!waitingLogged) {
                    logger.info("[JShark][FOLLOW] No closed volume ready yet "
                            + "(caught up to the in-progress volume). Waiting for capture to rotate out "
                            + "a new closed volume...");
                    waitingLogged = true;
                }
                idleSleep(pollMs);
                continue;
            }

            // 回放已关闭的分卷；任何异常均视为失败，直接终止（不跳过，避免丢数据）。
            waitingLogged = false;
            control.setWaitingForData(false);
            try {
                logger.info("[JShark][FOLLOW] Replaying volume: {}", toReplay);
                connectTo(toReplay);
                replayPacketsDirectly();
                disconnect();
                processed.add(toReplay);
                anyReplayed = true;

                // 指定了 --end 时：当前分卷的最大包捕获时间戳已到达/越过结束边界，
                // 说明 [*, end] 内的数据已被全部覆盖，之后的分卷只有 end 之后的数据，
                // 已在 SQL 中过滤，因此直接退出、不再 follow。
                if (endAtMs != null
                        && lastPacketTimestamp != null
                        && lastPacketTimestamp >= endAtMs) {
                    logger.info("[JShark][FOLLOW] --end reached (volume max {} >= absolute end {}), "
                                    + "stopping replay.",
                            new java.sql.Timestamp(lastPacketTimestamp),
                            new java.sql.Timestamp(endAtMs));
                    endReached = true;
                    control.markEndReached();
                    stopRequested = true;
                }
            } catch (SQLException e) {
                disconnect();
                if (isLockConflict(e)) {
                    // 锁冲突是异常状况：本应只读已关闭的旧卷，却读到了 capture 仍在写入的卷，
                    // 说明程序逻辑或用户配置（--split/--speed/延时）有误——使用问题。
                    // 跳过会造成数据缺失，故直接终止。
                    logger.error("[JShark][FOLLOW] FATAL: lock conflict opening volume {}. "
                                    + "This should NOT happen with correct --split/--speed/delay configuration, "
                                    + "and indicates a logic or user-configuration error "
                                    + "(a still-being-written volume was read). "
                                    + "Terminating replay instead of skipping to avoid silent data loss. "
                                    + "Detail: {}", toReplay, e.getMessage(), e);
                } else {
                    logger.error("[JShark][FOLLOW] FATAL: SQL error replaying volume {}. "
                                    + "Terminating replay to avoid silent data loss. Detail: {}",
                            toReplay, e.getMessage(), e);
                }
                failed = true;
                control.reportError(e);
                stopRequested = true;
            } catch (Exception e) {
                disconnect();
                logger.error("[JShark][FOLLOW] FATAL: unexpected error replaying volume {}. "
                        + "Terminating replay. Detail: {}", toReplay, e.getMessage(), e);
                failed = true;
                control.reportError(e);
                stopRequested = true;
            }
        }

        if (failed) {
            logger.error("[JShark][FOLLOW] Replay terminated due to the error above.");
        } else if (endReached) {
            logger.info("[JShark][FOLLOW] Replay finished after reaching --end, following {} volume(s).",
                    processed.size());
        } else if (anyReplayed) {
            logger.info("[JShark][FOLLOW] Replay stopped by user after following {} volume(s).", processed.size());
        } else {
            logger.info("[JShark][FOLLOW] Replay stopped by user before any volume was replayed.");
        }
    }

    /**
     * 判断 SQLException 是否由 DuckDB 文件锁冲突引起。
     *
     * <p>锁冲突意味着试图打开一个仍被其他进程（此处为 capture）持有写锁/正在写入的数据库文件。
     * 在多进程时延回放场景下属于异常状况。</p>
     *
     * @param e SQL 异常
     * @return true 表示是锁冲突类错误
     */
    private static boolean isLockConflict(SQLException e) {
        if (e == null) {
            return false;
        }
        String msg = e.getMessage();
        if (msg == null) {
            msg = "";
        }
        String lower = msg.toLowerCase();
        return lower.contains("lock")
                || lower.contains("conflicting")
                || lower.contains("database is locked")
                || lower.contains("unable to open");
    }

    /**
     * 滚动跟随模式的空闲等待（可被 stop/seek 打断，避免长时间无响应）。
     *
     * @param ms 等待毫秒数
     */
    private void idleSleep(long ms) {
        long deadline = System.currentTimeMillis() + ms;
        while (System.currentTimeMillis() < deadline) {
            if (stopRequested || control.shouldStop() || control.hasPendingSeek()) {
                return;
            }
            try {
                Thread.sleep(Math.min(100L, Math.max(1L, deadline - System.currentTimeMillis())));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                stopRequested = true;
                return;
            }
        }
    }

    /** @return 目录中是否存在仍在写入的 {@code -capturing} 卷 */
    private boolean hasCapturingVolume() {
        for (String path : SplitUtil.discoverAllSplitStyle(dbFile)) {
            if (SplitUtil.isInProgressCaptureVolume(path)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 直接重放数据包（不使用Schedule和积累队列）
     */
    @SuppressWarnings("unchecked")
    private void replayPacketsDirectly() throws SQLException {
        // 分卷/滚动跟随时本方法会被反复调用；每次进入新卷先丢弃上一卷末尾与"等待新分卷"
        // 形成的观测窗口，避免整段空闲被控制器当成"发送方跟不上"（见 resetWindow 的注释）。
        if (speedController != null) {
            speedController.resetWindow();
        }
        // 查询第一帧和最后一帧的时间戳作为基本信息
        queryFirstPacketTimestamp();
        queryLastPacketTimestamp();

        // 打印时间范围信息
        if (firstPacketTimestamp != null && lastPacketTimestamp != null) {
            long durationMs = lastPacketTimestamp - firstPacketTimestamp;
            control.setDataRange(firstPacketTimestamp, lastPacketTimestamp);
            long from = startAtMs != null ? startAtMs : firstPacketTimestamp;
            long to = endAtMs != null ? endAtMs : lastPacketTimestamp;
            // 起点：只在会话首段建立。seek 重开段会以新的播放起点再次执行本方法，
            // 若允许覆盖，窗口就会随每次 seek 收缩（UI 拖动范围变小、“回到起点”失效）。
            control.windowStartIfUnset(from);
            // 终点：显式 --end 用配置值；LIVE（分卷跟随）交给 LiveEndWatcher 增长；
            // 其余有限数据源用真实末包时间补齐 —— 否则 --start 且未给 --end 时窗口终点
            // 永远未知，status.window.toMs / status.timing.etaMs 会一直是 null。
            if (endAtMs != null) {
                control.limitWindowTo(to);
                control.setWindowTo(to);
            } else if (!SplitUtil.isSplitMode(dbFile)) {
                control.setWindowTo(to);
            }
            logger.info("Replay time range: {} ~ {} (duration: {} ms = {} seconds)", 
                       new java.sql.Timestamp(firstPacketTimestamp),
                       new java.sql.Timestamp(lastPacketTimestamp),
                       durationMs, durationMs / 1000);
        }
        
        StringBuilder sql = new StringBuilder(
            "SELECT Id, TimeStamp, rawData, sourceIp, destinationIp, sourcePort, destinationPort, ipProtocol, appProtocol, additionalInfo " +
            "FROM   JSharkLog WHERE 1=1 "
        );

        List<Object> params = new ArrayList<>();
        
        // 时间范围过滤（TimeStamp 是绝对捕获时间，--start/--end 直接比较）
        if (startAtMs != null) {
            sql.append(" AND TimeStamp >= ?");
            params.add(new java.sql.Timestamp(startAtMs));
            logger.info("Start capture time filter: {}", new java.sql.Timestamp(startAtMs));
        }
        if (endAtMs != null) {
            sql.append(" AND TimeStamp <= ?");
            params.add(new java.sql.Timestamp(endAtMs));
            logger.info("End capture time filter: {}", new java.sql.Timestamp(endAtMs));
        }
        
        // IP过滤
        if (sourceIpFilter != null && !sourceIpFilter.isEmpty()) {
            sql.append(" AND sourceIp = ?");
            params.add(sourceIpFilter);
        }
        if (destinationIpFilter != null && !destinationIpFilter.isEmpty()) {
            sql.append(" AND destinationIp = ?");
            params.add(destinationIpFilter);
        }
        
        // 端口过滤
        if (sourcePortFilter != null) {
            sql.append(" AND sourcePort = ?");
            params.add(sourcePortFilter);
        }
        if (destinationPortFilter != null) {
            sql.append(" AND destinationPort = ?");
            params.add(destinationPortFilter);
        }
        
        // IP协议过滤
        if (ipProtocolFilter != null && !ipProtocolFilter.isEmpty()) {
            sql.append(" AND ipProtocol = ?");
            params.add(ipProtocolFilter);
        }
        
        // 应用协议过滤
        if (appProtocolFilter != null && !appProtocolFilter.isEmpty()) {
            sql.append(" AND appProtocol = ?");
            params.add(appProtocolFilter);
        }
        
        // 排序：(TimeStamp, Id)。
        // Id 即 ingestSeq（进程内全局单调），作为同毫秒/同微秒内多条记录的稳定次序，
        // 保证"不重排"——重排会让接收侧看到假乱序、假重传。
        sql.append(" ORDER BY TimeStamp ASC, Id ASC");
        
        try (PreparedStatement stmt = connection.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            try (ResultSet rs = stmt.executeQuery()) {
                int count = 0;
                
                // 重置ID范围
                this.periodMinId.set(Long.MAX_VALUE);
                this.periodMaxId.set(Long.MIN_VALUE);
                this.totalMinId.set(Long.MAX_VALUE);
                this.totalMaxId.set(Long.MIN_VALUE);
                
                while (rs.next()) {
                    // 检查是否收到停止信号（CTRL+C）或控制通道 stop/seek
                    if (stopRequested || control.shouldStop()) {
                        logger.info("Replay stopped by user");
                        break;
                    }
                    if (control.hasPendingSeek()) {
                        logger.info("Seek requested; abandoning current segment");
                        break;
                    }
                    
                    // 读取所有字段
                    Long id = rs.getObject("Id", Long.class);
                    java.sql.Timestamp loadTime = rs.getTimestamp("TimeStamp");
                    long loadTimeMillis = loadTime != null ? loadTime.getTime() : System.currentTimeMillis();
                    control.examined();
                    control.position(loadTimeMillis);
                    byte[] rawData = readRawData(rs);
                    String sourceIp = rs.getString("sourceIp");
                    String destinationIp = rs.getString("destinationIp");
                    Integer sourcePort = rs.getObject("sourcePort", Integer.class);
                    Integer destinationPort = rs.getObject("destinationPort", Integer.class);
                    String ipProtocol = rs.getString("ipProtocol");
                    String additionalInfoJson = rs.getString("additionalInfo");

                    // 应用表达式过滤
                    if (expressionFilter != null && !expressionFilter.isEmpty()) {
                        Map<String, Object> additionalInfo = null;
                        if (additionalInfoJson != null && !additionalInfoJson.isEmpty()) {
                            try {
                                additionalInfo = JSON.parseObject(additionalInfoJson, Map.class);
                            } catch (Exception e) {
                                logger.debug("Failed to parse additionalInfo JSON: {}", additionalInfoJson, e);
                            }
                        }
                        if (!matchesFilter(additionalInfo, expressionFilter)) {
                            // 不匹配过滤条件，跳过此数据包
                            control.filtered();
                            continue;
                        }
                    }

                    // 使用 AtomicLong 的 CAS 操作更新统计信息，无需锁保护
                    // 这样可以避免与 printStats() 定时器产生锁竞争

                    // 更新周期最小ID
                    long currentPeriodMin = this.periodMinId.get();
                    while (id < currentPeriodMin) {
                        if (this.periodMinId.compareAndSet(currentPeriodMin, id)) {
                            break;
                        }
                        currentPeriodMin = this.periodMinId.get();
                    }

                    // 更新周期最大ID
                    long currentPeriodMax = this.periodMaxId.get();
                    while (id > currentPeriodMax) {
                        if (this.periodMaxId.compareAndSet(currentPeriodMax, id)) {
                            break;
                        }
                        currentPeriodMax = this.periodMaxId.get();
                    }

                    // 更新总最小ID
                    long currentTotalMin = this.totalMinId.get();
                    while (id < currentTotalMin) {
                        if (this.totalMinId.compareAndSet(currentTotalMin, id)) {
                            break;
                        }
                        currentTotalMin = this.totalMinId.get();
                    }

                    // 更新总最大ID
                    long currentTotalMax = this.totalMaxId.get();
                    while (id > currentTotalMax) {
                        if (this.totalMaxId.compareAndSet(currentTotalMax, id)) {
                            break;
                        }
                            currentTotalMax = this.totalMaxId.get();
                    }

                    if (!replayClockStarted) {
                        replayClockStarted = true;
                        logger.info("Starting replay with speed multiplier: {}", speedMultiplier);
                    }

                    // 应用目标映射（根据源IP:源端口匹配，映射目标IP:目标端口）。
                    // 注意顺序：先做"能否发送"的判定，再进入时间轴等待 ——
                    // 被跳过的包（无效端口）不占用时间轴，否则会造成虚假的间隔。
                    TargetMapping.MappingResult mappingResult = targetMapping.apply(
                        sourceIp, sourcePort != null ? sourcePort : 0,
                        destinationIp, destinationPort != null ? destinationPort : 0
                    );
                    String sendIp = mappingResult.ip();
                    int sendPort = mappingResult.port();

                    // 跳过无效目标端口的包（端口为0表示数据库中该字段为NULL，如ICMP等非传输层协议包）
                    if (sendPort <= 0 || sendPort > 65535) {
                        logger.debug("Skipping packet with invalid destination port: {} -> {}:{} (protocol: {})",
                                    id, sendIp, sendPort, ipProtocol);
                        periodFailure.incrementAndGet();
                        control.skipped();
                        continue;
                    }

                    // ===== 精确倍率时间轴 =====
                    // 严格仿射：t_out = φ + (pktTime − anchorTime)/speed，总时长 = 首末包间隔/speed。
                    // 首个被实际重放的包锚定零点；之后每个包都相对同一锚点计算，因此：
                    //   - 无累积漂移
                    //   - 绝不提前发送（earlyCount 恒为 0）
                    //   - 落后时不补睡，只如实记录迟到量
                    ReplayClock.PacketTime packetTime = (loadTime != null)
                            ? ReplayClock.PacketTime.of(loadTime)
                            : ReplayClock.PacketTime.of(java.time.Instant.ofEpochMilli(loadTimeMillis));

                    // 本段墙钟起点：本卷第一个真正要重放的包（等待/锚定之前）。
                    // 不能只在"首次锚定"时记录——分卷模式下时钟只锚定一次，后续卷若沿用
                    // 已被清零的 replayStartNano，accumulateMeasuredElapsed 会用"当前时刻 − 0"
                    // 当成耗时，报告里的实测倍率会瞬间趋近 0。
                    if (replayStartNano == 0) {
                        replayStartNano = System.nanoTime();
                    }

                    // 统一定时检查点：消费调速 → 处理暂停（恢复后平移时间轴）→ 判断是否放弃本段
                    if (stopRequested || control.checkpoint(replayClock, speedController, true)) {
                        logger.info(control.hasPendingSeek()
                                ? "Seek requested; abandoning current segment"
                                : "Replay stopped by user");
                        break;
                    }

                    ReplayClock.Schedule schedule;
                    if (!replayClock.isAnchored()) {
                        schedule = replayClock.anchor(packetTime);
                        firstReplayedPacketTime = packetTime;
                    } else {
                        schedule = replayClock.scheduleNext(packetTime);
                        // 长等待被切成 ≤50ms 的片，便于及时响应停止/暂停/调速
                        while (schedule.waitNanos() > 0) {
                            replayClock.await(schedule);
                            if (stopRequested || control.checkpoint(replayClock, speedController, true)) {
                                break;
                            }
                            schedule = replayClock.scheduleNext(packetTime);
                        }
                    }
                    lastReplayedPacketTime = packetTime;

                    if (stopRequested || control.shouldStop()) {
                        logger.info("Replay stopped by user");
                        break;
                    }
                    if (control.hasPendingSeek()) {
                        logger.info("Seek requested; abandoning current segment");
                        break;
                    }

                    // 更新周期统计计数器（使用 AtomicLong 无锁操作）
                    periodPackets.incrementAndGet();
                    periodBytes.addAndGet(rawData == null ? 0 : rawData.length);

                    // 计算发送延迟（用于周期统计的最大延迟）
                    long scheduleDelay = schedule.latenessNanos();
                    long delay = Math.abs(scheduleDelay);
                    long currentMaxDelay = periodMaxDelayNanos.get();
                    while (delay > currentMaxDelay) {
                        if (periodMaxDelayNanos.compareAndSet(currentMaxDelay, delay)) {
                            break;
                        }
                        currentMaxDelay = periodMaxDelayNanos.get();
                    }

                    // 自适应降速：按 500ms 窗口结算"欠账增长"，必要时改写时间轴倍率。
                    // 位置在"本包已调度、尚未发送"处：setSpeed 重锚到最近调度的包（即本包），
                    // 因此下一包的间隔从此刻按新倍率拉开，绝不会为追赶而提前发送。
                    if (speedController != null) {
                        AdaptiveSpeedController.Decision decision =
                                speedController.observe(System.nanoTime(), delay);
                        if (decision.changed()) {
                            replayClock.setSpeed(decision.speed());
                            control.speedObserved(speedMultiplier, replayClock.speed());
                            control.minSpeedObserved(speedController.minSpeed());
                            control.adaptiveObserved(speedController.downCount(), speedController.upCount());
                        }
                    }

                    // 如果使用了映射，记录日志（仅首次或变化时）
                    if (!sendIp.equals(destinationIp) || sendPort != (destinationPort != null ? destinationPort : 0)) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Packet remapped: {}:{} -> {}:{}",
                                        destinationIp, destinationPort, sendIp, sendPort);
                        }
                    }
                    
                    packetSender.sendPacket(sendIp, sendPort, rawData, ipProtocol);
                    control.sent(rawData == null ? 0 : rawData.length);
                    periodSuccess.incrementAndGet();
                    replayEndNano = System.nanoTime();
                    count++;
                    // 每 20 秒打印"过去这一段"的平均回放流量（MB/s + pps）
                    rateMeter.addPacket(rawData == null ? 0 : rawData.length);
                    rateMeter.tick();
                }
                
                if (count == 0) {
                    logger.warn("No packets to replay");
                } else
                {
                    rateMeter.flush();
                    accumulateMeasuredElapsed();
                    // 获取总ID范围，处理未设置的情况
                    long minIdValue = totalMinId.get();
                    long maxIdValue = totalMaxId.get();
                    String minIdStr = (minIdValue == Long.MAX_VALUE) ? "N/A" : String.valueOf(minIdValue);
                    String maxIdStr = (maxIdValue == Long.MIN_VALUE) ? "N/A" : String.valueOf(maxIdValue);
                    
                    logger.info("Replay completed. Total packets processed: {}, Min ID: {}, Max ID: {}",
                               count, minIdStr, maxIdStr);
                    // 打印最终统计信息
                    printStats();
                }
            }
        }
    }

    /**
     * 打印重放时序报告：理想时长 / 实际时长 / 实测倍率 / 迟到统计。
     * <p>
     * <b>实测倍率</b> = 首末包原始时间差 ÷ 实际耗时。它如实反映"是否真的按目标倍率发完了"：
     * 发送能力不足、下游限速、系统抖动都会让它低于目标，此时给出 WARN 与处置建议，
     * <b>绝不伪装达标</b>。
     * </p>
     */
    private void reportTiming() {
        if (replayClock == null || firstReplayedPacketTime == null || lastReplayedPacketTime == null) {
            return;
        }
        ReplayTiming.log(logger, replayClock, speedController, speedMultiplier,
                firstReplayedPacketTime.toEpochNanos(), lastReplayedPacketTime.toEpochNanos(),
                measuredElapsedNanos);
    }

    /**
     * 帧级重放：把数据库中的 {@code frameData} 原样注入网卡。
     *
     * <h3>与载荷模式的差别</h3>
     * <ul>
     *   <li>数据源是 {@link DbFrameSource}（取 {@code frameData}），不是 {@code rawData}</li>
     *   <li>发送走 {@link RawFrameSender}（pcap 注入），不是 Netty</li>
     *   <li>时钟与发送器<b>跨分卷共享</b>，因此跨卷节奏连续、实测倍率按全程统计</li>
     *   <li>过滤与目标映射规则与载荷模式完全一致</li>
     * </ul>
     *
     * <h3>--start/--end 的语义</h3>
     * <p>
     * 与载荷模式保持一致：直接按绝对捕获时间下推到 SQL，因此跨分卷时窗口是全局统一的。
     * </p>
     */
    private void replayFramesFromDatabase() {
        if (injectionInterface == null) {
            throw new PacketCaptureException(
                    "Frame-level replay requires an injection interface. Specify --injectInterface=<IP>.");
        }

        List<String> volumes = SplitUtil.discoverVolumes(dbFile);
        Long absoluteStart = startAtMs;
        Long absoluteEnd = endAtMs;
        if (absoluteStart != null) {
            logger.info("Start time filter: {} (absolute)",
                    new java.sql.Timestamp(absoluteStart));
        }
        if (absoluteEnd != null) {
            logger.info("End time filter: {} (absolute)",
                    new java.sql.Timestamp(absoluteEnd));
        }
        // 窗口与 payload 路径同一套语义：起点 only-once（seek 不得收缩），终点上限只收紧。
        if (absoluteStart != null) {
            control.windowStartIfUnset(absoluteStart);
        }
        if (absoluteEnd != null) {
            control.limitWindowTo(absoluteEnd);
            control.setWindowTo(absoluteEnd);
        }

        // --start/--end：按卷名（分卷窗口起点时间戳）缩小回放范围
        if (absoluteStart != null || absoluteEnd != null) {
            volumes = SplitUtil.selectVolumesInCaptureWindow(
                    volumes, absoluteStart, absoluteEnd);
            logger.info("[JShark] Frame replay restricted to {} volume(s) within the --start/--end window.",
                    volumes.size());
        }
        if (appProtocolFilter != null && !appProtocolFilter.isEmpty()) {
            String message = "[JShark] --applicationProtocol cannot be applied in frame mode "
                    + "(appProtocol is a per-record column, not a frame property); the filter is ignored";
            logger.warn(message);
            control.addWarning("OPTION_IGNORED", message);
        }

        // 2) 跨分卷共享时钟与发送器：节奏连续、统计为全程
        try (RawFrameSender sender = new RawFrameSender(injectionInterface)) {
            // 会话级缓存（CLI 注入）：seek 重开段不再重跑自检；
            // 直接构造工具的调用方没注入时仍自行自检一次。
            StartupSelfCheck.Result check = startupCheck;
            if (check == null) {
                check = StartupSelfCheck.run(injectionInterface, -1, 0);
            }
            if (check != null) {
                sender.setToleratesReportedError(
                        check.verdict() == StartupSelfCheck.InjectVerdict.OBSERVED_DESPITE_ERROR,
                        check.detail());
                if (check.verdict() == StartupSelfCheck.InjectVerdict.FAILED) {
                    logger.error("[JShark] Injection self-check FAILED on this NIC; frames will not reach the "
                            + "network. Pick another NIC with --injectInterface, then retry.");
                }
            }

            ReplayClock clock = new ReplayClock(speedMultiplier, null, null);
            // 帧级重放同样自适应：控制器跨卷共享（与 clock 一致），目标倍率是用户给的上限
            AdaptiveSpeedController frameSpeedController =
                    new AdaptiveSpeedController(speedMultiplier, adaptiveSpeedEnabled);
            control.setAdaptive(adaptiveSpeedEnabled);
            control.speedObserved(speedMultiplier, speedMultiplier);
            control.minSpeedObserved(speedMultiplier);
            control.setLive(false, false);
            FrameReplayEngine.Result total = new FrameReplayEngine.Result(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false);

            for (String volume : volumes) {
                if (stopRequested || control.shouldStop() || control.hasPendingSeek()) {
                    logger.info("Replay stopped by user before volume: {}", volume);
                    break;
                }
                DbFrameSource source = new DbFrameSource(volume, absoluteStart, absoluteEnd,
                        sourceIpFilter, destinationIpFilter, sourcePortFilter, destinationPortFilter,
                        ipProtocolFilter, 0);
                logger.info("[JShark] Replaying volume (frame mode): {}", volume);
                FrameReplayEngine engine = new FrameReplayEngine(source,
                        sourceIpFilter, destinationIpFilter,
                        sourcePortFilter, destinationPortFilter, ipProtocolFilter);
                engine.setSpeedController(frameSpeedController);
                engine.setControl(control);
                FrameReplayEngine.Result part;
                try {
                    part = engine.run(clock, frameRewriter, sender, targetMapping);
                } catch (Exception e) {
                    // 数据源自己已经给出可操作的错误（例如 payload 捕获的库没有 frameData），
                    // 原样抛出，别再包一层“failed to replay volume”把原因埋进 cause 链。
                    if (e instanceof PacketCaptureException pe) {
                        throw pe;
                    }
                    throw new PacketCaptureException("Failed to replay volume " + volume, e);
                }
                total = total.plus(part);
                if (part.stopped()) {
                    break;
                }
                // 用最近一次 run 的引擎做报告（它持有改写器计数与全局跨度）
                if (stopRequested) {
                    break;
                }
                lastFrameEngine = engine;
            }

            if (lastFrameEngine != null) {
                lastFrameEngine.report(clock, total);
            }
            frameResult = total;
            logger.info("[JShark] Frame replay completed: examined={}, sent={}, failed={}, reportedErrorButSent={}",
                    total.examined(), total.sent(), total.injectionFailures(), total.sentDespiteReportedError());
        }
        replayCompleted = true;
    }

    /** @return 帧级重放的统计结果；未运行帧级重放时返回 null */
    public FrameReplayEngine.Result frameResult() {
        return frameResult;
    }

    /**
     * 启动统计定时器（每5秒打印一次）
     */
    private void startStatsTimer() {
        // 守护线程：统计定时器是纯后台辅助任务，绝不能有"阻止 JVM 退出"的能力。
        // 原来用默认线程工厂（非守护），只在 stopStatsTimer() 被调用时才释放；
        // 一旦走到超时/异常路径没停掉它，测试 JVM 就会挂住。
        statsTimer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jshark-replay-stats");
            t.setDaemon(true);
            return t;
        });
        statsTimer.scheduleAtFixedRate(this::printStats, 5, 5, TimeUnit.SECONDS);
        logger.info("Statistics timer started (5-second interval)");
    }
    
    /**
     * 停止统计定时器
     */
    private void stopStatsTimer() {
        if (statsTimer != null) {
            statsTimer.shutdown();
            try {
                if (!statsTimer.awaitTermination(3, TimeUnit.SECONDS)) {
                    statsTimer.shutdownNow();
                }
            } catch (InterruptedException e) {
                statsTimer.shutdownNow();
                Thread.currentThread().interrupt();
            }
            logger.info("Statistics timer stopped");
        }
    }
    
    /**
     * 打印统计信息
     */
    private void printStats() {
        // 如果重放已完成，停止定时器
        if (replayCompleted) {
            stopStatsTimer();
            return;
        }
        
        // 使用 AtomicLong.getAndSet 原子性地获取并重置，避免锁带来的竞态条件
        long packets = periodPackets.getAndSet(0);
        long bytes = periodBytes.getAndSet(0);
        long success = periodSuccess.getAndSet(0);
        long failure = periodFailure.getAndSet(0);
        long maxDelayNanos = periodMaxDelayNanos.getAndSet(0);
        
        // 获取并重置周期ID范围
        long minIdValue = periodMinId.getAndSet(Long.MAX_VALUE);
        long maxIdValue = periodMaxId.getAndSet(Long.MIN_VALUE);
        
        // 处理未设置的情况
        String minIdStr = (minIdValue == Long.MAX_VALUE) ? "N/A" : String.valueOf(minIdValue);
        String maxIdStr = (maxIdValue == Long.MIN_VALUE) ? "N/A" : String.valueOf(maxIdValue);
        
        logger.info("[Replay Stats] Packets: {}, Bytes: {}, Success: {}, Failure: {}, Max Delay: {}ms, "
                        + "Speed: {}x, Min ID: {}, Max ID: {}",
                   packets, bytes, success, failure, maxDelayNanos / 1e6,
                   replayClock != null ? String.format("%.3f", replayClock.speed()) : "N/A",
                   minIdStr, maxIdStr);
    }
    
    /**
     * 查询数据库中第一帧的时间戳（TimeStamp最小值）
     * 用于报告数据范围、补齐未显式指定时的窗口起点
     */
    private void queryFirstPacketTimestamp() throws SQLException {
        String sql = "SELECT MIN(TimeStamp) AS firstTs FROM JSharkLog";
        try (PreparedStatement stmt = connection.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                java.sql.Timestamp ts = rs.getTimestamp("firstTs");
                if (ts != null) {
                    firstPacketTimestamp = ts.getTime();
                    logger.info("First packet timestamp: {} ({})", 
                               firstPacketTimestamp, ts);
                } else {
                    logger.warn("No packets found in database, cannot determine first packet timestamp");
                    firstPacketTimestamp = null;
                }
            }
        }
    }

    /**
     * 查询数据库中最后一帧的时间戳（TimeStamp最大值）
     */
    private void queryLastPacketTimestamp() throws SQLException {
        String sql = "SELECT MAX(TimeStamp) AS lastTs FROM JSharkLog";
        try (PreparedStatement stmt = connection.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                java.sql.Timestamp ts = rs.getTimestamp("lastTs");
                if (ts != null) {
                    lastPacketTimestamp = ts.getTime();
                    logger.info("Last packet timestamp: {} ({})", 
                               lastPacketTimestamp, ts);
                } else {
                    logger.warn("No packets found in database, cannot determine last packet timestamp");
                    lastPacketTimestamp = null;
                }
            }
        }
    }

    /**
     * 检查additionalInfo是否匹配过滤表达式
     * 使用FilterNinja表达式解析器，支持：
     * 1. 括号分组：()
     * 2. 逻辑运算：&& (AND), || (OR)
     * 3. 比较运算：=, !=, >, <, >=, <=
     * 4. 字符串匹配：like (支持通配符 * 和 ?)
     * 示例：
     *   dis.pdu.type=28 && dis.exercise.id=17
     *   (dis.pdu.type=28 || dis.pdu.type=1) && dis.exercise.id!=0
     *   dis.pdu.type>20 && dis.pdu.type<30
     *   dis.entity.name like "*tank*"
     */
    private boolean matchesFilter(Map<String, Object> additionalInfo, String filterExpr) {
        if (additionalInfo == null || additionalInfo.isEmpty()) {
            return false; // 没有additionalInfo，不匹配
        }
        
        try {
            // 使用FilterNinja表达式解析器
            return ExpressionParser.evaluate(filterExpr, additionalInfo);
        } catch (Exception e) {
            logger.error("Error evaluating filter expression: {}", filterExpr, e);
            return false; // 解析错误时默认不匹配
        }
    }

}
