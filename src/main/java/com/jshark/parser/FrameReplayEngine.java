package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 帧级重放引擎：从任意 {@link FrameSource} 取帧，按精确倍率发出。
 *
 * <h3>职责边界</h3>
 * <table border="1">
 *   <caption>引擎与数据源的分工</caption>
 *   <tr><th>引擎负责</th><th>数据源负责</th></tr>
 *   <tr>
 *     <td>
 *       精确倍率时序（{@link ReplayClock}）· 过滤 · 目标映射（{@link TargetMapping}）·
 *       帧改写（{@link FrameRewriter}）· 注入（{@link RawFrameSender}）· 统计与报告
 *     </td>
 *     <td>按时间顺序产出"可注入的完整帧"及其地址元数据</td>
 *   </tr>
 * </table>
 *
 * <h3>时间轴规则</h3>
 * <ul>
 *   <li>数据源声明为"时间有序"（pcap）时，直接用其时间戳做严格仿射倍率：
 *       总时长 = 首末包间隔 / speed，绝不提前发送。</li>
 *   <li>数据源声明为"顺序不等于时间严格递增"（数据库，TIMESTAMP 只有微秒精度）时，
 *       引擎把时间轴钳制为<b>非递减</b>后再调度：同一微秒内的多帧视为同一时刻并发发出。
 *       否则会出现"时间戳回退 → 应发时刻已经过去 → 全部记为迟到"，反而掩盖真实节奏。</li>
 * </ul>
 */
public class FrameReplayEngine {

    private static final Logger logger = LoggerFactory.getLogger(FrameReplayEngine.class);

    /**
     * 重放结果统计。
     *
     * <p>{@code measuredElapsedNanos} 是<b>真实墙钟耗时</b>（首个被调度帧 → 最后一次 send 返回），
     * 不是首末帧的原始时间跨度；分卷模式下由 {@link #plus(Result)} 逐段累加，
     * 因此"等待新分卷"的空闲不会被算进实测耗时。</p>
     */
    public record Result(long examined, long sent, long sentBytes, long filtered,
                         long skippedNoPort, long skippedWithoutFrame, long rewriteRejected,
                         long sentDespiteReportedError, long injectionFailures,
                         long measuredElapsedNanos, boolean stopped) {

        /**
         * 累加另一个结果（用于分卷模式：多个卷共用同一个时钟与发送器）。
         *
         * @param other 另一段结果
         * @return 累加后的新结果
         */
        public Result plus(Result other) {
            if (other == null) {
                return this;
            }
            return new Result(examined + other.examined, sent + other.sent, sentBytes + other.sentBytes,
                    filtered + other.filtered, skippedNoPort + other.skippedNoPort,
                    skippedWithoutFrame + other.skippedWithoutFrame,
                    rewriteRejected + other.rewriteRejected,
                    sentDespiteReportedError + other.sentDespiteReportedError,
                    injectionFailures + other.injectionFailures,
                    measuredElapsedNanos + other.measuredElapsedNanos,
                    stopped || other.stopped);
        }
    }

    /** 时间跨度（首末被重放帧） */
    public record Span(long firstNanos, long lastNanos) {
        /** @return 是否可用于时序报告 */
        public boolean valid() {
            return firstNanos >= 0 && lastNanos >= 0;
        }
    }

    private final FrameSource source;
    private final String sourceIpFilter;
    private final String destinationIpFilter;
    private final Integer sourcePortFilter;
    private final Integer destinationPortFilter;
    private final String ipProtocolFilter;

    private final AtomicLong examined = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong sentBytes = new AtomicLong();
    private final AtomicLong filtered = new AtomicLong();
    private final AtomicLong skippedNoPort = new AtomicLong();
    private final AtomicLong rewriteRejected = new AtomicLong();

    private volatile boolean stopRequested;

    /** 自适应降速控制器；null 表示不启用（严格按倍率发送） */
    private AdaptiveSpeedController speedController;

    /** 控制/进度通道；null 表示普通 CLI（仅本地 stop 标志）。 */
    private ReplayControl control;

    /** 上一个已调度帧的时间（纳秒），用于把时间轴钳制为非递减 */
    private long lastScheduledNanos = Long.MIN_VALUE;

    /**
     * 构造引擎。
     *
     * @param source              数据源
     * @param sourceIpFilter      源 IP 过滤（null/空表示不限）
     * @param destinationIpFilter 目的 IP 过滤（null/空表示不限）
     * @param sourcePortFilter    源端口过滤（null 表示不限）
     * @param destinationPortFilter 目的端口过滤（null 表示不限）
     * @param ipProtocolFilter    IP 协议过滤（null/空表示不限）
     */
    public FrameReplayEngine(FrameSource source,
                             String sourceIpFilter, String destinationIpFilter,
                             Integer sourcePortFilter, Integer destinationPortFilter,
                             String ipProtocolFilter) {
        this.source = source;
        this.sourceIpFilter = sourceIpFilter;
        this.destinationIpFilter = destinationIpFilter;
        this.sourcePortFilter = sourcePortFilter;
        this.destinationPortFilter = destinationPortFilter;
        this.ipProtocolFilter = ipProtocolFilter;
    }

    /** 请求停止（由 CTRL+C 处理调用） */
    public void stop() {
        stopRequested = true;
    }

    /**
     * 附加自适应降速控制器（可为 null 表示不启用）。
     *
     * <p>控制器由调用方创建并跨卷共享：分卷模式下多个卷共用同一个时钟，
     * 倍率也必须只有一份，否则目标倍率会在卷与卷之间漂移。</p>
     *
     * @param controller 控制器；null 表示严格按倍率发送（不降速）
     */
    public void setSpeedController(AdaptiveSpeedController controller) {
        this.speedController = controller;
    }

    /**
     * 注入控制/进度通道。
     *
     * @param control 控制通道；null 表示普通 CLI 行为
     */
    public void setControl(ReplayControl control) {
        this.control = control;
    }

    /** @return 是否应停止当前段（用户 stop 或 seek） */
    private boolean shouldStopSegment() {
        return stopRequested || (control != null && control.shouldStop());
    }

    private boolean hasPendingSeek() {
        return control != null && control.hasPendingSeek();
    }

    /**
     * 执行重放。
     * <p>
     * 时钟与发送器由调用方提供：分卷模式下多个卷共用同一个时钟，保证跨卷节奏连续。
     * </p>
     *
     * @param clock         重放时钟（跨卷共享）
     * @param rewriter      帧改写器
     * @param sender        帧注入发送器
     * @param targetMapping 目标映射
     * @return 本段统计结果
     * @throws Exception 数据源读取失败
     */
    public Result run(ReplayClock clock, FrameRewriter rewriter, FrameSender sender,
                      TargetMapping targetMapping) throws Exception {
        this.lastRewriter = rewriter;
        // 同一个控制器在分卷模式下跨卷共享；进入新卷前丢弃上一卷末尾与"等待新分卷"期间
        // 留下的观测窗口。否则整段空闲会被当成欠账增长，控制器会在每个卷边界错误降速。
        if (speedController != null) {
            speedController.resetWindow();
        }
        // 本段真实墙钟耗时：取"首个成功调度的帧"到"最后一次 send 返回"。
        // 不能用首末帧的原始时间跨度冒充——那是理想时间轴，不是实际花了多久。
        long wallStartNanos = -1;
        long wallEndNanos = -1;
        source.open();
        try {
            while (!shouldStopSegment() && !hasPendingSeek()) {
                FrameSource.Frame frame = source.next();
                if (frame == null) {
                    // 数据源被 stop/seek 打断时也会返回 null：这不是“播到末尾”。
                    if (control != null && !hasPendingSeek() && !shouldStopSegment()) {
                        control.markEndReached();
                    }
                    break;
                }
                examined.incrementAndGet();
                if (control != null) {
                    control.examined();
                    control.position(TimeUnit.NANOSECONDS.toMillis(frame.timestampNanos()));
                }

                if (!passesFilter(frame)) {
                    filtered.incrementAndGet();
                    if (control != null) {
                        control.filtered();
                    }
                    continue;
                }

                // 目标映射：按 源IP:源端口 匹配，改写目的 IP/端口
                TargetMapping.MappingResult mapped = targetMapping.apply(
                        frame.srcIp(), frame.srcPort() != null ? frame.srcPort() : 0,
                        frame.dstIp(), frame.dstPort() != null ? frame.dstPort() : 0);

                // 帧改写：只改目的地址/端口与受影响的校验和
                FrameRewriter.RewriteResult rewritten =
                        rewriter.rewrite(frame.frameData(), mapped.ip(), mapped.port());
                if (!rewritten.injectable()) {
                    rewriteRejected.incrementAndGet();
                    if (control != null) {
                        // 过滤规则没命中是 filtered；改写后无法注入是 skipped（语义不同，别混用）
                        control.skipped();
                    }
                    continue;
                }

                if (!scheduleAndWait(clock, frame)) {
                    break;
                }

                if (wallStartNanos < 0) {
                    wallStartNanos = System.nanoTime();
                }
                boolean delivered = sender.send(rewritten.bytes());
                wallEndNanos = System.nanoTime();
                if (delivered) {
                    sent.incrementAndGet();
                    sentBytes.addAndGet(rewritten.bytes().length);
                    if (control != null) {
                        control.sent(rewritten.bytes().length);
                    }
                } else if (control != null) {
                    // 失败已由 sender 内部（framesFailed/framesSkipped）计数；
                    // 协议侧只补一个失败数，且不把失败算进"已发送"。
                    control.sendFailed();
                }
            }
        } finally {
            source.close();
        }

        long measuredElapsedNanos = (wallStartNanos >= 0 && wallEndNanos >= wallStartNanos)
                ? wallEndNanos - wallStartNanos
                : 0;
        return new Result(examined.get(), sent.get(), sentBytes.get(), filtered.get(),
                skippedNoPort.get(), source.skippedWithoutFrame(), rewriteRejected.get(),
                sender.framesSentDespiteError(), sender.framesFailed(),
                measuredElapsedNanos, shouldStopSegment());
    }

    /**
     * 按时间轴等待到该帧的应发时刻。
     *
     * @param clock 重放时钟
     * @param frame 当前帧
     * @return false 表示收到停止请求
     */
    private boolean scheduleAndWait(ReplayClock clock, FrameSource.Frame frame) {
        if (stopRequested) {
            return false;
        }
        if (control != null && control.checkpoint(clock, speedController, true)) {
            return false;
        }

        ReplayClock.PacketTime packetTime = ReplayClock.PacketTime.ofEpochNanos(effectiveNanos(frame));
        if (!clock.isAnchored()) {
            // 首个被重放的帧锚定时间轴零点：其应发时刻就是"现在"
            clock.anchor(packetTime);
        }
        ReplayClock.Schedule schedule = clock.scheduleNext(packetTime);
        while (schedule.waitNanos() > 0) {
            clock.await(schedule);
            if (stopRequested) {
                break;
            }
            if (control != null && control.checkpoint(clock, speedController, true)) {
                break;
            }
            schedule = clock.scheduleNext(packetTime);
        }
        if (shouldStopSegment() || hasPendingSeek()) {
            return false;
        }
        // 自适应降速：本帧已调度、尚未注入，此刻调速会把新倍率从"本帧"起算
        if (speedController != null) {
            AdaptiveSpeedController.Decision decision =
                    speedController.observe(System.nanoTime(), schedule.latenessNanos());
            if (decision.changed()) {
                clock.setSpeed(decision.speed());
                if (control != null) {
                    control.speedObserved(
                            speedController.targetSpeed() > 0 ? speedController.targetSpeed() : clock.speed(),
                            clock.speed());
                    control.minSpeedObserved(speedController.minSpeed());
                    control.adaptiveObserved(speedController.downCount(), speedController.upCount());
                }
            }
        }
        lastScheduledNanos = packetTime.toEpochNanos();
        return true;
    }

    /**
     * 计算用于调度的时刻：默认用帧时间戳；数据源不保证时间顺序时钳制为非递减。
     *
     * @param frame 帧
     * @return 调度用纳秒时刻
     */
    private long effectiveNanos(FrameSource.Frame frame) {
        long ts = frame.timestampNanos();
        if (source.isOrderedByTimestamp()) {
            return ts;
        }
        return Math.max(ts, lastScheduledNanos == Long.MIN_VALUE ? ts : lastScheduledNanos);
    }

    /** 过滤：源/目的 IP、源/目的端口、IP 协议（与 DbReplayTool / PcapReplayTool 规则一致） */
    private boolean passesFilter(FrameSource.Frame frame) {
        if (sourceIpFilter != null && !sourceIpFilter.isEmpty()
                && !sourceIpFilter.equals(frame.srcIp())) {
            return false;
        }
        if (destinationIpFilter != null && !destinationIpFilter.isEmpty()
                && !destinationIpFilter.equals(frame.dstIp())) {
            return false;
        }
        if (sourcePortFilter != null && !sourcePortFilter.equals(frame.srcPort())) {
            return false;
        }
        if (destinationPortFilter != null && !destinationPortFilter.equals(frame.dstPort())) {
            return false;
        }
        return ipProtocolFilter == null || ipProtocolFilter.isEmpty()
                || ipProtocolFilter.equalsIgnoreCase(frame.ipProtocol());
    }

    /**
     * 打印时序与改写报告。
     *
     * @param clock  重放时钟（跨卷共享）
     * @param result 运行统计（可为多卷累加后的结果）
     */
    public void report(ReplayClock clock, Result result) {
        logger.info("[JShark] Replay summary: examined={}, sent={} ({} bytes), filtered={}, "
                        + "rewriteRejected={}, skippedWithoutFrame={}, reportedErrorButSent={}, failed={}",
                result.examined(), result.sent(), result.sentBytes(), result.filtered(),
                result.rewriteRejected(), result.skippedWithoutFrame(),
                result.sentDespiteReportedError(), result.injectionFailures());

        // 空库/全部被过滤时改写器一次未触发，counters 为空：空 map 不能喂给 new EnumMap<>()
        // （会抛 "Specified map is empty"，把"回放正常做完"变成一次异常退出），
        // 因此先判空，只在有内容时才构造 EnumMap 并打印。
        Map<FrameRewriter.Status, Long> counters = rewriterCounters();
        if (!counters.isEmpty()) {
            logger.info("[JShark] Frame rewrite results: {}", new EnumMap<>(counters));
        }

        ReplayClock.Stats stats = clock.stats();
        if (stats.scheduled() <= 0) {
            logger.info("[Replay Timing] No frame was scheduled; timing report skipped");
            return;
        }
        double targetSpeed = speedController != null ? speedController.targetSpeed() : clock.speed();
        ReplayTiming.log(logger, clock, speedController, targetSpeed,
                clock.firstScheduledEpochNanos(), clock.lastScheduledEpochNanos(),
                result.measuredElapsedNanos());
    }

    /** 由最近一次 run 使用的改写器，供报告读取状态计数 */
    private FrameRewriter lastRewriter;

    private Map<FrameRewriter.Status, Long> rewriterCounters() {
        return lastRewriter != null ? lastRewriter.counters() : Map.of();
    }

    /** @return 已发送帧数 */
        /** @return 参与重放的帧数 */
    }
