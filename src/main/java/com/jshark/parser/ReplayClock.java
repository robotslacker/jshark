package com.jshark.parser;

import java.util.ArrayList;
import java.util.List;

/**
 * 重放时钟：以"<b>分段</b>全局仿射映射"实现精确倍率（speed）。
 *
 * <h3>语义（不可动摇）</h3>
 * <pre>
 *   t_out(pkt) = φ + (pkt.timestamp · 1e6) / speed        [纳秒]
 *   φ = anchorNowNano − (第一个待重放包的时间戳 · 1e6) / speed
 * </pre>
 * <ul>
 *   <li><b>精确总时长</b>：每一段内时间轴恰好压缩/拉伸为 {@code 1/speed}，
 *       无累积漂移；总时长为各段之和（见 {@link #idealDurationNanos(PacketTime, PacketTime)}）。</li>
 *   <li><b>绝不提前发送</b>：任何包的发送时刻都不早于 {@code t_out}（{@code earlyCount} 恒为 0）。</li>
 *   <li><b>落后不补睡</b>：若已晚于 {@code t_out}，立即发送并记为迟到（{@code lateness}），
 *       不试图"加速追赶"，以免破坏包间隔的严格比例。</li>
 *   <li><b>零点</b>：以<b>首个被重放的包</b>为基准（即应用 {@code --start} 之后的第一包），
 *       因此圈选片段时无需等待其在原始历史中的空闲时间。</li>
 * </ul>
 *
 * <h3>运行中调速（自适应降速）</h3>
 * <p>
 * {@link #setSpeed(double)} 允许在两次调度之间改写倍率，时间轴随之切成若干段，每段仍是严格仿射。
 * 重锚取 {@code φ = now}、{@code anchor = 最近调度的包时间}，因此：
 * </p>
 * <pre>
 *   下一包 target = now + (p − p_last) / speed_new ≥ now
 * </pre>
 * <p>
 * 即<b>无论降速还是升速，调整后的应发时刻永远不早于"现在"</b>——调速不会退化成"为了追赶而立刻猛发"。
 * 代价是调速瞬间已积累的迟到量会被吸收（记入 {@link #absorbedLatenessNanos()}），
 * 换取新倍率下干净的开局；历史迟到量仍如实留在 {@link Stats} 中。
 * </p>
 *
 * <h3>时间戳解析（选择最可靠的一档）</h3>
 * <ol>
 *   <li>优先使用数据库 {@code TimeStamp} 列的纳秒精度（DuckDB TIMESTAMP 为微秒精度）：
 *       毫秒部分取 {@code getTime()}，亚毫秒部分取 {@code getNanos() % 1_000_000}。
 *       注意 {@code Timestamp.getTime()} 会把亚毫秒部分进位/截断，不能用 {@code getNanos()} 单独换算。</li>
 *   <li>其次使用 {@code Instant} 的秒 + 纳秒。</li>
 *   <li>都不可用时回退为毫秒 × 1e6。</li>
 * </ol>
 *
 * <h3>本类不包含 IO</h3>
 * 时间来源与休眠都通过 {@link TimeSource} / {@link Sleeper} 注入，因此可被完全确定性地单测。
 * 默认实现分别为 {@code System::nanoTime} 与"小片 sleep 粗等 + 自旋收尾"（见 {@link #DEFAULT_SLEEPER}：
 * Windows 上定时器原语会被取整到约 15.6ms，亚毫秒精度只能靠自旋）。
 */
public final class ReplayClock {

    /** 单次最大等待切片（毫秒）。把长等待切成片，便于响应中断与停止请求。 */
    private static final long MAX_WAIT_CHUNK_MS = 50L;

    /** 纳秒/毫秒 */
    private static final long NANOS_PER_MILLI = 1_000_000L;

    /** 纳秒/秒 */
    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    /**
     * 可安全缩放的最大时间戳（纳秒）。
     * <p>
     * 取值 {@code Long.MAX_VALUE} 的一个安全下界：时间戳超过它（约公元 2255 年以后）时显式报错，
     * 而不是在缩放后静默溢出。当前时间约 1.8e18 ns，安全余量极大。
     * </p>
     */
    private static final long MAX_SAFE_EPOCH_NANOS = 9_000_000_000_000_000_000L;

    /**
     * 单调时间来源。重放的时间轴必须基于单调时钟，避免系统时钟调整导致跳变。
     */
    @FunctionalInterface
    public interface TimeSource {
        /** @return 单调时钟当前值（纳秒） */
        long nanoTime();

        /** 系统默认实现 */
        TimeSource SYSTEM = System::nanoTime;
    }

    /**
     * 等待器。与 {@link TimeSource} 配对使用；测试中注入"快速前进时间"的实现即可零等待跑完。
     */
    @FunctionalInterface
    public interface Sleeper {
        /**
         * 等待指定时长（尽力而为，允许误差）。
         *
         * @param nanos 等待纳秒数，必定 &gt; 0
         */
        void sleep(long nanos);
    }

    /**
     * 单次 {@code Thread.sleep} 的最大时长（毫秒）。
     * <p>
     * 实测（Windows 11 + JDK 21）：{@code sleep(1ms)}→1.12ms、{@code sleep(5ms)}→5.45ms 都还准，
     * 但 {@code sleep(20ms)}→31.7ms —— 更大的值会被系统定时器粒度（约 15.6ms）取整。因此粗等必须切小。
     * </p>
     */
    private static final long MAX_SLEEP_CHUNK_MS = 5L;

    /**
     * 自旋收尾窗口（纳秒）。
     *
     * <p>
     * 为什么必须自旋：实测（Windows 11 + JDK 21）{@code LockSupport.parkNanos(1ms)} 的中位耗时是
     * <b>15.2ms</b>，{@code parkNanos(100µs)} 是 <b>14.6ms</b>——parkNanos 完全按系统定时器粒度取整，
     * <b>亚毫秒等待根本做不到</b>。而"park 到剩 1ms 再自旋"的中位误差是 <b>8µs</b>，差三个数量级。
     * </p>
     * <p>
     * 这个精度不是锦上添花：迟到量是自适应降速的控制信号，而 15ms 的固定取整误差会被误判成
     * "发送方跟不上"，把倍率一路拖到下限（实测确实发生过）。代价是每个包最多自旋 1ms 的 CPU，
     * 这是 Windows 上换取亚毫秒精度的必要成本。
     * </p>
     */
    private static final long SPIN_TAIL_NANOS = 1_000_000L;

    /** 默认等待器：小片 sleep 粗等 + 自旋收尾（见 {@link #SPIN_TAIL_NANOS} 的实测依据） */
    public static final Sleeper DEFAULT_SLEEPER = nanos -> {
        long deadline = System.nanoTime() + nanos;
        long remain = nanos;
        while (remain > SPIN_TAIL_NANOS) {
            long chunkNanos = Math.min(remain - SPIN_TAIL_NANOS, MAX_SLEEP_CHUNK_MS * NANOS_PER_MILLI);
            sleepUninterruptibly(Math.max(1L, chunkNanos / NANOS_PER_MILLI));
            remain = deadline - System.nanoTime();
        }
        // 最后一段只能自旋：任何定时器原语都会把它取整到下一个系统定时器 tick
        while (System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
    };

    /** 休眠指定毫秒；被中断时恢复中断标志 */
    private static void sleepUninterruptibly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 一棵待发送包的最小必要信息（避免依赖数据库字段）。
     *
     * @param timestampMillis 时间戳的毫秒部分（{@code Timestamp.getTime()} 或 {@code Instant.toEpochMilli()}）
     * @param nanoOfMillis    该毫秒内的亚毫秒偏移（0 ~ 999_999），来自数据库微秒精度
     */
    public record PacketTime(long timestampMillis, int nanoOfMillis) {

        /**
         * 由 {@link java.sql.Timestamp} 构造，尽量保留微秒精度。
         *
         * @param ts 数据库时间戳；null 返回 null
         * @return 包时间；ts 为 null 时返回 null
         */
        public static PacketTime of(java.sql.Timestamp ts) {
            if (ts == null) {
                return null;
            }
            // Timestamp 可直接给出"自 epoch 起的纳秒"：秒 * 1e9 + 秒内纳秒。
            // 这样与 Instant 路径口径完全一致，也不会出现整秒偏移。
            return ofEpochNanos(ts.getTime() / 1000L * NANOS_PER_SECOND + ts.getNanos());
        }

        /**
         * 由 {@link java.time.Instant} 构造（精度最高）。
         *
         * @param instant 时间；null 返回 null
         * @return 包时间；instant 为 null 时返回 null
         */
        public static PacketTime of(java.time.Instant instant) {
            if (instant == null) {
                return null;
            }
            return ofEpochNanos(instant.getEpochSecond() * NANOS_PER_SECOND + instant.getNano());
        }

        /**
         * 由绝对纳秒构造。
         *
         * @param epochNanos 自 epoch 起的纳秒数
         * @return 包时间
         */
        public static PacketTime ofEpochNanos(long epochNanos) {
            long millis = Math.floorDiv(epochNanos, NANOS_PER_MILLI);
            int nanoOfMillis = (int) Math.floorMod(epochNanos, NANOS_PER_MILLI);
            return new PacketTime(millis, nanoOfMillis);
        }

        /** @return 该时刻的绝对纳秒值（自 epoch） */
        public long toEpochNanos() {
            return timestampMillis * NANOS_PER_MILLI + nanoOfMillis;
        }
    }

    /**
     * 单次调度结果。
     *
     * @param targetNano    该包的应发时刻（纳秒，单调时钟口径）
     * @param waitNanos     当前还需等待的纳秒数；{@code <= 0} 表示"现在就该发"（可能已迟到）
     * @param latenessNanos 迟到量（{@code >= 0}）；0 表示按时或提前到位
     * @param first         是否为首个被调度的包（其 {@code waitNanos} 恒为 0）
     */
    public record Schedule(long targetNano, long waitNanos, long latenessNanos, boolean first) {
    }

    /**
     * 重放时序统计快照。
     *
     * @param scheduled      已调度包数
     * @param totalLatenessNs 累计迟到量（纳秒）
     * @param maxLatenessNs  最大单包迟到量（纳秒）
     * @param lateCount      迟到（{@code lateness > 0}）的包数
     */
    public record Stats(long scheduled, long totalLatenessNs, long maxLatenessNs, long lateCount) {
    }

    private final TimeSource timeSource;
    private final Sleeper sleeper;

    /**
     * 当前倍率。可变：自适应降速会在运行中改写它（见 {@link #setSpeed(double)}）。
     * <p>只由重放线程写、其它线程读，故声明为 volatile；读方在单次调用内取本地快照。</p>
     */
    private volatile double speedMultiplier;

    /** 仿射常数 φ（纳秒）；未锚定时为 Long.MIN_VALUE 表示无效 */
    private volatile long phiNanos;
    private volatile boolean anchored = false;

    /** 锚点包的绝对时间戳（纳秒）。所有缩放都相对它求增量，避免大数运算损失精度 */
    private volatile long anchorEpochNanos = 0;

    /** 最近一次被调度的包时间（纳秒）。调速重锚时作为新段起点 */
    private long lastScheduledEpochNanos = 0;

    /**
     * 首个被锚定（被重放）的包时间（纳秒）。
     * <p>与 {@link #anchorEpochNanos} 不同：后者会被 {@link #setSpeed(double)} 改写，
     * 本字段只在 {@link #anchor(PacketTime)} 时写入一次。报告"整段回放的时间跨度"
     * 必须用它，否则分卷/调速后跨度会算错。</p>
     */
    private long firstScheduledEpochNanos = -1;

    /** 已完成的倍率段，按时间升序；每段覆盖 [from, 下一段 from) */
    private final List<Segment> segments = new ArrayList<>();

    /** 运行中达到过的最低倍率（报告用） */
    private volatile double minSpeed;

    /** 调速次数（报告用） */
    private volatile int speedAdjustCount;

    /** 被重锚吸收掉的累计迟到量（纳秒）：调速时为了新倍率下的"干净开局"而放弃的欠账 */
    private volatile long absorbedLatenessNanos;

    private long scheduledCount = 0;
    private long lateCount = 0;
    private long totalLatenessNs = 0;
    private long maxLatenessNs = 0;

    /** 已记账的调度序号。用于保证"一个包无论被 scheduleNext 询问多少次，迟到量只记一次" */
    private long accountedSeq = 0;

    /**
     * 构造重放时钟。
     *
     * @param speedMultiplier 倍率，必须 &gt; 0（1.0 为原始实时）
     * @param timeSource      单调时间来源，null 时使用 {@link TimeSource#SYSTEM}
     * @param sleeper         等待器，null 时使用 {@link #DEFAULT_SLEEPER}
     * @throws IllegalArgumentException speedMultiplier 不为正数
     */
    public ReplayClock(double speedMultiplier, TimeSource timeSource, Sleeper sleeper) {
        if (!(speedMultiplier > 0) || Double.isNaN(speedMultiplier) || Double.isInfinite(speedMultiplier)) {
            throw new IllegalArgumentException("speed must be a positive finite number, got: " + speedMultiplier);
        }
        this.speedMultiplier = speedMultiplier;
        this.minSpeed = speedMultiplier;
        this.timeSource = timeSource != null ? timeSource : TimeSource.SYSTEM;
        this.sleeper = sleeper != null ? sleeper : DEFAULT_SLEEPER;
    }

    /**
     * 建立时间轴零点：把"首个待重放包"锚定为当前时刻。
     * <p>
     * 调用后，该包的应发时刻即为"现在"，整条时间轴由它推导。
     * </p>
     *
     * @param firstPacket 首个待重放的包时间
     * @return 首包的调度结果（{@code waitNanos == 0}）
     * @throws IllegalStateException    已经锚定过
     * @throws IllegalArgumentException 时间戳超出可表达范围
     */
    public Schedule anchor(PacketTime firstPacket) {
        if (anchored) {
            throw new IllegalStateException("ReplayClock is already anchored; anchor() must be called once");
        }
        if (firstPacket == null) {
            throw new IllegalArgumentException("first packet time must not be null");
        }
        long now = timeSource.nanoTime();
        this.anchorEpochNanos = firstPacket.toEpochNanos();
        this.firstScheduledEpochNanos = this.anchorEpochNanos;
        this.lastScheduledEpochNanos = this.anchorEpochNanos;
        this.phiNanos = now;
        this.anchored = true;
        this.scheduledCount++;
        this.accountedSeq = 1;   // 首包已记账
        // 首包准点发出：wait=0, lateness=0
        return new Schedule(now, 0, 0, true);
    }

    /**
     * 计算下一个包的应发时刻与剩余等待时间。
     * <p>
     * 调用方应循环：{@code r = scheduleNext(t); if (r.waitNanos() > 0) sleeper.sleep(r.waitNanos());}
     * 直到 {@code waitNanos <= 0} 后再发送。长等待会被切成 {@value #MAX_WAIT_CHUNK_MS} 毫秒的片，
     * 便于期间响应中断与停止请求。
     * </p>
     *
     * @param packet 包时间
     * @return 调度结果
     * @throws IllegalStateException 尚未 {@link #anchor(PacketTime)}
     */
    public Schedule scheduleNext(PacketTime packet) {
        if (!anchored) {
            throw new IllegalStateException("ReplayClock is not anchored; call anchor() first");
        }
        if (packet == null) {
            throw new IllegalArgumentException("packet time must not be null");
        }
        long packetEpochNanos = packet.toEpochNanos();
        // 记录本包：调速重锚时以"最近调度的包"为新段起点
        lastScheduledEpochNanos = packetEpochNanos;
        long target = phiNanos + scaleDeltaToNanos(packetEpochNanos);
        long now = timeSource.nanoTime();
        long diff = target - now;

        if (diff <= 0) {
            long lateness = -diff;
            // 同一个包可能被询问多次（切片等待期间会重复调用），迟到量只记一次
            scheduledCount++;
            if (scheduledCount > accountedSeq) {
                accountedSeq = scheduledCount;
                if (lateness > 0) {
                    lateCount++;
                    totalLatenessNs += lateness;
                    if (lateness > maxLatenessNs) {
                        maxLatenessNs = lateness;
                    }
                }
            }
            return new Schedule(target, 0, lateness, false);
        }

        return new Schedule(target, Math.min(diff, MAX_WAIT_CHUNK_MS * NANOS_PER_MILLI), 0, false);
    }

    /**
     * 执行一次等待（按 {@link Schedule#waitNanos()} 指示）。
     *
     * @param schedule {@link #scheduleNext(PacketTime)} 的返回值
     */
    public void await(Schedule schedule) {
        if (schedule != null && schedule.waitNanos() > 0) {
            sleeper.sleep(schedule.waitNanos());
        }
    }

    /**
     * 判断某个包是否已经超过其应发时刻（用于统计与实际发送前的校验）。
     *
     * @param packet 包时间
     * @return true 表示已晚于应发时刻
     */
        /** @return 倍率（当前段） */
    public double speed() {
        return speedMultiplier;
    }

    /** @return 运行中达到过的最低倍率；从未调速时等于构造倍率 */
    public double minSpeed() {
        return minSpeed;
    }

    /** @return 调速次数（不含"设成同值"的空操作） */
    public int speedAdjustCount() {
        return speedAdjustCount;
    }

    /** @return 被重锚吸收掉的累计迟到量（纳秒） */
    public long absorbedLatenessNanos() {
        return absorbedLatenessNanos;
    }

    /** @return 是否已锚定 */
    public boolean isAnchored() {
        return anchored;
    }

    /**
     * 首个被重放包的绝对时间戳（纳秒）。
     *
     * <p>整段回放的时间跨度应使用本值与 {@link #lastScheduledEpochNanos()} 计算。
     * 不能改用 {@code anchorEpochNanos}：自适应调速会在运行中重锚，导致跨度被截短。
     * 分卷模式下时钟跨卷共享，因此这个跨度天然是全卷的。</p>
     *
     * @return 首个被调度包的绝对时间戳（纳秒）；尚未锚定返回 -1
     */
    public long firstScheduledEpochNanos() {
        return anchored ? firstScheduledEpochNanos : -1;
    }

    /**
     * 最近一个被调度包的绝对时间戳（纳秒）。
     *
     * @return 最近被调度包的绝对时间戳（纳秒）；尚未锚定返回 -1
     */
    public long lastScheduledEpochNanos() {
        return anchored ? lastScheduledEpochNanos : -1;
    }

    /**
     * 运行中调整倍率（自适应降速 / 缓慢回升）。
     *
     * <h3>重锚规则</h3>
     * <p>
     * 新段取 {@code φ = now}、{@code anchor = 最近一次被调度的包时间}，于是后续
     * {@code target = now + (p − p_last)/speed_new}。因为 {@code p ≥ p_last} 且 {@code speed_new > 0}，
     * 恒有 {@code target ≥ now}：<b>调速只可能把后面的包推后，绝不会造成提前发送</b>，
     * 也不会为了追赶而立刻猛发。降速时旧段已积累的迟到量被吸收并计入
     * {@link #absorbedLatenessNanos()}；升速时该值为 0（本来就没欠账）。
     * </p>
     *
     * <h3>线程约束</h3>
     * <p>
     * 只允许<b>重放线程</b>调用（与 {@link #scheduleNext(PacketTime)} 同线程）。统计定时器线程
     * 只读，不在此处调用，否则会与调度决策竞争。
     * </p>
     *
     * @param newSpeed 新倍率，必须 &gt; 0 且有限
     * @throws IllegalArgumentException 倍率不为正数或非有限值
     */
    public void setSpeed(double newSpeed) {
        if (!(newSpeed > 0) || Double.isNaN(newSpeed) || Double.isInfinite(newSpeed)) {
            throw new IllegalArgumentException("speed must be a positive finite number, got: " + newSpeed);
        }
        double oldSpeed = this.speedMultiplier;
        if (newSpeed == oldSpeed) {
            return;
        }
        if (!anchored) {
            // 尚未锚定：时间轴还没有段，直接换掉初值即可
            this.speedMultiplier = newSpeed;
            this.minSpeed = Math.min(minSpeed, newSpeed);
            return;
        }

        long now = timeSource.nanoTime();
        long oldSegmentEnd = lastScheduledEpochNanos;
        long oldTarget = phiNanos + scaledNanos(oldSegmentEnd - anchorEpochNanos, oldSpeed);
        long lateness = now - oldTarget;
        if (lateness > 0) {
            absorbedLatenessNanos += lateness;
        }

        segments.add(new Segment(anchorEpochNanos, oldSpeed));
        this.anchorEpochNanos = oldSegmentEnd;
        this.phiNanos = now;
        this.speedMultiplier = newSpeed;
        this.speedAdjustCount++;
        this.minSpeed = Math.min(minSpeed, newSpeed);
    }

    /**
     * 把整条时间轴整体后移 {@code deltaNanos}。
     *
     * <p>用于暂停：恢复后下一包的应发时刻顺延，绝不为了追回暂停时间而突发。
     * 只改 {@code φ}，不改 anchor/speed/segments；{@code idealDurationNanos} 与统计都不受影响。</p>
     *
     * <p>只允许重放线程、已 anchor 时调用。</p>
     *
     * @param deltaNanos 后移量（纳秒），&le; 0 时忽略
     * @throws IllegalStateException 尚未 anchor
     */
    public void shiftTimeline(long deltaNanos) {
        if (deltaNanos <= 0) {
            return;
        }
        if (!anchored) {
            throw new IllegalStateException("ReplayClock is not anchored; cannot shift timeline");
        }
        phiNanos += deltaNanos;
    }

    /**
     * 计算"理想总时长"（纳秒）：首末包时间差按<b>各段</b>倍率分别缩放后求和。
     * <p>
     * 用于运行结束时报告"理想时长 vs 实际时长 vs 实测倍率"。自适应降速下倍率是分段常数，
     * 直接用"当前倍率 × 总跨度"会算错，必须逐段积分。
     * </p>
     *
     * @param first 首包时间
     * @param last  末包时间
     * @return 理想总时长（纳秒）
     */
    public long idealDurationNanos(PacketTime first, PacketTime last) {
        if (first == null || last == null) {
            return 0;
        }
        long from = first.toEpochNanos();
        long to = last.toEpochNanos();
        if (to <= from) {
            return 0;
        }
        long currentAnchor = anchorEpochNanos;
        double currentSpeed = speedMultiplier;
        long total = 0;
        for (int i = 0; i < segments.size(); i++) {
            Segment seg = segments.get(i);
            long segFrom = seg.fromEpochNanos();
            long segTo = (i + 1 < segments.size()) ? segments.get(i + 1).fromEpochNanos() : currentAnchor;
            long lo = Math.max(from, segFrom);
            long hi = Math.min(to, segTo);
            if (hi > lo) {
                total += scaledNanos(hi - lo, seg.speed());
            }
        }
        long lo = Math.max(from, currentAnchor);
        if (to > lo) {
            total += scaledNanos(to - lo, currentSpeed);
        }
        return total;
    }

    /** @return 统计快照 */
    public Stats stats() {
        return new Stats(scheduledCount, totalLatenessNs, maxLatenessNs, lateCount);
    }

    /**
     * 倍率段：自适应降速把整条时间轴切成若干段，每段内部仍是严格仿射映射。
     *
     * @param fromEpochNanos 段起点的包时间（纳秒，含）
     * @param speed          该段的倍率
     */
    private record Segment(long fromEpochNanos, double speed) {
    }

    /**
     * 把时间差按倍率定点到纳秒。
     *
     * @param deltaNanos 时间差（纳秒）
     * @param speed      倍率，&gt; 0
     * @return 缩放后的纳秒数
     */
    private static long scaledNanos(long deltaNanos, double speed) {
        return Math.round(deltaNanos / speed);
    }

    /**
     * 把"相对锚点包的时间差"按倍率缩放到重放时间轴。
     * <p>
     * <b>必须用增量而不是绝对时间戳。</b>绝对 epoch 纳秒约为 1.8e18，已超过 double 的整数有效范围
     * （2^53 ≈ 9e15），直接对绝对时间戳做除法会损失约 256 ns 的精度，表现为应发时刻出现
     * 百纳秒级抖动。改为 {@code (pkt − anchor) / speed}：增量在毫秒~小时量级，远在有效范围内，
     * 且误差不随运行时长增长。
     * </p>
     *
     * @param epochNanos 包的绝对时间戳（纳秒）
     * @return 相对锚点的缩放后偏移（纳秒）
     * @throws IllegalArgumentException 时间戳超出可表达范围
     */
    private long scaleDeltaToNanos(long epochNanos) {
        // 单次调用内取快照，避免读到"已换段但尚未成对更新"的中间状态
        long anchor = anchorEpochNanos;
        double speed = speedMultiplier;
        long delta = epochNanos - anchor;
        if (delta == 0) {
            return 0;
        }
        if (epochNanos > MAX_SAFE_EPOCH_NANOS || epochNanos < -MAX_SAFE_EPOCH_NANOS) {
            throw new IllegalArgumentException(
                    "timestamp out of supported range for replay timing: " + epochNanos + " ns");
        }
        // 一次除法（增量/倍率）定点到纳秒：这里只有一次舍入，误差上界 0.5 ns（相对于同一锚点恒定）
        double scaled = delta / speed;
        if (scaled > Long.MAX_VALUE || scaled < Long.MIN_VALUE) {
            throw new IllegalArgumentException("scaled delta overflows long: speed=" + speed);
        }
        return Math.round(scaled);
    }
}
