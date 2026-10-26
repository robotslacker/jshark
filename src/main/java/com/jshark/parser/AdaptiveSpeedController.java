package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 自适应降速控制器（AIMD）。
 *
 * <h3>要解决的问题</h3>
 * <p>
 * 用户给的 {@code --speed} 是<b>上限</b>，不是承诺。当倍率超出发送方真实能力时，
 * 回放会持续迟到（{@code ReplayClock} 从不提前、也不补睡），包间隔被挤压成"尽力而为"，
 * 时序保真度反而比"慢一点但准点"更差。本控制器按窗口观测迟到率，把倍率降到可持续的水平：
 * <b>宁可发得慢，也不将就用户给的倍率</b>。
 * </p>
 *
 * <h3>控制律</h3>
 * <ul>
 *   <li><b>降速触发（抗噪）</b>：自上次调整起<b>持续</b>累积的欠账增长
 *       （连续若干窗口一路在涨、没有停顿）超过 {@value #REDUCE_DEFICIT_THRESHOLD_NANOS}
 *       纳秒（默认 5 秒）<b>且</b>该增长持续 ≥ {@value #SUSTAIN_WINDOW_NANOS} 纳秒，
 *       才真正降速。一上来的一次性尖峰（开局数据库预热、首屏突发、启动积压）只涨一两个
 *       窗口就停下来，会被清零、永远到不了预算——因此不会"怎么一上来就降速"。
 *       ms 级调度抖动（GC、线程抢占、定时器取整）更是够不到几秒量级。降速仍按实测
 *       可持续速率一步到位 {@code speed ← speed × (1−ρ) × 0.98}，单次降幅不超过 50%。</li>
 *   <li><b>低包率保护</b>：窗口内包数 < {@value #MIN_PACKETS_PER_WINDOW} 时<b>不结算</b>，
 *       窗口继续累积（时长随之变长），攒够样本再结算。样本太少时首末两包迟到差被单点
 *       噪声主导，既不能据此调整，也不该把它算进累计欠账；延迟结算让低包率数据源仍然
 *       参与自适应，只是判定间隔更长。</li>
 *   <li><b>慢升</b>：连续 {@value #WINDOWS_BEFORE_SPEEDUP} 个窗口 {@code ρ < 0.2%} 才
 *       {@code speed ← speed × 1.02}，且永不超过目标倍率。升速本质是主动探测，
 *       "当前可行"并不等于"更快也可行"。</li>
 *   <li><b>死区</b>：{@code ρ ≥ 0.2%} 但未达到降速触发条件时视为达标，
 *       重置升速计数（避免缓慢积累后突然加速）。</li>
 *   <li><b>滞回</b>：降速需累计预算 + 持续性双条件，升速需连续多窗口，共同抑制振荡。</li>
 *   <li><b>下限</b>：硬编码 {@value #SPEED_FLOOR}。触底后不再降速，改为限流告警，
 *       因为此时再降也不会让时序变准，只会让回放无限拖长。</li>
 *   <li><b>启动保护</b>：首个窗口不调整——锚定、JIT、建连、数据库预热都会造成假迟到。</li>
 * </ul>
 *
 * <h3>指标为何用"欠账增长率"</h3>
 * <p>
 * 设 {@code L = now − 应发时刻}（迟到量，即当前欠账），窗口内发了 N 个包、墙钟耗时 W，
 * 这些包在目标时间轴上的理想跨度是 I，则
 * </p>
 * <pre>
 *   L_end − L_start = W − I        （欠账增长 = 多花掉的时间）
 *   ρ = (L_end − L_start) / W = 1 − I/W = 1 − 实际速率/目标速率
 * </pre>
 * <p>
 * 于是 {@code speed × (1−ρ)} 就是可持续倍率的<b>一步估计</b>。
 * </p>
 * <p>
 * <b>为什么不用绝对迟到量</b>：绝对量会把"永久偏移"和"持续落后"混为一谈。
 * 实测就踩过这个坑——回放开头一次启动积压（数据库/建连/首屏）会留下几百毫秒的固定欠账，
 * 此后发送速率其实已经达标（实测倍率 20.0017x、包间隔 0.473ms vs 目标 0.5ms），
 * 但"Σ迟到/墙钟"始终很高，控制器于是把它当成"发送方跟不上"，一路棘轮降到下限，
 * 把一次本来完全正常的回放拖成了 0.1x。改用欠账<b>增长</b>后，固定偏移不再触发降速，
 * 只有真正越落越远（每窗口欠账还在涨）才降速。
 * </p>
 *
 * <h3>职责边界</h3>
 * <p>
 * 本类<b>不改时间轴</b>：它只给出决策，由调用方（回放线程）把新倍率应用到
 * {@link ReplayClock#setSpeed(double)}。这样控制律可以脱离真实时钟做纯逻辑单测。
 * </p>
 */
public final class AdaptiveSpeedController {

    private static final Logger logger = LoggerFactory.getLogger(AdaptiveSpeedController.class);

    /** 倍率下限：触底后不再降速（硬编码，不提供 CLI 参数） */
    public static final double SPEED_FLOOR = 0.1;

    /** 采样窗口（纳秒）：按时间而非包数——降速后单位时间包数会变少，包数窗口会越来越迟钝 */
    private static final long WINDOW_NANOS = 500_000_000L;

    /**
     * 窗口结算所需的最小包数：不足时窗口<b>继续累积</b>，不结算也不丢弃。
     *
     * <p>结算只看"窗口首包 vs 末包"的迟到差。窗口内只有 1~3 个包时，这个差值就是
     * 两个包各自的<b>瞬时</b>迟到之差——一次 GC/线程抢占/系统定时器取整造成的几~十几毫秒
     * 抖动会被直接当成"这一窗口涨了多少"。样本太少时既不能据此调整倍率，也不能把它
     * 算进累计欠账，所以先不结算，等包数够了再一次性结算：窗口时长会自然拉长，
     * 首末差被更多样本平均，低包率数据源也仍然参与自适应（只是判定间隔更长）。</p>
     */
    private static final int MIN_PACKETS_PER_WINDOW = 8;

    /**
     * 降速触发所需的累计欠账增长（纳秒，默认 5 秒）。
     *
     * <p>从"上一次调整（降/升到目标）/重置"起，<b>持续</b>累积的欠账增长超过该预算
     * 才真正降速。这是用户要求的语义：总延时超过 5s 才考虑降速。
     * ms 级调度抖动无论单窗口还是累计都够不到几秒量级，因此不会因为"网络几乎没压力"
     * 而频繁降速；只有持续、累积的落后才跨越这个预算。</p>
     */
    private static final long REDUCE_DEFICIT_THRESHOLD_NANOS = 5_000_000_000L;

    /**
     * 触发降速所需的最小持续时长（纳秒，默认 5 秒）。
     *
     * <p>降速必须<b>同时</b>满足两个条件：
     * <ol>
     *   <li>累计欠账增长 ≥ {@link #REDUCE_DEFICIT_THRESHOLD_NANOS}（预算）；</li>
     *   <li>该增长是<b>连续 ≥ 本时长</b>的窗口叠加出来的（一路持续在涨，没有停顿）。</li>
     * </ol>
     * 任何"只涨了一两个窗口就停下来"的一次性尖峰（启动积压、开局数据库预热、首屏突发）
     * 都会在欠账停止增长时被清零，永远到不了预算——因此不会一上来就把倍率打下去。</p>
     *
     * <p>持续时长按"结算窗口数 × {@link #WINDOW_NANOS}"估算：每个结算窗口至少
     * 500ms（低包率时更长），所以真实持续时长只会 ≥ 这个值，是保守的下界。</p>
     */
    private static final long SUSTAIN_WINDOW_NANOS = 5_000_000_000L;

    /** 低阈值：窗口迟到率低于它才有资格升速 */
    private static final double LOW_LATENESS_RATIO = 0.002;

    /** 升速前需要连续达标的窗口数 */
    private static final int WINDOWS_BEFORE_SPEEDUP = 3;

    /** 降速时保留的余量：按实测可持续速率的 98% 走，避免刚好卡在临界点反复触阈值 */
    private static final double DOWN_MARGIN = 0.98;

    /** 单次降速的最大幅度（相对当前倍率） */
    private static final double MAX_DOWN_FACTOR_PER_STEP = 0.5;

    /** 单次升速的幅度 */
    private static final double UP_FACTOR = 1.02;

    /** 触底告警的最小间隔（纳秒），避免刷屏 */
    private static final long FLOOR_WARN_INTERVAL_NANOS = 5_000_000_000L;

    /** 认为"倍率确实变了"的最小差值 */
    private static final double MIN_SPEED_DELTA = 1e-6;

    /**
     * 单包迟到噪声门限（纳秒）：低于它的迟到视为调度抖动，不计入本窗口增长。
     *
     * <p>真正的"跟不上"是<b>累积性</b>的——欠账逐包增长；而调度抖动是孤立、有界的。
     * 该门限与 {@link #MIN_PACKETS_PER_WINDOW}（每个结算窗口至少 8 个包）一起，
     * 保证单点抖动不进入累计欠账信号。</p>
     */
    private static final long PACING_NOISE_FLOOR_NANOS = 500_000L;

    private double targetSpeed;
    private final boolean enabled;

    /** 当前生效倍率（本类是它的唯一所有者；调用方据此改写时间轴） */
    private double speed;

    /** 当前窗口起点；< 0 表示尚未开始 */
    private long windowStartNanos = -1;

    /**
     * 窗口起点的欠账（= 窗口内首个包的迟到量）。
     * <p>只有"欠账增长"才代表越落越远；固定偏移不影响速率，不该触发降速。</p>
     */
    private long windowStartDeficitNs = -1;

    /**
     * 自上次调整/重置起的<b>持续累计欠账增长</b>（纳秒）。
     *
     * <p>只累加"连续增长的窗口"：一旦某个窗口欠账不再增长（{@code Δ ≤ 0}），说明
     * 之前的积压是一次性的、已经停止恶化，就把累计清零。配合
     * {@link #consecutiveGrowthWindows} 一起，"总延时超过预算"与"持续超过预算"两把尺子
     * 同时满足才降速。这样一上来的一次性启动尖峰（几百 ms 涨一下就不涨了）不会被误判成
     * "持续跟不上"。</p>
     */
    private long deficitSinceAdjustNs = 0;

    /** 欠账连续增长的结算窗口数（本段、自上次调整起）。它 × 500ms 是持续时长的下界。 */
    private int consecutiveGrowthWindows = 0;

    /** 已观测到的最近一个包的迟到量（= 当前欠账） */
    private long lastDeficitNs = 0;

    /** 当前窗口内已观测的包数（仅本窗口） */
    private int windowPackets = 0;

    /** 连续达标窗口数（升速条件） */
    private int lowStreak = 0;

    /** 是否仍处于启动保护窗口 */
    private boolean warmup = true;

    private int downCount = 0;
    private int upCount = 0;
    private double minSpeed;
    private boolean reachedFloor = false;
    private long lastFloorWarnNanos = -1;

    /**
     * 构造控制器。
     *
     * @param targetSpeed 用户给定的目标倍率（上限），必须 &gt; 0 且有限
     * @param enabled     false 表示禁用自适应（仅供测试固定倍率；命令行不提供这个入口）：只观测、不调整
     * @throws IllegalArgumentException 目标倍率不为正数或非有限值
     */
    public AdaptiveSpeedController(double targetSpeed, boolean enabled) {
        if (!(targetSpeed > 0) || Double.isNaN(targetSpeed) || Double.isInfinite(targetSpeed)) {
            throw new IllegalArgumentException("speed must be a positive finite number, got: " + targetSpeed);
        }
        this.targetSpeed = targetSpeed;
        this.speed = targetSpeed;
        this.minSpeed = targetSpeed;
        this.enabled = enabled;
    }

    /**
     * 观察一个已发送的包，必要时在本窗口结束时给出调整决策。
     *
     * <p>调用方应把 {@link Decision#changed()} 为 true 的结果应用到时间轴。</p>
     *
     * @param nowNanos      当前单调时刻（纳秒）
     * @param latenessNanos 该包的迟到量（纳秒，&ge; 0；未迟到为 0）
     * @return 决策（未到窗口边界或样本不足时返回 {@link Reason#NONE}）
     */
    public Decision observe(long nowNanos, long latenessNanos) {
        if (windowStartNanos < 0) {
            windowStartNanos = nowNanos;
            windowStartDeficitNs = latenessNanos;
        }
        lastDeficitNs = latenessNanos;
        windowPackets++;

        long elapsed = nowNanos - windowStartNanos;
        // 窗口按时间结算；样本不足时继续累积（不结算、也不丢弃），攒够包数再结算。
        // 低包率时窗口时长自然变长，首末两包迟到差不再被单点抖动主导。
        if (elapsed < WINDOW_NANOS || windowPackets < MIN_PACKETS_PER_WINDOW) {
            return new Decision(false, speed, speed, 0.0, elapsed, windowPackets, Reason.NONE);
        }

        // 本窗口欠账净增长了多少 = 比理想时间轴多花掉的时间（扣除抖动容许量）
        long deficitGrowth = Math.max(0L, lastDeficitNs - windowStartDeficitNs - PACING_NOISE_FLOOR_NANOS);
        // 只统计"连续增长"：本窗口还在涨 → 累加并续长度；一旦停止增长 → 清零。
        // 一次性尖峰（启动积压等）会在欠账停止增长的那个窗口被清零，到不了预算，不降速。
        // 样本不足的窗口从未走到这里，因此单点抖动不会被计入累计欠账。
        if (deficitGrowth > 0) {
            deficitSinceAdjustNs += deficitGrowth;
            consecutiveGrowthWindows++;
        } else {
            deficitSinceAdjustNs = 0;
            consecutiveGrowthWindows = 0;
        }

        double latenessRatio = (double) deficitGrowth / elapsed;
        int packets = windowPackets;
        boolean settledWarmup = warmup;
        windowStartNanos = nowNanos;
        windowStartDeficitNs = latenessNanos;
        windowPackets = 0;
        if (settledWarmup) {
            warmup = false;
        }

        if (!enabled) {
            return decide(false, latenessRatio, elapsed, packets, Reason.DISABLED, nowNanos);
        }
        if (settledWarmup) {
            return decide(false, latenessRatio, elapsed, packets, Reason.WARMUP, nowNanos);
        }

        // ---- 降速触发：累计欠账增长 ≥ 5s 且 该增长持续 ≥ 5s（连续窗口）才降速 ----
        // 预算与持续性两把尺子同时对偶：任一不满足都不降。单窗口 75% 的一次性尖峰，因
        // 之后不再持续增长而被清零，永远不会触发——这正是"怎么一上来就降速"的修复点。
        boolean deficitBudgetExceeded =
                deficitSinceAdjustNs >= REDUCE_DEFICIT_THRESHOLD_NANOS;
        boolean sustained =
                consecutiveGrowthWindows * WINDOW_NANOS >= SUSTAIN_WINDOW_NANOS;
        if (deficitBudgetExceeded && sustained) {
            lowStreak = 0;
            return reduce(latenessRatio, elapsed, packets, nowNanos);
        }

        // ---- 升速：欠账在过去没有累积（预算没被占用）时，才有资格向上探测 ----
        if (latenessRatio < LOW_LATENESS_RATIO) {
            lowStreak++;
            if (speed >= targetSpeed - MIN_SPEED_DELTA) {
                return decide(false, latenessRatio, elapsed, packets, Reason.AT_TARGET, nowNanos);
            }
            if (lowStreak < WINDOWS_BEFORE_SPEEDUP) {
                return decide(false, latenessRatio, elapsed, packets, Reason.SPEEDUP_PENDING, nowNanos);
            }
            return increase(latenessRatio, elapsed, packets, nowNanos);
        }

        // 死区：视为达标，但不足以支撑升速
        lowStreak = 0;
        return decide(false, latenessRatio, elapsed, packets, Reason.DEAD_ZONE, nowNanos);
    }

    /**
     * 运行中重设目标倍率（用户调速 / 新段开局）。
     *
     * <p>用户明确给定新倍率时立即把当前 {@code speed} 对齐到目标（而不是等 AIMD 的 +2%/窗口
     * 缓慢爬升）；随后控制器仍按迟到率继续降速兜底。重置观测窗口并进入一个 warmup 窗口，
     * 避免把旧倍率下的欠账算到新倍率头上。</p>
     *
     * @param newTarget 新目标倍率，必须 &gt; 0 且有限
     * @throws IllegalArgumentException 非正数/非有限值
     */
    public void retarget(double newTarget) {
        if (!(newTarget > 0) || Double.isNaN(newTarget) || Double.isInfinite(newTarget)) {
            throw new IllegalArgumentException("speed must be a positive finite number, got: " + newTarget);
        }
        this.targetSpeed = newTarget;
        this.speed = newTarget;
        this.minSpeed = Math.min(this.minSpeed, newTarget);
        resetWindow();
        this.warmup = true;
        this.lowStreak = 0;
    }

    /**
     * 进入新重放段（定位/重启）时重置基线。
     *
     * <p>与 {@link #retarget(double)} 相同，但语义上用于“新段时间轴从目标倍率开局”；
     * 保留会话级 down/up/min 统计。</p>
     *
     * @param target 新段目标倍率
     */
        /**
     * 丢弃尚未结算的观测窗口，下一次 {@link #observe(long, long)} 重新建立基线。
     *
     * <h3>为什么需要</h3>
     * <p>
     * 回放侧存在<b>已知的空闲期</b>：{@code --split} 的滚动跟随要等新分卷出现、
     * 切换分卷时要建连/查询、多卷之间还要轮询。空闲期里没有包可发，恢复后首个包的
     * 迟到量会包含整段空闲时间；若不重置窗口，这段空闲会被当成"欠账增长"，
     * 控制器会把倍率错误地砍半——实测在跟随模式下每个分卷边界都会发生一次，
     * 而砍半后要花近一分钟才能靠 2%/窗口的 AIMD 升回来。
     * </p>
     * <p>
     * 本方法只丢弃"这一次窗口从哪里开始算"，<b>不改变当前倍率</b>，也不清除
     * {@code downCount}/{@code upCount}/{@code minSpeed} 等历史统计。下一次
     * {@link #observe(long, long)} 会以该包自身的迟到量作为新窗口的起点，
     * 因此固定偏移（空闲造成的固定迟到）不会产生任何"增长"信号。
     * </p>
     */
    public void resetWindow() {
        windowStartNanos = -1;
        windowStartDeficitNs = -1;
        windowPackets = 0;
        lowStreak = 0;
        // 新段/空闲后重新建立"自调整起累计欠账"的基线，避免把旧段的累计落后带到新段
        deficitSinceAdjustNs = 0;
        consecutiveGrowthWindows = 0;
    }

    /** 快降：按实测可持续速率一步到位 */
    private Decision reduce(double latenessRatio, long elapsed, int packets, long nowNanos) {
        // ρ ≥ 1 表示"一个窗口的迟到量超过了窗口本身"（窗口内已积压成倍欠账），
        // 此时 (1−ρ) 会变成非正数，直接乘会得到负的"可持续倍率"。夹到 0：
        // 含义是"远低于下限"，实际值由 lowerBound/floor 决定。
        double remainingRatio = Math.max(0.0, 1.0 - latenessRatio);
        double sustainable = speed * remainingRatio * DOWN_MARGIN;
        double lowerBound = Math.max(SPEED_FLOOR, speed * MAX_DOWN_FACTOR_PER_STEP);
        double next = Math.max(lowerBound, Math.min(speed, sustainable));
        next = Math.min(next, targetSpeed);
        boolean capped = sustainable < lowerBound && lowerBound < speed;

        if (next >= speed - MIN_SPEED_DELTA) {
            if (speed <= SPEED_FLOOR + MIN_SPEED_DELTA) {
                // 已经在下限：再降也不会更准，只告警（限流）
                reachedFloor = true;
                if (lastFloorWarnNanos < 0 || nowNanos - lastFloorWarnNanos >= FLOOR_WARN_INTERVAL_NANOS) {
                    lastFloorWarnNanos = nowNanos;
                    logger.warn("[Adaptive Speed] already at floor {}x but deficit is still growing {}%/window "
                                + "(sustainable≈{}x). Replay continues at the floor; the sender or the "
                                + "downstream link cannot keep up — consider a lower --speed or fixing the bottleneck.",
                            String.format("%.2f", SPEED_FLOOR),
                            String.format("%.1f", latenessRatio * 100),
                            String.format("%.2f", speed * (1.0 - latenessRatio)));
                }
                return decide(false, latenessRatio, elapsed, packets, Reason.FLOOR, nowNanos);
            }
            return decide(false, latenessRatio, elapsed, packets, Reason.NONE, nowNanos);
        }

        double previous = speed;
        speed = next;
        downCount++;
        minSpeed = Math.min(minSpeed, speed);
        // 本次降速即"新的起点"：累计欠账预算从此清零，下次再从 0 累计到 5s
        deficitSinceAdjustNs = 0;
        consecutiveGrowthWindows = 0;
        logger.info("[Adaptive Speed] {}x -> {}x (deficit growth {}% over {} ms, {} packets, sustainable≈{}x{})",
                String.format("%.3f", previous),
                String.format("%.3f", speed),
                String.format("%.1f", latenessRatio * 100),
                String.format("%.0f", elapsed / 1e6),
                packets,
                String.format("%.3f", sustainable),
                capped ? ", capped at -50% per step" : "");
        return new Decision(true, previous, speed, latenessRatio, elapsed, packets, Reason.DOWN);
    }

    /** 慢升：小幅探测，封顶在目标倍率 */
    private Decision increase(double latenessRatio, long elapsed, int packets, long nowNanos) {
        double next = Math.min(targetSpeed, speed * UP_FACTOR);
        if (next <= speed + MIN_SPEED_DELTA) {
            return decide(false, latenessRatio, elapsed, packets, Reason.AT_TARGET, nowNanos);
        }
        double previous = speed;
        speed = next;
        upCount++;
        lowStreak = 0;
        deficitSinceAdjustNs = 0;
        consecutiveGrowthWindows = 0;
        logger.info("[Adaptive Speed] {}x -> {}x (deficit growth {}% for {} consecutive windows, probing upward)",
                String.format("%.3f", previous),
                String.format("%.3f", speed),
                String.format("%.2f", latenessRatio * 100),
                WINDOWS_BEFORE_SPEEDUP);
        return new Decision(true, previous, speed, latenessRatio, elapsed, packets, Reason.UP);
    }

    private Decision decide(boolean changed, double latenessRatio, long elapsed, int packets,
                            Reason reason, long nowNanos) {
        return new Decision(changed, speed, speed, latenessRatio, elapsed, packets, reason);
    }

    /** @return 当前生效倍率 */
    public double speed() {
        return speed;
    }

    /** @return 用户给定的目标倍率（上限） */
    public double targetSpeed() {
        return targetSpeed;
    }

    /** @return 是否启用自适应降速 */
    public boolean enabled() {
        return enabled;
    }

    /** @return 降速次数 */
    public int downCount() {
        return downCount;
    }

    /** @return 运行中达到过的最低倍率 */
    public double minSpeed() {
        return minSpeed;
    }

    /** @return 升速次数 */
    public int upCount() {
        return upCount;
    }

    /** @return 是否曾经触底（floor） */
    public boolean reachedFloor() {
        return reachedFloor;
    }

    /** 调整原因 */
    public enum Reason {
        /** 未到窗口边界或样本不足，未结算 */
        NONE,
        /** 自适应被禁用（仅测试内部开关） */
        DISABLED,
        /** 启动保护窗口：只观测不调整 */
        WARMUP,
        /** 降速 */
        DOWN,
        /** 升速 */
        UP,
        /** 迟到率处于死区：达标但不足以升速 */
        DEAD_ZONE,
        /** 已达目标倍率上限 */
        AT_TARGET,
        /** 升速条件还差几个达标窗口 */
        SPEEDUP_PENDING,
        /** 已在下限，无法再降 */
        FLOOR
    }

    /**
     * 一次窗口结算的结果。
     *
     * @param changed        倍率是否变化（true 时调用方需应用到 {@link ReplayClock}）
     * @param previousSpeed  调整前倍率
     * @param speed          调整后倍率
     * @param latenessRatio  本窗口欠账增长率 ρ（= 1 − 实际速率/目标速率）
     * @param windowNanos    本窗口墙钟时长
     * @param windowPackets  本窗口包数
     * @param reason         决策原因
     */
    public record Decision(boolean changed, double previousSpeed, double speed, double latenessRatio,
                           long windowNanos, int windowPackets, Reason reason) {

        /** @return 本窗口时长（毫秒） */
        public double windowMillis() {
            return windowNanos / 1e6;
        }
    }
}
