package com.jshark;

import com.jshark.parser.ReplayClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A3 验收测试：重放时钟的严格精确倍率。
 *
 * <h3>验证项</h3>
 * <ol>
 *   <li>speed=1 / 2 / 0.5 下，总时长严格按倍率缩放（误差 &lt; 0.1%，且与仿射模型逐纳秒相等）</li>
 *   <li>{@code earlyCount} 恒为 0：任何包都不会提前发送</li>
 *   <li>落后时不补睡：迟到量逐包如实累计，并与解析模型逐纳秒一致</li>
 *   <li>长等待被切成片，等待总量仍等于理想间隔</li>
 *   <li>亚毫秒（微秒）精度被保留</li>
 *   <li>输入时间戳单调时，应发时刻严格单调</li>
 *   <li>时间戳转换（Timestamp / Instant）口径一致</li>
 * </ol>
 *
 * <p>全部为纯计算断言：不需要网络、不需要特权、不真实等待。</p>
 *
 * <p><b>注意：</b>本测试的所有时间戳都用<b>整数纳秒</b>累加构造。绝对 epoch 纳秒约 1.7e18，
 * 超出 double 的整数有效范围（2^53），若用 {@code base + i * stepMs * 1e6} 的 double 写法
 * 会损失约 256 ns 精度，使时间戳整体前移并污染逐纳秒断言。</p>
 */
public class ReplayClockTest {

    private static final Logger logger = LoggerFactory.getLogger(ReplayClockTest.class);

    /** 基准时刻：2023-11-15T06:13:20Z */
    private static final long BASE_EPOCH_MS = java.time.LocalDateTime
            .of(2023, 11, 15, 6, 13, 20)
            .toInstant(java.time.ZoneOffset.UTC)
            .toEpochMilli();

    private static int totalChecks;
    private static int failedChecks;

    /** 可控时间源：{@code advance()} 由等待器驱动前进 */
    private static final class FakeTime implements ReplayClock.TimeSource {
        private long now;

        FakeTime(long start) {
            this.now = start;
        }

        @Override
        public long nanoTime() {
            return now;
        }

        void advance(long nanos) {
            now += nanos;
        }
    }

    /** 与 FakeTime 配对的等待器：不真实休眠，只把假时钟推进相应时长 */
    private static final class FakeSleeper implements ReplayClock.Sleeper {
        private final FakeTime time;
        private long totalSlept;

        FakeSleeper(FakeTime time) {
            this.time = time;
        }

        @Override
        public void sleep(long nanos) {
            totalSlept += nanos;
            time.advance(nanos);
        }
    }

    @org.junit.jupiter.api.Test
    void replayClockRegression() {
        logger.info("=================================================");
        logger.info("  A3 验收：重放时钟精确倍率");
        logger.info("=================================================");

        checkTimeStampConversion();
        checkExactScaling();
        checkNoEarlySend();
        checkLateDoesNotCatchUp();
        checkLongWaitIsChunked();
        checkSubMillisecondPrecision();
        checkMonotonicTargets();
        checkGuardConditions();
        checkSpeedChangeNeverEarly();
        checkSpeedChangeAbsorbsLateness();
        checkSegmentedIdealDuration();
        checkSpeedChangeContracts();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    // ==================== 用例 ====================

    /** 用例 1：Timestamp / Instant 两条路径的纳秒口径必须一致，且保留微秒 */
    private static void checkTimeStampConversion() {
        logger.info("---- [1] 时间戳转换口径 ----");
        Timestamp ts = new Timestamp(1_700_000_000_123L);
        ts.setNanos(123_456_789); // 123.456789 ms
        ReplayClock.PacketTime fromTs = ReplayClock.PacketTime.of(ts);
        ReplayClock.PacketTime fromInstant = ReplayClock.PacketTime.of(ts.toInstant());

        check(fromTs.toEpochNanos() == fromInstant.toEpochNanos(),
                "Timestamp 与 Instant 转换口径一致 (" + fromTs.toEpochNanos() + ")");
        check(fromTs.toEpochNanos() == 1_700_000_000L * 1_000_000_000L + 123_456_789L,
                "保留微秒精度 (" + fromTs.toEpochNanos() + " ns)");
        check(fromTs.nanoOfMillis() == 123_456_789 % 1_000_000,
                "毫秒内余数正确 (" + fromTs.nanoOfMillis() + " ns)");

        Timestamp whole = Timestamp.from(Instant.ofEpochSecond(1_700_000_000L));
        check(ReplayClock.PacketTime.of(whole).toEpochNanos() == 1_700_000_000L * 1_000_000_000L,
                "整秒时间戳无偏移");
    }

    /** 用例 2：总时长与包间隔严格按倍率缩放 */
    private static void checkExactScaling() {
        logger.info("---- [2] 严格精确倍率 ----");
        for (double speed : new double[] {1.0, 2.0, 0.5}) {
            List<ReplayClock.PacketTime> packets = linePackets(1001, 10_000_000L);
            long spanNanos = 1000L * 10_000_000L;              // 首末包时间差 = 10 s
            long idealNanos = Math.round(spanNanos / speed);   // 理想总时长

            long actualNanos = runSchedule(speed, packets);
            double errPct = 100.0 * Math.abs(idealNanos - actualNanos) / (double) idealNanos;

            check(actualNanos == idealNanos,
                    String.format("speed=%.1f 总时长与仿射模型逐纳秒相等 (%d ns)", speed, actualNanos));
            check(errPct < 0.1,
                    String.format("speed=%.1f 总时长 %.6f s 与理想 %.6f s 偏差 %.4f%% (< 0.1%%)",
                            speed, actualNanos / 1e9, idealNanos / 1e9, errPct));
        }
    }

    /** 用例 3：任何包都不提前发送 */
    private static void checkNoEarlySend() {
        logger.info("---- [3] 绝不提前发送 ----");
        FakeTime time = new FakeTime(1_000_000_000L);
        ReplayClock clock = new ReplayClock(2.0, time, null);
        List<ReplayClock.PacketTime> packets = linePackets(200, 5_000_000L);
        clock.anchor(packets.get(0));

        int early = 0;
        for (int i = 1; i < packets.size(); i++) {
            ReplayClock.Schedule s = clock.scheduleNext(packets.get(i));
            if (s.waitNanos() > 0) {
                time.advance(s.waitNanos());
            }
            // 等待结束后确认：当前时刻不早于应发时刻（绝不提前发送）
            if (time.nanoTime() < s.targetNano()) {
                early++;
            }
        }
        check(early == 0, "提前发送次数 == 0 (" + early + ")");
        check(clock.stats().lateCount() == 0, "无迟到包 (" + clock.stats().lateCount() + ")");
    }

    /** 用例 4：落后时不补睡，迟到如实统计 */
    private static void checkLateDoesNotCatchUp() {
        logger.info("---- [4] 落后不补睡 ----");
        FakeTime time = new FakeTime(0L);
        FakeSleeper sleeper = new FakeSleeper(time);
        ReplayClock clock = new ReplayClock(1.0, time, sleeper);

        // 间隔 1ms，而每包"发送耗时"为 1.2ms → 必然逐步落后
        long gapNanos = 1_000_000L;
        long sendCostNanos = 1_200_000L;
        List<ReplayClock.PacketTime> packets = linePackets(100, gapNanos);
        clock.anchor(packets.get(0));

        List<Long> observedLateness = new ArrayList<>();
        int sleepsWhileLate = 0;

        for (int i = 1; i < packets.size(); i++) {
            // 与生产调度完全同构：先问"还要不要等"，等完再问一次，读到的即"发送瞬间"的迟到量
            ReplayClock.Schedule s = clock.scheduleNext(packets.get(i));
            while (s.waitNanos() > 0) {
                sleeper.sleep(s.waitNanos());
                s = clock.scheduleNext(packets.get(i));
            }
            observedLateness.add(s.latenessNanos());
            // 模拟发送本身的开销
            time.advance(sendCostNanos);
        }

        // 解析模型：与实测循环严格同口径。
        // 时间线：首包准点发出并消耗一次发送开销 → 第 1 个后续包需等待 1 个间隔（等待也消耗时间）
        // → 此后每包净落后 (发送开销 − 间隔)。因此调度第 i 个包时时钟为 (i−1)×开销 + 间隔。
        int mismatches = 0;
        long expectTotal = 0;
        long expectMax = 0;
        long expectLateCount = 0;
        List<Long> expectedLateness = new ArrayList<>();
        for (int i = 1; i < packets.size(); i++) {
            long clockTime = (i - 1) * sendCostNanos + gapNanos;
            long deadline = i * gapNanos;
            long expect = Math.max(clockTime - deadline, 0);
            expectedLateness.add(expect);
            if (observedLateness.get(i - 1) != expect) {
                mismatches++;
            }
            if (expect > 0) {
                expectLateCount++;
                expectTotal += expect;
                expectMax = Math.max(expectMax, expect);
            }
        }

        if (mismatches > 0) {
            logger.error("  诊断：observed[0..4]={} expected[0..4]={}",
                    observedLateness.subList(0, Math.min(5, observedLateness.size())),
                    expectedLateness.subList(0, Math.min(5, expectedLateness.size())));
        }

        List<ReplayClock.PacketTime> firstLate = new ArrayList<>();
        for (int i = 0; i < observedLateness.size(); i++) {
            if (observedLateness.get(i) > 0) {
                firstLate.add(packets.get(i + 1));
                break;
            }
        }

        ReplayClock.Stats stats = clock.stats();
        check(mismatches == 0, "逐包迟到量与解析模型逐纳秒一致（不一致 " + mismatches + " 项）");
        check(stats.lateCount() == expectLateCount,
                "迟到包数 == " + expectLateCount + " (实际 " + stats.lateCount() + ")");
        check(stats.totalLatenessNs() == expectTotal,
                "累计迟到量 == " + expectTotal / 1e6 + " ms (实际 " + stats.totalLatenessNs() / 1e6 + " ms)");
        check(stats.maxLatenessNs() == expectMax,
                "最大迟到量 == " + expectMax / 1e6 + " ms (实际 " + stats.maxLatenessNs() / 1e6 + " ms)");
        check(observedLateness.get(0) == 0L, "首个后续包仍按时发出（迟到 0）");
        check(!firstLate.isEmpty(), "确实构造出了落后场景（首个迟到包 " + firstLate + "）");
        // 唯一的一次等待发生在尚未落后的那个包上；一旦落后就再未等待（不补睡）
        check(sleeper.totalSlept == gapNanos,
                "落后后不再补睡：全程仅等待 1 次 " + gapNanos / 1e6 + " ms（实际 " + sleeper.totalSlept + " ns）");
    }

    /** 用例 5：长等待被切片，但等待总量不变 */
    private static void checkLongWaitIsChunked() {
        logger.info("---- [5] 长等待切片 ----");
        FakeTime time = new FakeTime(0L);
        FakeSleeper sleeper = new FakeSleeper(time);
        ReplayClock clock = new ReplayClock(1.0, time, sleeper);

        // 只放两个包：间隔 10 秒，远超 50ms 的切片上限
        List<ReplayClock.PacketTime> packets = new ArrayList<>();
        packets.add(ReplayClock.PacketTime.ofEpochNanos(epochMs(0) * 1_000_000L));
        packets.add(ReplayClock.PacketTime.ofEpochNanos(epochMs(10_000) * 1_000_000L));
        clock.anchor(packets.get(0));

        int loops = 0;
        int oversize = 0;
        ReplayClock.Schedule s = clock.scheduleNext(packets.get(1));
        while (s.waitNanos() > 0) {
            long chunk = s.waitNanos();
            if (chunk > 50L * 1_000_000L) {
                oversize++;
            }
            sleeper.sleep(chunk);
            loops++;
            s = clock.scheduleNext(packets.get(1));
        }

        check(oversize == 0, "单次等待均不超过 50ms（超限 " + oversize + " 次）");
        check(loops >= 199 && loops <= 201, "10s 等待被切成约 200 片（实际 " + loops + "）");
        check(sleeper.totalSlept == 10_000L * 1_000_000L,
                "等待总量恰为 10s（实际 " + sleeper.totalSlept / 1e6 + " ms）");
        check(s.latenessNanos() == 0, "切片结束后不迟到");
    }

    /** 用例 6：亚毫秒精度被保留（10.5ms 间隔在 speed=1 下仍为 10.5ms） */
    private static void checkSubMillisecondPrecision() {
        logger.info("---- [6] 亚毫秒精度 ----");
        FakeTime time = new FakeTime(0L);
        FakeSleeper sleeper = new FakeSleeper(time);
        ReplayClock clock = new ReplayClock(1.0, time, sleeper);

        long stepNanos = 10_500_000L; // 10.5 ms
        List<ReplayClock.PacketTime> packets = linePackets(100, stepNanos);
        clock.anchor(packets.get(0));

        long firstWait = clock.scheduleNext(packets.get(1)).waitNanos();
        for (int i = 1; i < packets.size(); i++) {
            ReplayClock.Schedule s = clock.scheduleNext(packets.get(i));
            while (s.waitNanos() > 0) {
                sleeper.sleep(s.waitNanos());
                s = clock.scheduleNext(packets.get(i));
            }
        }

        check(firstWait == stepNanos,
                "首包间隔保留亚毫秒精度 10.5 ms（实际 " + firstWait / 1e6 + " ms）");
        check(sleeper.totalSlept == 99L * stepNanos,
                "总等待 = 99 × 10.5 ms（实际 " + sleeper.totalSlept / 1e6 + " ms）");
        check(clock.stats().lateCount() == 0, "无迟到");
    }

    /** 用例 7：单调输入 → 应发时刻严格单调 */
    private static void checkMonotonicTargets() {
        logger.info("---- [7] 应发时刻单调 ----");
        FakeTime time = new FakeTime(0L);
        ReplayClock clock = new ReplayClock(4.0, time, null);
        List<ReplayClock.PacketTime> packets = linePackets(500, 3_000_000L);
        clock.anchor(packets.get(0));

        long prevTarget = -1;
        int violations = 0;
        for (int i = 1; i < packets.size(); i++) {
            long target = clock.scheduleNext(packets.get(i)).targetNano();
            if (prevTarget >= 0 && target < prevTarget) {
                violations++;
            }
            prevTarget = target;
        }
        check(violations == 0, "应发时刻无回退 (" + violations + ")");
    }

    /** 用例 8：契约与边界 */
    private static void checkGuardConditions() {
        logger.info("---- [8] 契约与边界 ----");

        boolean threw = false;
        try {
            new ReplayClock(0.0, ReplayClock.TimeSource.SYSTEM, null);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check(threw, "speed=0 被拒绝");

        threw = false;
        try {
            new ReplayClock(-1.0, ReplayClock.TimeSource.SYSTEM, null);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check(threw, "speed=-1 被拒绝");

        ReplayClock clock = new ReplayClock(1.0, new FakeTime(0), null);
        threw = false;
        try {
            clock.scheduleNext(ReplayClock.PacketTime.ofEpochNanos(0));
        } catch (IllegalStateException e) {
            threw = true;
        }
        check(threw, "未锚定即调度被拒绝");

        clock.anchor(ReplayClock.PacketTime.ofEpochNanos(epochMs(0) * 1_000_000L));
        threw = false;
        try {
            clock.anchor(ReplayClock.PacketTime.ofEpochNanos(0));
        } catch (IllegalStateException e) {
            threw = true;
        }
        check(threw, "重复锚定被拒绝");

        // 巨大但合法的时间跨度（1 天）不应溢出
        ReplayClock big = new ReplayClock(1.0, new FakeTime(0), null);
        big.anchor(ReplayClock.PacketTime.ofEpochNanos(epochMs(0) * 1_000_000L));
        long dayNanos = 86_400L * 1_000_000_000L;
        ReplayClock.Schedule s = big.scheduleNext(
                ReplayClock.PacketTime.ofEpochNanos(epochMs(0) * 1_000_000L + dayNanos));
        check(s.targetNano() == dayNanos, "1 天跨度无溢出 (" + s.targetNano() / 1e9 + " s)");

        check(ReplayClock.PacketTime.of((Timestamp) null) == null, "null Timestamp 返回 null");
        check(ReplayClock.PacketTime.of((Instant) null) == null, "null Instant 返回 null");
    }

    // ==================== 用例（自适应调速） ====================

    /**
     * 用例 9：运行中调速（自适应降速/回升）后，应发时刻不得提前，且全程单调不回退。
     *
     * <p>这是"宁肯发得慢也不将就用户倍率"的数学保证：重锚取 {@code φ = now}，
     * 于是调整后第一个包满足 {@code target = now + Δ/speed ≥ now}，绝不会出现
     * "为了追赶而立刻猛发"。</p>
     */
    private static void checkSpeedChangeNeverEarly() {
        logger.info("---- [9] 调速后绝不提前 ----");
        FakeTime time = new FakeTime(1_000_000_000L);
        FakeSleeper sleeper = new FakeSleeper(time);
        ReplayClock clock = new ReplayClock(4.0, time, sleeper);
        List<ReplayClock.PacketTime> packets = linePackets(200, 1_000_000L);
        clock.anchor(packets.get(0));

        double[] speedPlan = {2.0, 1.0, 0.5, 3.0, 0.1, 4.0};
        int earlyAfterAdjust = 0;
        int backwardTarget = 0;
        int adjustments = 0;
        long prevTarget = Long.MIN_VALUE;

        for (int i = 1; i < packets.size(); i++) {
            long nowAtAdjust = time.nanoTime();
            boolean adjusted = (i % 20 == 0);
            if (adjusted) {
                clock.setSpeed(speedPlan[(i / 20) % speedPlan.length]);
                adjustments++;
            }

            ReplayClock.Schedule s = clock.scheduleNext(packets.get(i));
            if (adjusted && s.targetNano() < nowAtAdjust) {
                earlyAfterAdjust++;
            }
            if (s.targetNano() < prevTarget) {
                backwardTarget++;
            }
            prevTarget = s.targetNano();

            // 等到应发时刻再"发送"，模拟回放循环
            while (s.waitNanos() > 0) {
                sleeper.sleep(s.waitNanos());
                s = clock.scheduleNext(packets.get(i));
                if (s.targetNano() < prevTarget) {
                    backwardTarget++;
                }
                prevTarget = s.targetNano();
            }
        }

        check(earlyAfterAdjust == 0, "调速后首个包不早于调整时刻 (" + earlyAfterAdjust + " 次违反)");
        check(backwardTarget == 0, "全程应发时刻不回退 (" + backwardTarget + " 次违反)");
        check(clock.speedAdjustCount() == adjustments,
                "调速计数正确 (" + clock.speedAdjustCount() + "/" + adjustments + ")");
        check(clock.minSpeed() == 0.1, "最低倍率被记录 (" + clock.minSpeed() + "x)");
        check(clock.speed() == 3.0, "最终倍率正确 (" + clock.speed() + "x)");
    }

    /**
     * 用例 10：调速重锚吸收已积累的迟到量，并且新段从"现在"起算。
     *
     * <p>不重锚（保留旧 φ）的后果是欠账永久挂在时间轴上：即便此后已经可持续，
     * 报告里的实测倍率也会永远低于目标。重锚用一次"干净开局"换掉这个永久偏移，
     * 被放弃的欠账单独记入 {@code absorbedLatenessNanos} 以便如实汇报。</p>
     */
    private static void checkSpeedChangeAbsorbsLateness() {
        logger.info("---- [10] 调速重锚吸收迟到 ----");
        FakeTime time = new FakeTime(0L);
        FakeSleeper sleeper = new FakeSleeper(time);
        ReplayClock clock = new ReplayClock(2.0, time, sleeper);
        List<ReplayClock.PacketTime> packets = linePackets(10, 1_000_000L);
        clock.anchor(packets.get(0));
        check(clock.firstScheduledEpochNanos() == packets.get(0).toEpochNanos(),
                "首包时间戳被记录（报告跨度用）");

        // p1 准点发出：speed=2 时 1ms 的原始间隔被压缩成 500µs
        ReplayClock.Schedule s = clock.scheduleNext(packets.get(1));
        while (s.waitNanos() > 0) {
            sleeper.sleep(s.waitNanos());
            s = clock.scheduleNext(packets.get(1));
        }
        check(s.latenessNanos() == 0, "p1 准点发出（无迟到）");
        check(time.nanoTime() == 500_000L, "p1 应发时刻 = 500µs (" + time.nanoTime() + " ns)");

        // 模拟一次 5ms 停顿：时间已远远越过旧时间轴的应发时刻
        long stall = 5_000_000L;
        time.advance(stall);
        long nowBefore = time.nanoTime();
        clock.setSpeed(1.0);

        check(clock.absorbedLatenessNanos() == stall,
                "吸收的迟到量 == 停顿量 (" + clock.absorbedLatenessNanos() + " ns)");

        ReplayClock.Schedule next = clock.scheduleNext(packets.get(2));
        check(next.targetNano() >= nowBefore, "重锚后下一包不早于现在");
        check(next.targetNano() == nowBefore + 1_000_000L,
                "重锚后下一包 = now + 1ms/1.0x (" + (next.targetNano() - nowBefore) + " ns 之后)");
        // 报告用的整段跨度必须从最初的首包算起：调速只重锚 φ/anchor，不能改写历史起点
        check(clock.firstScheduledEpochNanos() == packets.get(0).toEpochNanos(),
                "调速不改变整段起点（仍是 p0）");
        check(clock.lastScheduledEpochNanos() == packets.get(2).toEpochNanos(),
                "最近调度包随调度前进 (p2)");

        // 不调速的反例：同一停顿会让欠账留在时间轴上（后续每包都迟到）
        FakeTime stuckTime = new FakeTime(0L);
        FakeSleeper stuckSleeper = new FakeSleeper(stuckTime);
        ReplayClock stuck = new ReplayClock(2.0, stuckTime, stuckSleeper);
        stuck.anchor(packets.get(0));
        stuckTime.advance(stall);
        check(stuck.scheduleNext(packets.get(1)).latenessNanos() == stall - 500_000L,
                "不重锚时迟到量挂在时间轴上 (" + (stall - 500_000L) + " ns)");
    }

    /** 用例 11：自适应降速下"理想总时长"必须逐段积分，而不是用当前倍率乘总跨度 */
    private static void checkSegmentedIdealDuration() {
        logger.info("---- [11] 分段理想时长 ----");
        FakeTime time = new FakeTime(0L);
        ReplayClock clock = new ReplayClock(2.0, time, null);
        List<ReplayClock.PacketTime> packets = linePackets(11, 1_000_000L); // p0..p10，跨度 10ms
        clock.anchor(packets.get(0));

        long singleSpeedIdeal = clock.idealDurationNanos(packets.get(0), packets.get(10));
        check(singleSpeedIdeal == 5_000_000L, "未调速：10ms/2.0x = 5ms (" + singleSpeedIdeal + " ns)");

        // 第一段 2.0x 跑到 p5（跨度 5ms），之后降到 1.0x 跑完剩下 5ms
        for (int i = 1; i <= 5; i++) {
            clock.scheduleNext(packets.get(i));
        }
        time.advance(3_000_000L); // 制造迟到，确保吸收路径也被走到
        clock.setSpeed(1.0);

        long segmented = clock.idealDurationNanos(packets.get(0), packets.get(10));
        check(segmented == 7_500_000L, "分段理想时长 = 5ms/2.0x + 5ms/1.0x = 7.5ms (" + segmented + " ns)");
        check(clock.absorbedLatenessNanos() > 0, "迟到被吸收 (" + clock.absorbedLatenessNanos() + " ns)");

        // 只统计区间的一部分时也要正确
        long partial = clock.idealDurationNanos(packets.get(2), packets.get(8));
        check(partial == 4_500_000L, "区间 [p2,p8] 分段积分 = 3ms/2.0x + 3ms/1.0x = 4.5ms (" + partial + " ns)");
    }

    /** 用例 12：调速的契约与边界 */
    private static void checkSpeedChangeContracts() {
        logger.info("---- [12] 调速契约与边界 ----");

        FakeTime time = new FakeTime(0L);
        ReplayClock clock = new ReplayClock(4.0, time, null);

        boolean threw = false;
        try {
            clock.setSpeed(0.0);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check(threw, "setSpeed(0) 被拒绝");

        threw = false;
        try {
            clock.setSpeed(Double.NaN);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check(threw, "setSpeed(NaN) 被拒绝");

        threw = false;
        try {
            clock.setSpeed(Double.POSITIVE_INFINITY);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        check(threw, "setSpeed(Inf) 被拒绝");

        // 未锚定时只是换初值：时间轴还没有段
        clock.setSpeed(0.5);
        check(clock.speed() == 0.5 && clock.minSpeed() == 0.5, "未锚定调速直接生效 (0.5x)");
        check(clock.speedAdjustCount() == 0, "未锚定调速不计入调整次数");
        check(clock.firstScheduledEpochNanos() == -1 && clock.lastScheduledEpochNanos() == -1,
                "未锚定时报告跨度不可用 (-1)");

        List<ReplayClock.PacketTime> packets = linePackets(4, 1_000_000L);
        clock.anchor(packets.get(0));
        check(clock.scheduleNext(packets.get(1)).targetNano() == 2_000_000L,
                "锚定后按新初值缩放 (1ms/0.5x = 2ms)");

        // 同值空操作：不产生新段、不增加计数
        int before = clock.speedAdjustCount();
        clock.setSpeed(0.5);
        check(clock.speedAdjustCount() == before, "同值调速是空操作");

        // 最低倍率只记录真正达到过的值
        clock.setSpeed(2.0);
        clock.setSpeed(3.0);
        check(clock.minSpeed() == 0.5, "最低倍率保持为历史最小值 (" + clock.minSpeed() + "x)");
        check(clock.speedAdjustCount() == before + 2, "调速次数累计正确 (" + clock.speedAdjustCount() + ")");
    }

    // ==================== 工具 ====================

    /**
     * 按固定间隔生成时间戳序列（整数纳秒累加，见类注释的精度说明）。
     *
     * @param count     包数
     * @param stepNanos 间隔（纳秒）
     */
    private static List<ReplayClock.PacketTime> linePackets(int count, long stepNanos) {
        long baseNanos = epochMs(0) * 1_000_000L;
        List<ReplayClock.PacketTime> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            list.add(ReplayClock.PacketTime.ofEpochNanos(baseNanos + i * stepNanos));
        }
        return list;
    }

    /**
     * 用假时钟跑完整个调度，返回"从首包到末包的实际耗时"（纳秒）。
     */
    private static long runSchedule(double speed, List<ReplayClock.PacketTime> packets) {
        FakeTime time = new FakeTime(1_000_000_000L);
        FakeSleeper sleeper = new FakeSleeper(time);
        ReplayClock clock = new ReplayClock(speed, time, sleeper);
        clock.anchor(packets.get(0));
        long start = time.nanoTime();
        for (int i = 1; i < packets.size(); i++) {
            ReplayClock.Schedule s = clock.scheduleNext(packets.get(i));
            while (s.waitNanos() > 0) {
                sleeper.sleep(s.waitNanos());
                s = clock.scheduleNext(packets.get(i));
            }
        }
        return time.nanoTime() - start;
    }

    /** 以基准时刻构造 epoch 毫秒 */
    private static long epochMs(long offsetMs) {
        return BASE_EPOCH_MS + offsetMs;
    }

    /** 断言成功（失败即测试失败）：保留原夹具的调用形态与中文消息，内部改用 JUnit 断言。 */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
