package com.jshark;

import com.jshark.parser.AdaptiveSpeedController;
import com.jshark.parser.AdaptiveSpeedController.Decision;
import com.jshark.parser.AdaptiveSpeedController.Reason;
import com.jshark.parser.ReplayClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自适应降速控制器的纯逻辑验收测试。
 *
 * <p>控制器不碰时间轴、不碰 IO，窗口用"显式传入的单调时刻"驱动，
 * 因此这里全部是确定性断言：不需要网络、不真实等待。</p>
 *
 * <h3>验证项</h3>
 * <ol>
 *   <li>超速时按实测可持续速率一步降到位（而不是每次 10% 慢慢试探）</li>
 *   <li>单次降幅上限 50%，防止一个异常窗口把倍率打崩</li>
 *   <li>止损于 floor=0.1：触底后不再降速，只标记 reachedFloor</li>
 *   <li>死区（达标但余量不足）不调整，避免在临界点反复横跳</li>
 *   <li>AIMD：连续 3 个达标窗口才升速 2%，且永不超过目标倍率</li>
 *   <li>降速后必须重新累计预算/持续窗口，不会连续降速</li>
 *   <li>低包率窗口延迟结算：包数不足 8 个时不结算、不累计，攒够后再按整段窗口判断</li>
 *   <li>首个窗口是启动保护：只观测、不调整</li>
 *   <li>内部禁用开关（仅测试）时只观测、永不调整</li>
 *   <li>分卷/空闲间隔（resetWindow）不计入控制信号，不得因此降速</li>
 * </ol>
 */
public class AdaptiveSpeedControllerTest {

    private static final Logger logger = LoggerFactory.getLogger(AdaptiveSpeedControllerTest.class);

    /** 采样窗口：与控制器的 WINDOW_NANOS 对应 */
    private static final long WINDOW_NANOS = 500_000_000L;

    private static final double EPS = 1e-9;

    /** 可控时间源：仅在闭环用例中使用（时间由等待器与"发送耗时"共同推进） */
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

    /** 窗口游标：每次 settle 都推进一个窗口并结算 */
    private long cursor;

    /**
     * 当前欠账（= 最近一个包的迟到量）。控制器看的是它的<b>增长</b>，
     * 因此夹具必须把欠账跨窗口连续地模拟出来，而不能每个窗口从 0 开始。
     */
    private long deficit;

    /**
     * 结算一个窗口：本窗口内欠账增长 {@code spacing × rho}。
     *
     * <p>用足够多的包（100 个）满足最小包数门槛。中间包紧贴窗口起点（不结算），
     * 增长全部由末包在窗口末尾结算。</p>
     *
     * @param c       控制器
     * @param spacing 该窗口的墙钟时长（纳秒）
     * @param rho     目标欠账增长率（= 1 − 实际速率/目标速率）
     */
    private Decision settle(AdaptiveSpeedController c, long spacing, double rho) {
        int packets = 100;
        long start = cursor;
        c.observe(start, deficit);                                // 窗口起点（建立/沿用基线）
        // 中间包紧贴窗口起点散布（时间几乎不动），只用来满足最小包数门槛，不触发结算
        for (int i = 1; i < packets - 1; i++) {
            cursor = start + i;
            c.observe(cursor, deficit);
        }
        // 末包携带全部增长、精确落在 start+spacing 处 → 在此结算，last 即本次决策
        deficit += Math.round(spacing * rho);
        cursor = start + spacing;
        return c.observe(cursor, deficit);
    }

    /**
     * 结算一个含 {@code packets} 个包的窗口，每包把欠账推高 {@code growthPerPacket}。
     *
     * @param c                 控制器
     * @param spacing           窗口墙钟时长（纳秒）
     * @param packets           窗口内包数
     * @param growthPerPacket   单包欠账增长（纳秒）；0 表示"只是有固定偏移，但没有越落越远"
     * @return 窗口末尾的决策
     */
    private Decision settleMany(AdaptiveSpeedController c, long spacing, int packets, long growthPerPacket) {
        long start = cursor;
        Decision last = null;
        for (int i = 0; i < packets; i++) {
            deficit += growthPerPacket;
            long t = start + (i + 1) * spacing / packets;
            last = c.observe(t, deficit);
            cursor = t;
        }
        return last;
    }

    /**
     * 结算一个含恰好 {@code count} 个包的窗口，末包携带全部增长并精确落在 {@code start+spacing}
     * 处结算（中间包紧贴窗口起点，不触发结算）。
     *
     * <p>与 {@code settle} 的区别：包数可任意指定，用于验证低包率延迟结算
     * （不足 8 个包时窗口继续累积）与累计欠账预算（5s）这两条控制律。</p>
     */
    private Decision settleCount(AdaptiveSpeedController c, long spacing, double rho, int count) {
        long start = cursor;
        c.observe(start, deficit);
        for (int i = 1; i < count - 1; i++) {
            cursor = start + i;
            c.observe(cursor, deficit);
        }
        deficit += Math.round(spacing * rho);
        cursor = start + spacing;
        return c.observe(cursor, deficit);
    }

    // ==================== 用例 ====================

    /** 用例 1：持续落后（累计>5s 且 持续>5s）才降到可持续速率（speed × (1−ρ) × 0.98） */
    @org.junit.jupiter.api.Test
    void downReachesSustainableSpeedAfterSustainedOverload() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(10.0, true);

        Decision warmup = settle(c, WINDOW_NANOS, 0.3);
        assertEquals(Reason.WARMUP, warmup.reason(), "首个窗口只观测");
        assertFalse(warmup.changed(), "启动保护窗口不调整");
        assertEquals(10.0, c.speed(), EPS, "启动保护期间倍率不变");

        // ρ=0.3/窗口 → 150ms/窗口；累计 5s 需 ~34 窗口，持续 5s 需 10 窗口 → 约第 34 窗口降速
        Decision down = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, WINDOW_NANOS, 0.3);
            if (d.reason() == Reason.DOWN) { down = d; break; }
        }
        assertEquals(Reason.DOWN, down == null ? null : down.reason(),
                "持续 ~30% 落后（累计≥5s 且 持续≥5s）后必须降速");
        assertTrue(down != null && down.changed());
        // 期望值由实测迟到率推出：speed × (1−ρ) × 0.98（ρ 略低于 0.3，因扣了 500µs 噪声门限）
        double expected = 10.0 * (1.0 - down.latenessRatio()) * 0.98;
        assertEquals(expected, c.speed(), 1e-6, "10x 在约 30% 迟到率下应降到可持续倍率附近");
        assertEquals(1, c.downCount());
    }

    /** 用例 2：单次降幅不超过 50% */
    @org.junit.jupiter.api.Test
    void singleStepDownIsCappedAtHalf() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(10.0, true);
        settle(c, WINDOW_NANOS, 0.5);            // 启动保护
        // ρ=0.99 → 495ms/窗口；累计 5s 需 ~11 窗口，持续 5s 需 10 窗口
        Decision down = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, WINDOW_NANOS, 0.99);
            if (d.reason() == Reason.DOWN) { down = d; break; }
        }
        assertEquals(Reason.DOWN, down == null ? null : down.reason(), "持续极端落后后必须降速");
        assertEquals(5.0, c.speed(), 1e-6, "极端迟到率下仍只降一半（10x -> 5x）");
    }

    /** 用例 3：止损于 floor，触底后不再降速 */
    @org.junit.jupiter.api.Test
    void stopsAtFloor() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(8.0, true);
        Decision last = settle(c, 1_000_000_000L, 0.5);  // 启动保护
        // 持续极端落后（ρ=0.95）→ 累计/持续达标即降一次（每次砍半）；需要足够窗口逐级降到 0.1x
        for (int i = 0; i < 200 && c.speed() > AdaptiveSpeedController.SPEED_FLOOR + EPS; i++) {
            last = settle(c, 1_000_000_000L, 0.95);
        }
        assertEquals(AdaptiveSpeedController.SPEED_FLOOR, c.speed(), EPS, "最终停在 floor=0.1x");

        int downsBefore = c.downCount();
        // 触底后再持续极端落后：需重新累计/持续达标，此番命中 FLOOR 分支（且不再真的降）
        Decision floored = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, 1_000_000_000L, 0.95);
            if (d.reason() == Reason.FLOOR) { floored = d; break; }
        }
        assertEquals(Reason.FLOOR, floored == null ? null : floored.reason(), "触底后给出 FLOOR 决策");
        assertFalse(floored.changed(), "触底后不再降速");
        assertEquals(downsBefore, c.downCount(), "触底后降速计数不再增长");
        assertTrue(c.reachedFloor(), "触底被记录");
    }

    /** 用例 4：死区（0.2% ≤ ρ ≤ 2%）视为达标，不调整 */
    @org.junit.jupiter.api.Test
    void deadZoneDoesNotAdjust() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(2.0, true);
        settle(c, WINDOW_NANOS, 0.5);   // 启动保护
        for (int i = 0; i < 10; i++) {
            Decision d = settle(c, WINDOW_NANOS, 0.01);
            assertEquals(Reason.DEAD_ZONE, d.reason());
            assertFalse(d.changed());
        }
        assertEquals(2.0, c.speed(), EPS, "死区内倍率不变");
        assertEquals(0, c.downCount());
        assertEquals(0, c.upCount());
    }

    /** 用例 5：AIMD 升速——连续 3 个达标窗口升速 2%，且封顶在目标倍率 */
    @org.junit.jupiter.api.Test
    void speedsUpSlowlyAndNeverExceedsTarget() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(4.0, true);
        settle(c, 1_000_000_000L, 0.3);                       // 启动保护
        // 持续 ~30% 落后（累计/持续达标）后降到 4 × (1−ρ) × 0.98
        Decision down = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, 1_000_000_000L, 0.3);
            if (d.reason() == Reason.DOWN) { down = d; break; }
        }
        double afterDown = c.speed();
        assertEquals(4.0 * (1.0 - down.latenessRatio()) * 0.98, afterDown, 1e-6);
        assertTrue(afterDown < 3.0, "确实降了速（约 2.75x）");

        // 前两个达标窗口不够，第三个才升
        assertEquals(Reason.SPEEDUP_PENDING, settle(c, 1_000_000_000L, 0.0).reason());
        assertEquals(Reason.SPEEDUP_PENDING, settle(c, 1_000_000_000L, 0.0).reason());
        Decision up = settle(c, 1_000_000_000L, 0.0);
        assertEquals(Reason.UP, up.reason());
        assertEquals(afterDown * 1.02, c.speed(), 1e-6, "升速幅度 2%");

        // 一直达标也不会超过目标倍率
        for (int i = 0; i < 200; i++) {
            settle(c, 1_000_000_000L, 0.0);
            assertTrue(c.speed() <= 4.0 + EPS, "倍率不得超过 --speed 上限，实际 " + c.speed());
        }
        assertEquals(4.0, c.speed(), EPS, "最终回到目标倍率");
        assertEquals(Reason.AT_TARGET, settle(c, 1_000_000_000L, 0.0).reason());
    }

    /** 用例 6：一次降速后必须重新累计预算，不会连续降速 */
    @org.junit.jupiter.api.Test
    void reductionRequiresReaccumulatedBudget() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(10.0, true);
        settle(c, WINDOW_NANOS, 0.3);              // 启动保护
        Decision firstDown = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, WINDOW_NANOS, 0.3);
            if (d.reason() == Reason.DOWN) { firstDown = d; break; }
        }
        assertEquals(Reason.DOWN, firstDown == null ? null : firstDown.reason());

        // 降速后累计/持续被清零：随后若干窗口即使仍 30% 落后也不会立刻连降
        for (int i = 0; i < 5; i++) {
            assertFalse(settle(c, WINDOW_NANOS, 0.3).changed(), "降速后需重新累计/持续才可再降，不会连降");
        }
        // 重新累计到 5s 后再次降速
        Decision next = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, WINDOW_NANOS, 0.3);
            if (d.reason() == Reason.DOWN) { next = d; break; }
        }
        assertEquals(Reason.DOWN, next == null ? null : next.reason(), "重新累计达标后可再次降速");
    }

    /** 用例 7：内部禁用开关（仅测试）时只观测、永不调整 */
    @org.junit.jupiter.api.Test
    void disabledControllerNeverAdjusts() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(5.0, false);
        for (int i = 0; i < 10; i++) {
            Decision d = settle(c, 1_000_000_000L, 0.9);
            assertEquals(Reason.DISABLED, d.reason());
            assertFalse(d.changed());
        }
        assertEquals(5.0, c.speed(), EPS);
        assertFalse(c.enabled());
        assertEquals(0, c.downCount());
        assertEquals(0, c.upCount());
    }

    /** 用例 8：启动保护只覆盖第一个窗口，且不阻塞后续止损 */
    @org.junit.jupiter.api.Test
    void warmupProtectsOnlyFirstWindow() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(2.0, true);
        assertEquals(Reason.WARMUP, settle(c, WINDOW_NANOS, 0.9).reason());
        double unchanged = c.speed();
        // 持续极端落后（ρ=0.9 → 450ms/窗口，累计/持续约 12 窗口后）止损
        Decision down = null;
        for (int i = 0; i < 80; i++) {
            Decision d = settle(c, WINDOW_NANOS, 0.9);
            if (d.reason() == Reason.DOWN) { down = d; break; }
        }
        assertEquals(Reason.DOWN, down == null ? null : down.reason(), "持续极端落后后止损");
        assertTrue(c.speed() < unchanged, "倍率确实下降");
    }

    /** 用例 9：契约——非法目标倍率被拒绝，窗口内查询不产生决策 */
    @org.junit.jupiter.api.Test
    void contracts() {
        assertThrows(IllegalArgumentException.class, () -> new AdaptiveSpeedController(0.0, true));
        assertThrows(IllegalArgumentException.class, () -> new AdaptiveSpeedController(-1.0, true));
        assertThrows(IllegalArgumentException.class, () -> new AdaptiveSpeedController(Double.NaN, true));

        AdaptiveSpeedController c = new AdaptiveSpeedController(3.0, true);
        Decision withinWindow = c.observe(100_000_000L, 50_000_000L);
        assertEquals(Reason.NONE, withinWindow.reason(), "未到窗口边界不结算");
        assertFalse(withinWindow.changed());
        assertEquals(0, c.downCount(), "窗口内不调整");
    }

    /**
     * 用例 11：闭环收敛——控制器 + {@link ReplayClock} 在"发送方真的跟不上"时，
     * 收敛到可持续倍率，且不会掉到 floor。
     *
     * <p>这是最接近真实回放的一条测试：时钟按目标倍率排期（用假时钟零等待），
     * 每个包再花固定的"发送耗时"，于是实际速率低于目标；控制器观察时钟报出的迟到量并改写倍率。
     * 新控制律要求"持续 ≥5s 才降速"，因此发包数要足够撑出 ≥5s 的持续落后窗口。</p>
     */
    @org.junit.jupiter.api.Test
    void convergesInClosedLoopWithClock() {
        long sourceSpacingNanos = 10_000_000L;   // 原始包间隔 10ms
        long sendCostNanos = 1_000_000L;         // 发送方每包固定花 1ms → 可持续倍率 ≈ 10x
        double targetSpeed = 20.0;
        double sustainableSpeed = (double) sourceSpacingNanos / sendCostNanos;

        FakeTime time = new FakeTime(0L);
        ReplayClock clock = new ReplayClock(targetSpeed, time, nanos -> time.advance(nanos));
        AdaptiveSpeedController controller = new AdaptiveSpeedController(targetSpeed, true);

        long baseNanos = 1_700_000_000L * 1_000_000_000L;
        int packets = 20000;                     // 12s 发包耗时，足够积累 ≥5s 的持续落后
        ReplayClock.PacketTime first = ReplayClock.PacketTime.ofEpochNanos(baseNanos);
        clock.anchor(first);

        long prevTarget = Long.MIN_VALUE;
        int backwardTargets = 0;
        for (int i = 1; i < packets; i++) {
            ReplayClock.PacketTime packet =
                    ReplayClock.PacketTime.ofEpochNanos(baseNanos + i * sourceSpacingNanos);
            ReplayClock.Schedule s = clock.scheduleNext(packet);
            while (s.waitNanos() > 0) {
                clock.await(s);
                s = clock.scheduleNext(packet);
            }
            // 与真实回放循环同序：本包已排期、尚未"发送"时就做调速决策
            AdaptiveSpeedController.Decision d = controller.observe(time.nanoTime(), s.latenessNanos());
            if (d.changed()) {
                clock.setSpeed(d.speed());
            }
            if (s.targetNano() < prevTarget) {
                backwardTargets++;
            }
            prevTarget = s.targetNano();
            time.advance(sendCostNanos);   // 模拟发送耗时
        }

        logger.info("闭环收敛：target={}x, final={}x, down={}, up={}, 可持续≈{}x",
                targetSpeed, controller.speed(), controller.downCount(), controller.upCount(), sustainableSpeed);

        assertTrue(controller.speed() < targetSpeed, "超速时必须降速");
        assertTrue(controller.speed() > AdaptiveSpeedController.SPEED_FLOOR + 1.0,
                "应停在可持续附近而不是 floor，实际 " + controller.speed() + "x");
        assertEquals(sustainableSpeed, controller.speed(), 1.0,
                "收敛到可持续倍率附近（实测 " + controller.speed() + "x）");
        assertTrue(controller.downCount() <= 4,
                "少量调整即收敛，不棘轮（实际 " + controller.downCount() + " 次）");
        assertFalse(controller.reachedFloor(), "不应触底");
        assertEquals(controller.speed(), clock.speed(), EPS, "时钟倍率与控制器一致");
        assertEquals(0, backwardTargets, "调速过程中应发时刻永不回退");
    }

    /**
     * 用例 10：固定欠账与调度抖动不得触发降速，只有"越落越远"才降速。
     *
     * <p>这是控制律最关键的一条：回放开头的一次启动积压（数据库/建连/首屏）会留下
     * 几百毫秒的<b>固定</b>欠账，此后速率其实已经达标。用"绝对迟到量"当信号会把这种
     * 情况误判成"发送方跟不上"，一路降到下限（实测踩过这个坑）。</p>
     */
    @org.junit.jupiter.api.Test
    void fixedDeficitAndJitterDoNotTriggerSlowdown() {
        // 1) 每个包都固定迟到 20ms（= 固定偏移，速率完全达标）
        AdaptiveSpeedController c = new AdaptiveSpeedController(20.0, true);
        settle(c, WINDOW_NANOS, 0.0);                       // 启动保护
        for (int i = 0; i < 5; i++) {
            Decision d = settleMany(c, WINDOW_NANOS, 100, 0L);
            assertFalse(d.changed(), "固定欠账不调整");
            assertEquals(0.0, d.latenessRatio(), EPS, "欠账没增长 → 增长率必须为 0");
        }
        assertEquals(20.0, c.speed(), EPS, "固定偏移不降速");
        assertEquals(0, c.downCount(), "固定偏移不产生降速");

        // 2) 欠账增长低于噪声容许量（0.5ms/窗口）也不调整
        AdaptiveSpeedController quiet = new AdaptiveSpeedController(20.0, true);
        settle(quiet, WINDOW_NANOS, 0.0);
        for (int i = 0; i < 5; i++) {
            assertFalse(settleMany(quiet, WINDOW_NANOS, 100, 10_000L).changed(), "亚容许量抖动不调整");
        }
        assertEquals(0, quiet.downCount());

        // 3) 真实跟不上（持续）：每包 3ms → 300ms/窗口 ≈ 60%；持续累计/达标后必须降速
        AdaptiveSpeedController loaded = new AdaptiveSpeedController(20.0, true);
        settle(loaded, WINDOW_NANOS, 0.0);                  // 启动保护
        Decision real = null;
        for (int i = 0; i < 40; i++) {
            Decision d = settleMany(loaded, WINDOW_NANOS, 100, 3_000_000L);
            if (d.reason() == Reason.DOWN) { real = d; break; }
        }
        assertEquals(Reason.DOWN, real == null ? null : real.reason(), "持续累积性欠账仍然触发降速");
        assertTrue(loaded.speed() < 20.0);
    }

    /**
     * 用例 12：分卷/空闲间隔不得被当成"欠账增长"。
     *
     * <p>滚动跟随模式在两个分卷之间会停下来等新卷；恢复后首个包的迟到量包含整段空闲。
     * 回放侧在进入新卷前调用 {@link AdaptiveSpeedController#resetWindow()}，空闲应被排除在
     * 控制信号之外，而不是让倍率在每个卷边界被错误地砍半。</p>
     */
    @org.junit.jupiter.api.Test
    void idleGapAfterResetDoesNotTriggerSlowdown() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(20.0, true);
        settle(c, WINDOW_NANOS, 0.0);   // 启动保护窗口：cursor=500ms，欠账=0

        // 空闲 10 秒后恢复：首个包的迟到量 = 10s（相对原时间轴），但这是固定偏移
        cursor += 10_000_000_000L;
        deficit = 10_000_000_000L;
        c.resetWindow();

        Decision first = c.observe(cursor, deficit);
        assertEquals(Reason.NONE, first.reason(), "reset 后首个包只重新建立窗口基线");

        for (int i = 0; i < 5; i++) {
            cursor += WINDOW_NANOS;
            Decision d = c.observe(cursor, deficit);
            assertFalse(d.changed(), "空闲造成的固定偏移不得触发降速");
            assertEquals(0.0, d.latenessRatio(), EPS, "空闲时间不得计入欠账增长");
        }
        assertEquals(20.0, c.speed(), EPS, "倍率必须保持目标上限");
        assertEquals(0, c.downCount(), "空闲间隔不产生降速");
    }

    /**
     * 用例 13：低包率窗口延迟结算，样本不足时不做任何判断。
     *
     * <p>网络几乎没压力时 500ms 内只有 4 个包，首末包迟到差会被单点调度噪声主导。
     * 此时窗口<b>不结算</b>（继续累积），既不改倍率，也不把噪声计入累计欠账；
     * 攒够 8 个包后再按整段窗口（这里是 1s）一次性结算。</p>
     */
    @org.junit.jupiter.api.Test
    void sparseWindowsDeferSettlementUntilEnoughSamples() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(20.0, true);
        settleCount(c, WINDOW_NANOS, 0.0, 100);             // 启动保护（正常包率）

        // 第一个 4 包窗口：不足 8 包，不结算
        Decision first = settleCount(c, WINDOW_NANOS, 0.8, 4);
        assertEquals(Reason.NONE, first.reason(), "样本不足时窗口不结算");
        assertFalse(first.changed(), "样本不足时不得改倍率");

        // 第二个 4 包窗口：累计 8 包、跨度 1s → 按整段窗口结算
        Decision second = settleCount(c, WINDOW_NANOS, 0.8, 4);
        assertEquals(Reason.DEAD_ZONE, second.reason(),
                "攒够 8 包后按 1s 窗口结算（800ms 增长 / 1s = 80%，预算未到，只算达标）");
        assertEquals(8, second.windowPackets(), "结算必须基于至少 8 个包");
        assertEquals(2 * WINDOW_NANOS, second.windowNanos(), "窗口跨两个采样周期");
        assertFalse(second.changed());

        assertEquals(20.0, c.speed(), EPS, "低包率下的噪声不得改变倍率");
        assertEquals(0, c.downCount(), "低包率下的噪声不降速");
        assertEquals(0, c.upCount(), "低包率下的噪声不升速");
    }

    /**
     * 用例 13b：极低包率（1 包/500ms）不会让控制器"永远失效"。
     *
     * <p>旧实现里每个 500ms 窗口只有 1~2 个包，会被直接丢弃、不参与任何判断，
     * 于是稀疏数据源上自适应等于被关闭。现在窗口一直累积到 8 个包才结算，
     * 只是判定间隔变长（这里是 4s），仍然能得出决策。</p>
     */
    @org.junit.jupiter.api.Test
    void verySparseStreamStillGetsDecisions() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(20.0, true);
        settleCount(c, WINDOW_NANOS, 0.0, 100);             // 启动保护（正常包率）

        // 每 500ms 只有 1 个包，直到第 8 个包（跨度 4s）才结算
        for (int i = 1; i <= 7; i++) {
            cursor += WINDOW_NANOS;
            deficit += 100_000_000L;
            Decision d = c.observe(cursor, deficit);
            assertEquals(Reason.NONE, d.reason(), "第 " + i + " 个稀疏包（<8）不结算");
            assertFalse(d.changed());
        }
        cursor += WINDOW_NANOS;
        deficit += 100_000_000L;
        Decision settled = c.observe(cursor, deficit);
        assertEquals(Reason.DEAD_ZONE, settled.reason(), "第 8 个稀疏包应触发结算");
        assertEquals(8, settled.windowPackets());
        assertEquals(8 * WINDOW_NANOS, settled.windowNanos(), "跨度为 8 个 500ms 采样周期");
        assertFalse(settled.changed(), "20% 的落后未达 5s 预算，先只算达标");
        assertEquals(0, c.downCount());
        assertEquals(0, c.upCount());
    }

    /**
     * 用例 14：累计欠账增长超过 5s 预算才降速（非抖动式）。
     *
     * <p>每窗口 20% 的落后（100ms/500ms），在累计预算（默认 5s）与持续时长（默认 5s）
     * 双条件都满足之前不应降速——避免"一串偶发中等落后"就频繁调整；达到后必须降速。</p>
     */
    @org.junit.jupiter.api.Test
    void cumulativeDeficitBudgetGatesSlowdown() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(20.0, true);
        settleCount(c, WINDOW_NANOS, 0.0, 100);   // 启动保护
        // 前 25 个窗口：每窗累计 100ms，共 2.5s < 5s 预算 → 不得降速
        // （持续时长此时已 12.5s，真正卡住降速的是累计预算）
        for (int i = 0; i < 25; i++) {
            assertFalse(settleCount(c, WINDOW_NANOS, 0.20, 100).changed(),
                    "累计未达 5s 预算前不得降速");
        }
        assertEquals(0, c.downCount(), "累计未达预算不降速");
        // 继续到累计 ≥5s（约第 50 个窗口）→ 必须降速
        int guard = 0;
        while (c.downCount() == 0 && guard++ < 60) {
            settleCount(c, WINDOW_NANOS, 0.20, 100);
        }
        assertTrue(c.downCount() > 0, "累计超过 5s 预算后必须降速");
    }

    /**
     * 用例 15：一次性启动尖峰（开局积压）随后平缓，不得触发降速。
     *
     * <p>正是"怎么一上来就降速"的回归：回放开局数据库预热/首屏突发会产生一两个窗口的
     * 巨大负欠账（<b>一次性</b>尖峰），但随后欠账不再增长。新控制律要求"持续 ≥5s，
     * 欠账一路在涨、没有停顿"才降速；一旦欠账停止增长，累计与持续都被清零，
     * 因此这类尖峰永远到不了预算，不会把初始倍率打下去。</p>
     */
    @org.junit.jupiter.api.Test
    void startupSpikeThenPlateauDoesNotSlowDown() {
        AdaptiveSpeedController c = new AdaptiveSpeedController(20.0, true);
        settleCount(c, WINDOW_NANOS, 0.0, 100);           // 启动保护
        // 2 个窗口大尖峰（ρ=0.75 → 375ms/窗口，复现日志里 ~75% 的开局积压）
        settleCount(c, WINDOW_NANOS, 0.75, 100);
        settleCount(c, WINDOW_NANOS, 0.75, 100);
        // 随后平缓：欠账不再增长（ρ=0），持续/累计被清零
        for (int i = 0; i < 30; i++) {
            assertFalse(settleCount(c, WINDOW_NANOS, 0.0, 100).changed(),
                    "一次性启动尖峰随后的平缓窗口不得降速");
        }
        assertEquals(20.0, c.speed(), EPS, "开局一次性尖峰不得改变倍率");
        assertEquals(0, c.downCount(), "开局一次性尖峰不产生降速");
    }
}
