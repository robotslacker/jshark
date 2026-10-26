package com.jshark.parser;

import org.slf4j.Logger;

import java.util.Locale;

/**
 * 重放时序报告（payload 与 frame 两条路径共用）。
 *
 * <h3>为什么集中</h3>
 * <p>
 * 同一套"理想时长 / 实际时长 / 实测倍率 / 迟到 / 自适应降速"统计，原先在
 * {@link DbReplayTool}、{@link PcapReplayTool} 与 {@link FrameReplayEngine} 里各写了一遍，
 * 三份的判据与措辞已经开始漂移（同样超标，一条说 "sender could not keep up"，
 * 另一条说 "check downstream limits"）。集中后，报告字段与阈值只有一个定义，
 * 排障时不会因为走的入口不同而看到不同的口径。
 * </p>
 *
 * <p>只负责打印，不修改时钟/控制器状态。</p>
 */
final class ReplayTiming {

    private ReplayTiming() {
    }

    /**
     * 打印一次重放会话的时序报告。
     *
     * @param log            调用方 logger（保留原来的 logger 名称）
     * @param clock          重放时钟
     * @param speedController 自适应控制器；null 表示没有（不打印自适应段）
     * @param targetSpeed    目标倍率（{@code --speed}）
     * @param firstNanos     首个被调度包的采集时刻（epoch 纳秒）
     * @param lastNanos      最后一个被调度包的采集时刻（epoch 纳秒）
     * @param actualNanos    实际墙钟耗时（纳秒）
     */
    static void log(Logger log, ReplayClock clock, AdaptiveSpeedController speedController,
                    double targetSpeed, long firstNanos, long lastNanos, long actualNanos) {
        ReplayClock.Stats stats = clock.stats();
        if (stats.scheduled() <= 1) {
            log.info("[Replay Timing] Only {} packet(s) scheduled; timing report skipped", stats.scheduled());
            return;
        }
        if (firstNanos < 0 || lastNanos <= firstNanos) {
            log.info("[Replay Timing] Incomplete timeline ({}..{}); timing report skipped",
                    firstNanos, lastNanos);
            return;
        }

        long spanNanos = lastNanos - firstNanos;
        ReplayClock.PacketTime first = ReplayClock.PacketTime.ofEpochNanos(firstNanos);
        ReplayClock.PacketTime last = ReplayClock.PacketTime.ofEpochNanos(lastNanos);
        long idealNanos = clock.idealDurationNanos(first, last);
        long elapsedNanos = Math.max(actualNanos, 0);
        double measuredSpeed = elapsedNanos > 0 ? (double) spanNanos / elapsedNanos : 0.0;

        log.info("[Replay Timing] packets={}, original span={} ms, ideal={} ms, actual={} ms, "
                        + "measured speed={}x (target {}x)",
                stats.scheduled(), spanNanos / 1e6, idealNanos / 1e6, elapsedNanos / 1e6,
                String.format(Locale.ROOT, "%.4f", measuredSpeed), targetSpeed);
        log.info("[Replay Timing] lateness: late={} packets, total={} ms, max={} ms, early=0",
                stats.lateCount(), stats.totalLatenessNs() / 1e6, stats.maxLatenessNs() / 1e6);

        // 自适应降速必须如实汇报：目标倍率 ≠ 实际倍率，否则报告会骗人
        boolean reduced = speedController != null && speedController.downCount() > 0;
        if (speedController != null) {
            log.info("[Replay Timing] adaptive speed: target={}x, final={}x, min={}x, down={}, up={}, "
                            + "absorbed lateness={} ms{}",
                    targetSpeed,
                    String.format(Locale.ROOT, "%.3f", clock.speed()),
                    String.format(Locale.ROOT, "%.3f", clock.minSpeed()),
                    speedController.downCount(),
                    speedController.upCount(),
                    clock.absorbedLatenessNanos() / 1e6,
                    speedController.reachedFloor() ? ", REACHED FLOOR" : "");
        }

        // 自适应已经主动降速时，实测倍率低于 --speed 是预期行为，不是故障
        double ratio = targetSpeed > 0 ? measuredSpeed / targetSpeed : 1.0;
        if (ratio < 0.95 && !reduced) {
            log.warn("[Replay Timing] WARNING: measured speed is only {}% of target {}x; "
                            + "the sender could not keep up. Lower --speed or check downstream limits.",
                    String.format(Locale.ROOT, "%.1f", ratio * 100), targetSpeed);
        }
    }
}
