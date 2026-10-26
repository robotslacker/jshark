package com.jshark.parser;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 控制/进度通道的单线程状态机测试：pause/resume、覆盖式 seek/speed、seek 重开段。
 */
public class ReplayControlTest {

    @Test
    void pauseAndResume() {
        ReplayControl c = new ReplayControl(1.0);
        assertFalse(c.isPaused());

        c.requestPause();
        assertTrue(c.pauseRequested());
        c.enterPaused();
        assertTrue(c.isPaused());
        assertFalse(c.pauseRequested());

        c.requestResume();
        assertFalse(c.isPaused());
        assertFalse(c.pauseRequested());
        assertEquals(1.0, c.targetSpeed(), 1e-9);
    }

    @Test
    void seekAndSpeedAreOverwriteSemantics() {
        ReplayControl c = new ReplayControl(1.0);

        c.requestSeek(100);
        c.requestSeek(200);
        assertEquals(200L, c.takeSeek());
        assertNull(c.takeSeek());

        c.requestSpeed(2.0);
        c.requestSpeed(4.0);
        assertEquals(4.0, c.takeSpeed(), 1e-9);
        assertNull(c.takeSpeed());
    }

    @Test
    void beginNewSegmentAllowsBackwardPlayheadAndClearsSegmentFlags() {
        ReplayControl c = new ReplayControl(1.0);
        c.position(5_000);
        c.requestStop();
        c.requestSeek(9_000);
        c.markEndReached();

        c.beginNewSegment(2_000);

        assertFalse(c.shouldStop());
        assertFalse(c.hasPendingSeek());
        assertFalse(c.endReached());
        assertEquals(2_000, c.playheadMs());
        assertNull(c.takeSeek());
    }

    @Test
    void seekKeepsFullPlaybackWindow() {
        ReplayControl c = new ReplayControl(1.0);
        c.setWindow(1_000, 2_000);
        c.beginNewSegment(1_500);
        assertEquals(1_000, c.windowFromMs(), "seek 不应让播放窗口起点跟着移动");
        assertEquals(2_000, c.windowToMs());
        assertEquals(1_500, c.playheadMs());
    }

    @Test
    void seekRestartCannotMoveWindowStartOrRelaxEndLimit() {
        ReplayControl c = new ReplayControl(1.0);
        // 段 1：--start=1000 --end=2000
        c.windowStartIfUnset(1_000);
        c.limitWindowTo(2_000);
        c.setWindowTo(2_000);

        // seek 到 1500：工具会被重建，新段再次落窗口（旧实现用 setWindow(target, MAX_VALUE)，
        // 结果既把起点改成 seek 目标，又把 --end 的终点上限抹掉）
        c.beginNewSegment(1_500);
        c.windowStartIfUnset(1_500);
        c.setWindow(c.windowFromMs(), Long.MAX_VALUE);

        assertEquals(1_000, c.windowFromMs(), "seek 不得移动窗口起点");
        assertEquals(2_000, c.windowToMs(), "seek 不得解除 --end 的终点上限");
        assertEquals(1_500, c.playheadMs());
    }

    @Test
    void dataEndFillsWindowWhenNoEndIsConfiguredAndSurvivesSeek() {
        ReplayControl c = new ReplayControl(1.0);
        // 段 1：--start=1000，未给 --end；有限数据源的末包时间是 9000
        c.windowStartIfUnset(1_000);
        c.setWindowTo(9_000);
        assertEquals(9_000, c.windowToMs(),
                "未给 --end 时窗口终点必须用真实末包时间补齐（status.timing.etaMs 依赖它）");

        // seek 重开段不得把终点重置回“未知”，也不得移动起点
        c.beginNewSegment(5_000);
        c.windowStartIfUnset(5_000);
        c.setWindow(c.windowFromMs(), Long.MAX_VALUE);

        assertEquals(1_000, c.windowFromMs());
        assertEquals(9_000, c.windowToMs());
    }

    @Test
    void positionIsMonotonicButSetPositionCanGoBack() {
        ReplayControl c = new ReplayControl(1.0);
        c.position(100);
        c.position(50);
        assertEquals(100, c.playheadMs());
        c.setPosition(50);
        assertEquals(50, c.playheadMs());
    }

    @Test
    void shiftTimelineMovesScheduledTimeWithoutChangingAnchor() {
        ReplayClock clock = new ReplayClock(1.0, null, null);
        ReplayClock.PacketTime p0 = ReplayClock.PacketTime.of(java.time.Instant.ofEpochMilli(1_000));
        ReplayClock.PacketTime p1 = ReplayClock.PacketTime.of(java.time.Instant.ofEpochMilli(1_010));
        clock.anchor(p0);
        long before = clock.scheduleNext(p1).waitNanos();

        clock.shiftTimeline(5_000_000L); // 5ms

        long after = clock.scheduleNext(p1).waitNanos();
        assertTrue(after > before, "暂停后应发时刻必须后移");
        assertTrue(clock.isAnchored(), "平移不改变锚定状态");
    }
}
