package com.jshark.parser;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ThroughputMeter} 的单元测试：累计计数、窗口判定、以及"不会因为窗口太短而算错/抛异常"。
 *
 * <p>这类统计代码的风险不是崩，而是<b>看起来对、实际口径错</b>（例如把 0 秒窗口算成 1 秒、
 * 或者把字节数算成位）。因此这里锁定口径与边界。</p>
 */
class ThroughputMeterTest {

    @Test
    @DisplayName("累计计数：包数与字节数按传入帧长累加")
    void accumulatesTotals() {
        ThroughputMeter m = new ThroughputMeter("Test", 60_000L);
        m.addPacket(100);
        m.addPacket(200);
        m.addPacket(300);
        assertEquals(3, m.totalPackets());
        assertEquals(600, m.totalBytes());
    }

    @Test
    @DisplayName("未到间隔不打印；到点后返回 true 并复位窗口")
    void ticksOnlyAfterInterval() throws Exception {
        ThroughputMeter m = new ThroughputMeter("Test", 50L);
        m.addPacket(1024);
        // 刚构造，间隔未到
        assertFalse(m.tick(), "间隔未到不应打印");

        Thread.sleep(80);
        assertTrue(m.tick(), "超过间隔应打印");
        // 窗口已复位：再立刻 tick 不应再次触发
        assertFalse(m.tick(), "窗口复位后不应立刻再次打印");
    }

    @Test
    @DisplayName("flush 在极短窗口/零流量下不抛异常（停机尾段路径）")
    void flushIsSafe() {
        ThroughputMeter m = new ThroughputMeter("Test", 20_000L);
        m.flush();              // 完全没有流量
        m.addPacket();          // 兼容重载：只计包不计字节
        m.flush("ctx");
        assertEquals(1, m.totalPackets());
        assertEquals(0, m.totalBytes());
    }

    @Test
    @DisplayName("非法间隔回退为默认 20 秒，且不影响计数")
    void invalidIntervalFallsBack() {
        ThroughputMeter m = new ThroughputMeter("Test", 0);
        m.addPacket(1);
        assertFalse(m.tick(), "间隔应为默认 20s，刚构造不应打印");
        assertEquals(1, m.totalPackets());
    }
}
