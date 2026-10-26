package com.jshark;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link TimeArgs} 契约：CLI 的 {@code --start/--end} 与控制通道的 {@code seek} 必须接受同一组写法。
 */
class TimeArgsTest {

    private static long local(int hour, int minute, int second) {
        return LocalDateTime.of(2026, 8, 21, hour, minute, second)
                .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    @Test
    void acceptsAllDocumentedFormatsAndAgreesOnTheSameInstant() {
        long expected = local(8, 10, 0);
        assertEquals(expected, TimeArgs.parse("2026-08-21 08:10:00"));
        assertEquals(expected, TimeArgs.parse("2026-08-21 08:10"));
        assertEquals(expected, TimeArgs.parse("2026-08-21T08:10:00"));
        assertEquals(expected, TimeArgs.parse("20260821081000"));
        assertEquals(expected, TimeArgs.parse("2026-08-21 08:10:00.000"));
    }

    @Test
    void acceptsIsoOffsetAndZulu() {
        long expected = Instant.parse("2026-08-21T00:10:00Z").toEpochMilli();
        assertEquals(expected, TimeArgs.parse("2026-08-21T00:10:00Z"));
        assertEquals(expected, TimeArgs.parse("2026-08-21T08:10:00+08:00"));
    }

    @Test
    void blankMeansUnbounded() {
        assertNull(TimeArgs.parse(null));
        assertNull(TimeArgs.parse("  "));
    }

    @Test
    void relativeOffsetIsRejectedWithActionableMessage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> TimeArgs.parse("00:05:00"));
        assertTrue(e.getMessage().contains("Invalid absolute time"), e.getMessage());
        assertTrue(e.getMessage().contains("--start/--end"), e.getMessage());
        assertTrue(e.getMessage().contains("relative offsets"), e.getMessage());
    }

    @Test
    void windowMustNotEndBeforeItStarts() {
        assertEquals(null, TimeArgs.parse(""));
        assertThrows(IllegalArgumentException.class,
                () -> TimeArgs.validateWindow(local(9, 0, 0), local(8, 0, 0)));
        TimeArgs.validateWindow(local(8, 0, 0), local(8, 0, 0));   // 相等合法
        TimeArgs.validateWindow(null, local(8, 0, 0));              // 只给 end 合法
    }
}
