package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.GraphicsEnvironment;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * LIVE 跟随模式下文件列表的每分钟自动刷新条件。
 *
 * <p>只有“live 源（存在正在采集的分卷）或支持滚动跟随的源（分卷 DB + payload）”
 * 且用户没有指定 End 时才刷新：End 一旦填了，回放窗口就被冻结，再去目录里捡新文件
 * 也不会改变本次回放。</p>
 */
public class ReplayUiLiveRefreshTest {

    @Test
    void refreshIntervalIsOneMinute() {
        assertEquals(60_000, ReplayUi.ReplayMainFrame.LIVE_REFRESH_INTERVAL_MS,
                "LIVE 目录刷新间隔应为一分钟");
    }

    @Test
    void refreshRunsOnlyForLiveOrFollowSourcesWithEmptyEnd() {
        assertTrue(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(false, true, ""));
        assertTrue(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(true, false, ""),
                "仍在采集的 live 源也可以刷新文件列表");
        assertTrue(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(true, true, "   "),
                "End 只有空白字符等同于未指定");
        assertTrue(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(false, true, null));

        assertFalse(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(false, false, ""),
                "既非 live 也不支持跟随的源（单卷/PCAP）不应轮询目录");
        assertFalse(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(true, true,
                        "2026-08-21 08:35:00"),
                "用户指定了 End 时必须冻结文件列表");
        assertFalse(ReplayUi.ReplayMainFrame.liveAutoRefreshEligible(false, true,
                        "2026-08-21 08:35:00"),
                "指定 End 后即使源支持跟随也不能刷新");
    }

    @Test
    void timerFollowsTheEndFieldOfALiveSource() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing Timer 的启停");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            onEdt(() -> {
                setField(frame, "inspection", liveInspection());
                invoke(frame, "applyInspection");
                return null;
            });
            assertTrue(onEdt(() -> timer(frame).isRunning()),
                    "live/follow 源且 End 为空时应启动每分钟刷新");

            onEdt(() -> {
                endField(frame).setText("2026-08-21 08:35:00");
                return null;
            });
            assertFalse(onEdt(() -> timer(frame).isRunning()),
                    "用户填写 End 后必须停止自动刷新");

            onEdt(() -> {
                endField(frame).setText("");
                return null;
            });
            assertTrue(onEdt(() -> timer(frame).isRunning()),
                    "清空 End 后应恢复每分钟刷新");
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 真窗口：工具 ====================

    private static ReplayUi.Inspection liveInspection() {
        long start = 1_787_270_000_000L;
        long end = start + 300_000L;
        JSONObject json = JSON.parseObject("""
                {
                  "summary": {"replayableCount": 1, "dataStartMs": %d, "dataEndMs": %d,
                              "durationMs": 300000, "live": true, "waiting": false},
                  "source": {"kind": "db", "followSupported": true, "frameCapable": true,
                             "frameVolumes": 1, "payloadOnlyVolumes": 0},
                  "files": [{"name": "cap_20260821080000-20260821080500.db",
                             "path": "C:\\\\tmp\\\\cap_20260821080000-20260821080500.db",
                             "kind": "final", "replayable": true,
                             "dataStartMs": %d, "dataEndMs": %d, "durationMs": 300000,
                             "bytes": 1024, "status": "ok", "hasFrames": true}]
                }
                """.formatted(start, end, start, end));
        return ReplayUi.Inspection.from(json);
    }

    private static ReplayUi.ReplayMainFrame showFrame() throws Exception {
        AtomicReference<ReplayUi.ReplayMainFrame> holder = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ReplayUi.installTheme(true);
            ReplayUi.ReplayMainFrame frame = new ReplayUi.ReplayMainFrame(new String[]{"--ui"});
            holder.set(frame);
            frame.setVisible(true);
            stopTimer(frame, "inspectDebounce");
        });
        SwingUtilities.invokeAndWait(() -> {
        });
        return holder.get();
    }

    private static void closeFrame(ReplayUi.ReplayMainFrame frame) throws Exception {
        onEdt(() -> {
            frame.dispose();
            return null;
        });
    }

    private static void stopTimer(ReplayUi.ReplayMainFrame frame, String name) {
        try {
            java.lang.reflect.Field field = frame.getClass().getDeclaredField(name);
            field.setAccessible(true);
            Object value = field.get(frame);
            if (value instanceof Timer timer) {
                timer.stop();
            }
        } catch (ReflectiveOperationException ignored) {
            // 字段改名/不存在时不影响结论。
        }
    }

    private static Timer timer(ReplayUi.ReplayMainFrame frame) {
        return (Timer) getField(frame, "liveRefreshTimer");
    }

    private static ReplayUi.DateTimeField endField(ReplayUi.ReplayMainFrame frame) {
        return (ReplayUi.DateTimeField) getField(frame, "endField");
    }

    private static Object getField(ReplayUi.ReplayMainFrame frame, String name) {
        try {
            java.lang.reflect.Field field = frame.getClass().getDeclaredField(name);
            field.setAccessible(true);
            return field.get(frame);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static void setField(ReplayUi.ReplayMainFrame frame, String name, Object value) {
        try {
            java.lang.reflect.Field field = frame.getClass().getDeclaredField(name);
            field.setAccessible(true);
            field.set(frame, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static void invoke(ReplayUi.ReplayMainFrame frame, String name) {
        try {
            java.lang.reflect.Method method = frame.getClass().getDeclaredMethod(name);
            method.setAccessible(true);
            method.invoke(frame);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static <T> T onEdt(Callable<T> callable) throws Exception {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                result.set(callable.call());
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        Throwable error = failure.get();
        if (error instanceof Error e) {
            throw e;
        }
        if (error instanceof Exception e) {
            throw e;
        }
        if (error != null) {
            throw new AssertionError(error);
        }
        return result.get();
    }
}
