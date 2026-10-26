package com.jshark;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.GraphicsEnvironment;
import java.awt.event.MouseEvent;
import java.lang.reflect.Field;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 回放播放器拖动预览的回归测试：当前时间必须显示拖到的位置，文件表必须按目标位置重置进度。
 *
 * <h3>为什么需要它</h3>
 * <p>子进程每 250ms 推一条 status。以前 {@code applyStatus} 无条件写
 * {@code currentTimeLabel}，于是拖动期间时间在“拖到的目标”和“旧的 playhead”之间来回跳：
 * 鼠标事件写目标 → status 写回旧值 → 下一次鼠标事件再写目标，肉眼就是持续抖动。
 * 现在拖动中（以及松手后 seek 尚未落地时）status 不得覆盖当前时间、拖柄和文件表进度。</p>
 *
 * <p>需要桌面环境的用例在 headless 下自动跳过。</p>
 */
public class ReplayUiSeekPreviewTest {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    /** 时间轴 1000..2000ms：中点即 1500ms。 */
    private static final long FROM = 1_000;
    private static final long TO = 2_000;

    @Test
    void statusDoesNotOverwriteDraggedTime() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 交互");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            ReplayUi.SeekBar bar = onEdt(() -> component(frame, "seekBar", ReplayUi.SeekBar.class));
            JLabel timeLabel = onEdt(() -> component(frame, "currentTimeLabel", JLabel.class));
            setField(frame, "running", true);

            onEdt(() -> {
                invokeApplyStatus(frame, status(1, 1_100));
                return null;
            });
            assertTrue(onEdt(bar::isEnabled), "回放中进度条应可拖动");

            int midX = 16 + Math.round((600 - 32) / 2f);
            onEdt(() -> {
                // 与 dispatch 放在同一个 EDT 任务里：中间一旦布局，setSize 会被改回真实宽度。
                bar.setSize(600, 34);
                dispatch(bar, MouseEvent.MOUSE_PRESSED, midX);
                return null;
            });
            String dragged = TS.format(Instant.ofEpochMilli(1_500));
            assertEquals(dragged, onEdt(timeLabel::getText),
                    "按下/拖动进度条后应显示拖到的位置");

            // 这一条 status 带着旧 playhead 回来：不能把时间拉回 1100ms。
            onEdt(() -> {
                invokeApplyStatus(frame, status(2, 1_100));
                return null;
            });
            assertEquals(dragged, onEdt(timeLabel::getText),
                    "拖动期间 status 回显不得覆盖当前时间（否则界面会抖）");

            onEdt(() -> {
                dispatch(bar, MouseEvent.MOUSE_RELEASED, midX);
                return null;
            });
            assertFalse(onEdt(bar::isDragging), "松手后应结束拖动");
        } finally {
            closeFrame(frame);
        }
    }

    @Test
    void pendingSeekKeepsTargetUntilAckSettlesIt() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 交互");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            JLabel timeLabel = onEdt(() -> component(frame, "currentTimeLabel", JLabel.class));
            setField(frame, "running", true);
            onEdt(() -> {
                invokeApplyStatus(frame, status(1, 1_100));
                return null;
            });

            // 松手后 seek 已发出、新段还没开播：时间停在目标上，旧的 playhead 不得回写。
            String target = TS.format(Instant.ofEpochMilli(1_600));
            onEdt(() -> {
                frame.beginSeekLoading(1_600, 42);
                timeLabel.setText(target);
                invokeApplyStatus(frame, status(2, 1_100));
                return null;
            });
            assertEquals(target, onEdt(timeLabel::getText),
                    "seek 未落地时不能显示旧 playhead");

            // seek 被拒 → 立刻回到最新 status 的位置，而不是永远停在目标值。
            onEdt(() -> {
                frame.onSeekAck(42, false);
                return null;
            });
            assertEquals(TS.format(Instant.ofEpochMilli(1_100)), onEdt(timeLabel::getText),
                    "seek 收尾后时间要对齐最新 status");
        } finally {
            closeFrame(frame);
        }
    }

    @Test
    void draggingBackwardResetsLaterFileProgress() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 交互");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            ReplayUi.SeekBar bar = onEdt(() -> component(frame, "seekBar", ReplayUi.SeekBar.class));
            setField(frame, "running", true);
            setField(frame, "progressVisible", true);
            ReplayUi.Inspection inspection = new ReplayUi.Inspection();
            inspection.files.add(fileRow(0, 1_000));
            inspection.files.add(fileRow(2_000, 4_000));
            setField(frame, "inspection", inspection);

            onEdt(() -> {
                invokeApplyStatus(frame, status(1, 0, 4_000, 3_000));
                return null;
            });
            assertArrayEquals(new double[]{1.0, 0.5}, fileProgress(frame), 1e-9,
                    "回放越过第一卷后，第一卷应显示完成，第二卷显示进行中");

            // 往前拖到 12.5%（时间轴 0..4000 → 500ms）。
            int x = 16 + Math.round((600 - 32) * 0.125f);
            onEdt(() -> {
                bar.setSize(600, 34);
                dispatch(bar, MouseEvent.MOUSE_PRESSED, x);
                return null;
            });
            assertArrayEquals(new double[]{0.5, -1.0}, fileProgress(frame), 1e-9,
                    "往回拖动时，目标时间之后的文件必须重置为未开始");
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 测试支撑 ====================

    private static ReplayUi.UiStatus status(long seq, long playhead) {
        return status(seq, FROM, TO, playhead);
    }

    private static ReplayUi.UiStatus status(long seq, long from, long to, long playhead) {
        ReplayUi.UiStatus s = new ReplayUi.UiStatus();
        s.seq = seq;
        s.state = "RUNNING";
        s.windowFrom = from;
        s.windowTo = to;
        s.playhead = playhead;
        s.speedCurrent = 1.0;
        return s;
    }

    private static ReplayUi.FileRow fileRow(long start, long end) {
        ReplayUi.FileRow f = new ReplayUi.FileRow();
        f.name = "volume.db";
        f.dataStart = start;
        f.dataEnd = end;
        return f;
    }

    private static double[] fileProgress(ReplayUi.ReplayMainFrame frame) throws Exception {
        return onEdt(() -> component(frame, "progressByRow", double[].class).clone());
    }

    private static void dispatch(ReplayUi.SeekBar bar, int id, int x) {
        bar.dispatchEvent(new MouseEvent(bar, id, System.currentTimeMillis(), 0,
                x, bar.getHeight() / 2, 1, false, MouseEvent.BUTTON1));
    }

    private static void invokeApplyStatus(ReplayUi.ReplayMainFrame frame, ReplayUi.UiStatus s) {
        try {
            java.lang.reflect.Method m = ReplayUi.ReplayMainFrame.class
                    .getDeclaredMethod("applyStatus", ReplayUi.UiStatus.class);
            m.setAccessible(true);
            m.invoke(frame, s);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("无法调用 applyStatus: " + e, e);
        }
    }

    private static <T> T component(ReplayUi.ReplayMainFrame frame, String name, Class<T> type) {
        try {
            Field field = ReplayUi.ReplayMainFrame.class.getDeclaredField(name);
            field.setAccessible(true);
            return type.cast(field.get(frame));
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("找不到字段 " + name + ": " + e, e);
        }
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static ReplayUi.ReplayMainFrame showFrame() throws Exception {
        AtomicReference<ReplayUi.ReplayMainFrame> holder = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ReplayUi.installTheme(true);
            ReplayUi.ReplayMainFrame frame = new ReplayUi.ReplayMainFrame(new String[]{"--ui"});
            holder.set(frame);
            frame.setVisible(true);
        });
        flushEdt();
        return holder.get();
    }

    private static void closeFrame(ReplayUi.ReplayMainFrame frame) throws Exception {
        onEdt(() -> {
            for (String name : new String[]{"logTimer", "inspectDebounce", "inspectTimeout",
                    "replayStartWatchdog"}) {
                try {
                    Field field = ReplayUi.ReplayMainFrame.class.getDeclaredField(name);
                    field.setAccessible(true);
                    Object value = field.get(frame);
                    if (value instanceof Timer timer) {
                        timer.stop();
                    }
                } catch (ReflectiveOperationException ignored) {
                    // 字段改名/不存在时不影响结论
                }
            }
            frame.dispose();
            return null;
        });
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

    private static void flushEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
        });
    }
}
