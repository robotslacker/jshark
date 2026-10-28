package com.jshark;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.TableCellRenderer;
import java.awt.Component;
import java.awt.GraphicsEnvironment;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * 文件表 Status 列在回放中的完成度渲染。
 *
 * <p>纯计算部分由 {@link ReplayUiProgressTest} 覆盖；这里验证“用户真正看到的那一层”：
 * 已经回放过的卷必须画成满格的 {@code Completed}，当前卷画百分比，尚未轮到的卷保持
 * 静态文本。之前这里只按单个下标更新，导致只有当前正在回放的卷有进度。</p>
 */
public class ReplayUiFileProgressRenderTest {

    private static final int STATUS_COL = 7;

    @Test
    void passedFilesRenderAsCompletedBars() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 JTable 的单元格渲染器");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            onEdt(() -> {
                setField(frame, "inspection", inspection());
                invoke(frame, "applyInspection");
                setField(frame, "running", true);
                setField(frame, "progressVisible", true);
                invokeApplyStatus(frame, status(1, 0, 5_000, 3_600));
                return null;
            });

            JTable table = fileTable(frame);
            // 0..1000、2000..3000 已经越过结束时间 → 满格 Completed
            assertCompleted(table, 0);
            assertCompleted(table, 1);
            // 当前卷 3500..4000，playhead 3600 → 20%
            JProgressBar current = bar(table, 2);
            assertEquals(200, current.getValue(), "当前卷应显示 20% 的进度");
            assertEquals("20%", current.getString());
            // 还没轮到的卷不画进度条
            Component future = renderCell(table, 3);
            if (future instanceof JProgressBar) {
                throw new AssertionError("尚未回放的卷不应显示进度条");
            }
        } finally {
            closeFrame(frame);
        }
    }

    private static void assertCompleted(JTable table, int row) {
        JProgressBar bar = bar(table, row);
        assertEquals(1000, bar.getValue(), "已经越过的卷必须画满格 (row " + row + ")");
        assertEquals("Completed", bar.getString(), "已经越过的卷必须显示 Completed (row " + row + ")");
    }

    private static JProgressBar bar(JTable table, int row) {
        Component cell = renderCell(table, row);
        JProgressBar bar = assertInstanceOf(JProgressBar.class, cell,
                "row " + row + " 应渲染为进度条，而不是静态文本");
        return bar;
    }

    private static Component renderCell(JTable table, int row) {
        TableCellRenderer renderer = table.getColumnModel().getColumn(STATUS_COL).getCellRenderer();
        return renderer.getTableCellRendererComponent(
                table, table.getValueAt(row, STATUS_COL), false, false, row, STATUS_COL);
    }

    private static ReplayUi.Inspection inspection() {
        ReplayUi.Inspection inspection = new ReplayUi.Inspection();
        inspection.dataStart = 0L;
        inspection.dataEnd = 5_000L;
        inspection.replayableCount = 4;
        inspection.files.add(file(0, 1_000));
        inspection.files.add(file(2_000, 3_000));
        inspection.files.add(file(3_500, 4_000));
        inspection.files.add(file(4_500, 5_000));
        return inspection;
    }

    private static ReplayUi.FileRow file(long start, long end) {
        ReplayUi.FileRow f = new ReplayUi.FileRow();
        f.name = "capture_" + start + "-" + end + ".db";
        f.path = "C:\\captures\\capture_" + start + "-" + end + ".db";
        f.kind = "final";
        f.replayable = true;
        f.hasFrames = true;
        f.dataStart = start;
        f.dataEnd = end;
        f.status = "ok";
        return f;
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

    private static JTable fileTable(ReplayUi.ReplayMainFrame frame) throws Exception {
        return (JTable) getField(frame, "fileTable");
    }

    private static Object getField(ReplayUi.ReplayMainFrame frame, String name) throws Exception {
        Field field = ReplayUi.ReplayMainFrame.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(frame);
    }

    private static void setField(ReplayUi.ReplayMainFrame frame, String name, Object value)
            throws Exception {
        Field field = ReplayUi.ReplayMainFrame.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(frame, value);
    }

    private static void invoke(ReplayUi.ReplayMainFrame frame, String name) throws Exception {
        Method method = ReplayUi.ReplayMainFrame.class.getDeclaredMethod(name);
        method.setAccessible(true);
        method.invoke(frame);
    }

    private static void invokeApplyStatus(ReplayUi.ReplayMainFrame frame, ReplayUi.UiStatus s)
            throws Exception {
        Method method = ReplayUi.ReplayMainFrame.class.getDeclaredMethod(
                "applyStatus", ReplayUi.UiStatus.class);
        method.setAccessible(true);
        method.invoke(frame, s);
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
                    "replayStartWatchdog", "liveRefreshTimer"}) {
                try {
                    Object value = getField(frame, name);
                    if (value instanceof Timer timer) {
                        timer.stop();
                    }
                } catch (NoSuchFieldException ignored) {
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
