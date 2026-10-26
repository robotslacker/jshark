package com.jshark;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code --ui} 默认布局与参数说明的回归测试。
 *
 * <h3>为什么需要它</h3>
 * <p>{@code JSplitPane} 没有显式分隔条位置时，首次布局只肯给参数区约一半高度：
 * 默认 1180×780 下 239px，而参数内容需要 285px。于是参数区底部被裁掉、平白多一条滚动条；
 * 字体更大或窗口更小时，连最后一行 {@code Target mapping} 都会整个落在可视区之外——
 * 这正是“必须先拖动分隔条才看得到目标映射”的现场。这类“看不见”的缺陷不会报错，
 * 只能靠断言“默认窗口里参数区整块放得下”来守住。</p>
 *
 * <p>同一批参数（尤其折叠起来的 {@code Filters}）以前完全没有 tooltip；这里顺带断言
 * 每个输入框都有说明，避免以后再漏。</p>
 *
 * <p>需要桌面环境的用例在 headless（CI / 无 DISPLAY）下自动跳过；纯计算的
 * {@link #dividerFitsContent()} 在任何环境都跑。</p>
 */
public class ReplayUiLayoutTest {

    // ==================== 纯计算：分隔条位置 ====================

    @Test
    void dividerFitsContent() {
        int available = 474; // 默认 1180×780 下分隔条可用高度（实测）
        int minBottom = ReplayUi.ReplayMainFrame.MIN_FILE_AREA_HEIGHT;

        // 内容放得下 → 分隔条按内容高度给出（整块参数区可见、不出现滚动条）
        assertEquals(285, ReplayUi.ReplayMainFrame.initialDividerLocation(285, available, minBottom));

        // 内容比“可用高度 - 文件表保底”还高 → 让出保底高度，其余全给参数区
        assertEquals(available - minBottom,
                ReplayUi.ReplayMainFrame.initialDividerLocation(501, available, minBottom));

        // 内容恰好等于上限 → 不越界
        assertEquals(available - minBottom,
                ReplayUi.ReplayMainFrame.initialDividerLocation(
                        available - minBottom, available, minBottom));

        // 还没布局 / 窗口过小 → 不返回负数
        assertEquals(0, ReplayUi.ReplayMainFrame.initialDividerLocation(285, 0, minBottom));
        assertEquals(0, ReplayUi.ReplayMainFrame.initialDividerLocation(0, available, minBottom));
        assertEquals(0, ReplayUi.ReplayMainFrame.initialDividerLocation(285, 100, minBottom));
    }

    // ==================== 真窗口：默认布局 ====================

    @Test
    void targetMappingIsVisibleInDefaultWindow() throws Exception {
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            Rectangle visible = onEdt(() -> paramsScroll(frame).getViewport().getViewRect());
            Rectangle mapping = onEdt(() -> {
                JScrollPane scroll = paramsScroll(frame);
                JLabel label = findLabel(scroll.getViewport().getView(), "Target mapping");
                assertNotNull(label, "参数区里没有 Target mapping 行");
                return label.getBounds();
            });
            int contentHeight = onEdt(() ->
                    paramsScroll(frame).getViewport().getView().getPreferredSize().height);

            assertTrue(visible.contains(mapping),
                    "默认窗口里 Target mapping 必须直接可见（无需拖动分隔条）：可视区 " + visible
                            + "，该行 " + mapping);
            assertTrue(visible.height >= contentHeight,
                    "参数区必须整块放得下：可视高度 " + visible.height + "，内容高度 " + contentHeight);
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 真窗口：每个参数都有 tooltip ====================

    @Test
    void everyParameterFieldHasTooltip() throws Exception {
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            List<JTextField> fields = onEdt(() -> {
                List<JTextField> found = new ArrayList<>();
                collectTextFields(frame.getContentPane(), found);
                return found;
            });
            // 7 个过滤器 + 4 段目标映射 + Inject / Destination MAC + Start / End + 路径
            // + 两个可编辑下拉框的输入区
            assertTrue(fields.size() >= 15,
                    "输入框数量异常（" + fields.size() + "），遍历可能失效，断言会变成空转");

            List<String> missing = onEdt(() -> {
                List<String> names = new ArrayList<>();
                for (JTextField field : fields) {
                    String tip = field.getToolTipText();
                    if (tip == null || tip.isBlank()) {
                        names.add(describe(field));
                    }
                }
                return names;
            });
            assertTrue(missing.isEmpty(), "以下输入框没有 tooltip：" + missing);

            assertNotNull(onEdt(() -> {
                JButton filters = findButton(frame.getContentPane(), "Filters");
                assertNotNull(filters, "找不到 Filters 折叠按钮");
                return filters.getToolTipText();
            }), "Filters 折叠按钮没有 tooltip");
        } finally {
            closeFrame(frame);
        }
    }

    @Test
    void expandingFiltersRefitsParameterArea() throws Exception {
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            int collapsed = onEdt(() -> findSplit(frame).getDividerLocation());

            onEdt(() -> {
                JButton filters = findButton(frame.getContentPane(), "Filters");
                assertNotNull(filters, "找不到 Filters 折叠按钮");
                filters.doClick();
                return null;
            });
            flushEdt();

            int expanded = onEdt(() -> findSplit(frame).getDividerLocation());
            assertTrue(expanded > collapsed,
                    "展开 Filters 后参数区应变高（收起 " + collapsed + " → 展开 " + expanded + "）");
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 建窗/关窗 ====================

    /** 建一个真实的回放窗口，并等参数区校正（排在 setVisible 之后）跑完。 */
    private static ReplayUi.ReplayMainFrame showFrame() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 布局");
        AtomicReference<ReplayUi.ReplayMainFrame> holder = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            // 生产环境是 Metal + 深色配色；换一套 LAF 首选高度就变了，测的就不是默认布局。
            ReplayUi.installTheme(true);
            ReplayUi.ReplayMainFrame frame = new ReplayUi.ReplayMainFrame(new String[]{"--ui"});
            holder.set(frame);
            frame.setVisible(true);
        });
        flushEdt();
        ReplayUi.ReplayMainFrame frame = holder.get();
        // 让布局真正生效（滚动条/分隔条位置都在 validate 时定案）
        onEdt(() -> {
            frame.validate();
            return null;
        });
        return frame;
    }

    /**
     * 关窗并停掉界面里的 Swing Timer。
     *
     * <p>Timer 会一直往 EDT 上投任务，窗口 dispose 之后没人停它；不去停的话，
     * 这份测试跑完 fork 出来的 JVM 可能迟迟不退出（surefire 每个测试类一个 JVM）。</p>
     */
    private static void closeFrame(ReplayUi.ReplayMainFrame frame) throws Exception {
        onEdt(() -> {
            stopTimers(frame);
            frame.dispose();
            return null;
        });
    }

    private static void stopTimers(ReplayUi.ReplayMainFrame frame) {
        for (String name : new String[]{"logTimer", "inspectDebounce", "inspectTimeout",
                "replayStartWatchdog"}) {
            try {
                java.lang.reflect.Field field = frame.getClass().getDeclaredField(name);
                field.setAccessible(true);
                Object value = field.get(frame);
                if (value instanceof Timer timer) {
                    timer.stop();
                }
            } catch (ReflectiveOperationException ignored) {
                // 字段改名/不存在时不影响结论：dispose 后这些 Timer 也只是空跑。
            }
        }
    }

    /** 在 EDT 上取一个值；异常原样抛回测试线程。 */
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

    /** 把 EDT 队列里已排队的任务跑完（必须在测试线程上调用）。 */
    private static void flushEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
        });
    }

    // ==================== 组件查找 ====================

    private static JScrollPane paramsScroll(JFrame frame) {
        JScrollPane scroll = findParamsScroll(frame.getContentPane());
        assertNotNull(scroll, "找不到参数区滚动面板");
        return scroll;
    }

    private static JScrollPane findParamsScroll(Component c) {
        if (c instanceof JScrollPane scroll && scroll.getViewport().getView() != null
                && findLabel(scroll.getViewport().getView(), "Target mapping") != null) {
            return scroll;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                JScrollPane found = findParamsScroll(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JSplitPane findSplit(Component c) {
        if (c instanceof JSplitPane split) {
            return split;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                JSplitPane found = findSplit(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JLabel findLabel(Component c, String text) {
        if (c instanceof JLabel label && text.equals(label.getText())) {
            return label;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                JLabel found = findLabel(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JButton findButton(Component c, String textPart) {
        if (c instanceof JButton button && button.getText() != null
                && button.getText().contains(textPart)) {
            return button;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                JButton found = findButton(child, textPart);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static void collectTextFields(Component c, List<JTextField> out) {
        if (c instanceof JTextField field) {
            out.add(field);
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectTextFields(child, out);
            }
        }
    }

    private static String describe(JTextField field) {
        Component parent = field.getParent();
        return field.getClass().getSimpleName()
                + (parent instanceof JComboBox<?> combo
                ? " (editor of " + combo.getSelectedItem() + ")"
                : " (parent " + (parent == null ? "null" : parent.getClass().getSimpleName()) + ")");
    }
}
