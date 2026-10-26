package com.jshark;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 转发器四栏布局回归。
 *
 * <h3>为什么需要它</h3>
 * <p>旧版把表单塞进 {@code JScrollPane}，内容恒为 1405px 宽：1100 窗口的可视区只有 672px，
 * 即使拉到 1500 也只有 1072px —— 右侧两栏永远看不全，窗口大小只改变“看到哪一段”。
 * 这类缺陷不报错，只能靠断言“四栏都在窗内、宽度随可用宽度按权重变化、关键控件不被裁”守住。</p>
 *
 * <p><b>为什么按“内容区宽度”而不是“窗口宽度”取三档：</b>可见窗口的最终尺寸由窗口管理器决定，
 * 请求一个超出屏幕的宽度会被静默夹回来（X11/远程桌面下很常见：{@code setSize(1440)} 实际只有
 * 1024），三档宽度退化成同一档，断言的失败信息就完全指不到布局本身。内容区尺寸是我们自己的
 * 组件，改它没有这层干扰，测到的仍然是“拿到多少宽度，四栏怎么分”。</p>
 *
 * <p>需要桌面环境的用例在 headless 下自动跳过；开关行为用例不建窗，任何环境都跑。</p>
 */
public class ForwarderUiLayoutTest {

    private static final int[][] SIZES = {{940, 620}, {1100, 720}, {1440, 840}};
    private static final String[] NAMES = {"udp", "forwarding", "peers", "traffic"};
    private static final int[] WEIGHTS = {3, 3, 5, 3};
    private static final int GAP = 10;
    private static final int TOTAL_WEIGHT = 14;

    // ==================== 四栏尺寸 ====================

    @Test
    void fourColumnsFillWindowAndScaleProportionally() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "需要桌面环境才能验证 Swing 布局");
        ForwarderUi.ForwarderFrame frame = showFrame();
        try {
            int[][] widths = new int[SIZES.length][];
            for (int i = 0; i < SIZES.length; i++) {
                final int width = SIZES[i][0];
                final int height = SIZES[i][1];
                // 布局与断言放在同一个 EDT 任务里完成：可见窗口的最终尺寸由窗口管理器决定
                // （X11 下会被夹到屏幕内，“设 1440 实际只有 1024”），直接改内容区尺寸才能
                // 稳定地问“给定宽度下四栏怎么分”。见类注释里的说明。
                widths[i] = onEdt(() -> layoutAt(frame, width, height));
            }

            for (int c = 0; c < NAMES.length; c++) {
                assertTrue(widths[1][c] > widths[0][c], grew(0, 1, c, widths));
                assertTrue(widths[2][c] > widths[1][c], grew(1, 2, c, widths));
            }
        } finally {
            closeFrame(frame);
        }
    }

    /**
     * 把内容区调成给定尺寸，逐栏校验布局并返回四栏宽度。
     *
     * <p>必须在 EDT 上调用：{@code setSize} + {@code validate} + 读取尺寸放在同一个任务里，
     * 中间不会插进窗口管理器的 resize 事件，量到的就是这一次布局的结果。</p>
     */
    private static int[] layoutAt(ForwarderUi.ForwarderFrame frame, int width, int height) {
        Container content = frame.getContentPane();
        content.setSize(width, height);
        content.validate();

        List<Component> columns = columns(content);
        assertEquals(NAMES.length, columns.size(), "应恰好有 4 栏");
        for (int c = 0; c < NAMES.length; c++) {
            assertEquals(NAMES[c], ((JComponent) columns.get(c)).getClientProperty("ui.column"),
                    "第 " + (c + 1) + " 栏顺序不对");
        }

        Container form = columns.get(0).getParent();
        double available = form.getWidth() - GAP * (NAMES.length - 1.0);
        int[] widths = new int[NAMES.length];
        for (int c = 0; c < NAMES.length; c++) {
            Component column = columns.get(c);
            widths[c] = column.getWidth();
            Rectangle bounds = column.getBounds();
            assertTrue(bounds.x >= 0 && bounds.x + bounds.width <= form.getWidth() + 1,
                    "栏越出表单：" + bounds + " / " + form.getSize());
            assertEquals(available * WEIGHTS[c] / TOTAL_WEIGHT, column.getWidth(), 2.0,
                    "第 " + (c + 1) + " 栏宽度必须严格按权重分配");
            assertContentsInside(column);
        }
        for (int c = 1; c < NAMES.length; c++) {
            int gap = columns.get(c).getBounds().x
                    - (columns.get(c - 1).getBounds().x + columns.get(c - 1).getWidth());
            assertEquals(GAP, gap, 1, "栏间距应为 " + GAP + "px");
        }
        assertEquals(form.getWidth(), rightEdge(columns), 2.0,
                "最后一栏必须贴住表单右边界（不能留出滚动条的余地）");
        return widths;
    }

    /** 内容区变宽后该栏没跟着变宽时的失败信息（带三档实际宽度，一眼看出是没布局还是没变宽）。 */
    private static String grew(int from, int to, int column, int[][] widths) {
        return "内容区 " + SIZES[from][0] + " → " + SIZES[to][0] + " 时第 " + (column + 1)
                + " 栏应变宽，实际 " + widths[from][column] + " → " + widths[to][column];
    }

    @Test
    void formIsNotWrappedInScrollPane() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "需要桌面环境才能验证 Swing 布局");
        ForwarderUi.ForwarderFrame frame = showFrame();
        try {
            Boolean wrapped = onEdt(() -> {
                Component form = columns(frame).get(0).getParent();
                for (Component p = form; p != null; p = p.getParent()) {
                    if (p instanceof JScrollPane) {
                        return true;
                    }
                }
                return false;
            });
            assertFalse(wrapped, "表单不能再被滚动容器包住（会退化成固定宽 + 横向滚动条）");
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 两个方向都能关 ====================

    @Test
    void bothDirectionsCanBeSwitchedOff() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            ForwarderUi.BridgePanel panel = new ForwarderUi.BridgePanel();
            JToggleButton utot = toggle(panel, "utot");
            JToggleButton ttou = toggle(panel, "ttou");
            assertNotNull(utot, "找不到 UDP → TCP 开关");
            assertNotNull(ttou, "找不到 TCP → UDP 开关");
            assertTrue(utot.isSelected() && ttou.isSelected(), "两个方向默认应开启");
            utot.doClick();
            ttou.doClick();
            assertFalse(utot.isSelected(), "UI 不应强制打开 UDP → TCP");
            assertFalse(ttou.isSelected(), "UI 不应强制打开 TCP → UDP");
        });
    }

    // ==================== 默认值 / 输入校验 ====================

    @Test
    void udpGroupAndPortDefaultsAreApplied() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            ForwarderUi.BridgePanel panel = new ForwarderUi.BridgePanel();
            assertEquals("224.3.0.0", field(panel, "group").getText());
            assertEquals("3000", field(panel, "port").getText());

            // 只允许“一个地址”：逗号、空格、字母的整段输入直接丢弃。
            JTextField group = field(panel, "group");
            group.setText("224.3.0.0,224.3.0.1");
            assertEquals("", group.getText());
            group.setText("abc");
            assertEquals("", group.getText());
            group.setText("239.1.2.3");
            assertEquals("239.1.2.3", group.getText());
        });
    }

    @Test
    void peerInputRequiresIpv4AndPort() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            ForwarderUi.BridgePanel panel = new ForwarderUi.BridgePanel();
            JTextField input = field(panel, "peer");
            JButton add = button(panel, "+ Add");
            assertNotNull(add, "找不到 + Add 按钮");
            JTable table = table(panel);
            assertNotNull(table, "找不到 peers 表格");
            JLabel error = label(panel, "peerError");

            input.setText("1.1.1.1");
            add.doClick();
            assertEquals(0, table.getRowCount(), "缺端口不应加入");
            assertTrue(error.getText().contains("IPv4:port"), "应显示可见错误：" + error.getText());

            input.setText("example.com:2000");
            add.doClick();
            assertEquals(0, table.getRowCount(), "主机名不应加入");

            input.setText("1.1.1.1:2000");
            add.doClick();
            assertEquals(1, table.getRowCount(), "合法 IP:port 应加入");
            assertEquals("1.1.1.1:2000", table.getValueAt(0, 0));
            assertEquals("stopped", table.getValueAt(0, 1), "未启动时 peer 状态应为 stopped");
            assertEquals(" ", error.getText(), "成功后应清空错误提示");

            panel.setPeerState("connecting");
            assertEquals("connecting", table.getValueAt(0, 1));
            panel.setPeerState("stopped");
            assertEquals("stopped", table.getValueAt(0, 1));
        });
    }

    @Test
    void startAndStopAreOneButton() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(), "需要桌面环境才能验证 Swing 布局");
        ForwarderUi.ForwarderFrame frame = showFrame();
        try {
            Boolean merged = onEdt(() -> {
                JButton start = button(frame.getContentPane(), "Start");
                JButton stop = button(frame.getContentPane(), "Stop");
                return start != null && stop == null;
            });
            assertTrue(merged, "Start/Stop 应合并为一个按钮（空闲时只显示 Start）");
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 组件查找 / 断言 ====================

    private static List<Component> columns(Container root) {
        List<Component> found = new ArrayList<>();
        collectColumns(root, found);
        found.sort(Comparator.comparingInt(c -> c.getBounds().x));
        return found;
    }

    private static void collectColumns(Component c, List<Component> out) {
        if (c instanceof JComponent jc && jc.getClientProperty("ui.column") != null) {
            out.add(c);
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectColumns(child, out);
            }
        }
    }

    private static int rightEdge(List<Component> columns) {
        Component last = columns.get(columns.size() - 1);
        return last.getBounds().x + last.getWidth();
    }

    /** 栏内可见控件（表格内部按视口裁剪的除外）必须整块落在栏内。 */
    private static void assertContentsInside(Component column) {
        for (Component child : descendants(column)) {
            if (!child.isVisible() || child.getWidth() == 0 || child.getHeight() == 0) {
                continue;
            }
            if (insideViewport(child, column)) {
                continue;
            }
            Rectangle bounds = SwingUtilities.convertRectangle(
                    child.getParent(), child.getBounds(), column);
            assertTrue(bounds.x >= -1 && bounds.y >= -1
                            && bounds.x + bounds.width <= column.getWidth() + 1
                            && bounds.y + bounds.height <= column.getHeight() + 1,
                    "控件被裁切：" + child.getClass().getSimpleName() + " " + bounds
                            + " 超出栏 " + column.getSize());
        }
    }

    private static List<Component> descendants(Component root) {
        List<Component> out = new ArrayList<>();
        collectDescendants(root, out);
        return out;
    }

    private static void collectDescendants(Component c, List<Component> out) {
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                out.add(child);
                collectDescendants(child, out);
            }
        }
    }

    private static boolean insideViewport(Component child, Component column) {
        for (Component p = child.getParent(); p != null && p != column; p = p.getParent()) {
            if (p instanceof JViewport) {
                return true;
            }
        }
        return false;
    }

    private static JToggleButton toggle(Container root, String key) {
        for (Component child : root.getComponents()) {
            if (child instanceof JToggleButton tb
                    && key.equals(tb.getClientProperty("ui.toggle"))) {
                return tb;
            }
            if (child instanceof Container container) {
                JToggleButton found = toggle(container, key);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JTextField field(Container root, String key) {
        JTextField found = find(root, JTextField.class, key);
        assertNotNull(found, "找不到输入框：" + key);
        return found;
    }

    private static JLabel label(Container root, String key) {
        JLabel found = find(root, JLabel.class, key);
        assertNotNull(found, "找不到标签：" + key);
        return found;
    }

    /** 按 {@code ui.field} 属性在整棵树里找第一个匹配的组件。 */
    private static <T extends JComponent> T find(Component root, Class<T> type, String key) {
        if (type.isInstance(root)
                && key.equals(((JComponent) root).getClientProperty("ui.field"))) {
            return type.cast(root);
        }
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                T found = find(child, type, key);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JButton button(Container root, String text) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton button && text.equals(button.getText())) {
                return button;
            }
            if (child instanceof Container container) {
                JButton found = button(container, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JTable table(Container root) {
        for (Component child : root.getComponents()) {
            if (child instanceof JTable table) {
                return table;
            }
            if (child instanceof Container container) {
                JTable found = table(container);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    // ==================== 建窗 / 关窗 ====================

    private static ForwarderUi.ForwarderFrame showFrame() throws Exception {
        AtomicReference<ForwarderUi.ForwarderFrame> holder = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ForwarderUi.installTheme(true);
            ForwarderUi.ForwarderFrame frame = new ForwarderUi.ForwarderFrame(new CountDownLatch(1));
            holder.set(frame);
            frame.setSize(1100, 720);
            frame.setVisible(true);
        });
        flushEdt();
        ForwarderUi.ForwarderFrame frame = holder.get();
        onEdt(() -> {
            frame.validate();
            return null;
        });
        return frame;
    }

    private static void closeFrame(ForwarderUi.ForwarderFrame frame) throws Exception {
        onEdt(() -> {
            frame.dispose();
            return null;
        });
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
}
