package com.jshark;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.UIManager;
import javax.swing.table.JTableHeader;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.Insets;

/**
 * 三个 Swing 界面（采集 / 重放 / 转发）共用的配色、Look&amp;Feel 与控件样式。
 *
 * <h3>为什么集中到一处</h3>
 * <p>
 * 这三个界面历史上是互相复制出来的：每个类里都有一份 14 个颜色常量、一份
 * {@code installTheme}、一份 {@code restyle} 和一份 {@code gbc}。改一次配色要改三处，
 * 而且三处早就出现了细微差异（有的漏了 ToggleButton，有的漏了 TextPane 边框），
 * 用户看到的就是"同一个产品的三个窗口长得不完全一样"。
 * </p>
 *
 * <p>配色只有深/浅两套，通过 {@link #install(boolean)} 切换；控件按
 * {@code ui.role}/{@code ui.kind}/{@code ui.primary} 这三个 client property 取色，
 * 因此界面代码只需要在构建时打标记，不必到处 {@code setBackground}。</p>
 *
 * <p>包内可见：只服务 {@code com.jshark} 下的三个界面类，不属于对外 API。</p>
 */
final class UiTheme {

    static Color BG = new Color(0x1E222A);
    static Color PANEL = new Color(0x252B35);
    static Color FG = new Color(0xDDE4EE);
    static Color MUTED = new Color(0x9AA6B5);
    static Color INPUT = new Color(0x161A20);
    static Color ACCENT = new Color(0xE0A44A);
    static Color DISABLED_BG = new Color(0x20252D);
    static Color SELECTION = new Color(0x3A4658);
    static Color BORDER = new Color(0x3A4658);
    static Color PLAYER_BG = new Color(0x171B22);
    static Color ON_ACCENT = new Color(0x1E222A);
    static Color STATE_OK = new Color(0x4CAF7D);
    static Color STATE_FAIL = new Color(0xE5534B);

    static boolean darkTheme = true;

    private UiTheme() {
    }

    /** @return 当前是否为深色主题 */
        /**
     * 安装 Metal LAF 与深/浅配色。
     *
     * <p>统一选 Metal：它对 {@link UIManager} 颜色覆盖的响应比 Windows LAF 稳定，
     * 不会出现"白底白字/标签空白"的平台差异。</p>
     *
     * @param dark true = 深色，false = 浅色
     */
    static void install(boolean dark) {
        darkTheme = dark;
        if (dark) {
            BG = new Color(0x1E222A);
            PANEL = new Color(0x252B35);
            FG = new Color(0xDDE4EE);
            MUTED = new Color(0x9AA6B5);
            INPUT = new Color(0x161A20);
            ACCENT = new Color(0xE0A44A);
            DISABLED_BG = new Color(0x20252D);
            SELECTION = new Color(0x3A4658);
            BORDER = new Color(0x3A4658);
            PLAYER_BG = new Color(0x171B22);
            ON_ACCENT = new Color(0x1E222A);
            STATE_OK = new Color(0x4CAF7D);
            STATE_FAIL = new Color(0xE5534B);
        } else {
            BG = new Color(0xF4F6F8);
            PANEL = new Color(0xFFFFFF);
            FG = new Color(0x1E222A);
            MUTED = new Color(0x5F6B7A);
            INPUT = new Color(0xFFFFFF);
            ACCENT = new Color(0xD98A1A);
            DISABLED_BG = new Color(0xE9ECF0);
            SELECTION = new Color(0xCCE0F5);
            BORDER = new Color(0xC9D0D8);
            PLAYER_BG = new Color(0xF0F2F5);
            ON_ACCENT = new Color(0x1E222A);
            STATE_OK = new Color(0x2E7D32);
            STATE_FAIL = new Color(0xC62828);
        }

        try {
            UIManager.setLookAndFeel(new javax.swing.plaf.metal.MetalLookAndFeel());
        } catch (Exception ignored) {
            // Metal 一定存在；失败也继续用当前 LAF
        }

        Color bg = BG;
        Color panel = PANEL;
        Color fg = FG;
        Color muted = MUTED;
        Color input = INPUT;
        Color accent = ACCENT;
        Color selection = SELECTION;
        Color border = BORDER;
        Color selectionFg = dark ? Color.WHITE : fg;
        Color darkShadow = dark ? new Color(0x11151A) : border;

        // Metal 会用自己那套浅色画输入框/下拉框边框，深色主题下就是一圈刺眼的白边。
        // 这里显式钉住边框，并给文本框留出内边距（否则文字贴着边框）。
        UIManager.put("TextField.border", BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(border),
                BorderFactory.createEmptyBorder(3, 5, 3, 5)));
        UIManager.put("TextArea.border", BorderFactory.createLineBorder(border));
        UIManager.put("ComboBox.border", BorderFactory.createLineBorder(border));
        UIManager.put("Button.border", BorderFactory.createLineBorder(border));
        UIManager.put("Spinner.border", BorderFactory.createLineBorder(border));
        UIManager.put("ScrollPane.border", BorderFactory.createLineBorder(border));

        UIManager.put("Panel.background", bg);
        UIManager.put("Label.foreground", fg);
        UIManager.put("Label.disabledForeground", muted);

        UIManager.put("Button.background", panel);
        UIManager.put("Button.foreground", fg);
        UIManager.put("Button.select", selection);
        UIManager.put("Button.disabledText", muted);
        UIManager.put("Button.focus", accent);

        UIManager.put("ToggleButton.background", panel);
        UIManager.put("ToggleButton.foreground", fg);
        UIManager.put("ToggleButton.border", BorderFactory.createLineBorder(border));

        UIManager.put("TextField.background", input);
        UIManager.put("TextField.foreground", fg);
        UIManager.put("TextField.caretForeground", accent);
        UIManager.put("TextField.disabledBackground", DISABLED_BG);
        UIManager.put("TextField.disabledForeground", muted);

        UIManager.put("TextArea.background", input);
        UIManager.put("TextArea.foreground", fg);
        UIManager.put("TextArea.caretForeground", accent);
        UIManager.put("TextArea.disabledBackground", DISABLED_BG);
        UIManager.put("TextArea.disabledForeground", muted);

        UIManager.put("TextPane.background", input);
        UIManager.put("TextPane.foreground", fg);

        UIManager.put("ComboBox.background", panel);
        UIManager.put("ComboBox.foreground", fg);
        UIManager.put("ComboBox.selectionBackground", selection);
        UIManager.put("ComboBox.selectionForeground", selectionFg);
        UIManager.put("ComboBox.disabledBackground", DISABLED_BG);
        UIManager.put("ComboBox.disabledForeground", muted);
        // Metal 的下拉箭头/按钮单独取色；不覆盖时禁用状态会露出浅灰底。
        UIManager.put("ComboBox.buttonBackground", panel);
        UIManager.put("ComboBox.buttonDarkShadow", darkShadow);
        UIManager.put("ComboBox.buttonHighlight", panel);
        UIManager.put("ComboBox.buttonShadow", selection);
        UIManager.put("ComboBox.arrowButtonBackground", panel);

        UIManager.put("Spinner.background", panel);
        UIManager.put("Spinner.foreground", fg);
        UIManager.put("Spinner.disabledBackground", DISABLED_BG);
        UIManager.put("Spinner.disabledForeground", muted);

        UIManager.put("Table.background", input);
        UIManager.put("Table.foreground", fg);
        UIManager.put("Table.gridColor", border);
        UIManager.put("Table.selectionBackground", selection);
        UIManager.put("Table.selectionForeground", selectionFg);
        UIManager.put("TableHeader.background", panel);
        UIManager.put("TableHeader.foreground", fg);

        UIManager.put("TabbedPane.background", bg);
        UIManager.put("TabbedPane.foreground", fg);
        UIManager.put("TabbedPane.selected", panel);
        UIManager.put("TabbedPane.contentAreaColor", bg);
        UIManager.put("TabbedPane.highlight", selection);
        UIManager.put("TabbedPane.darkShadow", darkShadow);
        UIManager.put("TabbedPane.light", panel);
        UIManager.put("TabbedPane.focus", accent);

        UIManager.put("ScrollPane.background", bg);
        UIManager.put("Viewport.background", input);
        UIManager.put("ScrollBar.background", bg);
        UIManager.put("ScrollBar.thumb", border);
        UIManager.put("ScrollBar.track", bg);

        UIManager.put("SplitPane.background", bg);
        UIManager.put("SplitPane.dividerSize", 6);
        UIManager.put("SplitPane.highlight", border);
        UIManager.put("SplitPane.darkShadow", darkShadow);

        UIManager.put("CheckBox.background", bg);
        UIManager.put("CheckBox.foreground", fg);

        UIManager.put("ToolTip.background", panel);
        UIManager.put("ToolTip.foreground", fg);
        UIManager.put("OptionPane.background", panel);
        UIManager.put("OptionPane.messageForeground", fg);
    }

    /**
     * 按 client property 递归重刷一棵控件树的颜色（切换主题后调用）。
     *
     * <p>取值约定：面板 {@code ui.role=player|panel}；标签 {@code ui.kind=muted|section|accent|state}；
     * 按钮 {@code ui.primary=true} 使用强调色。</p>
     *
     * @param c 根控件
     */
    static void restyle(Component c) {
        if (c instanceof JPanel p) {
            String role = (String) p.getClientProperty("ui.role");
            if ("player".equals(role)) {
                p.setBackground(PLAYER_BG);
            } else if ("panel".equals(role)) {
                p.setBackground(PANEL);
            } else if (p.isOpaque()) {
                p.setBackground(BG);
            }
        } else if (c instanceof JLabel l) {
            String kind = (String) l.getClientProperty("ui.kind");
            if ("muted".equals(kind) || "section".equals(kind)) {
                l.setForeground(MUTED);
            } else if ("accent".equals(kind)) {
                l.setForeground(ACCENT);
            } else if (!"state".equals(kind)) {
                l.setForeground(FG);
            }
        } else if (c instanceof JTextField tf) {
            tf.setBackground(INPUT);
            tf.setForeground(FG);
            tf.setDisabledTextColor(MUTED);
        } else if (c instanceof JTextArea ta) {
            ta.setBackground(INPUT);
            ta.setForeground(FG);
        } else if (c instanceof JComboBox<?> cb) {
            cb.setBackground(PANEL);
            cb.setForeground(FG);
        } else if (c instanceof JSpinner sp) {
            sp.setBackground(INPUT);
            sp.setForeground(FG);
        } else if (c instanceof JTable t) {
            t.setBackground(INPUT);
            t.setForeground(FG);
            t.setGridColor(BORDER);
            t.setSelectionBackground(SELECTION);
            t.setSelectionForeground(FG);
            JTableHeader header = t.getTableHeader();
            if (header != null) {
                header.setBackground(PANEL);
                header.setForeground(FG);
            }
        } else if (c instanceof JTabbedPane tp) {
            tp.setBackground(BG);
            tp.setForeground(FG);
        } else if (c instanceof JScrollPane sp) {
            sp.setBackground(BG);
            sp.getViewport().setBackground(INPUT);
        } else if (c instanceof JCheckBox cb) {
            cb.setBackground(BG);
            cb.setForeground(FG);
        } else if (c instanceof JToggleButton tb) {
            tb.setBackground(PANEL);
            tb.setForeground(FG);
        } else if (c instanceof JButton b) {
            if (Boolean.TRUE.equals(b.getClientProperty("ui.primary"))) {
                b.setBackground(ACCENT);
                b.setForeground(ON_ACCENT);
            } else {
                b.setBackground(PANEL);
                b.setForeground(FG);
            }
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                restyle(child);
            }
        }
    }

    /**
     * 表单常用的 GridBag 约束：左对齐、统一内边距。
     *
     * @param x 列
     * @param y 行
     * @return 新的约束对象
     */
    static GridBagConstraints gbc(int x, int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.insets = new Insets(3, 4, 3, 4);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    /**
     * 小号分组标题（大写、加粗、次要色）。
     *
     * @param text 文本
     * @return 配好样式的标签
     */
    static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.putClientProperty("ui.kind", "section");
        l.setForeground(MUTED);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 10f));
        return l;
    }

    /**
     * 次要说明文字。
     *
     * @param text 文本
     * @return 配好样式的标签
     */
    static JLabel labelMuted(String text) {
        JLabel l = new JLabel(text);
        l.putClientProperty("ui.kind", "muted");
        l.setForeground(MUTED);
        return l;
    }

    /**
     * 更小的提示文字（用于输入框下方）。
     *
     * @param text 文本
     * @return 配好样式的标签
     */
    static JLabel hintText(String text) {
        JLabel l = labelMuted(text);
        l.setFont(l.getFont().deriveFont(Font.PLAIN, 10.5f));
        return l;
    }
}
