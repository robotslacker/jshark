package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.parser.SplitUtil;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JComponent;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.Window;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import static com.jshark.UiFormat.*;
import static com.jshark.UiTheme.*;

/**
 * {@code --ui} 的 Swing 瘦客户端：不跑重放引擎，只负责
 * 参数、{@code --inspect} 展示、{@code --control stdio} 子进程与 status 回显。
 */
public final class ReplayUi {

    private static final DateTimeFormatter DATE_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    /** CLI argument format: keep milliseconds because volume data ranges have ms precision. */
    private static final DateTimeFormatter ARG_TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private ReplayUi() {
    }

    public static void launch(String[] args) {
        installTheme(true);
        SwingUtilities.invokeLater(() -> {
            try {
                new ReplayMainFrame(args).setVisible(true);
            } catch (Throwable t) {
                t.printStackTrace();
                JOptionPane.showMessageDialog(null,
                        "Failed to launch UI: " + t.getMessage(),
                        "JShark Replay", JOptionPane.ERROR_MESSAGE);
                System.exit(1);
            }
        });
    }

    /**
     * Install the Metal LAF plus either the dark or light palette.
     *
     * <p>包内可见是为了让布局回归测试能按生产环境（Metal + 深色配色）建窗：
     * 换一套 LAF 时组件首选高度会变，测出来的就不是用户看到的那个默认布局了。</p>
     *
     * @param dark true = dark theme, false = light theme
     */
    static void installTheme(boolean dark) {
        UiTheme.install(dark);
        if (dark) {
            SeekBar.applyTheme(new Color(0x39404D), ACCENT, new Color(0xF4C46A), new Color(0x2A3034));
        } else {
            SeekBar.applyTheme(new Color(0xD5DAE1), ACCENT, ACCENT, new Color(0xE6E9ED));
        }
    }
    /**
     * Apply the JShark replay icon (copied from SlackDB's favicon) to a frame or dialog.
     * Multiple sizes let the OS pick the best one for the title bar / taskbar.
     *
     * @param window target window
     */
    static void applyWindowIcon(Window window) {
        UiIcons.apply(window);
    }

    // ==================== Date-time input ====================

    /**
     * Text field that also swaps its background/foreground when disabled. Metal LAF keeps a
     * bright background for disabled text fields, which looks broken in the dark theme.
     */
    static final class DarkTextField extends JTextField {
        DarkTextField() {
            super();
            init();
        }

        DarkTextField(String text) {
            super(text);
            init();
        }

        DarkTextField(String text, int columns) {
            super(text, columns);
            init();
        }

        DarkTextField(int columns) {
            super(columns);
            init();
        }

        private void init() {
            refreshTheme();
        }

        void refreshTheme() {
            setBackground(isEnabled() ? INPUT : DISABLED_BG);
            setForeground(isEnabled() ? FG : MUTED);
            setCaretColor(ACCENT);
            setDisabledTextColor(MUTED);
        }

        @Override
        public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);
            refreshTheme();
        }
    }

    /**
     * Absolute date-time input: a text field plus a calendar picker button.
     *
     * <p>The text remains editable (format {@code yyyy-MM-dd HH:mm:ss}); the picker is a
     * lightweight modal calendar because Swing has no built-in date chooser. An empty
     * value means "unbounded" for {@code --start}/{@code --end}.</p>
     */
    static final class DateTimeField extends JPanel {
        private final JTextField text = new DarkTextField(20);
        private final JButton pick = new JButton("Pick…");

        DateTimeField(String tooltip) {
            super(new BorderLayout(4, 0));
            setOpaque(false);
            text.setToolTipText(tooltip);
            text.setDisabledTextColor(MUTED);
            pick.setToolTipText("Choose date and time");
            pick.setPreferredSize(new Dimension(72, 26));
            add(text, BorderLayout.CENTER);
            add(pick, BorderLayout.EAST);
            pick.addActionListener(e -> openPicker());
        }

        String getText() {
            return text.getText();
        }

        void setText(String value) {
            text.setText(value == null ? "" : value);
        }

        javax.swing.text.Document getDocument() {
            return text.getDocument();
        }

        @Override
        public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);
            text.setEnabled(enabled);
            pick.setEnabled(enabled);
        }

        private void openPicker() {
            Long parsed;
            try {
                parsed = parseAbsoluteTime(text.getText());
            } catch (RuntimeException e) {
                parsed = null;
            }
            LocalDateTime initial = parsed == null
                    ? LocalDateTime.now()
                    : LocalDateTime.ofInstant(Instant.ofEpochMilli(parsed), ZoneId.systemDefault());
            DateTimeDialog dialog = new DateTimeDialog(
                    SwingUtilities.getWindowAncestor(this), initial);
            dialog.setVisible(true);
            if (dialog.isCleared()) {
                text.setText("");
            } else if (dialog.getPicked() != null) {
                text.setText(dialog.getPicked().format(DATE_TIME_FORMAT));
            }
        }
    }

    /** Modal calendar + time picker used by {@link DateTimeField}. */
    static final class DateTimeDialog extends JDialog {
        private YearMonth month;
        private LocalDate selected;
        private final JSpinner hourSpinner;
        private final JSpinner minuteSpinner;
        private final JSpinner secondSpinner;
        private final JLabel monthLabel = new JLabel();
        private final JPanel dayPanel = new JPanel(new GridLayout(0, 7, 2, 2));
        private LocalDateTime picked;
        private boolean cleared;

        DateTimeDialog(Window owner, LocalDateTime initial) {
            super(owner, "Select date and time", ModalityType.APPLICATION_MODAL);
            applyWindowIcon(this);
            this.selected = initial.toLocalDate();
            this.month = YearMonth.from(selected);
            this.hourSpinner = numberSpinner(initial.getHour(), 0, 23);
            this.minuteSpinner = numberSpinner(initial.getMinute(), 0, 59);
            this.secondSpinner = numberSpinner(initial.getSecond(), 0, 59);

            JPanel root = new JPanel(new BorderLayout(8, 8));
            root.setBackground(PANEL);
            root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JPanel header = new JPanel(new BorderLayout(4, 4));
            header.setOpaque(false);
            JPanel nav = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            nav.setOpaque(false);
            JButton prevYear = smallButton("<<");
            JButton prevMonth = smallButton("<");
            JButton nextMonth = smallButton(">");
            JButton nextYear = smallButton(">>");
            prevYear.addActionListener(e -> shiftMonth(-12));
            prevMonth.addActionListener(e -> shiftMonth(-1));
            nextMonth.addActionListener(e -> shiftMonth(1));
            nextYear.addActionListener(e -> shiftMonth(12));
            nav.add(prevYear);
            nav.add(prevMonth);
            monthLabel.setForeground(FG);
            monthLabel.setFont(monthLabel.getFont().deriveFont(Font.BOLD, 14f));
            nav.add(monthLabel);
            nav.add(nextMonth);
            nav.add(nextYear);
            header.add(nav, BorderLayout.WEST);
            root.add(header, BorderLayout.NORTH);

            dayPanel.setOpaque(false);
            root.add(dayPanel, BorderLayout.CENTER);

            JPanel footer = new JPanel(new BorderLayout(8, 8));
            footer.setOpaque(false);
            JPanel timeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            timeRow.setOpaque(false);
            JLabel timeLabel = new JLabel("Time");
            timeLabel.setForeground(FG);
            timeRow.add(timeLabel);
            timeRow.add(hourSpinner);
            timeRow.add(new JLabel(":"));
            timeRow.add(minuteSpinner);
            timeRow.add(new JLabel(":"));
            timeRow.add(secondSpinner);
            footer.add(timeRow, BorderLayout.NORTH);

            JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
            actions.setOpaque(false);
            JButton clearBtn = new JButton("Clear");
            JButton nowBtn = new JButton("Now");
            JButton cancelBtn = new JButton("Cancel");
            JButton okBtn = new JButton("OK");
            clearBtn.addActionListener(e -> {
                cleared = true;
                dispose();
            });
            nowBtn.addActionListener(e -> {
                LocalDateTime now = LocalDateTime.now();
                selected = now.toLocalDate();
                month = YearMonth.from(selected);
                hourSpinner.setValue(now.getHour());
                minuteSpinner.setValue(now.getMinute());
                secondSpinner.setValue(now.getSecond());
                refreshCalendar();
            });
            cancelBtn.addActionListener(e -> dispose());
            okBtn.addActionListener(e -> {
                picked = LocalDateTime.of(selected,
                        LocalTime.of((Integer) hourSpinner.getValue(),
                                (Integer) minuteSpinner.getValue(),
                                (Integer) secondSpinner.getValue()));
                dispose();
            });
            actions.add(clearBtn);
            actions.add(nowBtn);
            actions.add(cancelBtn);
            actions.add(okBtn);
            footer.add(actions, BorderLayout.SOUTH);
            root.add(footer, BorderLayout.SOUTH);

            getRootPane().setDefaultButton(okBtn);
            getRootPane().registerKeyboardAction(e -> dispose(),
                    javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
                    JComponent.WHEN_IN_FOCUSED_WINDOW);

            setContentPane(root);
            refreshCalendar();
            setResizable(false);
            pack();
            setLocationRelativeTo(owner);
        }

        LocalDateTime getPicked() {
            return picked;
        }

        boolean isCleared() {
            return cleared;
        }

        private static JButton smallButton(String text) {
            JButton button = new JButton(text);
            button.setPreferredSize(new Dimension(34, 26));
            return button;
        }

        private static JSpinner numberSpinner(int value, int min, int max) {
            JSpinner spinner = new JSpinner(new SpinnerNumberModel(value, min, max, 1));
            spinner.setPreferredSize(new Dimension(52, 26));
            JSpinner.DefaultEditor editor = (JSpinner.DefaultEditor) spinner.getEditor();
            editor.getTextField().setHorizontalAlignment(JTextField.CENTER);
            editor.getTextField().setBackground(INPUT);
            editor.getTextField().setForeground(FG);
            editor.getTextField().setCaretColor(ACCENT);
            // BasicSpinnerUI's arrow buttons ignore Button.background in some Metal builds.
            for (Component child : spinner.getComponents()) {
                if (child instanceof JButton button) {
                    button.setBackground(PANEL);
                    button.setForeground(FG);
                    button.setOpaque(true);
                }
            }
            return spinner;
        }

        private void shiftMonth(int delta) {
            month = month.plusMonths(delta);
            int day = Math.min(selected.getDayOfMonth(), month.lengthOfMonth());
            selected = month.atDay(day);
            refreshCalendar();
        }

        private void refreshCalendar() {
            monthLabel.setText(month.getMonth().getDisplayName(TextStyle.FULL, Locale.ENGLISH)
                    + " " + month.getYear());
            dayPanel.removeAll();
            for (int i = 1; i <= 7; i++) {
                DayOfWeek day = DayOfWeek.of(i);
                JLabel label = new JLabel(day.getDisplayName(TextStyle.SHORT, Locale.ENGLISH),
                        javax.swing.SwingConstants.CENTER);
                label.setForeground(MUTED);
                dayPanel.add(label);
            }
            LocalDate first = month.atDay(1);
            int lead = first.getDayOfWeek().getValue() - DayOfWeek.MONDAY.getValue();
            for (int i = 0; i < lead; i++) {
                dayPanel.add(new JLabel(""));
            }
            for (int d = 1; d <= month.lengthOfMonth(); d++) {
                LocalDate date = month.atDay(d);
                JButton button = new JButton(String.valueOf(d));
                button.setPreferredSize(new Dimension(34, 26));
                button.setMargin(new Insets(0, 0, 0, 0));
                if (date.equals(selected)) {
                    button.setBackground(ACCENT);
                    button.setForeground(BG);
                } else {
                    button.setBackground(PANEL);
                    button.setForeground(FG);
                }
                button.addActionListener(e -> {
                    selected = date;
                    refreshCalendar();
                });
                dayPanel.add(button);
            }
            // Always render six weeks so the dialog does not resize between months.
            for (int i = lead + month.lengthOfMonth(); i < 42; i++) {
                dayPanel.add(new JLabel(""));
            }
            dayPanel.revalidate();
            dayPanel.repaint();
        }
    }

    // ==================== Start 前的本地预览 ====================

    /**
     * 预览用的时间选择结果（绝对 epoch 毫秒）。
     *
     * @param fromMs  裁剪后的起点
     * @param toMs    裁剪后的终点
     * @param clamped 是否被数据范围裁剪
     * @param empty   是否与数据范围没有交集
     */
    record Selection(long fromMs, long toMs, boolean clamped, boolean empty) {
    }

    /**
     * 只做“Start 前预览”：把界面上的 {@code --start/--end}（绝对捕获时间）
     * 裁剪到 inspect 得到的数据范围。
     *
     * <p>权威结果仍由子进程的 {@code --inspect} 计算；这里只服务标签与 Start 门禁，
     * 因此参数还没输完/格式不对时返回 {@code null}，不抛异常。</p>
     *
     * @param dataStart 数据范围起点（epoch ms）
     * @param dataEnd   数据范围终点（epoch ms）
     * @param start     {@code --start} 文本（绝对时间）
     * @param end       {@code --end} 文本（绝对时间）
     * @return 预览结果；数据范围未知或参数无效时为 null
     */
    static Selection previewSelection(Long dataStart, Long dataEnd,
                                      String start, String end) {
        if (dataStart == null || dataEnd == null) {
            return null;
        }
        Long from = null;
        Long to = null;
        try {
            if (!isBlank(start)) {
                from = parseAbsoluteTime(start);
            }
            if (!isBlank(end)) {
                to = parseAbsoluteTime(end);
            }
        } catch (RuntimeException e) {
            return null;
        }
        long requestedFrom = from == null ? dataStart : from;
        long requestedTo = to == null ? dataEnd : to;
        long clampedFrom = Math.max(requestedFrom, dataStart);
        long clampedTo = Math.min(requestedTo, dataEnd);
        return new Selection(clampedFrom, clampedTo,
                clampedFrom != requestedFrom || clampedTo != requestedTo,
                clampedFrom > clampedTo);
    }

    /** 绝对捕获时间：yyyy-MM-dd HH:mm[:ss[.SSS]]、yyyyMMddHHmmss，'T' 分隔也接受。 */
    static Long parseAbsoluteTime(String text) {
        String s = text == null ? "" : text.trim().toUpperCase(java.util.Locale.ROOT);
        if (s.isEmpty()) {
            return null;
        }
        if (s.matches("\\d{14}")) {
            return LocalDateTime.parse(s, DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
                    .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        }
        String normalized = s.replace('T', ' ');
        DateTimeFormatter fmt;
        if (normalized.matches(".*\\.\\d+$")) {
            fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        } else if (normalized.matches(".*:\\d{2}:\\d{2}$")) {
            fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        } else {
            fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
        }
        return LocalDateTime.parse(normalized, fmt)
                .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * Default End value for the inspected source.
     *
     * <p>Follow/LIVE (split DB + payload) must keep End empty: any explicit end would stop
     * following newly rotated volumes. Other sources default to the selected data end.</p>
     *
     * @param followSupported whether the source follows new volumes
     * @param endMs           selected range end (epoch ms)
     * @return field text, or empty for follow mode
     */
    static String defaultEndText(boolean followSupported, long endMs) {
        return followSupported ? "" : ARG_TIME_FORMAT.format(Instant.ofEpochMilli(endMs));
    }

    /**
     * Compose the four mapping columns into the CLI format {@code SrcIP:SrcPort-DstIP:DstPort}.
     *
     * <p>Each column may contain comma-separated values; the Nth value from every column forms
     * one rule. Empty values become the {@code *} wildcard. All-empty columns mean "no mapping".</p>
     *
     * @param srcIp   source IP column
     * @param srcPort source port column
     * @param dstIp   destination IP column
     * @param dstPort destination port column
     * @return comma-separated mapping string, or empty when nothing was entered
     */
    static String composeTargetMapping(String srcIp, String srcPort, String dstIp, String dstPort) {
        List<String> srcIps = splitCsv(srcIp);
        List<String> srcPorts = splitCsv(srcPort);
        List<String> dstIps = splitCsv(dstIp);
        List<String> dstPorts = splitCsv(dstPort);
        int count = Math.max(Math.max(srcIps.size(), srcPorts.size()),
                Math.max(dstIps.size(), dstPorts.size()));
        if (count == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                out.append(", ");
            }
            out.append(valueAt(srcIps, i)).append(':')
                    .append(valueAt(srcPorts, i)).append('-')
                    .append(valueAt(dstIps, i)).append(':')
                    .append(valueAt(dstPorts, i));
        }
        return out.toString();
    }

    private static List<String> splitCsv(String text) {
        List<String> values = new ArrayList<>();
        if (text == null) {
            return values;
        }
        for (String part : text.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private static String valueAt(List<String> values, int index) {
        return index < values.size() ? values.get(index) : "*";
    }

    /**
     * Split a CLI mapping string back into the four UI columns. Multiple rules are preserved by
     * joining each column with commas; malformed rules are ignored.
     *
     * @param mapping CLI mapping string ({@code SrcIP:SrcPort-DstIP:DstPort,...})
     * @return four column strings (possibly empty)
     */
    static String[] targetMappingFields(String mapping) {
        List<String> srcIps = new ArrayList<>();
        List<String> srcPorts = new ArrayList<>();
        List<String> dstIps = new ArrayList<>();
        List<String> dstPorts = new ArrayList<>();
        if (mapping != null) {
            for (String rule : mapping.split(",")) {
                String trimmed = rule.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                int dash = trimmed.indexOf('-');
                if (dash <= 0) {
                    continue;
                }
                String[] src = trimmed.substring(0, dash).trim().split(":", -1);
                String[] dst = trimmed.substring(dash + 1).trim().split(":", -1);
                if (src.length != 2 || dst.length != 2) {
                    continue;
                }
                srcIps.add(src[0].trim());
                srcPorts.add(src[1].trim());
                dstIps.add(dst[0].trim());
                dstPorts.add(dst[1].trim());
            }
        }
        return new String[]{
                String.join(", ", srcIps),
                String.join(", ", srcPorts),
                String.join(", ", dstIps),
                String.join(", ", dstPorts)
        };
    }

    /**
     * Rewrite {@code --start/--end} in a child-process argument list from the effective window.
     *
     * <p>Used when the UI's file range selector trims leading/trailing files, or when the user
     * explicitly set/cleared the time fields. Auto-filled default values are <b>not</b> forwarded
     * as explicit bounds (important for LIVE follow: an empty End must keep following new volumes).
     * The engine is unchanged: it only sees a normal absolute time window.</p>
     *
     * @param args          argument list (option/value pairs; mutated and returned)
     * @param explicitStart user explicitly supplied a non-empty Start
     * @param explicitEnd   user explicitly supplied a non-empty End
     * @param fromMs        effective window start (epoch ms)
     * @param toMs          effective window end (epoch ms)
     * @param trimsHead     whether replayable files before the selected range exist
     * @param trimsTail     whether replayable files after the selected range exist
     * @return the same list, with normalized time arguments
     */
    static List<String> overrideTimeWindowArgs(List<String> args,
                                               boolean explicitStart, boolean explicitEnd,
                                               Long fromMs, Long toMs,
                                               boolean trimsHead, boolean trimsTail) {
        if (!trimsHead && !trimsTail && !explicitStart && !explicitEnd) {
            return args;
        }
        // Drop the raw text values; only the effective (clamped) bounds are authoritative.
        for (int i = args.size() - 2; i >= 0; i--) {
            if ("--start".equals(args.get(i)) || "--end".equals(args.get(i))) {
                args.remove(i + 1);
                args.remove(i);
            }
        }
        if ((trimsHead || explicitStart) && fromMs != null) {
            args.add("--start");
            args.add(ARG_TIME_FORMAT.format(Instant.ofEpochMilli(fromMs)));
        }
        if ((trimsTail || explicitEnd) && toMs != null) {
            args.add("--end");
            args.add(ARG_TIME_FORMAT.format(Instant.ofEpochMilli(toMs)));
        }
        return args;
    }

    // ==================== 子进程客户端 ====================

    /** 子进程回调；实现方负责切回 EDT。 */
    interface Callbacks {
        default void onHello(JSONObject json) {
        }

        default void onStatus(JSONObject json) {
        }

        default void onAck(JSONObject json) {
        }

        default void onTerminal(JSONObject json) {
        }

        default void onInspectProgress(JSONObject json) {
        }

        default void onInspectResult(JSONObject json) {
        }

        default void onInspectError(JSONObject json) {
        }

        default void onLog(String line) {
        }

        default void onExit(int code) {
        }
    }

    static final class EngineProcess {
        private final UiProcess process;
        private final Callbacks callbacks;
        /** 会话代号：Stop→Start 之后，旧子进程的残留消息据此丢弃。 */
        private final long generation;

        static EngineProcess inspect(List<String> args, Callbacks cb, long generation) throws Exception {
            return new EngineProcess(args, true, generation, cb);
        }

        static EngineProcess control(List<String> args, Callbacks cb, long generation) throws Exception {
            return new EngineProcess(args, false, generation, cb);
        }

        private EngineProcess(List<String> args, boolean inspect, long generation, Callbacks callbacks)
                throws Exception {
            this.generation = generation;
            this.callbacks = callbacks;
            String prefix = inspect ? "jshark-inspect" : "jshark-control";
            UiProcess client = UiProcess.start(buildCommand(args, inspect), prefix, new UiProcess.Events() {
                @Override
                public void onEvent(JSONObject json) {
                    String type = json.getString("type");
                    if (type == null) {
                        return;
                    }
                    switch (type) {
                        case "hello" -> callbacks.onHello(json);
                        case "status" -> callbacks.onStatus(json);
                        case "ack" -> callbacks.onAck(json);
                        case "terminal", "finished", "failed" -> callbacks.onTerminal(json);
                        case "inspect-progress" -> callbacks.onInspectProgress(json);
                        case "inspect-result" -> callbacks.onInspectResult(json);
                        case "inspect-error" -> callbacks.onInspectError(json);
                        default -> callbacks.onLog("[protocol] " + json.toJSONString());
                    }
                }

                @Override
                public void onLog(String line) {
                    callbacks.onLog(line);
                }

                @Override
                public void onExit(int code) {
                    callbacks.onExit(code);
                }
            });
            if (inspect) {
                // inspect 是单向输出，不需要 stdin
                client.closeStdin();
            }
            this.process = client;
        }

        private static List<String> buildCommand(List<String> args, boolean inspect) {
            List<String> cmd = new ArrayList<>(
                    UiLauncher.command(CliReplay.class, "com.jshark.CliReplay", args));
            if (inspect) {
                cmd.add("--inspect");
            } else {
                cmd.add("--control");
                cmd.add("stdio");
            }
            return cmd;
        }

        /**
         * 写一条控制命令。
         *
         * @return 该命令的 id；写失败返回 -1（由进程退出/看门狗兜底）
         */
        long send(String cmd, Map<String, Object> args) {
            try {
                return process.send(cmd, args);
            } catch (Exception e) {
                callbacks.onLog("[control] write failed: " + e.getMessage());
                return -1;
            }
        }

        void stopGracefully() {
            if (process.isClosed()) {
                return;
            }
            try {
                process.send("stop", null);
            } catch (Exception e) {
                callbacks.onLog("[control] write failed: " + e.getMessage());
            }
            Thread killer = new Thread(() -> {
                try {
                    if (!process.process().waitFor(5, TimeUnit.SECONDS)) {
                        process.terminate(1_000);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "jshark-child-killer");
            killer.setDaemon(true);
            killer.start();
        }

        void kill() {
            process.terminate(1_000);
        }

        long generation() {
            return generation;
        }
    }

    // ==================== 自绘播放进度条 ====================

    /**
     * 轻量播放器式进度条：圆角轨道 + 进度 + 圆形拖柄。
     *
     * <p>拖动过程中只回调 {@code adjusting=true} 做预览；松手时才提交 seek。
     * {@link #setFraction(double)} 只重绘、不触发回调，避免 status 回显把用户拖动打断。
     * 拖动期间当前时间也要显示拖动位置而不是回放 playhead（见
     * {@code ReplayMainFrame.seekPreviewActive()}），否则每来一条 status 就会把时间
     * 拉回旧值、下一次鼠标事件又改回目标值，界面看起来一直在抖。</p>
     */
    static final class SeekBar extends JComponent {
        interface Listener {
            void onSeek(double fraction, boolean adjusting);
        }

        private static Color TRACK = new Color(0x39404D);
        private static Color PROGRESS = new Color(0xE0A44A);
        private static Color KNOB = new Color(0xF4C46A);
        private static Color DISABLED = new Color(0x2A303A);

        static void applyTheme(Color track, Color progress, Color knob, Color disabled) {
            TRACK = track;
            PROGRESS = progress;
            KNOB = knob;
            DISABLED = disabled;
        }

        private double fraction;
        private boolean dragging;
        private Listener listener;

        SeekBar() {
            setOpaque(false);
            setPreferredSize(new Dimension(600, 34));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            MouseAdapter mouse = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (!isEnabled()) {
                        return;
                    }
                    dragging = true;
                    updateFromMouse(e.getX(), e.getY(), true);
                }

                @Override
                public void mouseDragged(MouseEvent e) {
                    if (!isEnabled() || !dragging) {
                        return;
                    }
                    updateFromMouse(e.getX(), e.getY(), true);
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    if (!isEnabled() || !dragging) {
                        return;
                    }
                    updateFromMouse(e.getX(), e.getY(), false);
                    dragging = false;
                }
            };
            addMouseListener(mouse);
            addMouseMotionListener(mouse);
        }

        void setListener(Listener listener) {
            this.listener = listener;
        }

                /** @return 用户是否正在拖动（拖动期间不要用 status 回显覆盖拖柄） */
        boolean isDragging() {
            return dragging;
        }

        void setFraction(double fraction) {
            this.fraction = Math.max(0, Math.min(1, fraction));
            repaint();
        }

        @Override
        public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);
            if (!enabled) {
                // 拖动中途被禁用（回放结束/停止）时不会再收到 release：结束拖动态，
                // 否则当前时间和拖柄会永远停在预览值上。
                dragging = false;
            }
            setCursor(enabled
                    ? Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                    : Cursor.getDefaultCursor());
            repaint();
        }

        private void updateFromMouse(int x, int y, boolean adjusting) {
            int left = 16;
            int right = Math.max(left + 1, getWidth() - 16);
            double f = (x - left) / (double) (right - left);
            setFraction(f);
            if (listener != null) {
                listener.onSeek(fraction, adjusting);
            }
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                int left = 16;
                int right = Math.max(left + 1, getWidth() - 16);
                int cy = getHeight() / 2;
                int trackH = 6;
                g2.setColor(isEnabled() ? TRACK : DISABLED);
                g2.fillRoundRect(left, cy - trackH / 2, right - left, trackH,
                        trackH, trackH);
                int filled = (int) Math.round((right - left) * fraction);
                g2.setColor(isEnabled() ? PROGRESS : DISABLED.brighter());
                g2.fillRoundRect(left, cy - trackH / 2, filled, trackH, trackH, trackH);

                int knobR = 8;
                int kx = left + filled;
                g2.setColor(isEnabled() ? KNOB : DISABLED.brighter());
                g2.fillOval(kx - knobR, cy - knobR, knobR * 2, knobR * 2);
                g2.setColor(new Color(0x1E222A));
                g2.setStroke(new BasicStroke(2f));
                g2.drawOval(kx - knobR, cy - knobR, knobR * 2, knobR * 2);
            } finally {
                g2.dispose();
            }
        }
    }

    // ==================== 主窗口 ====================

    static final class ReplayMainFrame extends JFrame {
        private static final DateTimeFormatter TS =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());
        private static final DateTimeFormatter DUR =
                DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.of("UTC"));
        /** 参数区铺满内容时，仍至少留给文件表的高度（像素）。 */
        static final int MIN_FILE_AREA_HEIGHT = 140;
        /**
         * LIVE 跟随模式下目录/文件列表的自动刷新间隔：一分钟。
         *
         * <p>采集端按分钟级分卷（最小 1m），一分钟足够发现新轮转出的最终卷；再密就会
         * 反复扫描目录与分卷。</p>
         */
        static final int LIVE_REFRESH_INTERVAL_MS = 60_000;

        /** 模式下拉框的默认说明；payload-only 数据源会临时换成“frame 不可用”的解释。 */
        private static final String MODE_TOOLTIP =
                "frame = inject the captured L2 frames (same segment only); "
                        + "payload = send the payloads through the OS stack";

        private final ArgForm form;
        private final List<javax.swing.JComponent> paramComponents = new ArrayList<>();

        private final JComboBox<String> sourceType = new JComboBox<>(new String[]{"Database", "PCAP"});
        private final JTextField pathField = new DarkTextField();
        private final JButton browseBtn = new JButton("Browse…");
        private final JButton refreshBtn = new JButton("Refresh");
        private final JComboBox<String> modeBox =
                new JComboBox<>(new DefaultComboBoxModel<>(new String[]{"frame", "payload"}));
        private final JComboBox<String> injectBox = new JComboBox<>();
        private final JLabel injectLabel = new JLabel("Inject interface (frame)");
        private final JLabel dstMacLabel = new JLabel("Destination MAC");
        private final JLabel modeNote = new JLabel();
        private final JTextField dstMacField = new DarkTextField("auto");
        private final DateTimeField startField = new DateTimeField(
                "Absolute capture time, e.g. 2026-08-21 08:10:00; empty = from the data start");
        private final DateTimeField endField = new DateTimeField(
                "Absolute capture time, e.g. 2026-08-21 08:35:00; empty = to the data end");
        private final JTextField sourceIpField = new DarkTextField();
        private final JTextField destIpField = new DarkTextField();
        private final JTextField sourcePortField = new DarkTextField();
        private final JTextField destPortField = new DarkTextField();
        private final JTextField ipProtoField = new DarkTextField();
        private final JTextField appProtoField = new DarkTextField();
        private final JTextField exfilterField = new DarkTextField();
        private final JTextField mapSrcIpField = new DarkTextField("*", 16);
        private final JTextField mapSrcPortField = new DarkTextField("*", 10);
        private final JTextField mapDstIpField = new DarkTextField("*", 16);
        private final JTextField mapDstPortField = new DarkTextField("*", 10);
        private final JComboBox<String> firstFileBox = new JComboBox<>();
        private final JComboBox<String> lastFileBox = new JComboBox<>();
        private final JComboBox<String> themeBox = new JComboBox<>(new String[]{"Dark", "Light"});
        private final JButton resetRangeBtn = new JButton("All files");
        private final JLabel fileRangeLabel = new JLabel("Files: —");
        private JPanel playerPanel;
        private JScrollPane paramsScroll;
        private JSplitPane split;
        private boolean updatingTheme;

        private final JLabel stateLabel = new JLabel("Ready");
        private final JLabel dataRangeLabel = new JLabel("Data range: —");
        private final JLabel dataDurationLabel = new JLabel("Duration: —");
        private final JLabel selectedLabel = new JLabel("Playback range: —");
        private final JLabel inspectLabel = new JLabel("Pick a source to inspect it");
        /** 检查数据源期间的“正在加载”指示：不确定进度时滚动，有分卷计数时显示进度。 */
        private final JProgressBar busyBar = new JProgressBar();
        private final JLabel currentTimeLabel = new JLabel("—");
        private final JLabel totalTimeLabel = new JLabel("—");
        private final JLabel etaLabel = new JLabel("Remaining: —");
        private final JLabel speedActualLabel = new JLabel("Current: —");
        private final JLabel countersLabel = new JLabel("Sent 0 packets · 0 B");
        private final JLabel modeLabel = new JLabel("Mode: —");
        private final SeekBar seekBar = new SeekBar();
        private final JComboBox<String> speedBox = new JComboBox<>(
                new String[]{"0.1", "0.25", "0.5", "1.0", "2.0", "4.0", "8.0", "16.0", "32.0"});
        private final JButton startBtn = new JButton("Start");
        private final JButton pauseBtn = new JButton("Pause");
        private final JButton stopBtn = new JButton("Stop");
        private final JTable fileTable;
        private final DefaultTableModel fileModel;
        private final JTextArea logArea = new JTextArea(10, 100);
        private final ConcurrentLinkedQueue<String> logQueue = new ConcurrentLinkedQueue<>();
        private final Timer logTimer;
        private final Timer inspectDebounce;
        /** LIVE 跟随：每分钟检查目录，把新轮转出的分卷补进文件表并刷新总时长。 */
        private final Timer liveRefreshTimer;
        /** 上次检查时的分卷清单签名；目录没变就不必再次打开所有分卷。 */
        private String lastLiveVolumeSignature;
        /** 窗口已关闭：在途的静默刷新回来时不得再启动计时器或更新已销毁的界面。 */
        private boolean closed;

        private Inspection inspection;
        private UiStatus lastStatus;
        private EngineProcess inspectProcess;
        private EngineProcess replayProcess;
        private Timer inspectTimeout;
        private boolean running;
        private long inspectGeneration;
        /** 用户是否显式选择过模式；未选择时不传 --replayMode，保持 CLI 的默认语义（默认 payload）。 */
        private boolean modeExplicit;
        /**
         * 数据源是 payload 捕获（没有 frameData）时，UI 只能按载荷重放。
         *
         * <p>必须显式把 {@code --replayMode payload} 传给子进程：即便 CLI 默认就是 payload，
         * 显式下发能保证与 UI 展示一致，且不依赖 UI 未来对网卡的填写行为。</p>
         */
        private boolean forcedPayload;
        /** 重建 mode 下拉项时挂起监听，避免程序化改选被当成“用户改了模式”。 */
        private boolean updatingModeBox;
        /** 数据源检查进行中：文件表与顶部会显示加载提示，避免被当成卡死。 */
        private boolean loading;
        private String loadingMessage = "";
        /**
         * 拖动进度条后的 seek 加载态：从命令发出，到子进程报回“新段已开始”（seeking=false）为止。
         *
         * <p>只看 {@code seeking=false} 不够：命令刚发出时仍可能有旧状态在途，会提前收起。
         * 所以还要等子进程对<b>这一条</b> seek 的 ack——它代表命令已被接受，
         * 之后收到的 {@code seeking=false} 才是“新段真的开播了”。</p>
         */
        private boolean seekLoading;
        private boolean seekAccepted;
        private long seekCommandId = -1;
        /** seek 完成判据的基线：新段开始重开那一刻的累计 examined/sent；-1 表示还没取到。 */
        private long seekBaselineExamined = -1;
        private long seekBaselineSent;
        /** seek 加载态覆盖掉的检查摘要，收尾时恢复。 */
        private String inspectLabelBeforeSeek;
        private boolean prefilling;
        /** 本次播放的完整时间范围（来自 inspect + 本地预览，作为 status 缺失时的兜底）。 */
        private Long playbackFrom;
        private Long playbackTo;
        /** 预览：时间参数与数据范围无交集（此时禁止 Start）。 */
        private boolean previewEmpty;
        /** 预览：时间参数能否解析（输入未完成/格式错误时禁止 Start）。 */
        private boolean previewValid = true;
        /** 重放会话代号：Stop→Start 后旧子进程的残留消息必须丢弃。 */
        private long replayGeneration;
        /** 已应用的最大 status.seq：防止乱序/旧快照回退界面。 */
        private long lastStatusSeq;
        /**
         * 回放中每个文件在 Status 列的完成度快照，下标与 {@code inspection.files} 一致。
         *
         * <p>[0,1] 表示画进度条（1 = 已完成）；-1 表示该卷不在所选回放窗口内、或还没轮到，
         * 渲染器沿用静态 Status 文本。整个数组按 playhead 重算：越过某卷就显示完成，
         * 向前拖动 seek 使 playhead 后退时，后面的卷自然回到 -1（未开始）。</p>
         */
        private volatile double[] progressByRow = new double[0];
        /**
         * 是否把文件表的 Status 列画成进度条。
         *
         * <p>发出 start 后置 true；回放进入终态（FINISHED/STOPPED/FAILED）时收起，
         * 恢复静态 Status 文本（例如 "Payload only" / 读取错误说明）。</p>
         */
        private volatile boolean progressVisible = false;
        /** 是否已向子进程发出 start（READY 握手）。 */
        private boolean replayStartSent;
        /**
         * 用户是否按过 Stop。
         *
         * <p>用 Stop 结束的会话不叫“失败”：子进程可能在 5 秒看门狗内没退干净而被强制结束，
         * 退出码会是 1，但那不代表重放逻辑失败。终态文案据此区分 Stopped / Failed。</p>
         */
        private volatile boolean stopRequestedByUser;
        /** 子进程 stderr 里最后一条疑似错误行：进程在发终态前就退出时用它解释 exit code。 */
        private volatile String lastChildError;
        /** 终态消息里的失败原因；优先于 stderr 行（后者带 Java 异常类名，给用户看太吵）。 */
        private volatile String terminalFailureText;
        /** 15 秒内没等到 READY：看门狗杀掉了子进程。 */
        private volatile boolean startTimedOut;
        /** 已经写入日志的 status 告警签名（避免每 250ms 重复刷屏）。 */
        private final java.util.Set<String> loggedStatusWarnings = new java.util.HashSet<>();
        private Timer replayStartWatchdog;
        /** inspect 结果缓存：键为源身份（路径+文件大小+mtime），时间参数变化时不用重新扫描。 */
        private final Map<String, Inspection> inspectionCache = new HashMap<>();
        private String inspectSummaryText = "Pick a source to inspect it";
        private boolean dataSourceDriftLogged;
        /** Guard against combo listeners firing while the file range is being repopulated. */
        private boolean updatingFileRange;
        /** True when the user (or CLI prefill) supplied a Start/End; auto defaults never override it. */
        private boolean startTouched;
        private boolean endTouched;
        /** Guard against the document listeners reacting to programmatic auto-fill. */
        private boolean updatingTimeFields;

        ReplayMainFrame(String[] args) {
            super("JShark Replay");
            applyWindowIcon(this);
            this.form = ArgForm.parse(args);
            this.fileModel = new DefaultTableModel(
                    new Object[]{"File", "Kind", "Start", "End", "Duration", "Size",
                            "Replayable", "Status", "Replay"}, 0) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }
            };
            this.fileTable = new JTable(fileModel) {
                /**
                 * 数据源检查期间文件表是空的：把“正在加载”直接画在表格空白区，
                 * 用户不用去顶部找那一行小字也能看出程序在工作。
                 */
                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    if (loading && getRowCount() == 0) {
                        Graphics2D g2 = (Graphics2D) g.create();
                        try {
                            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                                    RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                            g2.setFont(getFont().deriveFont(Font.BOLD, 13f));
                            g2.setColor(MUTED);
                            String text = loadingMessage.isBlank() ? "Loading…" : loadingMessage;
                            FontMetrics fm = g2.getFontMetrics();
                            int x = Math.max(8, (getWidth() - fm.stringWidth(text)) / 2);
                            int y = Math.max(fm.getAscent() + 8, getHeight() / 2);
                            g2.drawString(text, x, y);
                        } finally {
                            g2.dispose();
                        }
                    }
                }
            };
            this.fileTable.setAutoCreateRowSorter(true);
            // 空表也要铺满视口，否则 paintComponent 拿不到空白区域，加载提示画不出来。
            this.fileTable.setFillsViewportHeight(true);

            this.logTimer = new Timer(200, e -> drainLogs());
            this.inspectDebounce = new Timer(400, e -> startInspect());
            this.inspectDebounce.setRepeats(false);
            this.liveRefreshTimer = new Timer(LIVE_REFRESH_INTERVAL_MS, e -> refreshLiveInspection());
            this.liveRefreshTimer.setRepeats(true);

            buildUi();
            prefill();
            setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    closeUi();
                }
            });

            logTimer.start();

            setMinimumSize(new Dimension(980, 680));
            setSize(1180, 780);
            setLocationRelativeTo(null);

            if (!form.get("db").isBlank() || !form.get("pcap").isBlank()) {
                inspectDebounce.restart();
            }
        }

        // ---------- 构建界面 ----------

        private void buildUi() {
            setLayout(new BorderLayout(8, 8));

            JPanel top = new JPanel();
            top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
            top.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));

            JPanel sourceRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            sourceRow.add(new JLabel("Source"));
            sourceType.setPreferredSize(new Dimension(110, 26));
            sourceRow.add(sourceType);
            pathField.setPreferredSize(new Dimension(520, 26));
            pathField.setDisabledTextColor(MUTED);
            sourceRow.add(pathField);
            sourceRow.add(browseBtn);
            sourceRow.add(refreshBtn);
            sourceRow.add(new JLabel("Mode"));
            sourceRow.add(modeBox);
            top.add(sourceRow);

            modeNote.setForeground(MUTED);
            modeNote.putClientProperty("muted", true);
            modeNote.setFont(modeNote.getFont().deriveFont(Font.PLAIN, 11f));
            JPanel modeNoteRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            modeNoteRow.add(modeNote);
            top.add(modeNoteRow);

            JPanel summary = new JPanel(new FlowLayout(FlowLayout.LEFT, 18, 2));
            summary.add(dataRangeLabel);
            summary.add(dataDurationLabel);
            summary.add(selectedLabel);
            summary.add(modeLabel);
            top.add(summary);

            JPanel inspectRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            inspectRow.add(inspectLabel);
            busyBar.setPreferredSize(new Dimension(140, 12));
            busyBar.setBorderPainted(false);
            busyBar.setBackground(INPUT);
            busyBar.setForeground(ACCENT);
            busyBar.setToolTipText("Reading the selected data source…");
            busyBar.setVisible(false);
            inspectRow.add(busyBar);
            inspectRow.add(Box.createHorizontalStrut(24));
            inspectRow.add(new JLabel("Theme"));
            themeBox.setPreferredSize(new Dimension(86, 26));
            inspectRow.add(themeBox);
            top.add(inspectRow);
            add(top, BorderLayout.NORTH);

            fileTable.setRowHeight(22);
            JPanel filePanel = new JPanel(new BorderLayout(4, 4));
            filePanel.add(buildFileRangeBar(), BorderLayout.NORTH);
            filePanel.add(new JScrollPane(fileTable), BorderLayout.CENTER);

            JScrollPane paramsScroll = new JScrollPane(buildParams());
            paramsScroll.setBorder(null);
            paramsScroll.getVerticalScrollBar().setUnitIncrement(16);

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, paramsScroll, filePanel);
            split.setResizeWeight(0.55);
            split.setContinuousLayout(true);
            split.setDividerSize(6);
            split.setBorder(null);
            // 记下来：窗口可见后要按内容高度校正分隔条，否则参数区最后一行
            // （Target mapping）会落在可视区之外，只能拖动分隔条才看得到。
            this.paramsScroll = paramsScroll;
            this.split = split;

            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Replay", split);
            logArea.setEditable(false);
            logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
            tabs.addTab("Log", new JScrollPane(logArea));
            add(tabs, BorderLayout.CENTER);

            add(buildPlayer(), BorderLayout.SOUTH);

            sourceType.setToolTipText("Replay source: a capture database (DuckDB) or a PCAP file");
            pathField.setToolTipText("Database (.db) or PCAP (.pcap) path to replay; Browse… picks a file");
            modeBox.setToolTipText(MODE_TOOLTIP);
            speedBox.setToolTipText("Replay speed multiplier — an upper bound; adaptive slowdown is always on");
            themeBox.setToolTipText("UI theme; locked while a replay is running");

            speedBox.setEditable(true);
            injectBox.setEditable(true);
            styleCombo(sourceType);
            styleCombo(modeBox);
            styleCombo(speedBox);
            styleCombo(firstFileBox);
            styleCombo(lastFileBox);
            styleCombo(injectBox);
            styleCombo(themeBox);
            paramComponents.add(themeBox);

            sourceType.addActionListener(e -> {
                clearInspection();
                inspectDebounce.restart();
            });
            pathField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    clearInspection();
                    inspectDebounce.restart();
                }

                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    clearInspection();
                    inspectDebounce.restart();
                }

                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                }
            });
            browseBtn.addActionListener(e -> browse());
            refreshBtn.addActionListener(e -> startInspect());
            modeBox.addActionListener(e -> {
                if (updatingModeBox) {
                    // 程序化重建下拉项（帧能力变化）不应被当成用户改模式，否则会再次触发检查。
                    return;
                }
                if (!prefilling) {
                    modeExplicit = true;
                }
                modeLabel.setText("Mode: " + effectiveModeHint());
                applyModeFieldState();
                clearInspection();
                inspectDebounce.restart();
            });
            firstFileBox.addActionListener(e -> onFileRangeChanged(true));
            lastFileBox.addActionListener(e -> onFileRangeChanged(false));
            themeBox.addActionListener(e -> onThemeSelected());
            resetRangeBtn.addActionListener(e -> {
                resetFileRange();
                updateFileRangeView();
                syncTimeFieldsToSelectedRange();
                updatePreview();
            });

            // 时间窗口变化：只重算本地预览，不重新扫描数据源（权威值由 --inspect 给出）。
            startField.getDocument().addDocumentListener(timeListener(true));
            endField.getDocument().addDocumentListener(timeListener(false));

            installFileTableRenderer();

            startBtn.addActionListener(e -> startReplay());
            pauseBtn.addActionListener(e -> togglePause());
            stopBtn.addActionListener(e -> stopReplay());
            pauseBtn.setEnabled(false);
            stopBtn.setEnabled(false);
            seekBar.setEnabled(false);
            seekBar.setListener((fraction, adjusting) -> {
                Long from = timelineFrom();
                Long to = timelineTo();
                if (from == null || to == null || to <= from) {
                    return;
                }
                long target = from + Math.round((to - from) * fraction);
                showSeekTarget(target);
                previewFileProgress(target);
                if (adjusting) {
                    return;
                }
                if (running) {
                    long id = send("seek", Map.of("positionMs", target));
                    beginSeekLoading(target, id);
                } else {
                    applyPreStartPosition(target);
                }
            });
            speedBox.addActionListener(e -> {
                if (running) {
                    try {
                        double speed = Double.parseDouble(speedText());
                        send("set_speed", Map.of("speed", speed));
                    } catch (NumberFormatException ex) {
                        log("[ui] invalid speed: " + speedText());
                    }
                }
            });
        }

        // ---------- 默认布局（参数区不能被裁掉一行） ----------

        /**
         * 窗口一显示就按参数区的内容高度校正分隔条。
         *
         * <p>分隔条没有显式位置时，{@code JSplitPane} 的首次布局只肯给参数区约一半高度：
         * 实测默认 1180×780 下 239px，而内容需要 285px。结果是参数区底部被裁掉、平白多一条
         * 滚动条；字体更大或窗口更小时，连最后一行 {@code Target mapping} 本身都会落在可视区
         * 之外——用户必须先拖动分隔条才知道它存在。这里在“显示”时校正一次，之后用户自己
         * 拖动分隔条的结果会保留下来（只有展开/收起 {@code Filters} 会重新校正，
         * 见 {@link #fitParamsArea()}）。</p>
         */
        @Override
        public void setVisible(boolean visible) {
            super.setVisible(visible);
            if (visible) {
                // 首次布局要等 setVisible 返回后才完成，所以排到 EDT 队列末尾再校正。
                SwingUtilities.invokeLater(this::fitParamsArea);
            }
        }

        /**
         * 把参数区调整到内容真正需要的高度（上限见 {@link #MIN_FILE_AREA_HEIGHT}）。
         *
         * <p>展开/收起 {@code Filters} 时也调用：展开会多出 7 行，能把高度都给它就先给
         * （文件表只保留 {@link #MIN_FILE_AREA_HEIGHT}）；收起后回到内容高度，不留大片空白。</p>
         */
        private void fitParamsArea() {
            if (split == null || paramsScroll == null) {
                return;
            }
            Component content = paramsScroll.getViewport().getView();
            if (content == null) {
                return;
            }
            int target = initialDividerLocation(
                    content.getPreferredSize().height,
                    split.getHeight() - split.getDividerSize(),
                    MIN_FILE_AREA_HEIGHT);
            if (target > 0) {
                split.setDividerLocation(target);
            }
        }

        /**
         * 让参数区完整可见的分隔条位置。
         *
         * @param contentHeight   参数区首选高度
         * @param availableHeight 可分给分隔条的总高度（面板高度减去分隔条自身）
         * @param minBottomHeight 至少留给文件表的高度
         * @return 分隔条位置（即参数区高度）；尚未完成布局时返回 0
         */
        static int initialDividerLocation(int contentHeight, int availableHeight, int minBottomHeight) {
            if (contentHeight <= 0 || availableHeight <= 0) {
                return 0;
            }
            int maxTop = availableHeight - Math.max(0, minBottomHeight);
            return Math.max(0, Math.min(contentHeight, maxTop));
        }

        /** File table colors: capturing amber, errors red, skipped rows muted. */
        private void installFileTableRenderer() {
            fileTable.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(
                        JTable table, Object value, boolean isSelected, boolean hasFocus,
                        int row, int column) {
                    java.awt.Component c = super.getTableCellRendererComponent(
                            table, value, isSelected, hasFocus, row, column);
                    applyFileRowForeground(c, table, table.convertRowIndexToModel(row), isSelected);
                    return c;
                }
            });
            // Status 列：回放进行中，正在播放的那一行显示进度条而不是文本。
            fileTable.getColumnModel().getColumn(STATUS_COL).setCellRenderer(new StatusProgressRenderer());
        }

        /** Status 列索引（列顺序：File Kind Start End Duration Size Replayable Status Replay）。 */
        private static final int STATUS_COL = 7;

        /** Replay 列索引（Yes/No：该卷能否回放）。 */
        private static final int REPLAY_COL = 8;

        /**
         * 文件表的行前景色规则，默认渲染器与 {@link StatusProgressRenderer} 共用。
         *
         * <p>优先级：不可回放（Replay=No）→ 弱化；capturing 卷 → 琥珀色；其余有 Status 文本
         * → 说明性文字（如 "Payload only"）弱化、其余按失败色；否则正常前景色。</p>
         */
        private void applyFileRowForeground(java.awt.Component c, JTable table, int modelRow,
                                            boolean isSelected) {
            if (isSelected) {
                return;
            }
            Object kind = table.getModel().getValueAt(modelRow, 1);
            Object status = table.getModel().getValueAt(modelRow, STATUS_COL);
            Object replay = table.getModel().getValueAt(modelRow, REPLAY_COL);
            if ("No".equals(replay)) {
                c.setForeground(MUTED);
            } else if ("capturing".equals(kind)) {
                c.setForeground(ACCENT);
            } else if (status != null && !String.valueOf(status).isEmpty()) {
                // “Payload only” 是说明而不是错误，别用失败色吓人。
                c.setForeground(informationalStatus(status) ? MUTED : STATE_FAIL);
            } else {
                c.setForeground(FG);
            }
        }

        /**
         * Status 列的渲染器：回放进行中，按 {@link #progressByRow} 画每个文件的完成度。
         *
         * <p>已经越过结束时间的卷显示 100%（"Completed"），当前卷显示百分比；
         * 还没轮到的卷保持文件表统一的状态文本。因为状态由 playhead 整体推导，
         * 向前 seek 后后面的卷会自动回到未开始状态，不会残留旧的完成标记。</p>
         */
        private final class StatusProgressRenderer extends javax.swing.table.DefaultTableCellRenderer {
            private final JProgressBar bar = new JProgressBar(0, 1000);

            StatusProgressRenderer() {
                bar.setStringPainted(true);
                bar.setBorderPainted(false);
                bar.setOpaque(true);
            }

            @Override
            public java.awt.Component getTableCellRendererComponent(
                    JTable table, Object value, boolean isSelected, boolean hasFocus,
                    int row, int column) {
                int modelRow = table.convertRowIndexToModel(row);
                double[] fractions = progressByRow;
                if (progressVisible && modelRow >= 0 && modelRow < fractions.length
                        && fractions[modelRow] >= 0) {
                    double fraction = fractions[modelRow];
                    bar.setValue((int) Math.round(fraction * 1000));
                    bar.setString(fraction >= 1.0
                            ? "Completed"
                            : (int) Math.round(fraction * 100) + "%");
                    // 底色跟随选中状态，避免整行高亮在这一格断开；填充色固定用强调色。
                    bar.setBackground(isSelected ? table.getSelectionBackground() : INPUT);
                    bar.setForeground(ACCENT);
                    bar.setFont(table.getFont());
                    return bar;
                }
                // 其余情况：沿用文件表统一的前景规则（含 "Payload only"、capturing、No 行）。
                java.awt.Component c = super.getTableCellRendererComponent(
                        table, value, isSelected, hasFocus, row, column);
                applyFileRowForeground(c, table, modelRow, isSelected);
                return c;
            }
        }

        private static void styleCombo(JComboBox<?> combo) {
            combo.setForeground(FG);
            combo.setBackground(PANEL);
            combo.setRenderer(new javax.swing.DefaultListCellRenderer() {
                @Override
                public java.awt.Component getListCellRendererComponent(
                        javax.swing.JList<?> list, Object value, int index,
                        boolean isSelected, boolean cellHasFocus) {
                    java.awt.Component c = super.getListCellRendererComponent(
                            list, value, index, isSelected, cellHasFocus);
                    if (!combo.isEnabled()) {
                        c.setForeground(MUTED);
                        c.setBackground(DISABLED_BG);
                    } else if (isSelected) {
                        c.setForeground(Color.WHITE);
                        c.setBackground(SELECTION);
                    } else {
                        c.setForeground(FG);
                        c.setBackground(PANEL);
                    }
                    return c;
                }
            });
            if (combo.isEditable()) {
                java.awt.Component editor = combo.getEditor().getEditorComponent();
                if (editor instanceof JTextField tf) {
                    // 可编辑下拉框的输入区是独立组件：不给它同样的说明，悬停在那里就什么都没有。
                    tf.setToolTipText(combo.getToolTipText());
                    tf.setForeground(FG);
                    tf.setBackground(INPUT);
                    tf.setDisabledTextColor(MUTED);
                    tf.setCaretColor(ACCENT);
                }
            }
        }

        /** File range selector: two selectors define a contiguous replay range. */
        private JPanel buildFileRangeBar() {
            JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            bar.add(fileRangeLabel);
            bar.add(new JLabel("First"));
            firstFileBox.setPreferredSize(new Dimension(260, 26));
            bar.add(firstFileBox);
            bar.add(new JLabel("Last"));
            lastFileBox.setPreferredSize(new Dimension(260, 26));
            bar.add(lastFileBox);
            bar.add(resetRangeBtn);
            firstFileBox.setEnabled(false);
            lastFileBox.setEnabled(false);
            resetRangeBtn.setEnabled(false);
            return bar;
        }

        private JPanel buildParams() {
            JPanel p = new JPanel(new GridBagLayout());
            p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
            int row = 0;
            injectBox.setEditable(true);
            injectBox.setPreferredSize(new Dimension(520, 26));
            populateInjectInterfaces();
            row = addComponentWithHint(p, row, injectLabel, injectBox,
                    "NIC used for raw frame injection; required in frame mode (no auto-detect).",
                    "<html>NIC IP used for raw frame injection. Candidates list the NIC name and its "
                            + "current IPv4.<br>Required for frame mode (no auto-detect); "
                            + "payload mode sends via the kernel stack.</html>");
            row = addComponentWithHint(p, row, dstMacLabel, dstMacField,
                    "preserve | auto | MAC | IP=MAC,… — frame mode only.",
                    "<html>Frame mode only. preserve = keep the captured MAC (same L2 segment).<br>"
                            + "Use auto / an explicit MAC / IP=MAC when the captured MAC is stale or "
                            + "the target moved to another L2 host. Ignored in payload mode.</html>");
            row = addDateTimeField(p, row, "Start (absolute)", startField);
            row = addDateTimeField(p, row, "End (absolute)", endField);

            JPanel filters = new JPanel(new GridBagLayout());
            filters.setOpaque(false);
            filters.setBorder(BorderFactory.createEmptyBorder(2, 12, 4, 12));
            int filterRow = 0;
            filterRow = addFieldTo(filters, filterRow, "Source IP", sourceIpField, 1,
                    "Exact source IP to replay, e.g. 192.168.1.100. Empty = any source.");
            filterRow = addFieldTo(filters, filterRow, "Source port", sourcePortField, 1,
                    "Exact source port to replay, e.g. 3000. Empty = any port.");
            filterRow = addFieldTo(filters, filterRow, "Destination IP", destIpField, 1,
                    "Exact destination IP to replay, e.g. 192.168.1.200. Empty = any destination.");
            filterRow = addFieldTo(filters, filterRow, "Destination port", destPortField, 1,
                    "Exact destination port to replay, e.g. 8200. Empty = any port.");
            filterRow = addFieldTo(filters, filterRow, "IP protocol", ipProtoField, 1,
                    "IP protocol name, e.g. UDP, TCP, ICMPv4, ICMPv6. Empty = any protocol.");
            filterRow = addFieldTo(filters, filterRow, "Application protocol", appProtoField, 1,
                    "Application protocol: DIS, HTTP or PG (anything else is recorded as UNKNOWN). "
                            + "Empty = any protocol.");
            addFieldTo(filters, filterRow, "Expression filter", exfilterField, 1,
                    "<html>Content expression, same syntax as --exfilter,<br>"
                            + "e.g. dis.pdu.type=28 &amp;&amp; dis.exercise.id=17.<br>"
                            + "Empty = no expression filter.</html>");
            row = addCollapsible(p, row, "Filters", filters,
                    "Show or hide the replay filters: source/destination IP and port, "
                            + "IP and application protocol, expression filter.");

            row = addMappingEditor(p, row);

            paramComponents.add(sourceType);
            paramComponents.add(pathField);
            paramComponents.add(browseBtn);
            paramComponents.add(refreshBtn);
            paramComponents.add(modeBox);
            return p;
        }

        /**
         * 加一行“标签 + 输入控件”，并在下面加一行灰色说明。
         *
         * <p>说明行只放一句摘要（默认窗口里参数区要能整块显示，说明行太长会把
         * {@code Target mapping} 挤出可视区）；完整说明放在控件的 tooltip 上。</p>
         */
        private int addComponentWithHint(JPanel p, int row, JLabel label,
                                         javax.swing.JComponent field, String hint, String tooltip) {
            p.add(label, gbc(0, row));
            GridBagConstraints c = gbc(1, row++);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            c.gridwidth = 3;
            p.add(field, c);
            paramComponents.add(field);
            JLabel hintLabel = new JLabel(hint);
            hintLabel.setForeground(MUTED);
            hintLabel.putClientProperty("muted", true);
            hintLabel.setFont(hintLabel.getFont().deriveFont(Font.PLAIN, 11f));
            hintLabel.setToolTipText(tooltip);
            GridBagConstraints hc = gbc(1, row++);
            hc.fill = GridBagConstraints.HORIZONTAL;
            hc.weightx = 1;
            hc.gridwidth = 3;
            hc.insets = new Insets(0, 6, 6, 4);
            p.add(hintLabel, hc);
            if (tooltip != null) {
                field.setToolTipText(tooltip);
            }
            return row;
        }

        private int addMappingEditor(JPanel p, int row) {
            JLabel label = new JLabel("Target mapping");
            GridBagConstraints lc = gbc(0, row);
            lc.anchor = GridBagConstraints.NORTHWEST;
            p.add(label, lc);

            JPanel editor = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            editor.setOpaque(false);
            mapSrcIpField.setColumns(16);
            mapSrcPortField.setColumns(10);
            mapDstIpField.setColumns(16);
            mapDstPortField.setColumns(10);
            mapSrcIpField.setDisabledTextColor(MUTED);
            mapSrcPortField.setDisabledTextColor(MUTED);
            mapDstIpField.setDisabledTextColor(MUTED);
            mapDstPortField.setDisabledTextColor(MUTED);
            mapSrcIpField.setToolTipText("* = any source IP; comma-separated values build several rules");
            mapSrcPortField.setToolTipText("* = any source port; comma-separated values build several rules");
            mapDstIpField.setToolTipText("New destination IP; * = keep the captured one");
            mapDstPortField.setToolTipText("New destination port; * = keep the captured one");
            editor.add(new JLabel("Source IP"));
            editor.add(mapSrcIpField);
            editor.add(new JLabel("Source port"));
            editor.add(mapSrcPortField);
            editor.add(new JLabel("→"));
            editor.add(new JLabel("Destination IP"));
            editor.add(mapDstIpField);
            editor.add(new JLabel("Destination port"));
            editor.add(mapDstPortField);

            GridBagConstraints ec = gbc(1, row++);
            ec.fill = GridBagConstraints.HORIZONTAL;
            ec.weightx = 1;
            ec.gridwidth = 3;
            p.add(editor, ec);

            JLabel hint = new JLabel("<html>"
                    + "Map matching source <b>IP:port</b> to the new destination <b>IP:port</b>. "
                    + "Use <b>*</b> as wildcard; the default <b>*</b> means no change.<br>"
                    + "For multiple rules, put comma-separated values in each column; "
                    + "the Nth value in every column forms one rule."
                    + "</html>");
            hint.setForeground(MUTED);
            hint.putClientProperty("muted", true);
            hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 11f));
            GridBagConstraints hc = gbc(1, row++);
            hc.fill = GridBagConstraints.HORIZONTAL;
            hc.weightx = 1;
            hc.gridwidth = 3;
            hc.insets = new Insets(0, 6, 6, 4);
            p.add(hint, hc);

            paramComponents.add(mapSrcIpField);
            paramComponents.add(mapSrcPortField);
            paramComponents.add(mapDstIpField);
            paramComponents.add(mapDstPortField);
            return row;
        }

        private int addCollapsible(JPanel p, int row, String title, JPanel content, String tooltip) {
            CollapsibleSection section = new CollapsibleSection(title, content);
            section.toggleButton().setToolTipText(tooltip);
            paramComponents.add(section.toggleButton());
            // 展开后的内容高出上百像素：顺手把参数区放开，否则展开的过滤器几乎全要滚动才看得到。
            section.addPropertyChangeListener("expanded",
                    e -> SwingUtilities.invokeLater(this::fitParamsArea));
            GridBagConstraints c = gbc(0, row++);
            c.gridwidth = 4;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            c.insets = new Insets(8, 4, 3, 4);
            p.add(section, c);
            return row;
        }

                /**
         * 加一行“标签 + 输入框”。
         *
         * @param tooltip 悬停说明；同时挂在标签与输入框上（用户可能从任一处开始悬停）
         */
        private int addFieldTo(JPanel p, int row, String label, JTextField field,
                               int gridWidth, String tooltip) {
            JLabel fieldLabel = new JLabel(label);
            if (tooltip != null) {
                fieldLabel.setToolTipText(tooltip);
                field.setToolTipText(tooltip);
            }
            p.add(fieldLabel, gbc(0, row));
            GridBagConstraints c = gbc(1, row++);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            c.gridwidth = gridWidth;
            field.setColumns(gridWidth > 1 ? 40 : 24);
            field.setDisabledTextColor(MUTED);
            p.add(field, c);
            paramComponents.add(field);
            return row;
        }

        private int addDateTimeField(JPanel p, int row, String label, DateTimeField field) {
            p.add(new JLabel(label), gbc(0, row));
            GridBagConstraints c = gbc(1, row++);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            c.gridwidth = 3;
            p.add(field, c);
            paramComponents.add(field);
            return row;
        }

        /**
         * A section header that expands/collapses its content. Used to keep the filter fields
         * (source/destination/protocol/expression) together without taking over the whole panel.
         */
        static final class CollapsibleSection extends JPanel {
            private final String title;
            private final JPanel content;
            private final JButton toggle;
            private boolean expanded;

            CollapsibleSection(String title, JPanel content) {
                super(new BorderLayout());
                this.title = title;
                this.content = content;
                this.expanded = false;
                setOpaque(false);
                content.setVisible(false);
                toggle = new JButton();
                toggle.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
                toggle.setFont(toggle.getFont().deriveFont(Font.BOLD, 13f));
                toggle.setBackground(PANEL);
                toggle.setForeground(FG);
                toggle.setBorder(BorderFactory.createLineBorder(BORDER));
                toggle.addActionListener(e -> setExpanded(!expanded));
                add(toggle, BorderLayout.NORTH);
                add(content, BorderLayout.CENTER);
                updateToggleText();
            }

            JButton toggleButton() {
                return toggle;
            }

            void refreshTheme() {
                toggle.setBackground(PANEL);
                toggle.setForeground(FG);
                toggle.setBorder(BorderFactory.createLineBorder(BORDER));
            }

            void setExpanded(boolean expanded) {
                boolean wasExpanded = this.expanded;
                this.expanded = expanded;
                content.setVisible(expanded);
                updateToggleText();
                revalidate();
                repaint();
                java.awt.Container parent = getParent();
                if (parent != null) {
                    parent.revalidate();
                    parent.repaint();
                }
                firePropertyChange("expanded", wasExpanded, expanded);
            }

            private void updateToggleText() {
                toggle.setText((expanded ? "\u25BE " : "\u25B8 ") + title);
            }
        }

                private JPanel buildPlayer() {
            JPanel south = new JPanel(new BorderLayout(4, 4));
            playerPanel = south;
            south.setBackground(PLAYER_BG);
            south.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));

            currentTimeLabel.setFont(new Font("Dialog", Font.BOLD, 18));
            currentTimeLabel.setForeground(ACCENT);
            etaLabel.setForeground(MUTED);
            etaLabel.putClientProperty("muted", true);
            totalTimeLabel.setForeground(MUTED);
            totalTimeLabel.putClientProperty("muted", true);
            stateLabel.setFont(new Font("Dialog", Font.BOLD, 13));

            etaLabel.setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 16));
            JPanel times = new JPanel(new BorderLayout());
            times.setOpaque(false);
            times.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            times.add(currentTimeLabel, BorderLayout.WEST);
            times.add(etaLabel, BorderLayout.CENTER);
            times.add(totalTimeLabel, BorderLayout.EAST);
            south.add(times, BorderLayout.NORTH);

            seekBar.setPreferredSize(new Dimension(600, 34));
            south.add(seekBar, BorderLayout.CENTER);

            JPanel transport = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            transport.setOpaque(false);
            for (JButton b : new JButton[]{startBtn, pauseBtn, stopBtn}) {
                // 逻辑字体 Dialog 会做 CJK 回退；指定 Segoe UI 时中文会变成方框。
                b.setFont(new Font("Dialog", Font.BOLD, 14));
                b.setPreferredSize(new Dimension(110, 34));
            }
            startBtn.setForeground(ON_ACCENT);
            startBtn.setBackground(ACCENT);
            transport.add(startBtn);
            transport.add(pauseBtn);
            transport.add(stopBtn);
            transport.add(Box.createHorizontalStrut(20));
            transport.add(new JLabel("Speed"));
            speedBox.setPreferredSize(new Dimension(80, 26));
            speedBox.setSelectedItem("1.0");
            transport.add(speedBox);
            transport.add(speedActualLabel);
            transport.add(countersLabel);
            transport.add(Box.createHorizontalStrut(20));
            transport.add(stateLabel);
            south.add(transport, BorderLayout.SOUTH);
            return south;
        }

        private void prefill() {
            prefilling = true;
            String db = form.get("db");
            String pcap = form.get("pcap");
            if (!pcap.isBlank()) {
                sourceType.setSelectedItem("PCAP");
                pathField.setText(pcap);
            } else if (!db.isBlank()) {
                sourceType.setSelectedItem("Database");
                pathField.setText(db);
            }
            modeBox.setSelectedItem(form.get("replayMode").isBlank() ? "payload" : form.get("replayMode"));
            applyModeFieldState();
            injectBox.setEditable(true);
            setInjectText(form.get("injectInterface"));
            dstMacField.setText(form.get("dstMac").isBlank() ? "auto" : form.get("dstMac"));
            startField.setText(form.get("start"));
            endField.setText(form.get("end"));
            startTouched = !form.get("start").isBlank();
            endTouched = !form.get("end").isBlank();
            sourceIpField.setText(form.get("sourceIp"));
            destIpField.setText(form.get("destinationIp"));
            sourcePortField.setText(form.get("sourcePort"));
            destPortField.setText(form.get("destinationPort"));
            ipProtoField.setText(form.get("ipProtocol"));
            appProtoField.setText(form.get("applicationProtocol"));
            exfilterField.setText(form.get("exfilter"));
            prefillTargetMapping(form.get("replayTargetMapping"));
            speedBox.setSelectedItem(form.get("speed").isBlank() ? "1.0" : form.get("speed"));
            modeExplicit = !form.get("replayMode").isBlank();
            themeBox.setSelectedItem(darkTheme ? "Dark" : "Light");
            modeLabel.setText("Mode: " + effectiveModeHint());
            prefilling = false;
        }

        private void prefillTargetMapping(String mapping) {
            if (mapping == null || mapping.isBlank()) {
                resetTargetMappingFields();
                return;
            }
            String[] fields = targetMappingFields(mapping);
            if (fields[0].isEmpty() && fields[1].isEmpty()
                    && fields[2].isEmpty() && fields[3].isEmpty()) {
                log("[ui] ignored invalid --replayTargetMapping: " + mapping);
                resetTargetMappingFields();
                return;
            }
            mapSrcIpField.setText(fields[0]);
            mapSrcPortField.setText(fields[1]);
            mapDstIpField.setText(fields[2]);
            mapDstPortField.setText(fields[3]);
        }

        private void resetTargetMappingFields() {
            mapSrcIpField.setText("*");
            mapSrcPortField.setText("*");
            mapDstIpField.setText("*");
            mapDstPortField.setText("*");
        }

        private boolean isFrameMode() {
            return !"payload".equals(modeBox.getSelectedItem());
        }

        /**
         * Start 之前的帧模式预检，避免拉起一个注定失败的子进程。
         *
         * <p>两个现实问题：</p>
         * <ol>
         *   <li>帧模式必须有注入网卡；空着直接 Start 只会让子进程在参数校验处退出（exit 1）。</li>
         *   <li>网卡列表只在界面启动时枚举过一次。笔记本换网/重连后 IP 会变，下拉里留着旧 IP，
         *       子进程就会报 “No network interface has IP …”。这里在 Start 前重新枚举一次：
         *       如果用户之前是从列表里选的条目而现在已不存在，就刷新列表并让用户重选。</li>
         * </ol>
         *
         * @return true 表示可以继续 Start
         */
        private boolean preflightFrameStart() {
            if (!isFrameMode()) {
                return true;
            }
            String ip = injectIp();
            if (ip.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Frame replay requires an injection interface.\n"
                                + "Pick the NIC whose IP is shown in “Inject interface (frame)”.\n"
                                + "The NIC must be usable by Npcap and JShark must run as Administrator.",
                        "JShark Replay", JOptionPane.WARNING_MESSAGE);
                return false;
            }

            String previous = injectText();
            populateInjectInterfaces();
            boolean wasPickedFromList = previous != null && previous.contains("(");
            if (wasPickedFromList && !injectCandidateExists(ip)) {
                if (injectBox.getItemCount() > 0) {
                    setInjectText(injectBox.getItemAt(0));
                }
                log("[ui] injection interface disappeared: " + previous + "; refreshed the interface list");
                JOptionPane.showMessageDialog(this,
                        "The selected injection interface is no longer available:\n  " + previous + "\n\n"
                                + "The list has been refreshed (network changed?). Pick the interface to inject from "
                                + "and press Start again.",
                        "JShark Replay", JOptionPane.WARNING_MESSAGE);
                return false;
            }
            // 用户手输的 IP 不要求在 Java 的网卡列表里（可能只是名字/可见性不同），保留原值。
            setInjectText(previous);
            return true;
        }

        /** @return 当前网卡下拉中是否存在以该 IP 开头的候选条目 */
        private boolean injectCandidateExists(String ip) {
            for (int i = 0; i < injectBox.getItemCount(); i++) {
                String item = injectBox.getItemAt(i);
                if (item != null && item.startsWith(ip + " ")) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Fill the inject-interface candidates with "IPv4 (NIC name)" entries.
         * Only up, non-loopback interfaces with an IPv4 address are listed.
         */
        private void populateInjectInterfaces() {
            injectBox.removeAllItems();
            for (String item : injectCandidates()) {
                injectBox.addItem(item);
            }
        }

        static List<String> injectCandidates() {
            List<String> items = new ArrayList<>();
            try {
                Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
                while (interfaces != null && interfaces.hasMoreElements()) {
                    NetworkInterface ni = interfaces.nextElement();
                    if (!ni.isUp() || ni.isLoopback()) {
                        continue;
                    }
                    String name = ni.getDisplayName();
                    if (name == null || name.isBlank()) {
                        name = ni.getName();
                    }
                    for (InterfaceAddress address : ni.getInterfaceAddresses()) {
                        InetAddress ip = address.getAddress();
                        if (ip instanceof Inet4Address) {
                            String item = ip.getHostAddress() + "  (" + name + ")";
                            if (!items.contains(item)) {
                                items.add(item);
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
                // Enumeration can fail on unusual platforms; the combo stays editable.
            }
            Collections.sort(items, String.CASE_INSENSITIVE_ORDER);
            return items;
        }

        private String injectText() {
            Object item = injectBox.isEditable()
                    ? injectBox.getEditor().getItem()
                    : injectBox.getSelectedItem();
            return item == null ? "" : item.toString().trim();
        }

        /** Extract the IP from an "IP  (NIC name)" candidate (or accept a typed IP). */
        private String injectIp() {
            return ipFromInjectText(injectText());
        }

        static String ipFromInjectText(String text) {
            if (text == null || text.trim().isEmpty()) {
                return "";
            }
            String value = text.trim();
            int space = value.indexOf(' ');
            return (space > 0 ? value.substring(0, space) : value).trim();
        }

        private void setInjectText(String ip) {
            String value = ip == null ? "" : ip.trim();
            if (value.isEmpty()) {
                // Default to the first detected NIC (IP + name); keep editable if none.
                if (injectBox.getItemCount() > 0) {
                    injectBox.setSelectedIndex(0);
                } else {
                    injectBox.getEditor().setItem("");
                }
                return;
            }
            for (int i = 0; i < injectBox.getItemCount(); i++) {
                String item = injectBox.getItemAt(i);
                if (item != null && (item.equals(value) || item.startsWith(value + " "))) {
                    injectBox.setSelectedItem(item);
                    return;
                }
            }
            injectBox.getEditor().setItem(value);
        }

        /**
         * Inject interface and destination MAC only apply to frame replay. In payload mode the
         * kernel stack builds the L2 header, so both fields are greyed out.
         */
        private void applyModeFieldState() {
            boolean editable = !running;
            boolean frame = isFrameMode();
            injectBox.setEnabled(editable && frame);
            dstMacField.setEnabled(editable && frame);
            injectLabel.setForeground(frame ? FG : MUTED);
            dstMacLabel.setForeground(frame ? FG : MUTED);
            if (frame) {
                modeNote.setText("frame: injects raw L2 frames — the target must be on the same L2 segment; "
                        + "use payload for routed targets.");
            } else if (forcedPayload) {
                modeNote.setText("payload: sends via the OS stack; this database stores no frame data "
                        + "(payload-only capture), so frame replay is unavailable.");
            } else {
                modeNote.setText("payload: sends via the OS stack — works across routers; "
                        + "source ports/TTL/seq are regenerated.");
            }
        }

        private String effectiveModeHint() {
            String mode = String.valueOf(modeBox.getSelectedItem());
            if ("payload".equals(mode)) {
                return forcedPayload
                        ? "payload (payload-level; no frames in this database)"
                        : "payload (payload-level)";
            }
            return injectIp().isBlank()
                    ? "frame (frame injection; inject interface required)"
                    : "frame (frame injection)";
        }

        // ---------- inspect ----------

        private void browse() {
            JFileChooser chooser = new JFileChooser();
            String current = pathField.getText().trim();
            if (!current.isEmpty()) {
                chooser.setSelectedFile(new File(current));
            }
            int rc = chooser.showOpenDialog(this);
            if (rc == JFileChooser.APPROVE_OPTION) {
                File picked = chooser.getSelectedFile();
                pathField.setText(picked.getAbsolutePath());
                // 选完文件立刻给反馈：防抖的 400ms + 子进程启动/扫描期间，界面不能看起来没反应。
                showLoading("Loading " + picked.getName() + "…");
            }
        }

        private List<String> buildReplayArgs() {
            List<String> args = new ArrayList<>();
            String path = pathField.getText().trim();
            if (path.isEmpty()) {
                return args;
            }
            if ("PCAP".equals(sourceType.getSelectedItem())) {
                args.add("--pcap");
            } else {
                args.add("--db");
            }
            args.add(path);
            args.addAll(replayModeArgs(modeExplicit, forcedPayload,
                    String.valueOf(modeBox.getSelectedItem())));
            args.add("--speed");
            args.add(speedText());
            if (isFrameMode()) {
                addIf(args, "--injectInterface", injectIp());
                addIf(args, "--dstMac", dstMacField.getText());
            }
            addIf(args, "--start", startTouched ? startField.getText() : "");
            addIf(args, "--end", endTouched ? endField.getText() : "");
            addIf(args, "--sourceIp", sourceIpField.getText());
            addIf(args, "--destinationIp", destIpField.getText());
            addIf(args, "--sourcePort", sourcePortField.getText());
            addIf(args, "--destinationPort", destPortField.getText());
            addIf(args, "--ipProtocol", ipProtoField.getText());
            addIf(args, "--applicationProtocol", appProtoField.getText());
            addIf(args, "--exfilter", exfilterField.getText());
            addIf(args, "--replayTargetMapping", composeTargetMapping(
                    mapSrcIpField.getText(), mapSrcPortField.getText(),
                    mapDstIpField.getText(), mapDstPortField.getText()));
            return args;
        }

        private String speedText() {
            if (speedBox.isEditable()) {
                Object editorValue = speedBox.getEditor().getItem();
                if (editorValue != null && !String.valueOf(editorValue).isBlank()) {
                    return String.valueOf(editorValue).trim();
                }
            }
            return String.valueOf(speedBox.getSelectedItem()).trim();
        }

        private static void addIf(List<String> args, String name, String value) {
            if (value != null && !value.trim().isEmpty()) {
                args.add(name);
                args.add(value.trim());
            }
        }

        /**
         * 是否要向下游传 {@code --replayMode}，以及传什么。
         *
         * <p>三种情况：</p>
         * <ul>
         *   <li>数据源强制 payload（没有 frameData）：必须显式传 payload，保证与 UI 展示一致。</li>
         *   <li>用户显式选过模式：按用户选择传。</li>
         *   <li>都没发生：不传，保持 CLI 的默认语义（默认 payload）。</li>
         * </ul>
         *
         * @param modeExplicit  用户是否显式选过模式
         * @param forcedPayload 数据源是否只支持 payload 重放
         * @param selected      下拉框当前值
         * @return 要追加的参数（可能为空）
         */
        static List<String> replayModeArgs(boolean modeExplicit, boolean forcedPayload, String selected) {
            if (forcedPayload) {
                return List.of("--replayMode", "payload");
            }
            if (modeExplicit && selected != null && !selected.isBlank()) {
                return List.of("--replayMode", selected);
            }
            return List.of();
        }

        private void startInspect() {
            startInspect(false);
        }

        /**
         * Start a read-only inspection of the selected source.
         *
         * @param quiet true for the periodic LIVE refresh: keep the current table, selection and
         *              player state on screen, don't show the loading overlay and don't refuse to
         *              run just because a replay is currently following new volumes
         */
        private void startInspect(boolean quiet) {
            if (running && !quiet) {
                return;
            }
            String path = pathField.getText().trim();
            if (path.isEmpty()) {
                if (quiet) {
                    return;
                }
                clearInspection();
                inspectLabel.setText("Pick a source first");
                return;
            }
            if (!sourceExists(path)) {
                // 路径可能还在输入中：不为必然失败的检查 spawn 一个 JVM。
                if (quiet) {
                    log("[live] source disappeared; keeping the current file list");
                    return;
                }
                clearInspection();
                inspectLabel.setText("Source not found: " + path);
                return;
            }
            String cacheKey = inspectionKey();
            Inspection cached = inspectionCache.get(cacheKey);
            if (!quiet) {
                // 手动检查期间暂停 LIVE 轮询；检查结果应用后由 applyInspection() 重新启动。
                liveRefreshTimer.stop();
            }
            if (cached != null) {
                lastLiveVolumeSignature = liveVolumeSignature();
                if (quiet) {
                    if (cached != inspection) {
                        FileRangeSnapshot selection = captureFileRange();
                        inspection = cached;
                        applyInspection(true, selection);
                        inspectSummaryText = inspectSummary(inspection);
                        if (!seekLoading) {
                            inspectLabel.setText(inspectSummaryText);
                        }
                    }
                    return;
                }
                ++inspectGeneration;   // 作废在途的旧检查结果
                if (inspectProcess != null) {
                    inspectProcess.kill();
                    inspectProcess = null;
                }
                if (inspectTimeout != null) {
                    inspectTimeout.stop();
                    inspectTimeout = null;
                }
                inspection = cached;
                hideLoading();
                applyInspection();
                inspectSummaryText = inspectSummary(inspection);
                inspectLabel.setText(inspectSummaryText + " (cached)");
                return;
            }
            long generation = ++inspectGeneration;
            if (inspectProcess != null) {
                inspectProcess.kill();
                inspectProcess = null;
            }
            if (inspectTimeout != null) {
                inspectTimeout.stop();
            }
            if (!quiet) {
                inspection = null;
                startBtn.setEnabled(false);
                showLoading("Loading " + new File(path).getName() + "…");
            }
            List<String> args;
            try {
                args = buildReplayArgs();
            } catch (Exception e) {
                if (quiet) {
                    log("[live] refresh skipped: invalid parameters: " + e.getMessage());
                    return;
                }
                hideLoading();
                inspectLabel.setText("Invalid parameters: " + e.getMessage());
                return;
            }
            try {
                // 记录“发起检查时”的目录签名：若扫描期间又有新卷落地，结果可能漏掉它，
                // 下次计时比较仍会不同，从而再刷新一次，不会把新文件永久漏掉。
                String requestedSignature = liveVolumeSignature();
                inspectProcess = EngineProcess.inspect(args, new Callbacks() {
                    @Override
                    public void onInspectProgress(JSONObject json) {
                        if (quiet) {
                            return;   // 静默刷新：不要用加载进度条盖住当前文件表
                        }
                        SwingUtilities.invokeLater(() -> {
                            if (generation != inspectGeneration) {
                                return;
                            }
                            JSONObject p = json;
                            int cur = p.getIntValue("current");
                            int total = p.getIntValue("total");
                            long packets = p.getLongValue("packets");
                            updateLoading(cur, total, packets);
                        });
                    }

                    @Override
                    public void onInspectResult(JSONObject json) {
                        SwingUtilities.invokeLater(() -> {
                            if (generation != inspectGeneration || closed) {
                                return;
                            }
                            if (!quiet) {
                                hideLoading();
                            }
                            FileRangeSnapshot selection = quiet ? captureFileRange() : null;
                            inspection = Inspection.from(json);
                            lastLiveVolumeSignature = requestedSignature;
                            inspectionCache.put(cacheKey, inspection);
                            if (inspectionCache.size() > 16) {
                                inspectionCache.clear();
                            }
                            applyInspection(quiet, selection);
                            if (inspectTimeout != null) {
                                inspectTimeout.stop();
                                inspectTimeout = null;
                            }
                            inspectProcess = null;
                            inspectSummaryText = inspectSummary(inspection);
                            if (!seekLoading) {
                                inspectLabel.setText(inspectSummaryText);
                            }
                            if (quiet) {
                                log("[live] refreshed file list: "
                                        + inspection.replayableCount + " replayable file(s)");
                            }
                        });
                    }

                    @Override
                    public void onInspectError(JSONObject json) {
                        SwingUtilities.invokeLater(() -> {
                            if (generation != inspectGeneration) {
                                return;
                            }
                            if (inspectTimeout != null) {
                                inspectTimeout.stop();
                                inspectTimeout = null;
                            }
                            inspectProcess = null;
                            JSONObject err = json.getJSONObject("error");
                            String message = err == null
                                    ? json.getString("message") : err.getString("message");
                            if (quiet) {
                                // 静默刷新失败时保留上一份可用结果，不把文件表清空。
                                log("[live] refresh failed: " + message);
                                return;
                            }
                            hideLoading();
                            inspection = null;
                            startBtn.setEnabled(false);
                            inspectLabel.setText("Inspect failed: " + message);
                            log("[inspect] " + json);
                        });
                    }

                    @Override
                    public void onLog(String line) {
                        log("[inspect] " + line);
                    }

                    @Override
                    public void onExit(int code) {
                        SwingUtilities.invokeLater(() -> {
                            if (generation != inspectGeneration) {
                                return;
                            }
                            if (inspection == null && inspectProcess != null) {
                                inspectProcess = null;
                                if (quiet) {
                                    log("[live] refresh exited early (" + code + "); keeping the current file list");
                                    return;
                                }
                                hideLoading();
                                inspectLabel.setText("Inspect failed (exit " + code + "); see the log");
                                startBtn.setEnabled(false);
                            }
                        });
                    }
                }, generation);
                inspectTimeout = new Timer(120_000, e -> {
                    if (inspectProcess != null) {
                        inspectProcess.kill();
                        inspectProcess = null;
                        if (quiet) {
                            log("[live] refresh timed out; keeping the current file list");
                        } else {
                            hideLoading();
                            inspectLabel.setText("Inspect timed out");
                        }
                    }
                });
                inspectTimeout.setRepeats(false);
                inspectTimeout.start();
            } catch (Exception e) {
                if (!quiet) {
                    hideLoading();
                    inspectLabel.setText("Inspect failed: " + e.getMessage());
                }
                log("[inspect] " + e);
            }
        }

        /**
         * Periodic LIVE refresh: re-scan the directory, append newly rotated volumes to the
         * file table and refresh the data range/duration.
         *
         * <p>Only applies while the source supports rolling follow (split DB + payload) and the
         * user has not set an End: an explicit End deliberately freezes the replay window, so
         * refreshing new files would not change what is replayed.</p>
         */
        private void refreshLiveInspection() {
            if (closed || inspection == null || inspectProcess != null || loading) {
                return;
            }
            if (!liveAutoRefreshEligible(inspection.live, inspection.followSupported,
                    endField.getText())) {
                updateLiveRefreshTimer();
                return;
            }
            String signature = liveVolumeSignature();
            if (signature != null && signature.equals(lastLiveVolumeSignature)) {
                // 目录里没有新增/轮转出的分卷：已关闭卷不可变，没必要反复打开它们。
                return;
            }
            startInspect(true);
        }

        /**
         * Whether the LIVE file list should poll the directory: the source is live (or supports
         * rolling follow) and the user has left End empty (an explicit End freezes the replay
         * window).
         *
         * @param live            a {@code -capturing} volume currently exists
         * @param followSupported source supports rolling follow (split DB + payload)
         * @param endText         current End field text
         * @return true if the per-minute refresh should run
         */
        static boolean liveAutoRefreshEligible(boolean live, boolean followSupported,
                                               String endText) {
            return (live || followSupported) && (endText == null || endText.trim().isEmpty());
        }

        /** Start/stop the LIVE refresh timer to match the current source and End state. */
        private void updateLiveRefreshTimer() {
            if (closed) {
                liveRefreshTimer.stop();
                return;
            }
            boolean eligible = inspection != null
                    && liveAutoRefreshEligible(inspection.live, inspection.followSupported,
                            endField.getText());
            if (eligible) {
                if (!liveRefreshTimer.isRunning()) {
                    liveRefreshTimer.start();
                }
            } else {
                liveRefreshTimer.stop();
            }
        }

        /**
         * Directory signature used to decide whether a LIVE refresh can be skipped.
         *
         * <p>All volume names participate (so a new {@code -capturing} file triggers a refresh),
         * but only closed volumes contribute size/mtime: closed volumes are immutable, while a
         * capturing file grows continuously and must not cause a full re-scan every minute.</p>
         */
        private String liveVolumeSignature() {
            if (!"db".equals(sourceKind())) {
                return null;
            }
            String path = pathField.getText().trim();
            if (path.isEmpty()) {
                return null;
            }
            List<String> files;
            try {
                files = new ArrayList<>(SplitUtil.discoverAllSplitStyle(path));
            } catch (RuntimeException e) {
                return null;
            }
            Collections.sort(files);
            StringBuilder key = new StringBuilder();
            for (String f : files) {
                File file = new File(f);
                key.append('|').append(file.getName());
                if (!SplitUtil.isInProgressCaptureVolume(f)) {
                    key.append(':').append(file.length())
                            .append(':').append(file.lastModified());
                }
            }
            return key.toString();
        }

        private void clearInspection() {
            // 源已改变：作废在途的检查（包括静默 LIVE 刷新），避免旧结果回来又把表填上。
            ++inspectGeneration;
            if (inspectProcess != null) {
                inspectProcess.kill();
                inspectProcess = null;
            }
            if (inspectTimeout != null) {
                inspectTimeout.stop();
                inspectTimeout = null;
            }
            inspection = null;
            liveRefreshTimer.stop();
            lastLiveVolumeSignature = null;
            startBtn.setEnabled(false);
            fileModel.setRowCount(0);
            dataRangeLabel.setText("Data range: —");
            dataDurationLabel.setText("Duration: —");
            selectedLabel.setText("Playback range: —");
            updatingFileRange = true;
            firstFileBox.removeAllItems();
            lastFileBox.removeAllItems();
            firstFileBox.setEnabled(false);
            lastFileBox.setEnabled(false);
            resetRangeBtn.setEnabled(false);
            fileRangeLabel.setText("Files: —");
            updatingFileRange = false;
            updatingTimeFields = true;
            startField.setText("");
            endField.setText("");
            updatingTimeFields = false;
            startTouched = false;
            endTouched = false;
            previewEmpty = false;
            previewValid = true;
            playbackFrom = null;
            playbackTo = null;
            lastStatus = null;
            seekBar.setEnabled(false);
            // 源未知时不能保留上一条源的“只能 payload”结论：把 frame 选项还回去。
            hideLoading();
            applyModeAvailability(null);
        }

        // ---------- 加载指示 ----------

        /**
         * 进入“正在加载”状态：顶部进度条滚动 + 文件表空白区显示提示。
         *
         * <p>数据源检查在子进程里做，UI 本身不会卡；但检查期间文件表是空的、Start 是灰的，
         * 看起来和“卡死”没有区别。这里给一个明确的加载态，长扫描时用户也知道它在干活。</p>
         *
         * <p>包内可见：回归测试要断言“加载时确实有可见的加载指示”。</p>
         *
         * @param message 例如 {@code Loading capture.db…}
         */
        void showLoading(String message) {
            loading = true;
            loadingMessage = message;
            busyBar.setIndeterminate(true);
            busyBar.setValue(0);
            busyBar.setVisible(true);
            inspectLabel.setText(message);
            fileTable.repaint();
        }

        /**
         * 有分卷级进度时切成确定进度条；{@code total <= 0} 时保持滚动。
         *
         * <p>PCAP 检查没有“总数”，但会持续报已读包数：把它显示出来，
         * 大文件扫描期间用户能看到计数在动。</p>
         *
         * @param current 已扫描分卷数
         * @param total   分卷总数（PCAP 为 0）
         * @param packets 已读包数（DB 分卷检查为 0）
         */
        void updateLoading(int current, int total, long packets) {
            if (!loading) {
                return;
            }
            if (total > 0) {
                int value = Math.max(0, Math.min(current, total));
                busyBar.setIndeterminate(false);
                busyBar.setMaximum(total);
                busyBar.setValue(value);
                inspectLabel.setText(loadingMessage + " · " + value + "/" + total + " volumes");
            } else if (packets > 0) {
                inspectLabel.setText(loadingMessage + " · " + String.format("%,d", packets)
                        + " packets scanned");
            }
            fileTable.repaint();
        }

        /** 结束加载态（幂等：重复调用不会闪一下）。 */
        void hideLoading() {
            if (!loading) {
                return;
            }
            loading = false;
            busyBar.setIndeterminate(true);
            busyBar.setVisible(false);
            fileTable.repaint();
        }

        // ---------- seek 加载态 ----------

        /**
         * 拖动进度条后进入 seek 加载态。
         *
         * <p>seek 是“停掉当前段 → 打开新段”：大库/大 PCAP 上重开段要几秒，而进度条已经跳到
         * 目标位置，看起来像什么都没发生。这里一直挂到新段真的开播（见 {@link #onSeekStatus}）。</p>
         *
         * <p>包内可见：回归测试要断言“切换完成前不会提前收起”。</p>
         *
         * @param targetMs  目标播放位置（epoch 毫秒）
         * @param commandId 这条 seek 命令的 id；小于 0（没有子进程）时不进入加载态
         */
        void beginSeekLoading(long targetMs, long commandId) {
            if (commandId < 0) {
                return;
            }
            if (!seekLoading) {
                // 连续拖动时保留第一次覆盖前的文本：收尾恢复的才是真正的检查摘要。
                inspectLabelBeforeSeek = inspectLabel.getText();
            }
            seekLoading = true;
            seekAccepted = false;
            seekCommandId = commandId;
            seekBaselineExamined = -1;
            seekBaselineSent = 0;
            showLoading("Seeking to " + TS.format(Instant.ofEpochMilli(targetMs)) + "…");
        }

        /**
         * 子进程对 seek 命令的 ack。
         *
         * <p>只有 ok 才说明命令被接受，可以开始等切换完成；被拒绝
         * （例如重放已经结束）必须立刻收起，否则加载态会一直挂着。</p>
         */
        void onSeekAck(long commandId, boolean ok) {
            if (!seekLoading || commandId != seekCommandId) {
                return;
            }
            if (ok) {
                seekAccepted = true;
            } else {
                finishSeekLoading();
            }
        }

        /**
         * 子进程状态回调：ack 之后，直到新段真的开始读数据才算“进度完全切换完成”。
         *
         * <p>为什么不能用 {@code seeking=false}：子进程在新段<b>打开之前</b>就把
         * {@code seeking} 置回 false 并推一条 RUNNING；真正的重开（大 PCAP 要跳过几百 MB）
         * 发生在那之后。只看 seeking 会在“还在扫码”时就把进度条撤掉，等于又回到
         * “看起来卡住”。所以以 {@code examined}/{@code sent} 的<b>增长</b>为完成信号：
         * 第一条 {@code seeking=false} 只当作基线，之后计数增长（或进入 LIVE 等数据）
         * 才是数据真的流起来了。</p>
         *
         * @param seeking  子进程是否仍在重开段
         * @param examined 累计已检查记录数
         * @param sent     累计已发送包数
         * @param waiting  是否在等待新分卷数据（LIVE）
         */
        void onSeekStatus(boolean seeking, long examined, long sent, boolean waiting) {
            if (!seekLoading || !seekAccepted) {
                return;
            }
            if (seeking) {
                return;
            }
            if (seekBaselineExamined < 0) {
                seekBaselineExamined = examined;
                seekBaselineSent = sent;
                // LIVE 的新段已经打开在等新数据：同样算切换完成。
                if (waiting) {
                    finishSeekLoading();
                }
                return;
            }
            if (examined > seekBaselineExamined || sent > seekBaselineSent) {
                finishSeekLoading();
            }
        }

        /** 收起 seek 加载态并恢复被覆盖的检查摘要（幂等）。 */
        private void finishSeekLoading() {
            if (!seekLoading) {
                return;
            }
            seekLoading = false;
            seekAccepted = false;
            seekCommandId = -1;
            seekBaselineExamined = -1;
            hideLoading();
            if (inspectLabelBeforeSeek != null) {
                inspectLabel.setText(inspectLabelBeforeSeek);
                inspectLabelBeforeSeek = null;
            }
            syncPlayheadDisplay();
        }

        /**
         * 预览结束（seek 成功、被拒或强制收起）后，把当前时间、拖柄与文件表进度对齐到最新 status。
         *
         * <p>预览期间它们冻结在目标值；不主动同步的话要等下一帧 status 才会回正，
         * 看起来像停顿了一下。seek 被拒时尤其需要立即恢复，否则文件表会停在没去成的目标上。</p>
         */
        private void syncPlayheadDisplay() {
            if (seekPreviewActive() || lastStatus == null) {
                return;
            }
            Long playhead = lastStatus.playhead;
            currentTimeLabel.setText(playhead == null ? "—" : TS.format(Instant.ofEpochMilli(playhead)));
            if (playhead == null) {
                return;   // 没有 playhead（如 LIVE 等数据）：保持拖柄现状
            }
            setFileProgress(playhead);
            Long from = timelineFrom();
            Long to = timelineTo();
            if (from != null && to != null && to > from) {
                double fraction = (playhead - from) / (double) (to - from);
                seekBar.setFraction(Math.max(0.0, Math.min(1.0, fraction)));
            }
        }

        /**
         * 按数据源能力调整模式下拉项：payload 捕获的库没有 {@code frameData}，frame 不能选。
         *
         * <p>为什么不能只是“提示一下”而要从选项里去掉：帧级重放会打开网卡、跑注入自检，
         * 然后才在第一个分卷上报“没有 frameData 列”。用户白等一场，还以为库坏了。
         * 选项不可能生效时就不该出现在下拉框里；同时必须显式下发 {@code --replayMode payload}，
         * 否则 CLI 看到默认填好的网卡会按 frame 解析。</p>
         *
         * @param frameCapable true = 数据源含可注入帧；false = 只能按载荷重放；
         *                     null = 还没检查出来（不限制）
         */
        void applyModeAvailability(Boolean frameCapable) {
            boolean payloadOnly = Boolean.FALSE.equals(frameCapable);
            DefaultComboBoxModel<String> model = (DefaultComboBoxModel<String>) modeBox.getModel();
            boolean hadFrameItem = model.getIndexOf("frame") >= 0;
            updatingModeBox = true;
            try {
                if (payloadOnly) {
                    if (hadFrameItem) {
                        Object selectedBefore = modeBox.getSelectedItem();
                        model.removeElement("frame");
                        if (!"payload".equals(modeBox.getSelectedItem())) {
                            model.setSelectedItem("payload");
                        }
                        // 只有“我们替用户改成了 payload”才需要额外显式下发；
                        // 用户自己选过 payload 时 modeExplicit 已经是 true。
                        forcedPayload = !"payload".equals(selectedBefore);
                    } else if (!forcedPayload && !"payload".equals(modeBox.getSelectedItem())) {
                        model.setSelectedItem("payload");
                    }
                    // 已经处于 payload-only 状态时保留 forcedPayload：重复检查不该把它清掉，
                    // 否则下次 Start 又会漏传 --replayMode payload。
                } else {
                    if (!hadFrameItem) {
                        model.insertElementAt("frame", 0);
                        if (forcedPayload) {
                            // 之前的 payload 是替用户选的（不是用户意图），恢复后回到默认 payload。
                            model.setSelectedItem("payload");
                        }
                    }
                    forcedPayload = false;
                }
            } finally {
                updatingModeBox = false;
            }
            modeBox.setToolTipText(payloadOnly
                    ? "frame is unavailable: this database has no frame data (payload-only capture), "
                      + "so only payload replay is possible"
                    : MODE_TOOLTIP);
            applyModeFieldState();
            modeLabel.setText("Mode: " + effectiveModeHint());
            if (payloadOnly && hadFrameItem) {
                log("[ui] payload-only database: frame replay is unavailable, payload selected");
            }
        }

        private void applyInspection() {
            applyInspection(false, null);
        }

        /** Snapshot of the user's First/Last file choice, taken before the inspection is replaced. */
        private record FileRangeSnapshot(List<String> paths, boolean allReplayable) {
        }

        /** Capture the current file-range selection so a silent refresh can restore it. */
        private FileRangeSnapshot captureFileRange() {
            int[] range = selectedRangeIndices(true);
            if (range == null || inspection == null) {
                return new FileRangeSnapshot(List.of(), false);
            }
            List<String> paths = new ArrayList<>();
            for (int i = range[0]; i <= range[1] && i < inspection.files.size(); i++) {
                paths.add(inspection.files.get(i).path);
            }
            return new FileRangeSnapshot(paths, coversAllReplayable(range));
        }

        /**
         * Render an inspection result into the table and summary labels.
         *
         * @param preserveSelection true for the LIVE refresh: keep the user's file-range choice
         * @param previousRange     selection captured before the inspection was replaced; when the
         *                          previous range covered all replayable files it is extended to
         *                          newly arrived files, so the total duration grows
         */
        private void applyInspection(boolean preserveSelection, FileRangeSnapshot previousRange) {
            if (inspection == null) {
                return;
            }
            boolean keepProgress = preserveSelection && progressVisible;
            // 换了数据源/文件列表，旧的进度条无意义：先收起，静默刷新时再按当前 playhead 重算。
            progressVisible = false;
            progressByRow = new double[0];
            fileModel.setRowCount(0);
            for (FileRow f : inspection.files) {
                fileModel.addRow(new Object[]{
                        f.name,
                        kindText(f.kind),
                        f.dataStart == null ? "—" : TS.format(Instant.ofEpochMilli(f.dataStart)),
                        f.dataEnd == null ? "—" : TS.format(Instant.ofEpochMilli(f.dataEnd)),
                        f.duration == null ? "—" : DUR.format(Instant.ofEpochMilli(f.duration)),
                        f.bytes < 0 ? "—" : formatBytes(f.bytes),
                        f.replayable ? "Yes" : "No",
                        statusText(f),
                        "Yes"
                });
            }
            dataRangeLabel.setText("Data range: " + rangeText(inspection.dataStart, inspection.dataEnd));
            dataDurationLabel.setText("Duration: " + durationText(inspection.duration));
            applyModeAvailability(inspection.frameCapable);
            populateFileRange();
            if (preserveSelection && previousRange != null) {
                restoreFileRange(previousRange.paths(), previousRange.allReplayable());
            }
            syncTimeFieldsToSelectedRange();
            updatePreview();
            if (keepProgress) {
                progressVisible = true;
                setFileProgress(lastStatus == null ? null : lastStatus.playhead);
            }
            if (running) {
                // populateFileRange() 会按“有多少个可回放文件”重新启用下拉框；
                // 回放进行中参数必须保持不可编辑，静默刷新不能把它解锁。
                setParamsEnabled(false);
            }
            updateLiveRefreshTimer();
        }

        /** @return true if the inclusive row range starts/ends at the first/last replayable file. */
        private boolean coversAllReplayable(int[] range) {
            if (range == null || inspection == null) {
                return false;
            }
            int first = -1;
            int last = -1;
            for (int i = 0; i < inspection.files.size(); i++) {
                if (inspection.files.get(i).replayable) {
                    if (first < 0) {
                        first = i;
                    }
                    last = i;
                }
            }
            return first >= 0
                    && ((range[0] == first && range[1] == last)
                    // 只有一个可回放文件时范围选择器不启用，selectedRangeIndices 返回整表；
                    // 这同样表示“全部文件”，新增文件后应继续跟随。
                    || (range[0] == 0 && range[1] == inspection.files.size() - 1
                        && replayableIndices().size() < 2));
        }

        /**
         * Restore the previous First/Last file selection after a silent refresh.
         *
         * <p>If the previous selection covered every replayable file, extend it to the new last
         * file: that is what "follow the live capture" means for the playback window. An explicit
         * sub-range is restored by path and therefore stays fixed when new files arrive.</p>
         */
        private void restoreFileRange(List<String> previousPaths, boolean previousAll) {
            List<Integer> selectable = replayableIndices();
            if (selectable.isEmpty()) {
                updateFileRangeView();
                return;
            }
            int first = 0;
            int last = selectable.size() - 1;
            if (!previousAll && !previousPaths.isEmpty()) {
                int restoredFirst = rangePositionOf(selectable, previousPaths.get(0));
                int restoredLast = rangePositionOf(selectable, previousPaths.get(previousPaths.size() - 1));
                if (restoredFirst >= 0) {
                    first = restoredFirst;
                }
                if (restoredLast >= 0) {
                    last = restoredLast;
                }
                if (first > last) {
                    int swap = first;
                    first = last;
                    last = swap;
                }
            }
            updatingFileRange = true;
            try {
                firstFileBox.setSelectedIndex(first);
                lastFileBox.setSelectedIndex(last);
            } finally {
                updatingFileRange = false;
            }
            updateFileRangeView();
        }

        /** Position of a file path within the combo items (which list replayable rows only). */
        private int rangePositionOf(List<Integer> selectable, String path) {
            if (path == null) {
                return -1;
            }
            for (int i = 0; i < selectable.size(); i++) {
                FileRow row = inspection.files.get(selectable.get(i));
                if (path.equals(row.path)) {
                    return i;
                }
            }
            return -1;
        }

        private static String kindText(String kind) {
            if (kind == null) {
                return "";
            }
            return switch (kind) {
                case "final" -> "Final";
                case "legacy" -> "Legacy";
                case "capturing" -> "Capturing";
                case "single" -> "Single";
                case "pcap" -> "PCAP";
                default -> kind;
            };
        }

        static String statusText(FileRow f) {
            String status = f.status == null ? "" : f.status;
            // 载荷捕获的卷能正常按载荷回放，只是没有帧；这属于说明，不是错误。
            if (("".equals(status) || "ok".equals(status)) && Boolean.FALSE.equals(f.hasFrames)) {
                return "Payload only (no frame data)";
            }
            return switch (status) {
                case "", "ok" -> "";
                case "capturing" -> "Still being written — not replayable";
                case "unreadable" -> "File missing or unreadable";
                case "empty" -> "No data";
                case "error" -> f.note == null || f.note.isBlank()
                        ? "Read error" : "Read error: " + f.note;
                default -> f.note == null || f.note.isBlank() ? status : f.note;
            };
        }

        /** Status 列里的说明性文字（不是失败原因），用弱化色而不是错误色渲染。 */
        static boolean informationalStatus(Object status) {
            return status != null && String.valueOf(status).startsWith("Payload only");
        }

        // ---------- File range ----------

        /** Replayable rows in display order; also the item order of both range combos. */
        private List<Integer> replayableIndices() {
            List<Integer> indices = new ArrayList<>();
            if (inspection == null) {
                return indices;
            }
            for (int i = 0; i < inspection.files.size(); i++) {
                if (inspection.files.get(i).replayable) {
                    indices.add(i);
                }
            }
            return indices;
        }

        private void populateFileRange() {
            updatingFileRange = true;
            firstFileBox.removeAllItems();
            lastFileBox.removeAllItems();
            List<Integer> selectable = replayableIndices();
            for (int idx : selectable) {
                String item = (idx + 1) + ". " + inspection.files.get(idx).name;
                firstFileBox.addItem(item);
                lastFileBox.addItem(item);
            }
            boolean canSelect = selectable.size() > 1;
            firstFileBox.setEnabled(canSelect);
            lastFileBox.setEnabled(canSelect);
            resetRangeBtn.setEnabled(canSelect);
            if (canSelect) {
                firstFileBox.setSelectedIndex(0);
                lastFileBox.setSelectedIndex(selectable.size() - 1);
            }
            updatingFileRange = false;
            updateFileRangeView();
        }

        private void resetFileRange() {
            if (firstFileBox.getItemCount() > 0) {
                firstFileBox.setSelectedIndex(0);
                lastFileBox.setSelectedIndex(firstFileBox.getItemCount() - 1);
            }
        }

        /** @return inclusive table-row range [from,to]; null means "no files". */
        private int[] selectedRangeIndices() {
            return selectedRangeIndices(false);
        }

        /**
         * @param ignoreEnabled read the combo selection even while it is disabled (a running
         *                      replay disables the range selectors but their value is still the
         *                      user's choice and must survive a silent LIVE refresh)
         * @return inclusive table-row range [from,to]; null means "no files"
         */
        private int[] selectedRangeIndices(boolean ignoreEnabled) {
            if (inspection == null || inspection.files.isEmpty()) {
                return null;
            }
            List<Integer> selectable = replayableIndices();
            if (selectable.size() < 2 || (!ignoreEnabled && !firstFileBox.isEnabled())) {
                return new int[]{0, inspection.files.size() - 1};
            }
            int first = firstFileBox.getSelectedIndex();
            int last = lastFileBox.getSelectedIndex();
            if (first < 0) {
                first = 0;
            }
            if (last < 0) {
                last = selectable.size() - 1;
            }
            int from = selectable.get(Math.min(first, last));
            int to = selectable.get(Math.max(first, last));
            return new int[]{from, to};
        }

        /** Data bounds of the currently selected file range; null when it has no data. */
        private long[] selectedDataBounds() {
            int[] range = selectedRangeIndices();
            if (range == null) {
                return null;
            }
            Long start = null;
            Long end = null;
            for (int i = range[0]; i <= range[1]; i++) {
                FileRow row = inspection.files.get(i);
                if (!row.replayable) {
                    continue;
                }
                if (start == null && row.dataStart != null) {
                    start = row.dataStart;
                }
                if (row.dataEnd != null) {
                    end = row.dataEnd;
                }
            }
            return start == null || end == null ? null : new long[]{start, end};
        }

        private void onFileRangeChanged(boolean firstChanged) {
            if (updatingFileRange || inspection == null) {
                return;
            }
            int first = firstFileBox.getSelectedIndex();
            int last = lastFileBox.getSelectedIndex();
            if (first < 0 || last < 0) {
                return;
            }
            if (first > last) {
                updatingFileRange = true;
                if (firstChanged) {
                    lastFileBox.setSelectedIndex(first);
                } else {
                    firstFileBox.setSelectedIndex(last);
                }
                updatingFileRange = false;
            }
            updateFileRangeView();
            syncTimeFieldsToSelectedRange();
            updatePreview();
        }

        private void updateFileRangeView() {
            int[] range = selectedRangeIndices();
            for (int i = 0; i < fileModel.getRowCount(); i++) {
                FileRow row = inspection == null || i >= inspection.files.size()
                        ? null : inspection.files.get(i);
                boolean inRange = range == null || (i >= range[0] && i <= range[1]);
                boolean replay = row != null && row.replayable && inRange;
                fileModel.setValueAt(replay ? "Yes" : "No", i, 8);
            }
            if (inspection == null || inspection.files.isEmpty()) {
                fileRangeLabel.setText("Files: —");
                firstFileBox.setToolTipText(null);
                lastFileBox.setToolTipText(null);
            } else if (range == null || (range[0] == 0 && range[1] == inspection.files.size() - 1)) {
                fileRangeLabel.setText("Files: all " + inspection.files.size());
                firstFileBox.setToolTipText(inspection.files.get(0).path);
                lastFileBox.setToolTipText(inspection.files.get(inspection.files.size() - 1).path);
            } else {
                fileRangeLabel.setText("Files: " + (range[0] + 1) + "–" + (range[1] + 1)
                        + " of " + inspection.files.size());
                firstFileBox.setToolTipText(inspection.files.get(range[0]).path);
                lastFileBox.setToolTipText(inspection.files.get(range[1]).path);
            }
        }

        /**
         * Express the selected file range as an absolute {@code --start/--end} window.
         *
         * <p>This is a pure UI concern: the engine still discovers all volumes, but only packets
         * inside the forwarded window are replayed. Leading/trailing files are excluded by passing
         * the effective data bounds of the selected range; the user's time fields are clamped to
         * the same range so the two selections never conflict.</p>
         */
        private void applyEffectiveTimeWindow(List<String> args) {
            if (inspection == null) {
                return;
            }
            int[] range = selectedRangeIndices();
            if (range == null) {
                return;
            }
            boolean trimsHead = false;
            for (int i = 0; i < range[0]; i++) {
                if (inspection.files.get(i).replayable) {
                    trimsHead = true;
                    break;
                }
            }
            boolean trimsTail = false;
            for (int i = range[1] + 1; i < inspection.files.size(); i++) {
                if (inspection.files.get(i).replayable) {
                    trimsTail = true;
                    break;
                }
            }
            boolean explicitStart = startTouched && !startField.getText().isBlank();
            boolean explicitEnd = endTouched && !endField.getText().isBlank();
            overrideTimeWindowArgs(args, explicitStart, explicitEnd,
                    playbackFrom, playbackTo, trimsHead, trimsTail);
        }

        private static String inspectSummary(Inspection inspection) {
            if (inspection.replayableCount > 0) {
                String summary = "Inspected: " + inspection.replayableCount + " replayable file(s)";
                if (Boolean.FALSE.equals(inspection.frameCapable)) {
                    return summary + " · payload-only (no frame data)";
                }
                if (inspection.payloadOnlyVolumes > 0) {
                    return summary + " · " + inspection.payloadOnlyVolumes + " file(s) without frames";
                }
                return summary;
            }
            if (inspection.live || inspection.waiting) {
                return "LIVE: waiting for a closed volume (Start is allowed)";
            }
            return "No replayable data";
        }

        /** 数据源是否存在（DB 也接受“只存在分卷、基准文件还没建”的情况）。 */
        private static boolean sourceExists(String path) {
            File file = new File(path);
            if (file.isFile()) {
                return true;
            }
            try {
                return !SplitUtil.discoverAllSplitStyle(path).isEmpty();
            } catch (RuntimeException e) {
                return false;
            }
        }

        /**
         * 源身份：路径 + 文件列表/大小/mtime。
         *
         * <p>时间窗口刻意不参与：改 {@code --start/--end} 只需要本地重算预览，
         * 不必重新扫描整个数据源。</p>
         */
        private String inspectionKey() {
            String path = pathField.getText().trim();
            if (path.isEmpty()) {
                return "";
            }
            File file = new File(path);
            StringBuilder key = new StringBuilder();
            key.append(sourceKind()).append('|').append(file.getAbsolutePath());
            List<String> files = new ArrayList<>();
            try {
                if ("pcap".equals(sourceKind())) {
                    if (file.isFile()) {
                        files.add(file.getAbsolutePath());
                    }
                } else {
                    files.addAll(SplitUtil.discoverAllSplitStyle(path));
                    if (files.isEmpty() && file.isFile()) {
                        files.add(file.getAbsolutePath());
                    }
                }
            } catch (RuntimeException ignored) {
                // 目录不可读：交给 inspect 报错
            }
            Collections.sort(files);
            for (String f : files) {
                File vf = new File(f);
                key.append('|').append(vf.getName())
                        .append(':').append(vf.length())
                        .append(':').append(vf.lastModified());
            }
            // 检查结果里的 followSupported / frameCapable 与重放模式有关（payload 才能跟随），
            // 模式或网卡变了必须重新检查，不能命中按旧模式算出来的缓存。
            key.append("|modeArgs:").append(replayModeArgs(modeExplicit, forcedPayload,
                    String.valueOf(modeBox.getSelectedItem())));
            if (isFrameMode()) {
                key.append("|inject:").append(injectIp());
            }
            return key.toString();
        }

        private String sourceKind() {
            return "PCAP".equals(sourceType.getSelectedItem()) ? "pcap" : "db";
        }

        // ---------- 时间窗口预览 ----------

        private javax.swing.event.DocumentListener timeListener(boolean start) {
            return new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    onTimeFieldEdited(start);
                }

                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    onTimeFieldEdited(start);
                }

                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                }
            };
        }

        /**
         * 用户改动 Start/End 后记为“已显式设置”：自动默认值不再覆盖它；
         * 清空即表示 unselect（Start/End 不再向上游传递显式边界）。
         */
        private void onTimeFieldEdited(boolean start) {
            if (prefilling || updatingTimeFields) {
                return;
            }
            if (start) {
                startTouched = true;
            } else {
                endTouched = true;
            }
            updatePreview();
            // 用户填了 End 就冻结回放窗口：LIVE 文件列表不再自动刷新；
            // 清空 End 时重新开始每分钟刷新（下一次计时从清空时刻算起）。
            updateLiveRefreshTimer();
        }

        /** 时间参数变化：只重算预览，不重新 inspect。 */
                /**
         * 把 Start/End 填成当前文件范围的数据起止时间（默认值）。
         * 用户显式改过/清空过的一侧不会被覆盖；Start 时也不会把自动默认值当作显式参数传给子进程。
         */
        private void syncTimeFieldsToSelectedRange() {
            if (inspection == null) {
                return;
            }
            long[] bounds = selectedDataBounds();
            if (bounds == null) {
                return;
            }
            updatingTimeFields = true;
            try {
                if (!startTouched) {
                    startField.setText(TS.format(Instant.ofEpochMilli(bounds[0])));
                }
                if (!endTouched) {
                    // Follow/LIVE has no natural end: keep End empty so new volumes keep being replayed.
                    endField.setText(defaultEndText(inspection.followSupported, bounds[1]));
                }
            } finally {
                updatingTimeFields = false;
            }
        }

        private void updatePreview() {
            if (inspection == null) {
                return;
            }
            long[] bounds = selectedDataBounds();
            if (bounds == null) {
                boolean live = inspection.live || inspection.waiting;
                selectedLabel.setText(live
                        ? "Playback range: — (LIVE; waiting for a closed volume)"
                        : "Playback range: — (no data in the selected files)");
                previewEmpty = !live;
                previewValid = true;
                startBtn.setEnabled(!running && startAllowed());
                updateSeekBarEnabled();
                return;
            }
            Selection selection = previewSelection(bounds[0], bounds[1],
                    startField.getText(), endField.getText());
            if (selection == null) {
                selectedLabel.setText("Playback range: — (time input incomplete or invalid)");
                previewEmpty = false;
                previewValid = false;
            } else {
                selectedLabel.setText("Playback range: " + rangeText(selection.fromMs(), selection.toMs())
                        + "  selected " + durationText(Math.max(0, selection.toMs() - selection.fromMs()))
                        + (selection.clamped() ? " (clamped to data)" : "")
                        + (selection.empty() ? " (no overlap)" : ""));
                playbackFrom = selection.fromMs();
                playbackTo = selection.toMs();
                previewEmpty = selection.empty();
                previewValid = true;
            }
            startBtn.setEnabled(!running && startAllowed());
            updateSeekBarEnabled();
        }

        private boolean startAllowed() {
            if (inspection == null) {
                return false;
            }
            boolean hasData = inspection.replayableCount > 0 || inspection.live || inspection.waiting;
            return hasData && previewValid && !previewEmpty;
        }

        /** Start 前拖动进度条 = 改播放起点（写回 {@code --start}）。 */
        private void applyPreStartPosition(long targetMs) {
            String formatted = TS.format(Instant.ofEpochMilli(targetMs));
            startField.setText(formatted);
            log("[ui] playback start set to " + formatted);
            // setText 触发文档监听 → updatePreview()
        }

        private void updateSeekBarEnabled() {
            Long from = timelineFrom();
            Long to = timelineTo();
            boolean timelineKnown = from != null && to != null && to > from;
            seekBar.setEnabled(timelineKnown && (running || startAllowed()));
        }

        // ---------- replay ----------

        private void startReplay() {
            if (running) {
                return;
            }
            if (inspection == null) {
                JOptionPane.showMessageDialog(this, "Pick and inspect a source with replayable data first.",
                        "JShark Replay", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (previewEmpty) {
                JOptionPane.showMessageDialog(this,
                        "The selected playback range does not overlap the data. Adjust the time or file range.",
                        "JShark Replay", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (!startAllowed()) {
                JOptionPane.showMessageDialog(this, "The current source has no replayable data.",
                        "JShark Replay", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (!preflightFrameStart()) {
                return;
            }
            List<String> args = buildReplayArgs();
            if (args.isEmpty()) {
                return;
            }
            stopRequestedByUser = false;
            lastChildError = null;
            terminalFailureText = null;
            startTimedOut = false;
            loggedStatusWarnings.clear();
            if (playbackFrom == null) {
                playbackFrom = inspection.dataStart;
            }
            if (playbackTo == null) {
                playbackTo = inspection.dataEnd;
            }
            applyEffectiveTimeWindow(args);
            long generation = ++replayGeneration;
            lastStatusSeq = 0;
            replayStartSent = false;
            dataSourceDriftLogged = false;
            lastStatus = null;
            // 开始回放后，文件表的 Status 切换为按 playhead 计算的进度；终态时收起（见 applyStatus）。
            progressVisible = true;
            progressByRow = new double[0];
            try {
                replayProcess = EngineProcess.control(args, new Callbacks() {
                    @Override
                    public void onHello(JSONObject json) {
                        if (generation == replayGeneration) {
                            String session = json.getString("session");
                            if (session == null) {
                                session = json.getString("sessionId");   // 旧子进程兼容
                            }
                            log("[control] hello session=" + session
                                    + " protocol=" + json.getIntValue("protocol"));
                        }
                    }

                    @Override
                    public void onStatus(JSONObject json) {
                        UiStatus status = UiStatus.from(json);
                        SwingUtilities.invokeLater(() -> {
                            if (generation != replayGeneration) {
                                return;   // 旧子进程的残留消息
                            }
                            maybeSendStart(status);
                            applyStatus(status);
                        });
                    }

                    @Override
                    public void onAck(JSONObject json) {
                        SwingUtilities.invokeLater(() -> {
                            if (generation != replayGeneration) {
                                return;
                            }
                            handleAck(json);
                        });
                    }

                    @Override
                    public void onTerminal(JSONObject json) {
                        SwingUtilities.invokeLater(() -> {
                            if (generation != replayGeneration) {
                                return;
                            }
                            stopStartWatchdog();
                            // 终态（FINISHED/FAILED/STOPPED）之后不会再有 status：seek 的加载态
                            // 和文件表进度条都必须在这里收掉，否则会一直挂在界面上。
                            finishSeekLoading();
                            clearProgress();
                            log("[control] " + json.getString("type"));
                            Object errorValue = json.get("error");
                            JSONObject error = errorValue instanceof JSONObject o ? o : null;
                            String reason = error != null ? error.getString("message")
                                    : (errorValue instanceof String text ? text : null);
                            if (reason == null || reason.isBlank()) {
                                reason = json.getString("message");
                            }
                            boolean failed = errorValue != null
                                    || Boolean.FALSE.equals(json.getBoolean("ok"));
                            if (!failed) {
                                return;
                            }
                            if (stopRequestedByUser) {
                                // 用户按了 Stop：即使子进程因 5 秒看门狗被强制结束（exit 1），
                                // 也不是重放逻辑失败。原因仍然写进日志供排查。
                                stateLabel.setText("Stopped");
                                if (reason != null && !reason.isBlank()) {
                                    log("[control] stopped: " + reason);
                                }
                            } else {
                                terminalFailureText = reason;
                                stateLabel.setText(reason == null || reason.isBlank()
                                        ? "Failed" : "Failed: " + oneLine(reason));
                                log("[control] failed: "
                                        + (reason == null || reason.isBlank() ? "unknown error" : reason));
                            }
                        });
                    }

                    @Override
                    public void onLog(String line) {
                        if (generation == replayGeneration) {
                            if (looksLikeChildError(line)) {
                                lastChildError = line;
                            }
                            ReplayMainFrame.this.log(line);
                        }
                    }

                    @Override
                    public void onExit(int code) {
                        SwingUtilities.invokeLater(() -> {
                            if (generation != replayGeneration) {
                                return;
                            }
                            stopStartWatchdog();
                            running = false;
                            replayProcess = null;
                            finishSeekLoading();
                            clearProgress();   // 子进程异常退出时也要收起进度条
                            setParamsEnabled(true);
                            setRunningControls(false);
                            startBtn.setEnabled(startAllowed());
                            if (stopRequestedByUser) {
                                stateLabel.setText("Stopped");
                            } else if (startTimedOut) {
                                stateLabel.setText("Start timed out (child stopped)");
                            } else if (code != 0 && terminalFailureText != null) {
                                stateLabel.setText("Failed: " + oneLine(terminalFailureText));
                            } else if (code != 0 && lastChildError != null) {
                                stateLabel.setText("Failed: " + oneLine(lastChildError));
                            } else {
                                stateLabel.setText(exitStateText(false, code));
                            }
                        });
                    }
                }, generation);
                running = true;
                setParamsEnabled(false);
                setRunningControls(true);
                startBtn.setEnabled(false);
                stateLabel.setText("Starting…");
                startStartWatchdog(generation);
                log("[ui] started replay child");
            } catch (Exception e) {
                running = false;
                replayProcess = null;
                stopStartWatchdog();
                clearProgress();   // 起不来就没有"正在回放的文件"，别留进度条
                setParamsEnabled(true);
                setRunningControls(false);
                startBtn.setEnabled(startAllowed());
                log("[ui] start failed: " + e);
                JOptionPane.showMessageDialog(this, "Failed to start replay: " + e.getMessage(),
                        "JShark Replay", JOptionPane.ERROR_MESSAGE);
            }
        }

        /**
         * READY → start 握手：子进程先报 READY，UI 明确说 start 之后才开播。
         *
         * <p>如果 READY 恰好被 status 合并掉了也不必卡死：状态本来就每 250ms 重发一次；
         * 万一最后收到的是 RUNNING（说明已经在跑），同样视为握手完成。</p>
         */
        private void maybeSendStart(UiStatus status) {
            if (replayStartSent || status.state == null) {
                return;
            }
            if ("READY".equals(status.state)) {
                replayStartSent = true;
                stopStartWatchdog();
                send("start", Map.of());
                log("[ui] child READY → start");
            } else if ("RUNNING".equals(status.state) || "PAUSED".equals(status.state)
                    || "FAILED".equals(status.state) || "STOPPED".equals(status.state)
                    || "FINISHED".equals(status.state)) {
                replayStartSent = true;
                stopStartWatchdog();
            }
        }

        private void startStartWatchdog(long generation) {
            stopStartWatchdog();
            replayStartWatchdog = new Timer(15_000, e -> {
                if (generation != replayGeneration || replayStartSent) {
                    return;
                }
                stopStartWatchdog();
                log("[ui] start timed out: no READY/hello handshake within 15s");
                stateLabel.setText("Start timed out");
                startTimedOut = true;
                if (replayProcess != null) {
                    replayProcess.kill();
                }
            });
            replayStartWatchdog.setRepeats(false);
            replayStartWatchdog.start();
        }

        private void stopStartWatchdog() {
            if (replayStartWatchdog != null) {
                replayStartWatchdog.stop();
                replayStartWatchdog = null;
            }
        }

        /**
         * 把子进程的 error/warnings 写进 Log 页（每条只写一次）。
         *
         * <p>这些信息原本已经随 status 上报，但 UI 没解析：注入自检失败、参数被忽略等
         * 只能靠用户翻 stderr。这里至少让 Log 页第一屏就能看到原因。</p>
         */
        private void logStatusDiagnostics(UiStatus s) {
            if (s.lastError != null && !s.lastError.isBlank()
                    && loggedStatusWarnings.add("error|" + s.lastError)) {
                log("[child] error: " + s.lastError);
            }
            for (String warning : s.warnings) {
                if (warning != null && !warning.isBlank()
                        && loggedStatusWarnings.add("warn|" + warning)) {
                    log("[child] warning: " + warning);
                }
            }
        }

        private void applyStatus(UiStatus s) {
            if (s.seq > 0 && s.seq <= lastStatusSeq) {
                return;   // 旧快照：只应用更大的 seq
            }
            lastStatusSeq = s.seq;
            lastStatus = s;
            logStatusDiagnostics(s);
            String extra = s.waiting ? " · waiting for a new volume" : (s.seeking ? " · seeking" : "");
            stateLabel.setText(s.state + statusMessage(s.message) + extra);
            if (!seekPreviewActive()) {
                currentTimeLabel.setText(s.playhead == null ? "—" : TS.format(Instant.ofEpochMilli(s.playhead)));
            }
            Long from = timelineFrom();
            Long to = timelineTo();
            Long total = (from != null && to != null) ? to - from : null;
            totalTimeLabel.setText(total == null ? "—" : durationText(total));
            etaLabel.setText(s.etaMs == null ? "Remaining: —" : "Remaining: " + durationText(s.etaMs));
            speedActualLabel.setText("Current: " + String.format("%.2fx", s.speedCurrent));
            countersLabel.setText("Sent " + s.sent + " packets · " + formatBytes(s.bytes));
            modeLabel.setText("Mode: " + s.effectiveMode
                    + ("payload".equals(s.effectiveMode) ? " (payload-level)" : " (frame-level)"));
            if (from != null && to != null && to > from && s.playhead != null) {
                if (!seekPreviewActive()) {
                    // 拖动/seek 期间不要用 status 回显覆盖拖柄：否则拖柄会来回跳
                    seekBar.setFraction((s.playhead - from) / (double) (to - from));
                }
                selectedLabel.setText("Playback range: " + rangeText(from, to));
            }
            updateSeekBarEnabled();
            if (s.sourceStart != null && s.sourceEnd != null) {
                dataRangeLabel.setText("Data range: " + rangeText(s.sourceStart, s.sourceEnd));
                dataDurationLabel.setText("Duration: " + durationText(s.sourceEnd - s.sourceStart));
            }
            warnIfSourceChanged(s);
            if ("PAUSED".equals(s.state)) {
                pauseBtn.setText("Resume");
            } else {
                pauseBtn.setText("Pause");
            }
            if ("FAILED".equals(s.state)) {
                stateLabel.setForeground(STATE_FAIL);
            } else if ("PAUSED".equals(s.state)) {
                stateLabel.setForeground(ACCENT);
            } else {
                stateLabel.setForeground(STATE_OK);
            }
            // seek 的加载态只认 ack 之后的第一条 seeking=false 作为基线，之后计数增长才算切换完成。
            onSeekStatus(s.seeking, s.examined, s.sent, s.waiting);
            if (isTerminalState(s.state)) {
                // 终态收起进度条：该行的静态 Status（"Payload only"、读取错误说明等）要重新可见。
                clearProgress();
            } else {
                updateProgress(s);
            }
        }

        /**
         * 拖动/seek 预览期间，当前时间只显示用户指定的位置。
         *
         * <p>这条路径不经过 {@link #applyStatus(UiStatus)}：拖动时每条 status 都会带着
         * 旧 playhead 回来，若照写就会把刚显示的目标时间拉回去，下一次鼠标事件再改回来，
         * 形成肉眼可见的抖动。</p>
         */
        private void showSeekTarget(long targetMs) {
            currentTimeLabel.setText(TS.format(Instant.ofEpochMilli(targetMs)));
        }

        /**
         * 当前时间与拖柄是否应停在被用户拖动/seek 的目标上，而不是跟随 status.playhead。
         *
         * <p>覆盖两段：拖动过程中（{@link SeekBar#isDragging()}），以及松手后 seek 还没
         * 真正落地（{@link #seekLoading}）。只看拖动不够——松手到新段开播之间 status
         * 仍会推送旧 playhead，时间/拖柄会先跳回原位再跳到新位置。</p>
         */
        private boolean seekPreviewActive() {
            return seekBar.isDragging() || seekLoading;
        }

        /** 回放是否已进入终态（之后不会再有进度推进）。 */
        private static boolean isTerminalState(String state) {
            return "FINISHED".equals(state) || "STOPPED".equals(state) || "FAILED".equals(state);
        }

        /**
         * 子进程退出后的状态文案。
         *
         * <p>用户按过 Stop 时，即使子进程被 5 秒看门狗强制结束（退出码 1），也不能显示
         * “Failed (exit 1)”——那会把一次正常停止说成重放失败，掩盖真正的错误。</p>
         *
         * @param userStop 用户是否按过 Stop
         * @param code     子进程退出码
         * @return 状态文案
         */
        static String exitStateText(boolean userStop, int code) {
            if (userStop) {
                return "Stopped";
            }
            return code == 0 ? "Exited" : "Failed (exit " + code + ")";
        }

        /** 收起进度条，恢复 Status 列的静态文本渲染。 */
        private void clearProgress() {
            if (!progressVisible) {
                return;
            }
            progressVisible = false;
            progressByRow = new double[0];
            fileTable.repaint();
        }

        /**
         * 根据当前 playhead 重算所有文件的完成度。
         *
         * <p>纯计算部分在 {@link ReplayUi#fileProgressByRow}，这里只负责比较与重绘。</p>
         */
        private void updateProgress(UiStatus s) {
            if (seekPreviewActive()) {
                // 拖动/seek 预览优先：此时 status 还带着旧 playhead，
                // 照写会把已经按目标位置重置好的文件状态又拉回去。
                return;
            }
            setFileProgress(s.playhead);
        }

        /** 拖动进度条时，让文件表也按拖动目标即时回显（往前拖会清掉后面卷的完成状态）。 */
        private void previewFileProgress(long targetMs) {
            setFileProgress(targetMs);
        }

        /**
         * 按 playhead 更新文件表每一行的完成度；playhead 为 null 时不画进度条。
         *
         * <p>整个状态从 playhead 重新推导，不做增量标记，因此来回 seek 不会留下
         * 某个卷“已经完成”的残留状态。</p>
         */
        private void setFileProgress(Long playheadMs) {
            if (!progressVisible || inspection == null) {
                return;
            }
            double[] next = ReplayUi.fileProgressByRow(
                    playheadMs, inspection.files, timelineFrom(), timelineTo());
            if (Arrays.equals(next, progressByRow)) {
                return;
            }
            progressByRow = next;
            fileTable.repaint();
        }

        /** 处理一条命令 ack：seek 的接受/拒绝影响加载态，失败原因进日志。 */
        private void handleAck(JSONObject json) {
            long id = json.getLongValue("id");
            boolean ok = json.getBooleanValue("ok");
            onSeekAck(id, ok);
            if (!ok) {
                JSONObject err = json.getJSONObject("error");
                log("[control] command failed: "
                        + (err == null ? json : err.getString("message")));
            }
        }

        /**
         * @param line 子进程 stderr 的一行
         * @return 是否像一条错误/异常（用于在子进程没发终态就退出时解释 exit code）
         */
        private static boolean looksLikeChildError(String line) {
            if (line == null || line.isBlank()) {
                return false;
            }
            String text = line.strip();
            return text.startsWith("Error:")
                    || text.contains(" ERROR ")
                    || text.contains("FATAL")
                    || text.contains("Exception");
        }

        /**
         * 把子进程的错误压成一行，供状态标签显示。
         *
         * <p>失败原因可能是多行堆栈/中英混排：状态栏只放第一行并截断，完整内容仍在 Log 页。</p>
         */
        static String oneLine(String message) {
            if (message == null) {
                return "";
            }
            String first = message.strip().split("\\R", 2)[0].strip();
            return first.length() <= 100 ? first : first.substring(0, 97) + "...";
        }

        /**
         * Only surface English status detail in the UI. The control protocol still uses the
         * child process's own language for {@code status.message}, so a CJK message is dropped
         * rather than leaking mixed-language text into the status bar.
         */
        private static String statusMessage(String message) {
            if (message == null || message.isBlank()) {
                return "";
            }
            boolean cjk = message.codePoints().anyMatch(cp ->
                    Character.UnicodeScript.of(cp) == Character.UnicodeScript.HAN);
            return cjk ? "" : " · " + message;
        }

        /** inspect 的起点与重放侧不一致 → 提示“数据源已变化”，不静默混用旧结果。 */
        private void warnIfSourceChanged(UiStatus s) {
            if (dataSourceDriftLogged || inspection == null
                    || s.sourceStart == null || inspection.dataStart == null) {
                return;
            }
            if (s.sourceStart != null && inspection.dataStart != null
                    && !s.sourceStart.equals(inspection.dataStart)) {
                dataSourceDriftLogged = true;
                inspectLabel.setText(inspectSummaryText + " · source changed");
                log("[ui] source changed: inspect start "
                        + TS.format(Instant.ofEpochMilli(inspection.dataStart))
                        + ", replay side " + TS.format(Instant.ofEpochMilli(s.sourceStart)));
            }
        }

        private void setRunningControls(boolean running) {
            pauseBtn.setEnabled(running);
            stopBtn.setEnabled(running);
            speedBox.setEnabled(true);
            updateSeekBarEnabled();
            startBtn.setEnabled(!running && startAllowed());
        }

        private void onThemeSelected() {
            if (updatingTheme || prefilling) {
                return;
            }
            boolean dark = "Dark".equals(themeBox.getSelectedItem());
            if (dark == darkTheme) {
                return;
            }
            if (running) {
                updatingTheme = true;
                themeBox.setSelectedItem(darkTheme ? "Dark" : "Light");
                updatingTheme = false;
                JOptionPane.showMessageDialog(this,
                        "Stop the replay before switching the theme.",
                        "JShark Replay", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            switchTheme(dark);
        }

        private void switchTheme(boolean dark) {
            updatingTheme = true;
            try {
                ReplayUi.installTheme(dark);
                SwingUtilities.updateComponentTreeUI(this);
                restyleTree(this);
                installFileTableRenderer();
                startBtn.setForeground(ON_ACCENT);
                startBtn.setBackground(ACCENT);
                currentTimeLabel.setForeground(ACCENT);
                if (playerPanel != null) {
                    playerPanel.setBackground(PLAYER_BG);
                }
                applyModeFieldState();
                updateStateLabelColor();
                themeBox.setSelectedItem(dark ? "Dark" : "Light");
                getContentPane().setBackground(BG);
                repaint();
            } finally {
                updatingTheme = false;
            }
        }

        /** Recursively re-apply custom colors after a LookAndFeel/theme change. */
        private void restyleTree(java.awt.Component component) {
            if (component instanceof DarkTextField field) {
                field.refreshTheme();
            }
            if (component instanceof JComboBox<?> combo) {
                styleCombo(combo);
            }
            if (component instanceof CollapsibleSection section) {
                section.refreshTheme();
            }
            if (component instanceof JPanel panel && panel.isOpaque()) {
                panel.setBackground(BG);
            }
            if (component instanceof JButton button && button != startBtn) {
                button.setBackground(PANEL);
                button.setForeground(FG);
            }
            if (component instanceof JProgressBar bar) {
                bar.setBackground(INPUT);
                bar.setForeground(ACCENT);
                bar.setBorderPainted(false);
            }
            if (component instanceof JTable table) {
                table.setBackground(INPUT);
                table.setForeground(FG);
                table.setGridColor(BORDER);
                table.setSelectionBackground(SELECTION);
                table.setSelectionForeground(darkTheme ? Color.WHITE : FG);
                if (table.getParent() instanceof javax.swing.JViewport viewport) {
                    viewport.setBackground(INPUT);
                }
            }
            if (component instanceof javax.swing.table.JTableHeader header) {
                header.setBackground(PANEL);
                header.setForeground(FG);
            }
            if (component instanceof JTextArea area) {
                area.setBackground(INPUT);
                area.setForeground(FG);
                area.setCaretColor(ACCENT);
                if (area.getParent() instanceof javax.swing.JViewport viewport) {
                    viewport.setBackground(INPUT);
                }
            }
            if (component instanceof JScrollPane scrollPane) {
                scrollPane.setBackground(BG);
                scrollPane.getViewport().setBackground(BG);
                scrollPane.setBorder(BorderFactory.createLineBorder(BORDER));
            }
            if (component instanceof JTabbedPane tabs) {
                tabs.setBackground(BG);
                tabs.setForeground(FG);
            }
            if (component instanceof JSplitPane split) {
                split.setBackground(BG);
            }
            if (component instanceof JLabel label) {
                if (Boolean.TRUE.equals(label.getClientProperty("muted"))) {
                    label.setForeground(MUTED);
                } else if (label == currentTimeLabel) {
                    label.setForeground(ACCENT);
                } else if (label == stateLabel) {
                    updateStateLabelColor();
                } else {
                    label.setForeground(FG);
                }
            }
            if (component instanceof java.awt.Container container) {
                for (java.awt.Component child : container.getComponents()) {
                    restyleTree(child);
                }
            }
            component.repaint();
        }

        private void updateStateLabelColor() {
            if (lastStatus != null && "FAILED".equals(lastStatus.state)) {
                stateLabel.setForeground(STATE_FAIL);
            } else if (lastStatus != null && "PAUSED".equals(lastStatus.state)) {
                stateLabel.setForeground(ACCENT);
            } else {
                stateLabel.setForeground(STATE_OK);
            }
        }

        private void setParamsEnabled(boolean enabled) {
            for (javax.swing.JComponent c : paramComponents) {
                c.setEnabled(enabled);
            }
            boolean canSelect = enabled && inspection != null && replayableIndices().size() > 1;
            firstFileBox.setEnabled(canSelect);
            lastFileBox.setEnabled(canSelect);
            resetRangeBtn.setEnabled(canSelect);
            applyModeFieldState();
        }

        private void togglePause() {
            if (!running) {
                return;
            }
            if (lastStatus != null && "PAUSED".equals(lastStatus.state)) {
                send("resume", null);
            } else {
                send("pause", null);
            }
        }

        private void stopReplay() {
            if (replayProcess == null) {
                return;
            }
            stopRequestedByUser = true;
            stateLabel.setText("Stopping…");
            pauseBtn.setEnabled(false);
            stopBtn.setEnabled(false);
            seekBar.setEnabled(false);
            // 停止时兜底：seek 还在重开段的加载态里，不能留一个永远不消失的进度条。
            finishSeekLoading();
            replayProcess.stopGracefully();
        }

        private Long timelineFrom() {
            if (lastStatus != null && lastStatus.windowFrom != null) {
                return lastStatus.windowFrom;
            }
            return playbackFrom;
        }

        private Long timelineTo() {
            if (lastStatus != null && lastStatus.windowTo != null) {
                return lastStatus.windowTo;
            }
            return playbackTo;
        }

        /**
         * 向子进程写命令。
         *
         * @return 命令 id；没有子进程时返回 -1
         */
        private long send(String cmd, Map<String, Object> args) {
            if (replayProcess != null) {
                return replayProcess.send(cmd, args);
            }
            return -1;
        }

        // ---------- 日志/关闭 ----------

        private void log(String line) {
            logQueue.offer(line);
        }

        private void drainLogs() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 200; i++) {
                String line = logQueue.poll();
                if (line == null) {
                    break;
                }
                sb.append(line).append('\n');
            }
            if (sb.length() == 0) {
                return;
            }
            logArea.append(sb.toString());
            try {
                int len = logArea.getDocument().getLength();
                if (len > 200_000) {
                    logArea.getDocument().remove(0, len - 200_000);
                }
            } catch (BadLocationException ignored) {
                // ignore
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        }

        private void closeUi() {
            if (running) {
                int rc = JOptionPane.showConfirmDialog(this,
                        "Replay is running. Stop it and exit?", "JShark Replay",
                        JOptionPane.OK_CANCEL_OPTION);
                if (rc != JOptionPane.OK_OPTION) {
                    return;
                }
            }
            liveRefreshTimer.stop();
            if (inspectTimeout != null) {
                inspectTimeout.stop();
                inspectTimeout = null;
            }
            stopStartWatchdog();
            if (inspectProcess != null) {
                inspectProcess.kill();
            }
            if (replayProcess != null) {
                replayProcess.stopGracefully();
            }
            dispose();
            new Timer(800, e -> System.exit(0)).start();
        }

        @Override
        public void dispose() {
            // 计时器不会随窗口 dispose 自动停止；测试/关闭窗口后必须显式停掉。
            closed = true;
            liveRefreshTimer.stop();
            if (inspectProcess != null) {
                inspectProcess.kill();
                inspectProcess = null;
            }
            super.dispose();
        }

        // ---------- 格式化 ----------

        private static String rangeText(Long from, Long to) {
            if (from == null || to == null) {
                return "—";
            }
            return TS.format(Instant.ofEpochMilli(from)) + " ~ " + TS.format(Instant.ofEpochMilli(to));
        }

        private static String durationText(Long ms) {
            if (ms == null) {
                return "—";
            }
            return DUR.format(Instant.ofEpochMilli(ms));
        }

            }

    // ==================== 参数解析 ====================

    static final class ArgForm {
        private final Map<String, String> values = new LinkedHashMap<>();

        static ArgForm parse(String[] args) {
            ArgForm f = new ArgForm();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    continue;
                }
                String name;
                String value = null;
                int eq = arg.indexOf('=');
                if (eq > 0) {
                    name = arg.substring(2, eq);
                    value = arg.substring(eq + 1);
                } else {
                    name = arg.substring(2);
                }
                switch (name) {
                    case "ui", "daemon", "control", "inspect", "help", "h" -> {
                        // UI 自身管理的选项，不传给子进程
                        if (value == null && i + 1 < args.length && !args[i + 1].startsWith("--")
                                && ("daemon".equals(name))) {
                            i++;
                        }
                    }
                    default -> {
                        if (value == null && i + 1 < args.length && !args[i + 1].startsWith("--")) {
                            value = args[++i];
                        }
                        if (value != null) {
                            f.values.put(name, value);
                        }
                    }
                }
            }
            return f;
        }

        String get(String key) {
            return values.getOrDefault(key, "");
        }
    }

    // ==================== 数据模型 ====================

    static final class FileRow {
        String name;
        String path;
        String kind;
        boolean replayable;
        /** 该卷是否含可注入帧；null 表示未知/不适用（capturing、空卷）。 */
        Boolean hasFrames;
        Long windowStart;
        Long windowEnd;
        Long dataStart;
        Long dataEnd;
        Long duration;
        long bytes;
        String status;
        String note;
    }

    /**
     * 计算文件表每一行在 Status 列的完成度快照。
     *
     * <p>返回值下标与 {@code files} 一致：[0,1] 表示该卷在本次回放窗口内的完成度，
     * 1 = 已越过结束时间（完成）；-1 表示该卷与窗口无交集、或还没轮到，渲染器保留原始
     * 状态文本。</p>
     *
     * <p>已越过的卷一律 100%：正常回放与向前 seek 得到同样的结果。playhead 后退时整个
     * 快照按新位置重算，后面的卷自然回到 -1（未开始），因此往回拖不需要额外的清状态逻辑。
     * playhead 早于所有可用卷时第一卷给 0%，保持“从卷首开始”的显示。</p>
     *
     * <p>纯计算、不碰 Swing，便于在无头环境单测；调用方负责节流重绘。</p>
     *
     * @param playheadMs 当前播放头（epoch 毫秒，可能为 null）
     * @param files      检查结果里的文件列表
     * @param fromMs     所选回放窗口起点（null = 不限）
     * @param toMs       所选回放窗口终点（null = 不限）
     * @return 与 files 等长的完成度数组；元素为 -1 表示不画进度条
     */
    static double[] fileProgressByRow(Long playheadMs, List<FileRow> files,
                                      Long fromMs, Long toMs) {
        if (files == null || files.isEmpty()) {
            return new double[0];
        }
        double[] fractions = new double[files.size()];
        Arrays.fill(fractions, -1.0);
        if (playheadMs == null) {
            return fractions;
        }
        long head = playheadMs;
        int firstUsable = -1;
        boolean anyStarted = false;
        for (int i = 0; i < files.size(); i++) {
            FileRow f = files.get(i);
            if (f.dataStart == null || f.dataEnd == null) {
                continue;   // 空卷 / capturing 卷：没有可用于计算进度的时间范围
            }
            long start = fromMs == null ? f.dataStart : Math.max(f.dataStart, fromMs);
            long end = toMs == null ? f.dataEnd : Math.min(f.dataEnd, toMs);
            if (end <= start) {
                continue;   // 该卷与所选回放窗口没有交集
            }
            if (firstUsable < 0) {
                firstUsable = i;
            }
            if (head < start) {
                continue;   // 还没轮到这一卷
            }
            fractions[i] = head >= end ? 1.0 : (head - start) / (double) (end - start);
            anyStarted = true;
        }
        if (!anyStarted && firstUsable >= 0) {
            fractions[firstUsable] = 0.0;   // playhead 早于所有卷：从第一卷 0% 开始
        }
        return fractions;
    }

    static final class Inspection {
        long replayableCount;
        Long dataStart;
        Long dataEnd;
        Long duration;
        Long selectedFrom;
        Long selectedTo;
        Long selectedDuration;
        boolean live;
        boolean waiting;
        /** DB split + payload: new volumes are followed; End must default to empty. */
        boolean followSupported;
        /** 数据源是否含可注入帧：true/false，null = 未能判定（没有可探测的卷）。 */
        Boolean frameCapable;
        int frameVolumes;
        int payloadOnlyVolumes;
        final List<FileRow> files = new ArrayList<>();

        static Inspection from(JSONObject json) {
            Inspection i = new Inspection();
            JSONObject summary = json.getJSONObject("summary");
            if (summary != null) {
                i.replayableCount = summary.getIntValue("replayableCount");
                i.dataStart = longOrNull(summary, "dataStartMs");
                i.dataEnd = longOrNull(summary, "dataEndMs");
                i.duration = longOrNull(summary, "durationMs");
                i.live = summary.getBooleanValue("live");
                i.waiting = summary.getBooleanValue("waiting");
            }
            JSONObject selected = json.getJSONObject("selected");
            if (selected != null) {
                i.selectedFrom = longOrNull(selected, "fromMs");
                i.selectedTo = longOrNull(selected, "toMs");
                i.selectedDuration = longOrNull(selected, "durationMs");
            }
            JSONObject source = json.getJSONObject("source");
            if (source != null) {
                i.followSupported = source.getBooleanValue("followSupported");
                i.frameCapable = source.getBoolean("frameCapable");
                i.frameVolumes = source.getIntValue("frameVolumes");
                i.payloadOnlyVolumes = source.getIntValue("payloadOnlyVolumes");
            }
            JSONArray files = json.getJSONArray("files");
            if (files != null) {
                for (int k = 0; k < files.size(); k++) {
                    JSONObject o = files.getJSONObject(k);
                    FileRow f = new FileRow();
                    f.name = o.getString("name");
                    f.path = o.getString("path");
                    f.kind = o.getString("kind");
                    f.replayable = o.getBooleanValue("replayable");
                    f.hasFrames = o.getBoolean("hasFrames");
                    f.windowStart = longOrNull(o, "windowStartMs");
                    f.windowEnd = longOrNull(o, "windowEndMs");
                    f.dataStart = longOrNull(o, "dataStartMs");
                    f.dataEnd = longOrNull(o, "dataEndMs");
                    f.duration = longOrNull(o, "durationMs");
                    f.bytes = o.getLongValue("bytes");
                    f.status = o.getString("status");
                    f.note = o.getString("note");
                    i.files.add(f);
                }
            }
            return i;
        }
    }

    static final class UiStatus {
        long seq;
        String state;
        String message;
        String requestedMode;
        String effectiveMode;
        Long windowFrom;
        Long windowTo;
        Long availableEnd;
        Long playhead;
        Long sourceStart;
        Long sourceEnd;
        Long etaMs;
        boolean paused;
        boolean seeking;
        boolean waiting;
        double speedTarget;
        double speedCurrent;
        long examined;
        long sent;
        long bytes;
        /** 子进程上报的非致命告警（例如注入自检失败、参数被忽略）。 */
        java.util.List<String> warnings = java.util.List.of();
        /** 最近一次 error 快照的 message；null 表示没有错误。 */
        String lastError;

        static UiStatus from(JSONObject json) {
            UiStatus s = new UiStatus();
            s.seq = json.getLongValue("seq");
            s.state = json.getString("state");
            s.message = json.getString("message");
            s.requestedMode = json.getString("requestedMode");
            s.effectiveMode = json.getString("effectiveMode");
            JSONObject window = json.getJSONObject("window");
            if (window != null) {
                s.windowFrom = longOrNull(window, "fromMs");
                s.windowTo = longOrNull(window, "toMs");
                s.availableEnd = longOrNull(window, "availableEndMs");
            }
            s.playhead = longOrNull(json, "playheadMs");
            s.paused = json.getBooleanValue("paused");
            s.seeking = json.getBooleanValue("seeking");
            s.waiting = json.getBooleanValue("waitingForData");
            JSONObject source = json.getJSONObject("source");
            if (source != null) {
                s.sourceStart = longOrNull(source, "dataStartMs");
                s.sourceEnd = longOrNull(source, "dataEndMs");
            }
            JSONObject speed = json.getJSONObject("speed");
            if (speed != null) {
                s.speedTarget = speed.getDoubleValue("target");
                s.speedCurrent = speed.getDoubleValue("current");
            }
            JSONObject counters = json.getJSONObject("counters");
            if (counters != null) {
                s.examined = counters.getLongValue("examined");
                s.sent = counters.getLongValue("sent");
                s.bytes = counters.getLongValue("bytes");
            }
            JSONObject timing = json.getJSONObject("timing");
            if (timing != null) {
                s.etaMs = longOrNull(timing, "etaMs");
            }
            com.alibaba.fastjson2.JSONArray warnings = json.getJSONArray("warnings");
            if (warnings != null && !warnings.isEmpty()) {
                java.util.List<String> messages = new java.util.ArrayList<>();
                for (int i = 0; i < warnings.size(); i++) {
                    JSONObject w = warnings.getJSONObject(i);
                    if (w != null) {
                        messages.add(w.getString("message"));
                    }
                }
                s.warnings = messages;
            }
            JSONObject lastError = json.getJSONObject("lastError");
            if (lastError != null) {
                s.lastError = lastError.getString("message");
            }
            return s;
        }
    }

    private static Long longOrNull(JSONObject o, String key) {
        if (o == null || !o.containsKey(key)) {
            return null;
        }
        return o.getLong(key);
    }
}
