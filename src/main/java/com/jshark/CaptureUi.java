package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import static com.jshark.UiFormat.*;
import static com.jshark.UiTheme.*;

/**
 * 采集端图形界面（{@code --ui}）。
 *
 * <h3>定位</h3>
 * <p>与重放 UI 同风格，但只做采集必需的事：配置 → Start → 看计数/分卷 → Stop。
 * 真正的采集在子进程里跑（{@code CliShark --control stdio}），UI 只负责组装参数、
 * 读 NDJSON 状态、发 start/stop；关窗时先让子进程完成 CHECKPOINT + 更名再退出。</p>
 *
 * <h3>线程</h3>
 * <p>所有 Swing 状态更新都经 {@link SwingUtilities#invokeLater}；子进程的 stdout/stderr
 * 各由一个守护线程读取，绝不在 EDT 上做阻塞 IO。</p>
 */
public final class CaptureUi {

    private CaptureUi() {
    }

    /**
     * 启动 GUI 并阻塞到窗口关闭。
     *
     * @param args 命令行参数（当前不做参数预填：与重放 UI 一样，不记住上次参数）
     */
    public static void launch(String[] args) {
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("Error: --ui requires a graphical environment (headless JVM detected)");
            throw new CliExitException(CliExitException.EXIT_USAGE, "--ui requires a graphical environment", null);
        }
        CountDownLatch closed = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                installTheme(true);
                CaptureFrame frame = new CaptureFrame(closed);
                frame.setVisible(true);
            } catch (Throwable t) {
                t.printStackTrace();
                closed.countDown();
                System.exit(1);
            }
        });
        try {
            closed.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ==================== 主题 ====================

    static void installTheme(boolean dark) {
        UiTheme.install(dark);
    }
    /** 主题切换后递归重新着色（UIManager 只管新组件与大部分默认值）。 */
        // ==================== 参数组装（可单测） ====================

    /**
     * UI 表单的一份纯数据快照（便于无头单测参数组装）。
     */
    record CaptureForm(String ip, String filter, String expression,
                       boolean parseDetails, boolean promiscuous, boolean immediate,
                       String multicast, boolean logDb, String logDbPath,
                       boolean pcap, String pcapPath, String split,
                       int parseThreads, String pcapBuffer, String logFile) {
    }

    /** null 安全去空白（表单输入可能为 null）。 */
    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    /**
     * 把表单翻译成 {@code CliShark} 参数（不含 {@code --control stdio}）。
     *
     * @param f 表单
     * @return 参数列表
     * @throws IllegalArgumentException 参数不合法（消息可直接展示给用户）
     */
    static List<String> buildArgs(CaptureForm f) {
        List<String> args = new ArrayList<>();
        String ip = trim(f.ip());
        if (ip.isEmpty()) {
            throw new IllegalArgumentException("Select an interface IP address.");
        }
        args.add("--ip_address");
        args.add(ip);

        String filter = trim(f.filter());
        if (!filter.isEmpty()) {
            args.add("--filter");
            args.add(filter);
        }
        String expression = trim(f.expression());
        if (!expression.isEmpty()) {
            args.add("--exfilter");
            args.add(expression);
        }
        // 表达式隐含 --enable_additioninfo=true（CLI 也会自动开启）；显式下发便于阅读命令行
        if (f.parseDetails() || !expression.isEmpty()) {
            args.add("--enable_additioninfo=true");
        }
        if (f.promiscuous()) {
            args.add("--promiscuous");
        }
        if (f.immediate()) {
            args.add("--immediate");
        }
        for (String group : multicastGroups(f.multicast())) {
            args.add("--multicast");
            args.add(group);
        }

        String logDb = trim(f.logDbPath());
        String pcap = trim(f.pcapPath());
        if (!f.logDb() && !f.pcap()) {
            throw new IllegalArgumentException("Enable Log DB or PCAP (at least one output is required).");
        }
        if (f.logDb()) {
            if (logDb.isEmpty()) {
                throw new IllegalArgumentException("Log DB is enabled but its path is empty.");
            }
            args.add("--logdb");
            args.add(logDb);
        }
        if (f.pcap()) {
            if (pcap.isEmpty()) {
                throw new IllegalArgumentException("PCAP is enabled but its path is empty.");
            }
            args.add("--pcapoutput");
            args.add(pcap);
        }

        String split = trim(f.split());
        if (!split.isEmpty()) {
            validateSplit(split);
            args.add("--split");
            args.add(split);
        }
        if (f.parseThreads() != 1) {
            if (f.parseThreads() <= 0) {
                throw new IllegalArgumentException("Parse threads must be a positive integer.");
            }
            args.add("--parse-threads");
            args.add(Integer.toString(f.parseThreads()));
        }
        String buffer = trim(f.pcapBuffer());
        if (!buffer.isEmpty()) {
            try {
                if (Integer.parseInt(buffer) <= 0) {
                    throw new NumberFormatException();
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("PCAP buffer must be a positive number of MB.");
            }
            args.add("--pcap-buffer");
            args.add(buffer);
        }
        String logFile = trim(f.logFile());
        if (!logFile.isEmpty()) {
            args.add("--logfile");
            args.add(logFile);
        }
        return args;
    }

    /**
     * 校验分卷间隔：{@code <n>m|h|d}，且至少 1 分钟。
     *
     * @param split 用户输入
     */
    static void validateSplit(String split) {
        if (split == null || !split.matches("\\d+[mhd]")) {
            throw new IllegalArgumentException("Split must look like 5m / 1h / 1d (unit is required).");
        }
        long value;
        try {
            value = Long.parseLong(split.substring(0, split.length() - 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Split value is too large.");
        }
        char unit = split.charAt(split.length() - 1);
        long minutes = switch (unit) {
            case 'm' -> value;
            case 'h' -> value * 60;
            default -> value * 24 * 60;
        };
        if (minutes < 1) {
            throw new IllegalArgumentException("Split must be at least 1m.");
        }
    }

    /** 逗号分隔的组播地址；空项忽略；非法 IPv4 报错。 */
    static List<String> multicastGroups(String text) {
        List<String> groups = new ArrayList<>();
        String s = trim(text);
        if (s.isEmpty()) {
            return groups;
        }
        for (String part : s.split(",")) {
            String g = part.trim();
            if (g.isEmpty()) {
                continue;
            }
            if (!g.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                throw new IllegalArgumentException("Invalid multicast address: " + g);
            }
            for (String octet : g.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    throw new IllegalArgumentException("Invalid multicast address: " + g);
                }
            }
            groups.add(g);
        }
        return groups;
    }

        // ==================== 格式化 ====================

                        // ==================== 表格模型 ====================

    record Volume(long seq, String file, long startMs, long endMs,
                  long packets, long bytes, String status) {
    }

    static final class UiStatus {
        long seq;
        String state = "";
        String message = "";
        long elapsedMs;
        long captured;
        long stored;
        long filtered;
        long dropped;
        long bytes;
        String currentVolume;
        final List<Volume> volumes = new ArrayList<>();

        static UiStatus from(JSONObject o) {
            UiStatus s = new UiStatus();
            s.seq = o.getLongValue("seq");
            s.state = o.getString("state");
            s.message = o.getString("message");
            s.elapsedMs = o.getLongValue("elapsedMs");
            s.captured = o.getLongValue("captured");
            s.stored = o.getLongValue("stored");
            s.filtered = o.getLongValue("filtered");
            s.dropped = o.getLongValue("dropped");
            s.bytes = o.getLongValue("bytes");
            s.currentVolume = o.getString("currentVolume");
            JSONArray arr = o.getJSONArray("volumes");
            if (arr != null) {
                for (int i = 0; i < arr.size(); i++) {
                    JSONObject v = arr.getJSONObject(i);
                    s.volumes.add(new Volume(v.getLongValue("seq"), v.getString("file"),
                            v.getLongValue("startMs"), v.getLongValue("endMs"),
                            v.getLongValue("packets"), v.getLongValue("bytes"),
                            v.getString("status")));
                }
            }
            return s;
        }
    }

    // ==================== 子进程 ====================

    private interface Callbacks {
        void onStatus(JSONObject json);

        void onTerminal(JSONObject json);

        void onLog(String line);

        void onExit(int code);
    }

    private static final class CaptureProcess {
        private final UiProcess process;

        private CaptureProcess(UiProcess process) {
            this.process = process;
        }

        static CaptureProcess start(List<String> args, Callbacks callbacks) throws IOException {
            List<String> cmd = new ArrayList<>(
                    UiLauncher.command(CliShark.class, "com.jshark.CliShark", args));
            cmd.add("--control");
            cmd.add("stdio");
            UiProcess client = UiProcess.start(cmd, "capture-ui", new UiProcess.Events() {
                @Override
                public void onEvent(JSONObject json) {
                    String type = json.getString("type");
                    if ("status".equals(type)) {
                        callbacks.onStatus(json);
                    } else if ("terminal".equals(type)) {
                        callbacks.onTerminal(json);
                    } else if ("hello".equals(type)) {
                        callbacks.onLog("[control] " + json.getString("session"));
                    } else if ("ack".equals(type) && !json.getBooleanValue("ok")) {
                        callbacks.onLog("[control] command failed: " + json.getString("error"));
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
            return new CaptureProcess(client);
        }

        long send(String cmd) throws IOException {
            return process.send(cmd);
        }

        void kill() {
            process.kill();
        }

        /** 采集已经结束：关闭 stdin 让子进程自然退出（不要 destroy，避免打断收尾）。 */
        void closeStdin() {
            process.closeStdin();
        }
    }

    // ==================== 主窗口 ====================

    static final class CaptureFrame extends JFrame {
        private static final String VERSION = version();

        private final CountDownLatch closed;

        private final JComboBox<String> nicBox = new JComboBox<>();
        private final JButton refreshBtn = new JButton("Refresh");
        private final JCheckBox promiscuousBox = new JCheckBox("Promiscuous");
        private final JCheckBox immediateBox = new JCheckBox("Immediate");
        private final JComboBox<String> themeBox = new JComboBox<>(new String[]{"Dark", "Light"});
        private final JTextField multicastField = new JTextField();

        private final JTextField filterField = new JTextField();
        private final JTextField exprField = new JTextField();
        private final JCheckBox parseDetailsBox = new JCheckBox("Parse details (additionalInfo)");

        private final JCheckBox logDbCheck = new JCheckBox();
        private final JTextField logDbField = new JTextField();
        private final JButton logDbBrowse = new JButton("Browse…");
        private final JCheckBox pcapCheck = new JCheckBox();
        private final JTextField pcapField = new JTextField();
        private final JButton pcapBrowse = new JButton("Browse…");
        private final JComboBox<String> splitBox = new JComboBox<>(new String[]{"", "1m", "5m", "10m", "1h"});

        private final JButton advancedToggle = new JButton("▸ Advanced");
        private final JPanel advancedPanel = new JPanel(new GridBagLayout());
        private final JSpinner parseThreadsSpinner =
                new JSpinner(new SpinnerNumberModel(1, 1, Math.max(4, 4 * Runtime.getRuntime().availableProcessors()), 1));
        private final JTextField pcapBufferField = new JTextField("64");
        private final JTextField logFileField = new JTextField();
        private final JButton logFileBrowse = new JButton("Browse…");

        private final DefaultTableModel volumeModel = new DefaultTableModel(
                new Object[]{"File", "Window", "Packets", "Size", "Status"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        private final JTable volumeTable = new JTable(volumeModel);
        private final JLabel volumeSummary = new JLabel("—");

        private final JLabel elapsedLabel = new JLabel("00:00:00");
        private final JLabel stateLabel = new JLabel("IDLE");
        private final JLabel hintLabel = new JLabel(" ");
        private final JLabel logCountLabel = new JLabel("Log 0 warnings · 0 errors");
        private final JLabel capturedValue = new JLabel("0");
        private final JLabel storedValue = new JLabel("0");
        private final JLabel filteredValue = new JLabel("0");
        private final JLabel droppedValue = new JLabel("0");
        private final JLabel rateLabel = new JLabel("—");
        private final JLabel currentPathLabel = new JLabel("—");
        private final JButton startBtn = new JButton("Start");
        private final JButton stopBtn = new JButton("Stop");

        private final JTextArea logArea = new JTextArea();
        private final JLabel envLabel = new JLabel("checking Npcap…");
        private final JLabel versionLabel = new JLabel("JShark " + VERSION + " · Capture");

        private final List<javax.swing.JComponent> paramComponents = new ArrayList<>();
        private final List<JButton> browseButtons = new ArrayList<>();

        private CaptureProcess process;
        private boolean running;
        private boolean startSent;
        private boolean closing;
        private boolean userClosing;
        private long lastStatusSeq;
        private Timer startWatchdog;
        private Timer stopWatchdog;
        private Timer closeTimer;
        private int warnings;
        private int errors;

        private long lastStatusNanos;
        private long lastCaptured;
        private long lastBytes;
        private double pps;
        private double mbps;

        CaptureFrame(CountDownLatch closed) {
            super("JShark Capture");
            this.closed = closed;
            UiIcons.apply(this);

            setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    closeUi();
                }

                @Override
                public void windowClosed(WindowEvent e) {
                    closed.countDown();
                }
            });

            buildUi();
            refreshInterfaces();
            probeEnvironment();

            setMinimumSize(new Dimension(980, 680));
            setSize(1180, 800);
            setLocationRelativeTo(null);

            themeBox.addActionListener(e -> {
                boolean dark = "Dark".equals(themeBox.getSelectedItem());
                if (dark == darkTheme) {
                    return;
                }
                installTheme(dark);
                SwingUtilities.updateComponentTreeUI(this);
                restyle(getContentPane());
                repaint();
            });
        }

        private static String version() {
            String v = CliShark.class.getPackage() == null
                    ? null : CliShark.class.getPackage().getImplementationVersion();
            return v == null ? "1.0.0" : v;
        }

        // ---------- 构建界面 ----------

        private void buildUi() {
            JPanel root = new JPanel(new BorderLayout(0, 6));
            root.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
            root.putClientProperty("ui.role", "root");
            setContentPane(root);

            root.add(buildHeader(), BorderLayout.NORTH);

            JTabbedPane tabs = new JTabbedPane();
            JPanel captureTab = new JPanel(new BorderLayout(0, 0));
            JScrollPane paramsScroll = new JScrollPane(buildParams());
            paramsScroll.setPreferredSize(new Dimension(0, 360));
            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                    paramsScroll, buildVolumesPanel());
            split.setResizeWeight(0.70);
            split.setContinuousLayout(true);
            split.setDividerSize(6);
            split.setBorder(null);
            captureTab.add(split, BorderLayout.CENTER);
            tabs.addTab("Capture", captureTab);
            logArea.setEditable(false);
            logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
            tabs.addTab("Log", new JScrollPane(logArea));
            root.add(tabs, BorderLayout.CENTER);

            JPanel south = new JPanel(new BorderLayout(0, 4));
            south.putClientProperty("ui.role", "player");
            south.add(buildPlayer(), BorderLayout.CENTER);
            south.add(buildStatusBar(), BorderLayout.SOUTH);
            root.add(south, BorderLayout.SOUTH);

            installActions();
        }

        private JPanel buildHeader() {
            JPanel header = new JPanel(new GridBagLayout());
            header.putClientProperty("ui.role", "root");

            nicBox.setEditable(true);
            nicBox.setPreferredSize(new Dimension(260, 28));
            refreshBtn.setPreferredSize(new Dimension(80, 28));
            themeBox.setPreferredSize(new Dimension(84, 28));
            multicastField.setPreferredSize(new Dimension(520, 28));

            GridBagConstraints c = gbc(0, 0);
            header.add(label("IP address"), c);
            c = gbc(1, 0);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 0;
            header.add(nicBox, c);
            header.add(Box.createHorizontalStrut(6), gbc(2, 0));
            header.add(refreshBtn, gbc(3, 0));
            header.add(promiscuousBox, gbc(4, 0));
            header.add(immediateBox, gbc(5, 0));
            c = gbc(6, 0);
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            header.add(Box.createHorizontalGlue(), c);
            header.add(labelMuted("Theme"), gbc(7, 0));
            header.add(themeBox, gbc(8, 0));

            JLabel env = labelMuted("Live capture · Npcap · run as administrator");
            env.putClientProperty("ui.kind", "muted");
            c = gbc(0, 1);
            c.gridwidth = 9;
            c.insets = new Insets(2, 4, 2, 4);
            header.add(env, c);

            header.add(label("Multicast"), gbc(0, 2));
            c = gbc(1, 2);
            c.gridwidth = 4;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            header.add(multicastField, c);
            c = gbc(5, 2);
            c.gridwidth = 4;
            c.insets = new Insets(3, 8, 3, 4);
            header.add(labelMuted("comma separated · optional · joined before capture"), c);

            promiscuousBox.putClientProperty("ui.kind", "check");
            immediateBox.putClientProperty("ui.kind", "check");
            paramComponents.add(nicBox);
            paramComponents.add(refreshBtn);
            paramComponents.add(promiscuousBox);
            paramComponents.add(immediateBox);
            paramComponents.add(multicastField);
            return header;
        }

        private JPanel buildParams() {
            JPanel p = new JPanel(new GridBagLayout());
            p.putClientProperty("ui.role", "root");
            p.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
            int row = 0;
            row = section(p, row, "FILTER");
            row = fieldRow(p, row, "BPF filter", filterField,
                    "Kernel-level filter, e.g. \"udp port 3000\" — leave empty to capture everything.");
            row = expressionRow(p, row);
            row = section(p, row, "OUTPUT");
            row = outputRow(p, row, logDbCheck, "Log DB", logDbField, logDbBrowse, true);
            row = outputRow(p, row, pcapCheck, "PCAP", pcapField, pcapBrowse, false);
            row = splitRow(p, row);
            row = advancedRow(p, row);
            return p;
        }

        private int section(JPanel p, int row, String caption) {
            JLabel l = new JLabel(caption);
            l.putClientProperty("ui.kind", "section");
            l.setForeground(MUTED);
            l.setFont(l.getFont().deriveFont(Font.BOLD, 10f));
            GridBagConstraints c = gbc(0, row);
            c.gridwidth = 4;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.insets = new Insets(12, 4, 4, 4);
            p.add(l, c);
            return row + 1;
        }

        private int fieldRow(JPanel p, int row, String labelText, JTextField field, String hint) {
            p.add(label(labelText), gbc(0, row));
            GridBagConstraints c = gbc(1, row);
            c.gridwidth = 3;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            p.add(field, c);
            paramComponents.add(field);
            GridBagConstraints hc = gbc(1, row + 1);
            hc.gridwidth = 3;
            p.add(hintRow(hint), hc);
            return row + 2;
        }

        private int expressionRow(JPanel p, int row) {
            p.add(label("Expression"), gbc(0, row));
            GridBagConstraints c = gbc(1, row);
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            p.add(exprField, c);
            GridBagConstraints pc = gbc(2, row);
            pc.gridwidth = 2;
            p.add(parseDetailsBox, pc);
            paramComponents.add(exprField);
            paramComponents.add(parseDetailsBox);
            GridBagConstraints hc = gbc(1, row + 1);
            hc.gridwidth = 3;
            p.add(hintRow("Matches additionalInfo; unmatched packets are dropped. "
                    + "Setting an expression automatically enables Parse details."), hc);
            return row + 2;
        }

        private int outputRow(JPanel p, int row, JCheckBox check, String labelText,
                              JTextField field, JButton browse, boolean checked) {
            check.setSelected(checked);
            JPanel head = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            head.setOpaque(false);
            head.add(check);
            head.add(label(labelText));
            p.add(head, gbc(0, row));
            GridBagConstraints c = gbc(1, row);
            c.gridwidth = 2;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            p.add(field, c);
            JButton b = browse;
            b.setPreferredSize(new Dimension(86, 28));
            p.add(b, gbc(3, row));
            paramComponents.add(check);
            paramComponents.add(field);
            paramComponents.add(b);
            browseButtons.add(b);
            return row + 2;
        }

        private int splitRow(JPanel p, int row) {
            p.add(label("Split"), gbc(0, row));
            splitBox.setEditable(true);
            splitBox.setPreferredSize(new Dimension(90, 28));
            splitBox.setToolTipText("Leave empty for a single file");
            p.add(splitBox, gbc(1, row));
            GridBagConstraints c = gbc(2, row);
            c.gridwidth = 2;
            c.insets = new Insets(3, 8, 3, 4);
            p.add(hintRow("m / h / d · minimum 1m · leave empty for a single file"), c);
            paramComponents.add(splitBox);
            return row + 1;
        }

        private int advancedRow(JPanel p, int row) {
            advancedToggle.setHorizontalAlignment(SwingConstants.LEFT);
            advancedToggle.setFont(advancedToggle.getFont().deriveFont(Font.BOLD, 12f));
            advancedToggle.setBorder(BorderFactory.createLineBorder(BORDER));
            advancedToggle.setBackground(PANEL);
            GridBagConstraints c = gbc(0, row);
            c.gridwidth = 4;
            c.fill = GridBagConstraints.HORIZONTAL;
            p.add(advancedToggle, c);
            paramComponents.add(advancedToggle);

            advancedPanel.setOpaque(false);
            advancedPanel.setVisible(false);
            int ar = 0;
            advancedPanel.add(label("Parse threads"), gbc(0, ar));
            parseThreadsSpinner.setPreferredSize(new Dimension(90, 28));
            advancedPanel.add(parseThreadsSpinner, gbc(1, ar));
            advancedPanel.add(label("PCAP buffer (MB)"), gbc(2, ar));
            pcapBufferField.setPreferredSize(new Dimension(90, 28));
            advancedPanel.add(pcapBufferField, gbc(3, ar));
            ar++;
            advancedPanel.add(label("Log file"), gbc(0, ar));
            GridBagConstraints lc = gbc(1, ar);
            lc.gridwidth = 2;
            lc.weightx = 1;
            lc.fill = GridBagConstraints.HORIZONTAL;
            advancedPanel.add(logFileField, lc);
            logFileBrowse.setPreferredSize(new Dimension(86, 28));
            advancedPanel.add(logFileBrowse, gbc(3, ar));
            paramComponents.add(parseThreadsSpinner);
            paramComponents.add(pcapBufferField);
            paramComponents.add(logFileField);
            paramComponents.add(logFileBrowse);
            browseButtons.add(logFileBrowse);

            c = gbc(0, row + 1);
            c.gridwidth = 4;
            c.fill = GridBagConstraints.HORIZONTAL;
            p.add(advancedPanel, c);
            return row + 2;
        }

        private JLabel hintRow(String text) {
            JLabel l = labelMuted(text);
            l.setFont(l.getFont().deriveFont(Font.PLAIN, 11f));
            return l;
        }

        private JPanel buildVolumesPanel() {
            JPanel panel = new JPanel(new BorderLayout(0, 4));
            panel.putClientProperty("ui.role", "root");
            JPanel head = new JPanel(new BorderLayout());
            head.setOpaque(false);
            JLabel title = new JLabel("VOLUMES");
            title.putClientProperty("ui.kind", "section");
            title.setFont(title.getFont().deriveFont(Font.BOLD, 10f));
            head.add(title, BorderLayout.WEST);
            volumeSummary.putClientProperty("ui.kind", "muted");
            head.add(volumeSummary, BorderLayout.EAST);
            panel.add(head, BorderLayout.NORTH);

            volumeTable.setRowHeight(22);
            volumeTable.setShowGrid(false);
            volumeTable.setFillsViewportHeight(true);
            volumeTable.setDefaultRenderer(Object.class, new VolumeRenderer());
            volumeTable.getTableHeader().setReorderingAllowed(false);
            TableColumn fileCol = volumeTable.getColumnModel().getColumn(0);
            fileCol.setPreferredWidth(520);
            volumeTable.getColumnModel().getColumn(1).setPreferredWidth(130);
            volumeTable.getColumnModel().getColumn(2).setPreferredWidth(90);
            volumeTable.getColumnModel().getColumn(3).setPreferredWidth(90);
            volumeTable.getColumnModel().getColumn(4).setPreferredWidth(100);
            JScrollPane scroll = new JScrollPane(volumeTable);
            scroll.setBorder(BorderFactory.createLineBorder(BORDER));
            scroll.setPreferredSize(new Dimension(0, 140));
            panel.add(scroll, BorderLayout.CENTER);
            return panel;
        }

        private JPanel buildPlayer() {
            JPanel player = new JPanel(new BorderLayout(0, 4));
            player.putClientProperty("ui.role", "player");
            player.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

            JPanel top = new JPanel(new BorderLayout());
            top.setOpaque(false);
            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
            left.setOpaque(false);
            elapsedLabel.setForeground(ACCENT);
            elapsedLabel.putClientProperty("ui.kind", "accent");
            elapsedLabel.setFont(elapsedLabel.getFont().deriveFont(Font.BOLD, 22f));
            stateLabel.putClientProperty("ui.kind", "state");
            stateLabel.setFont(stateLabel.getFont().deriveFont(Font.BOLD, 12f));
            hintLabel.putClientProperty("ui.kind", "state");
            left.add(elapsedLabel);
            left.add(stateLabel);
            left.add(hintLabel);
            top.add(left, BorderLayout.WEST);
            logCountLabel.putClientProperty("ui.kind", "muted");
            logCountLabel.setHorizontalAlignment(SwingConstants.RIGHT);
            top.add(logCountLabel, BorderLayout.EAST);

            JPanel counters = new JPanel(new FlowLayout(FlowLayout.LEFT, 36, 0));
            counters.setOpaque(false);
            counters.add(stat("Captured", capturedValue));
            counters.add(stat("Stored", storedValue));
            counters.add(stat("Filtered", filteredValue));
            counters.add(stat("Dropped", droppedValue));
            rateLabel.setForeground(ACCENT);
            rateLabel.putClientProperty("ui.kind", "accent");
            rateLabel.setFont(rateLabel.getFont().deriveFont(Font.PLAIN, 12f));

            JPanel transport = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            transport.setOpaque(false);
            startBtn.setPreferredSize(new Dimension(110, 34));
            stopBtn.setPreferredSize(new Dimension(110, 34));
            startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD, 14f));
            stopBtn.setFont(stopBtn.getFont().deriveFont(Font.BOLD, 14f));
            startBtn.putClientProperty("ui.primary", true);
            startBtn.setBackground(ACCENT);
            startBtn.setForeground(ON_ACCENT);
            stopBtn.setEnabled(false);
            transport.add(startBtn);
            transport.add(stopBtn);
            JLabel stopHint = labelMuted("Stop finalizes the last volume (CHECKPOINT + rename) before the window closes.");
            stopHint.setFont(stopHint.getFont().deriveFont(Font.PLAIN, 11f));
            transport.add(stopHint);

            JPanel current = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            current.setOpaque(false);
            current.add(labelMuted("Current volume"));
            currentPathLabel.setFont(new Font("Consolas", Font.PLAIN, 11));
            current.add(currentPathLabel);

            JPanel bottom = new JPanel(new BorderLayout(0, 2));
            bottom.setOpaque(false);
            bottom.add(transport, BorderLayout.NORTH);
            bottom.add(current, BorderLayout.SOUTH);

            JPanel center = new JPanel(new BorderLayout(0, 2));
            center.setOpaque(false);
            center.add(counters, BorderLayout.WEST);
            rateLabel.setBorder(BorderFactory.createEmptyBorder(18, 0, 0, 0));
            JPanel rateWrap = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
            rateWrap.setOpaque(false);
            rateWrap.add(rateLabel);
            center.add(rateWrap, BorderLayout.EAST);

            player.add(top, BorderLayout.NORTH);
            player.add(center, BorderLayout.CENTER);
            player.add(bottom, BorderLayout.SOUTH);
            return player;
        }

        private JPanel stat(String name, JLabel value) {
            JPanel p = new JPanel();
            p.setOpaque(false);
            p.setLayout(new javax.swing.BoxLayout(p, javax.swing.BoxLayout.Y_AXIS));
            JLabel l = labelMuted(name);
            l.setFont(l.getFont().deriveFont(Font.PLAIN, 10f));
            value.setFont(value.getFont().deriveFont(Font.BOLD, 15f));
            p.add(l);
            p.add(value);
            return p;
        }

        private JPanel buildStatusBar() {
            JPanel bar = new JPanel(new BorderLayout());
            bar.putClientProperty("ui.role", "player");
            bar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            left.setOpaque(false);
            JLabel dot = new JLabel("●");
            dot.setForeground(STATE_OK);
            left.add(dot);
            envLabel.putClientProperty("ui.kind", "muted");
            envLabel.setFont(envLabel.getFont().deriveFont(Font.PLAIN, 10f));
            left.add(envLabel);
            bar.add(left, BorderLayout.WEST);
            versionLabel.putClientProperty("ui.kind", "muted");
            versionLabel.setFont(versionLabel.getFont().deriveFont(Font.PLAIN, 10f));
            bar.add(versionLabel, BorderLayout.EAST);
            return bar;
        }

        private void installActions() {
            refreshBtn.addActionListener(e -> refreshInterfaces());
            logDbBrowse.addActionListener(e -> browseInto(logDbField, "Choose the DuckDB log file"));
            pcapBrowse.addActionListener(e -> browseInto(pcapField, "Choose the PCAP output file"));
            logFileBrowse.addActionListener(e -> browseInto(logFileField, "Choose the log file"));
            logDbCheck.addActionListener(e -> logDbField.setEnabled(!running && logDbCheck.isSelected()));
            pcapCheck.addActionListener(e -> pcapField.setEnabled(!running && pcapCheck.isSelected()));
            advancedToggle.addActionListener(e -> {
                boolean show = !advancedPanel.isVisible();
                advancedPanel.setVisible(show);
                advancedToggle.setText((show ? "▾ " : "▸ ") + "Advanced");
                revalidate();
                repaint();
            });
            startBtn.addActionListener(e -> startCapture());
            stopBtn.addActionListener(e -> stopCapture());
            logDbField.setEnabled(logDbCheck.isSelected());
            pcapField.setEnabled(pcapCheck.isSelected());
        }

        private void browseInto(JTextField target, String title) {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle(title);
            String current = target.getText().trim();
            if (!current.isEmpty()) {
                File f = new File(current);
                chooser.setSelectedFile(f);
            }
            if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                target.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        }

        // ---------- 网卡 / 环境 ----------

        private void refreshInterfaces() {
            Object editorItem = nicBox.getEditor().getItem();
            String selected = editorItem == null ? "" : editorItem.toString();
            List<String> items = new ArrayList<>();
            try {
                for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                    if (!ni.isUp() || ni.isLoopback()) {
                        continue;
                    }
                    for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                        if (ia.getAddress() instanceof Inet4Address) {
                            items.add(ia.getAddress().getHostAddress() + "  ·  " + ni.getDisplayName());
                        }
                    }
                }
            } catch (Exception ignored) {
                // 枚举失败时保持空列表，用户仍可手动输入 IP
            }
            items.sort(Comparator.naturalOrder());
            nicBox.removeAllItems();
            for (String item : items) {
                nicBox.addItem(item);
            }
            if (!selected.isBlank()) {
                nicBox.getEditor().setItem(selected);
            } else if (!items.isEmpty()) {
                nicBox.setSelectedIndex(0);
            }
        }

        private void probeEnvironment() {
            Thread t = new Thread(() -> {
                String text;
                try {
                    List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
                    String raw = String.valueOf(Pcaps.libVersion());
                    java.util.regex.Matcher m = java.util.regex.Pattern
                            .compile("version\\s+([0-9][0-9.]*)").matcher(raw);
                    String ver = m.find() ? m.group(1) : raw;
                    text = "Npcap " + ver + " · " + (devs == null ? 0 : devs.size())
                            + " interfaces · run as administrator to capture";
                } catch (Throwable e) {
                    text = "Npcap unavailable — install Npcap and run as administrator";
                }
                String finalText = text;
                SwingUtilities.invokeLater(() -> envLabel.setText(finalText));
            }, "npcap-probe");
            t.setDaemon(true);
            t.start();
        }

        // ---------- 采集控制 ----------

        private CaptureForm readForm() {
            Object editorItem = nicBox.getEditor().getItem();
            String nic = editorItem == null ? "" : editorItem.toString();
            int sep = nic.indexOf("  ·  ");
            String ip = sep >= 0 ? nic.substring(0, sep).trim() : nic.trim();
            Object splitItem = splitBox.isEditable()
                    ? splitBox.getEditor().getItem() : splitBox.getSelectedItem();
            return new CaptureForm(ip, filterField.getText(), exprField.getText(),
                    parseDetailsBox.isSelected(),
                    promiscuousBox.isSelected(), immediateBox.isSelected(),
                    multicastField.getText(), logDbCheck.isSelected(), logDbField.getText(),
                    pcapCheck.isSelected(), pcapField.getText(),
                    splitItem == null ? "" : String.valueOf(splitItem),
                    (Integer) parseThreadsSpinner.getValue(), pcapBufferField.getText(),
                    logFileField.getText());
        }

        private void startCapture() {
            List<String> args;
            try {
                args = buildArgs(readForm());
            } catch (IllegalArgumentException e) {
                setHint(e.getMessage(), STATE_FAIL);
                return;
            }
            setHint("Starting capture…", MUTED);
            lastStatusSeq = 0;
            startSent = false;
            lastStatusNanos = 0;
            lastCaptured = 0;
            lastBytes = 0;
            pps = 0;
            mbps = 0;
            volumeModel.setRowCount(0);
            volumeSummary.setText("—");
            logArea.setText("");
            warnings = 0;
            errors = 0;
            logCountLabel.setText("Log 0 warnings · 0 errors");
            currentPathLabel.setText("—");

            try {
                process = CaptureProcess.start(args, new Callbacks() {
                    @Override
                    public void onStatus(JSONObject json) {
                        UiStatus status = UiStatus.from(json);
                        SwingUtilities.invokeLater(() -> applyStatus(status));
                    }

                    @Override
                    public void onTerminal(JSONObject json) {
                        // 终态由后续 status 统一处理；这里只记录一行日志
                        SwingUtilities.invokeLater(() -> log("[control] " + json.getString("type")));
                    }

                    @Override
                    public void onLog(String line) {
                        SwingUtilities.invokeLater(() -> log(line));
                    }

                    @Override
                    public void onExit(int code) {
                        SwingUtilities.invokeLater(() -> onProcessExit(code));
                    }
                });
            } catch (IOException e) {
                setHint("Failed to start capture: " + e.getMessage(), STATE_FAIL);
                return;
            }

            running = true;
            setParamsEnabled(false);
            setRunningControls(true);
            stateLabel.setText("STARTING");
            stateLabel.setForeground(ACCENT);
            startStartWatchdog();
        }

        private void applyStatus(UiStatus s) {
            if (s.seq > 0 && s.seq <= lastStatusSeq) {
                return;
            }
            lastStatusSeq = s.seq;

            if ("READY".equals(s.state) && !startSent) {
                startSent = true;
                stopStartWatchdog();
                send("start");
            }

            String state = s.state == null ? "" : s.state;
            stateLabel.setText(state.isEmpty() ? "—" : state);
            stateLabel.setForeground(switch (state) {
                case "RUNNING" -> STATE_OK;
                case "FAILED" -> STATE_FAIL;
                case "STOPPING", "STARTING" -> ACCENT;
                default -> MUTED;
            });

            elapsedLabel.setText(formatElapsed(s.elapsedMs));
            capturedValue.setText(formatCount(s.captured));
            storedValue.setText(formatCount(s.stored));
            filteredValue.setText(formatCount(s.filtered));
            droppedValue.setText(formatCount(s.dropped));
            updateRate(s);
            currentPathLabel.setText(s.currentVolume == null || s.currentVolume.isBlank()
                    ? "—" : s.currentVolume);

            applyVolumes(s);

            String message = s.message == null ? "" : s.message;
            if (!message.isBlank() && ("FAILED".equals(state) || "STOPPING".equals(state))) {
                setHint(message, STATE_FAIL);
            }
            if ("FINISHED".equals(state) || "FAILED".equals(state)) {
                finishRun(state, message);
            }
        }

        private void updateRate(UiStatus s) {
            long now = System.nanoTime();
            if (lastStatusNanos > 0 && now > lastStatusNanos) {
                double secs = (now - lastStatusNanos) / 1_000_000_000.0;
                if (secs > 0.05) {
                    pps = Math.max(0, s.captured - lastCaptured) / secs;
                    mbps = Math.max(0, s.bytes - lastBytes) / secs / (1024.0 * 1024.0);
                }
            }
            lastStatusNanos = now;
            lastCaptured = s.captured;
            lastBytes = s.bytes;
            rateLabel.setText(pps >= 1000
                    ? String.format("%.1fk pps · %.2f MB/s", pps / 1000.0, mbps)
                    : String.format("%.0f pps · %.2f MB/s", pps, mbps));
        }

        private void applyVolumes(UiStatus s) {
            int capturing = 0;
            for (Volume v : s.volumes) {
                if ("capturing".equals(v.status())) {
                    capturing++;
                }
            }
            volumeSummary.setText(s.volumes.size() + " volumes"
                    + (capturing > 0 ? " · " + capturing + " capturing" : ""));

            boolean sameShape = s.volumes.size() == volumeModel.getRowCount();
            if (sameShape) {
                for (int i = 0; i < s.volumes.size(); i++) {
                    Object current = volumeModel.getValueAt(i, 0);
                    if (!String.valueOf(s.volumes.get(i).file()).equals(String.valueOf(current))) {
                        sameShape = false;
                        break;
                    }
                }
            }
            if (!sameShape) {
                volumeModel.setRowCount(0);
                for (Volume v : s.volumes) {
                    volumeModel.addRow(new Object[]{
                            v.file(), formatWindow(v.startMs(), v.endMs()),
                            formatCount(v.packets()), formatBytes(v.bytes()), v.status()});
                }
                return;
            }
            // 行集合没变：原地更新，避免每 250ms 重建表格导致闪烁/滚动位置丢失。
            for (int i = 0; i < s.volumes.size(); i++) {
                Volume v = s.volumes.get(i);
                volumeModel.setValueAt(formatWindow(v.startMs(), v.endMs()), i, 1);
                volumeModel.setValueAt(formatCount(v.packets()), i, 2);
                volumeModel.setValueAt(formatBytes(v.bytes()), i, 3);
                volumeModel.setValueAt(v.status(), i, 4);
            }
        }

        private void finishRun(String state, String message) {
            if (!running) {
                return;
            }
            running = false;
            stopStartWatchdog();
            stopStopWatchdog();
            setParamsEnabled(true);
            setRunningControls(false);
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            if ("FAILED".equals(state) && message != null && !message.isBlank()) {
                setHint(message, STATE_FAIL);
            } else if ("FINISHED".equals(state)) {
                setHint("Finished. Last volume checkpointed and renamed.", MUTED);
            }
            closeChild();
            if (closing) {
                dispose();
            }
        }

        private void closeChild() {
            CaptureProcess p = process;
            process = null;
            if (p != null) {
                p.closeStdin();
            }
        }

        private void onProcessExit(int code) {
            process = null;
            if (!running) {
                return;
            }
            running = false;
            stopStartWatchdog();
            stopStopWatchdog();
            setParamsEnabled(true);
            setRunningControls(false);
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            if (code == 0) {
                stateLabel.setText("FINISHED");
                stateLabel.setForeground(STATE_OK);
                setHint("Finished.", MUTED);
            } else {
                stateLabel.setText("FAILED");
                stateLabel.setForeground(STATE_FAIL);
                setHint("Capture process exited with code " + code + " — see the Log tab.", STATE_FAIL);
            }
            if (closing) {
                dispose();
            }
        }

        private void stopCapture() {
            if (!running || process == null) {
                return;
            }
            send("stop");
            stateLabel.setText("STOPPING");
            stateLabel.setForeground(ACCENT);
            stopBtn.setEnabled(false);
            setHint("Finalizing the last volume (CHECKPOINT + rename)…", ACCENT);
            startStopWatchdog();
        }

        /** 停止请求的兜底：收尾预算 6s，15s 还没结束就认为子进程卡住。 */
        private void startStopWatchdog() {
            stopStopWatchdog();
            stopWatchdog = new Timer(15_000, e -> {
                if (running) {
                    log("[ui] stop timed out: child did not finish within 15s; killing it");
                    setHint("Stop timed out — the capture child was killed; check the last volume.", STATE_FAIL);
                    if (process != null) {
                        process.kill();
                    }
                }
            });
            stopWatchdog.setRepeats(false);
            stopWatchdog.start();
        }

        private void stopStopWatchdog() {
            if (stopWatchdog != null) {
                stopWatchdog.stop();
                stopWatchdog = null;
            }
        }

        private void send(String cmd) {
            CaptureProcess p = process;
            if (p == null) {
                return;
            }
            try {
                p.send(cmd);
            } catch (IOException e) {
                log("[ui] failed to send " + cmd + ": " + e.getMessage());
            }
        }

        private void startStartWatchdog() {
            stopStartWatchdog();
            startWatchdog = new Timer(15_000, e -> {
                if (running && !startSent) {
                    stopStartWatchdog();
                    log("[ui] start timed out: no READY within 15s");
                    setHint("Capture child did not become ready within 15s — see the Log tab.", STATE_FAIL);
                    if (process != null) {
                        process.kill();
                    }
                }
            });
            startWatchdog.setRepeats(false);
            startWatchdog.start();
        }

        private void stopStartWatchdog() {
            if (startWatchdog != null) {
                startWatchdog.stop();
                startWatchdog = null;
            }
        }

        private void setRunningControls(boolean isRunning) {
            startBtn.setEnabled(!isRunning);
            stopBtn.setEnabled(isRunning);
            themeBox.setEnabled(!isRunning);
        }

        private void setParamsEnabled(boolean enabled) {
            for (javax.swing.JComponent c : paramComponents) {
                c.setEnabled(enabled);
            }
            for (JButton b : browseButtons) {
                b.setEnabled(enabled);
            }
            if (!enabled) {
                advancedToggle.setEnabled(false);
            } else {
                advancedToggle.setEnabled(true);
                logDbField.setEnabled(logDbCheck.isSelected());
                pcapField.setEnabled(pcapCheck.isSelected());
            }
        }

        private void setHint(String text, Color color) {
            hintLabel.setText(text == null || text.isBlank() ? " " : text);
            hintLabel.setForeground(color);
        }

        private void log(String line) {
            if (line == null) {
                return;
            }
            String upper = line.toUpperCase(java.util.Locale.ROOT);
            if (upper.contains("ERROR") || upper.contains("EXCEPTION")) {
                errors++;
            } else if (upper.contains("WARN")) {
                warnings++;
            }
            logCountLabel.setText("Log " + warnings + " warnings · " + errors + " errors");
            logArea.append(line + System.lineSeparator());
            int len = logArea.getDocument().getLength();
            if (len > 400_000) {
                logArea.replaceRange("", 0, len - 300_000);
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        }

        private void closeUi() {
            userClosing = true;
            if (!running) {
                dispose();
                return;
            }
            if (!startSent) {
                // 子进程还没进入采集（连 READY 都没收到）：直接结束，不必等收尾。
                closing = true;
                if (process != null) {
                    process.kill();
                }
                dispose();
                return;
            }
            int rc = JOptionPane.showConfirmDialog(this,
                    "A capture is running. Stop it and finalize the last volume?",
                    "JShark Capture", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (rc != JOptionPane.OK_OPTION) {
                return;
            }
            closing = true;
            stopCapture();
            if (closeTimer != null) {
                closeTimer.stop();
            }
            long deadline = System.currentTimeMillis() + 10_000;
            closeTimer = new Timer(200, e -> {
                if (!running || System.currentTimeMillis() > deadline) {
                    closeTimer.stop();
                    if (process != null) {
                        process.kill();
                    }
                    dispose();
                }
            });
            closeTimer.start();
        }

        @Override
        public void dispose() {
            if (closeTimer != null) {
                closeTimer.stop();
            }
            stopStartWatchdog();
            stopStopWatchdog();
            super.dispose();
            // 只有用户关窗才退出进程；测试/嵌入式 dispose 不应杀掉 JVM。
            if (userClosing) {
                new Timer(300, e -> System.exit(0)).start();
            }
        }
    }

    // ==================== 表格渲染 ====================

    private static final class VolumeRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            String status = String.valueOf(table.getModel().getValueAt(row, 4));
            if (column == 0) {
                String path = String.valueOf(value);
                setText(fileName(path));
                setToolTipText(path);
                setHorizontalAlignment(SwingConstants.LEFT);
            } else if (column == 1) {
                setHorizontalAlignment(SwingConstants.LEFT);
                setToolTipText(null);
            } else if (column == 2 || column == 3) {
                setHorizontalAlignment(SwingConstants.RIGHT);
                setToolTipText(null);
            } else {
                setHorizontalAlignment(SwingConstants.LEFT);
                setToolTipText(null);
            }
            if (!isSelected) {
                if (column == 4) {
                    setForeground(switch (status) {
                        case "complete" -> STATE_OK;
                        case "capturing" -> ACCENT;
                        default -> MUTED;
                    });
                } else if (column == 1 || column == 3) {
                    setForeground(MUTED);
                } else {
                    setForeground(FG);
                }
            }
            return c;
        }
    }

    // ==================== 小工具 ====================

    private static JLabel label(String text) {
        return new JLabel(text);
    }

        }
