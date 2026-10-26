package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.PlainDocument;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.RoundRectangle2D;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import static com.jshark.UiFormat.*;
import static com.jshark.UiTheme.*;

/**
 * 转发器图形界面（{@code --ui}）。
 *
 * <p>思路与采集 UI 一致：UI 只负责表单和状态，真正的转发在
 * {@code CliForwarder --control stdio} 子进程里；已填内容保留在内存里（不落盘）。</p>
 */
public final class ForwarderUi {

    private ForwarderUi() {
    }

    public static void launch(String[] args) {
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("Error: --ui requires a graphical environment (headless JVM detected)");
            throw new CliExitException(CliExitException.EXIT_USAGE, "--ui requires a graphical environment", null);
        }
        CountDownLatch closed = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                installTheme(true);
                ForwarderFrame frame = new ForwarderFrame(closed);
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
        // ==================== 协议解析 ====================

    record Peer(String address, String state, long sinceMs) {
    }

    static final class UiStatus {
        long seq;
        String state = "";
        /** 服务端模式（bridge），当前 UI 不展示，但属于状态协议的一部分（回归测试按字段校验）。 */
        String mode = "";
        String message = "";
        long elapsedMs;
        long udpToTcpPackets;
        long udpToTcpBytes;
        long tcpToUdpPackets;
        long tcpToUdpBytes;
        long dropped;
        long udpIn;
        /** 服务端算好的丢包率，保留用于协议回归；UI 展示时按 dropped/udpIn 重算。 */
        double dropRate;
        String listen = "";
        String udpLocal = "";
        final List<Peer> peers = new ArrayList<>();

        static UiStatus from(JSONObject o) {
            UiStatus s = new UiStatus();
            s.seq = o.getLongValue("seq");
            s.state = o.getString("state");
            s.mode = o.getString("mode");
            s.message = o.getString("message");
            s.elapsedMs = o.getLongValue("elapsedMs");
            JSONObject up = o.getJSONObject("udpToTcp");
            if (up != null) {
                s.udpToTcpPackets = up.getLongValue("packets");
                s.udpToTcpBytes = up.getLongValue("bytes");
            }
            JSONObject down = o.getJSONObject("tcpToUdp");
            if (down != null) {
                s.tcpToUdpPackets = down.getLongValue("packets");
                s.tcpToUdpBytes = down.getLongValue("bytes");
            }
            s.dropped = o.getLongValue("dropped");
            s.udpIn = o.getLongValue("udpIn");
            s.dropRate = o.getDoubleValue("dropRate");
            s.listen = o.getString("listen");
            s.udpLocal = o.getString("udpLocal");
            JSONArray peers = o.getJSONArray("peers");
            if (peers != null) {
                for (int i = 0; i < peers.size(); i++) {
                    JSONObject p = peers.getJSONObject(i);
                    s.peers.add(new Peer(p.getString("address"), p.getString("state"),
                            p.getLongValue("sinceMs")));
                }
            }
            return s;
        }
    }

    // ==================== 子进程 ====================

    interface Callbacks {
        void onStatus(JSONObject json);

        void onLog(String line);

        void onExit(int code);
    }

    static final class ForwarderProcess {
        private final UiProcess process;

        private ForwarderProcess(UiProcess process) {
            this.process = process;
        }

        static ForwarderProcess start(List<String> args, Callbacks callbacks) throws IOException {
            UiProcess client = UiProcess.start(buildCommand(args), "forwarder-ui", new UiProcess.Events() {
                @Override
                public void onEvent(JSONObject json) {
                    String type = json.getString("type");
                    if ("status".equals(type)) {
                        callbacks.onStatus(json);
                    } else if ("hello".equals(type)) {
                        callbacks.onLog("[control] " + json.getString("session"));
                    } else if ("ack".equals(type) && !json.getBooleanValue("ok")) {
                        callbacks.onLog("[control] command failed: " + json.getString("error"));
                    } else if ("terminal".equals(type)) {
                        callbacks.onLog("[control] terminal: " + json.getString("message"));
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
            return new ForwarderProcess(client);
        }

        /**
         * 子进程命令：显式指定主类，避免从“主 jar”（Main-Class=CliShark）启动时误跑 capture。
         *
         * <p>注意发行物是 Spring Boot 可执行 jar，类在 {@code BOOT-INF/classes} 下，
         * {@code -cp app.jar com.jshark.CliForwarder} 会报 ClassNotFoundException；
         * 这类 jar 必须经 {@code PropertiesLauncher} + {@code -Dloader.main} 指定主类。</p>
         */
        static List<String> buildCommand(List<String> args) {
            List<String> cmd = UiLauncher.command(CliForwarder.class, "com.jshark.CliForwarder", args);
            cmd.add("--control");
            cmd.add("stdio");
            return cmd;
        }

        /** 命令拼装本体（可单测）：bootLauncher 非空表示当前是 Spring Boot 可执行 jar。 */
        static List<String> buildCommand(List<String> args, String jar, String bootLauncher) {
            List<String> cmd = UiLauncher.command("com.jshark.CliForwarder", args, jar, bootLauncher);
            cmd.add("--control");
            cmd.add("stdio");
            return cmd;
        }

        /**
         * 判断 {@code jarPath} 是不是 Spring Boot 可执行 jar；是则返回与之匹配的
         * {@code PropertiesLauncher} 类名（兼容 Boot 3.2 前后两种包名），否则返回 null。
         */
        static String springBootLauncher(String jarPath) {
            return UiLauncher.springBootLauncher(jarPath, "com.jshark.CliForwarder");
        }

        long send(String cmd) throws IOException {
            return process.send(cmd);
        }

        void closeStdin() {
            process.closeStdin();
        }

        void kill() {
            process.kill();
        }
    }

    // ==================== 四栏表单 ====================

    /**
     * 单表单四栏：UDP SOURCE（含 LISTEN PORT）/ FORWARDING / PEERS / TRAFFIC。
     *
     * <p>四栏宽度由 {@link #addColumn} 的权重决定，窗口缩放时按比例伸缩；
     * 不再用滚动容器兜住“固定宽表单”。</p>
     */
    static final class BridgePanel extends JPanel {
        private static final int GAP = 10;
        private static final int[] WEIGHTS = {3, 3, 5, 3};

        private final JTextField group = new JTextField();
        private final JTextField port = new JTextField();
        private final JComboBox<String> localIf = new JComboBox<>();
        private final JTextField listenPort = new JTextField();
        private final ToggleSwitch utotSwitch = new ToggleSwitch("UDP → TCP");
        private final ToggleSwitch ttouSwitch = new ToggleSwitch("TCP → UDP");
        private final JTextField peerInput = new JTextField();
        private final JLabel peerError = new JLabel(" ");
        private final DefaultTableModel model = tableModel("Peer");
        private final JTable table = new JTable(model);
        private final JButton add = new JButton("+ Add");
        private final JButton remove = new JButton("Remove");
        private final List<ForwarderArgs.Endpoint> peers = new ArrayList<>();
        private Component trafficColumn;

        BridgePanel() {
            super();
            putClientProperty("ui.role", "root");
            setLayout(new GridBagLayout());
            localIf.setEditable(true);
            addItem(localIf);
            group.setDocument(new Ipv4Document());
            group.setText("224.3.0.0");
            port.setDocument(new DigitDocument());
            port.setText("3000");
            listenPort.setDocument(new DigitDocument());

            group.putClientProperty("ui.field", "group");
            port.putClientProperty("ui.field", "port");
            listenPort.putClientProperty("ui.field", "listen");
            peerInput.putClientProperty("ui.field", "peer");
            peerError.putClientProperty("ui.field", "peerError");
            peerError.setFont(peerError.getFont().deriveFont(Font.PLAIN, 11f));
            peerError.setForeground(MUTED);

            // 两个方向默认都开启；允许都关，Start 时由 ForwarderArgs 拒绝。
            utotSwitch.setSelected(true);
            ttouSwitch.setSelected(true);
            utotSwitch.putClientProperty("ui.toggle", "utot");
            ttouSwitch.putClientProperty("ui.toggle", "ttou");

            add.addActionListener(e -> addEndpoint());
            remove.addActionListener(e -> removeEndpoint());

            addColumn(udpColumn(), 0);
            addColumn(forwardingColumn(), 1);
            addColumn(peersColumn(), 2);
        }

        /** 把 TRAFFIC 栏挂到第 4 列（控件归主窗口所有，状态刷新逻辑不动）。 */
        void attachTraffic(Component column) {
            if (trafficColumn != null) {
                return;
            }
            trafficColumn = column;
            addColumn(column, 3);
        }

        /**
         * 四栏按权重精确分宽：先把每栏自身的 preferred/minimum 钉成极小值。
         * 否则 GridBagLayout 按“内容首选宽度”分列，表格/提示一长比例就漂移
         * （旧版滚动条常驻、列被裁就是这个原因）。
         */
        private void addColumn(Component column, int index) {
            column.setPreferredSize(new Dimension(1, 1));
            column.setMinimumSize(new Dimension(1, 1));
            GridBagConstraints c = new GridBagConstraints();
            c.gridx = index;
            c.gridy = 0;
            c.weightx = WEIGHTS[index];
            c.weighty = 1;
            c.fill = GridBagConstraints.BOTH;
            c.insets = new Insets(0, index == 0 ? 0 : GAP, 0, 0);
            add(column, c);
        }

        // ========== 第 1 栏 ==========

        /** udpaddr（group:port）与 udpif；LISTEN PORT 移到本栏底部。 */
        private JPanel udpColumn() {
            JPanel col = column("udp");
            int row = 0;
            row = addSection(col, row, "UDP SOURCE");

            JPanel groupRow = new JPanel(new GridBagLayout());
            groupRow.setOpaque(false);
            GridBagConstraints gl = new GridBagConstraints();
            gl.gridx = 0;
            gl.gridy = 0;
            gl.anchor = GridBagConstraints.WEST;
            gl.fill = GridBagConstraints.HORIZONTAL;
            gl.weightx = 1;
            gl.insets = new Insets(0, 0, 2, 6);
            groupRow.add(smallMuted("UDP group"), gl);
            gl = new GridBagConstraints();
            gl.gridx = 1;
            gl.gridy = 0;
            gl.anchor = GridBagConstraints.WEST;
            gl.insets = new Insets(0, 0, 2, 0);
            groupRow.add(smallMuted("Port"), gl);

            group.setPreferredSize(new Dimension(150, 30));
            group.setMinimumSize(new Dimension(80, 30));
            GridBagConstraints gc = new GridBagConstraints();
            gc.gridx = 0;
            gc.gridy = 1;
            gc.weightx = 1;
            gc.fill = GridBagConstraints.HORIZONTAL;
            gc.insets = new Insets(0, 0, 0, 6);
            groupRow.add(group, gc);
            port.setPreferredSize(new Dimension(64, 30));
            port.setMinimumSize(new Dimension(56, 30));
            gc = new GridBagConstraints();
            gc.gridx = 1;
            gc.gridy = 1;
            groupRow.add(port, gc);
            row = addRow(col, row, groupRow);

            row = addFieldLabel(col, row, "Local interface");
            localIf.setPreferredSize(new Dimension(180, 30));
            localIf.setMinimumSize(new Dimension(120, 30));
            localIf.setToolTipText("udpif = local interface CIDR, e.g. 192.168.1.0/24");
            row = addRow(col, row, localIf);
            row = addHint(col, row, "udpif = interface CIDR");

            group.setToolTipText("UDP group: one IPv4 multicast address, e.g. 224.3.0.0");
            port.setToolTipText("udpaddr = group : port");

            row = addSpacer(col, row, 22);
            row = addSection(col, row, "LISTEN PORT");
            listenPort.setPreferredSize(new Dimension(120, 30));
            listenPort.setMinimumSize(new Dimension(80, 30));
            listenPort.setToolTipText("Local TCP listen port (--port), used by TCP → UDP");
            row = addRow(col, row, listenPort);
            row = addHint(col, row, "TCP → UDP direction only");
            addFiller(col, row);
            return col;
        }

        // ========== 第 2 栏 ==========

        /** 两个方向开关；两个都关也允许，Start 时再拒绝。 */
        private JPanel forwardingColumn() {
            JPanel col = column("forwarding");
            int row = addSection(col, 0, "FORWARDING");
            row = addToggle(col, row, utotSwitch);
            row = addToggle(col, row, ttouSwitch);
            row = addSpacer(col, row, 6);
            row = addHint(col, row, "At least select one forward rule.");
            addFiller(col, row);
            return col;
        }

        // ========== 第 3 栏 ==========

        /** peers 表格 + 增删。 */
        private JPanel peersColumn() {
            JPanel col = column("peers");
            int row = addSection(col, 0, "PEERS");

            GridBagConstraints c = gbc(0, row++);
            c.gridwidth = 2;
            c.weightx = 1;
            c.weighty = 1;
            c.fill = GridBagConstraints.BOTH;
            c.insets = new Insets(0, 0, 8, 0);
            col.add(tableScroll(table), c);

            peerInput.setPreferredSize(new Dimension(180, 30));
            peerInput.setMinimumSize(new Dimension(80, 30));
            peerInput.setToolTipText("IPv4:port of the other side, e.g. 1.1.1.1:2000 (--peerN)");
            row = addRow(col, row, peerInput);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            buttons.setOpaque(false);
            buttons.add(add);
            buttons.add(remove);
            c = gbc(0, row++);
            c.gridwidth = 2;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.insets = new Insets(6, 0, 0, 0);
            col.add(buttons, c);

            GridBagConstraints ec = gbc(0, row++);
            ec.gridwidth = 2;
            ec.weightx = 1;
            ec.fill = GridBagConstraints.HORIZONTAL;
            ec.insets = new Insets(4, 0, 0, 0);
            col.add(peerError, ec);

            row = addHint(col, row, "Peer = other side's IP:port");
            return col;
        }

        private void addEndpoint() {
            try {
                ForwarderArgs.Endpoint ep = ForwarderArgs.endpoint(peerInput.getText(), "Peer");
                if (peers.stream().anyMatch(p -> p.text().equals(ep.text()))) {
                    setPeerError("Peer already added: " + ep.text());
                    return;
                }
                peers.add(ep);
                model.addRow(new Object[]{ep.text(), "stopped", "—"});
                peerInput.setText("");
                setPeerError(null);
            } catch (IllegalArgumentException e) {
                setPeerError(e.getMessage());
            }
        }

        /** 在 Add 行下方给出可见的校验提示，而不是只写进 tooltip。 */
        private void setPeerError(String message) {
            boolean blank = message == null || message.isBlank();
            peerError.setText(blank ? " " : message);
            peerError.setForeground(blank ? MUTED : STATE_FAIL);
            peerInput.setToolTipText(blank
                    ? "IPv4:port of the other side, e.g. 1.1.1.1:2000 (--peerN)"
                    : message);
        }

        private void removeEndpoint() {
            int row = table.getSelectedRow();
            if (row < 0) {
                return;
            }
            row = table.convertRowIndexToModel(row);
            peers.remove(row);
            model.removeRow(row);
        }

        List<String> args() {
            return ForwarderArgs.buildBridge(new ForwarderArgs.BridgeForm(
                    group.getText(), port.getText(), String.valueOf(localIf.getEditor().getItem()),
                    listenPort.getText(), utotSwitch.isSelected(), ttouSwitch.isSelected(), peers));
        }

        void setEnabledAll(boolean enabled) {
            group.setEnabled(enabled);
            port.setEnabled(enabled);
            localIf.setEnabled(enabled);
            listenPort.setEnabled(enabled);
            peerInput.setEnabled(enabled);
            utotSwitch.setEnabled(enabled);
            ttouSwitch.setEnabled(enabled);
            add.setEnabled(enabled);
            remove.setEnabled(enabled);
            table.setEnabled(enabled);
        }

        void applyStatus(UiStatus status, boolean active) {
            if (!active) {
                return;
            }
            applyPeers(model, status.peers, peers);
        }

        /** 批量设置 peer 行状态：未启动/已停止显示 stopped，启动时先显示 connecting。 */
        void setPeerState(String state) {
            for (int i = 0; i < model.getRowCount(); i++) {
                model.setValueAt(state, i, 1);
                model.setValueAt("—", i, 2);
            }
        }
    }

    // ==================== 主窗口 ====================

    static final class ForwarderFrame extends JFrame {
        private final CountDownLatch closed;
        private final JComboBox<String> themeBox = new JComboBox<>(new String[]{"Dark", "Light"});
        private final JLabel stateLabel = new JLabel("IDLE");
        private final JLabel stateChip = new JLabel("IDLE");
        private final JLabel hintLabel = new JLabel(" ");
        private final JLabel modeHint = new JLabel(" ");
        private final JLabel elapsedLabel = new JLabel("00:00:00");
        private final JLabel logCountLabel = new JLabel("Log 0 warnings · 0 errors");
        private final JLabel udpToTcpValue = new JLabel("0");
        private final JLabel udpToTcpDetail = new JLabel("0 B · 0 pps");
        private final JLabel tcpToUdpValue = new JLabel("0");
        private final JLabel tcpToUdpDetail = new JLabel("0 B · 0 pps");
        private final JLabel droppedValue = new JLabel("0");
        private final JLabel listenValue = new JLabel("—");
        private final JLabel udpLocalValue = new JLabel("—");
        private final JLabel peersSummary = new JLabel("—");
        private final JLabel endpointsLabel = new JLabel("—");
        private final JButton startStopBtn = new JButton("Start");
        private final JButton pauseBtn = new JButton("Pause");
        private final JTextArea logArea = new JTextArea();
        private final JLabel envLabel = new JLabel("ready");
        private final JLabel versionLabel = new JLabel("JShark " + version() + " · Forwarder");

        private final BridgePanel bridgePanel = new BridgePanel();

        private boolean running;
        private boolean stopping;
        private boolean paused;
        private boolean waitingHint;
        /** 每次 Start 自增；旧进程的迟到回调按它丢弃，避免污染新一轮会话。 */
        private long runId;
        /** 子进程上报的终止状态（FINISHED/FAILED）与消息，用于进程真正退出后收尾。 */
        private String terminalState;
        private String terminalMessage;
        private boolean startSent;
        private boolean closing;
        private boolean userClosing;
        private ForwarderProcess process;
        private Timer startWatchdog;
        private Timer stopWatchdog;
        private Timer closeTimer;
        private long lastStatusSeq;
        private long lastStatusNanos;
        private long lastUp;
        private long lastDown;
        private double upPps;
        private double downPps;
        private int warnings;
        private int errors;

        ForwarderFrame(CountDownLatch closed) {
            super("JShark Forwarder");
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
            probeEnvironment();

            setMinimumSize(new Dimension(940, 620));
            setSize(1100, 720);
            setLocationRelativeTo(null);

            themeBox.addActionListener(e -> {
                boolean dark = "Dark".equals(themeBox.getSelectedItem());
                if (dark == darkTheme) {
                    return;
                }
                installTheme(dark);
                SwingUtilities.updateComponentTreeUI(this);
                restyle(getContentPane());
                updateStartStop();
                repaint();
            });
        }

        private static String version() {
            String v = CliForwarder.class.getPackage() == null
                    ? null : CliForwarder.class.getPackage().getImplementationVersion();
            return v == null ? "1.0.0" : v;
        }

        private void buildUi() {
            JPanel root = new JPanel(new BorderLayout(0, 6));
            root.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
            root.putClientProperty("ui.role", "root");
            setContentPane(root);
            root.add(buildHeader(), BorderLayout.NORTH);

            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Forward", buildForwardTab());
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
            setState("IDLE", MUTED);
        }

        private JPanel buildHeader() {
            JPanel header = new JPanel(new GridBagLayout());
            header.putClientProperty("ui.role", "root");

            modeHint.setText("UDP multicast ⇄ TCP peers");
            modeHint.putClientProperty("ui.kind", "muted");
            GridBagConstraints c = gbc(0, 0);
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            header.add(modeHint, c);

            stateChip.putClientProperty("ui.kind", "state");
            stateChip.setFont(stateChip.getFont().deriveFont(Font.BOLD, 11f));
            stateChip.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(STATE_OK, 1),
                    BorderFactory.createEmptyBorder(4, 10, 4, 10)));
            header.add(stateChip, gbc(1, 0));
            header.add(labelMuted("Theme"), gbc(2, 0));
            themeBox.setPreferredSize(new Dimension(84, 30));
            header.add(themeBox, gbc(3, 0));
            return header;
        }

        private JPanel buildForwardTab() {
            JPanel tab = new JPanel(new BorderLayout());
            tab.putClientProperty("ui.role", "root");
            tab.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));
            bridgePanel.attachTraffic(buildTrafficPanel());
            tab.add(bridgePanel, BorderLayout.CENTER);
            return tab;
        }

        /** 第 4 栏：累计计数 + 运行状态；控件由主窗口持有，状态刷新仍走 applyStatus。 */
        private JPanel buildTrafficPanel() {
            JPanel col = column("traffic");
            col.putClientProperty("ui.role", "root");
            int row = addSection(col, 0, "TRAFFIC");
            row = trafficBlock(col, row, "UDP → TCP", udpToTcpValue, udpToTcpDetail);
            row = trafficBlock(col, row, "TCP → UDP", tcpToUdpValue, tcpToUdpDetail);

            JPanel dropped = new JPanel(new BorderLayout());
            dropped.setOpaque(false);
            dropped.add(labelMuted("Dropped"), BorderLayout.WEST);
            droppedValue.setToolTipText(
                    "Datagrams dropped while no peer was ready / locally received UDP datagrams.");
            droppedValue.putClientProperty("ui.kind", "accent");
            droppedValue.setForeground(ACCENT);
            droppedValue.setFont(new Font("Consolas", Font.PLAIN, 11));
            droppedValue.setHorizontalAlignment(SwingConstants.RIGHT);
            dropped.add(droppedValue, BorderLayout.EAST);
            GridBagConstraints c = gbc(0, row++);
            c.gridwidth = 2;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.insets = new Insets(4, 0, 0, 0);
            col.add(dropped, c);

            row = addSpacer(col, row, 18);
            row = addSection(col, row, "STATUS");
            row = addStatusRow(col, row, "Listen", listenValue);
            row = addStatusRow(col, row, "UDP", udpLocalValue);
            row = addStatusRow(col, row, "Peers", peersSummary);
            addFiller(col, row);
            return col;
        }

        private int trafficBlock(JPanel col, int row, String title, JLabel value, JLabel detail) {
            GridBagConstraints c = gbc(0, row++);
            c.gridwidth = 2;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.insets = new Insets(8, 0, 0, 0);
            col.add(smallMuted(title), c);

            value.setFont(value.getFont().deriveFont(Font.BOLD, 18f));
            c = gbc(0, row++);
            c.gridwidth = 2;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            col.add(value, c);

            detail.putClientProperty("ui.kind", "accent");
            detail.setForeground(ACCENT);
            c = gbc(0, row++);
            c.gridwidth = 2;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            col.add(detail, c);
            return row;
        }

        private JPanel buildPlayer() {
            JPanel player = new JPanel(new BorderLayout(0, 4));
            player.putClientProperty("ui.role", "player");
            player.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

            JPanel top = new JPanel(new BorderLayout());
            top.setOpaque(false);
            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
            left.setOpaque(false);
            elapsedLabel.putClientProperty("ui.kind", "accent");
            elapsedLabel.setForeground(ACCENT);
            elapsedLabel.setFont(elapsedLabel.getFont().deriveFont(Font.BOLD, 22f));
            stateLabel.putClientProperty("ui.kind", "state");
            hintLabel.putClientProperty("ui.kind", "state");
            left.add(elapsedLabel);
            left.add(stateLabel);
            left.add(hintLabel);
            top.add(left, BorderLayout.WEST);
            logCountLabel.putClientProperty("ui.kind", "muted");
            top.add(logCountLabel, BorderLayout.EAST);

            JPanel transport = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            transport.setOpaque(false);
            startStopBtn.setPreferredSize(new Dimension(110, 34));
            pauseBtn.setPreferredSize(new Dimension(110, 34));
            startStopBtn.setFont(startStopBtn.getFont().deriveFont(Font.BOLD, 14f));
            pauseBtn.setFont(pauseBtn.getFont().deriveFont(Font.BOLD, 14f));
            startStopBtn.putClientProperty("ui.primary", true);
            pauseBtn.setEnabled(false);
            transport.add(startStopBtn);
            transport.add(pauseBtn);
            transport.add(labelMuted("Stop closes peer channels and leaves the multicast group."));
            updateStartStop();

            JPanel current = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            current.setOpaque(false);
            current.add(labelMuted("Endpoints"));
            endpointsLabel.setFont(new Font("Consolas", Font.PLAIN, 11));
            current.add(endpointsLabel);

            JPanel bottom = new JPanel(new BorderLayout(0, 2));
            bottom.setOpaque(false);
            bottom.add(transport, BorderLayout.NORTH);
            bottom.add(current, BorderLayout.SOUTH);

            player.add(top, BorderLayout.NORTH);
            player.add(bottom, BorderLayout.CENTER);
            return player;
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
            startStopBtn.addActionListener(e -> {
                if (running) {
                    stopForwarder();
                } else {
                    startForwarder();
                }
            });
            pauseBtn.addActionListener(e -> togglePause());
        }

        /** Start/Stop 合并按钮：空闲时“Start”，运行中“Stop”，停止过程显示“Stopping…”。 */
        private void updateStartStop() {
            if (stopping) {
                startStopBtn.setText("Stopping…");
                startStopBtn.setBackground(STATE_FAIL);
                startStopBtn.setForeground(FG);
            } else if (running) {
                startStopBtn.setText("Stop");
                startStopBtn.setBackground(STATE_FAIL);
                startStopBtn.setForeground(FG);
            } else {
                startStopBtn.setText("Start");
                startStopBtn.setBackground(ACCENT);
                startStopBtn.setForeground(ON_ACCENT);
            }
        }

        private void probeEnvironment() {
            try {
                int count = localSubnets().size();
                envLabel.setText(count + " local IPv4 subnet(s)");
            } catch (Exception e) {
                envLabel.setText("local addresses unavailable");
            }
        }

        // ---------- 运行控制 ----------

        private void startForwarder() {
            if (running) {
                return;
            }
            List<String> args;
            try {
                args = bridgePanel.args();
            } catch (IllegalArgumentException e) {
                // 参数不合法（含两个转发方向都关闭）一律拒绝启动，并明确告知原因。
                setHint(e.getMessage(), STATE_FAIL);
                JOptionPane.showMessageDialog(this, e.getMessage(),
                        "Cannot start forwarder", JOptionPane.ERROR_MESSAGE);
                return;
            }
            final long myRun = ++runId;
            terminalState = null;
            terminalMessage = null;
            setHint("Starting forwarder…", MUTED);
            stopping = false;
            bridgePanel.setPeerState("connecting");
            lastStatusSeq = 0;
            startSent = false;
            lastStatusNanos = 0;
            lastUp = lastDown = 0;
            upPps = downPps = 0;
            warnings = 0;
            errors = 0;
            logArea.setText("");
            logCountLabel.setText("Log 0 warnings · 0 errors");
            endpointsLabel.setText("—");
            listenValue.setText("—");
            udpLocalValue.setText("—");
            peersSummary.setText("—");
            droppedValue.setText("0 pkt · —");

            try {
                process = ForwarderProcess.start(args, new Callbacks() {
                    @Override
                    public void onStatus(JSONObject json) {
                        UiStatus status = UiStatus.from(json);
                        SwingUtilities.invokeLater(() -> {
                            if (myRun == runId) {
                                applyStatus(status);
                            }
                        });
                    }

                    @Override
                    public void onLog(String line) {
                        SwingUtilities.invokeLater(() -> {
                            if (myRun == runId) {
                                log(line);
                            }
                        });
                    }

                    @Override
                    public void onExit(int code) {
                        SwingUtilities.invokeLater(() -> {
                            if (myRun == runId) {
                                onProcessExit(code);
                            }
                        });
                    }
                });
            } catch (IOException e) {
                setHint("Failed to start forwarder: " + e.getMessage(), STATE_FAIL);
                bridgePanel.setPeerState("stopped");
                return;
            }
            running = true;
            paused = false;
            pauseBtn.setText("Pause");
            setParamsEnabled(false);
            startStopBtn.setEnabled(true);
            pauseBtn.setEnabled(true);
            updateStartStop();
            setState("STARTING", ACCENT);
            waitingHint = false;
            startStartWatchdog();
        }

        private void applyStatus(UiStatus s) {
            // 停止/收尾阶段不再接受状态帧：避免把 peer/整体状态刷回 ready/running。
            if (!running || stopping) {
                return;
            }
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
            Color stateColor = switch (state) {
                case "RUNNING" -> STATE_OK;
                case "WAITING", "STARTING", "STOPPING", "PAUSED" -> ACCENT;
                case "FAILED" -> STATE_FAIL;
                default -> MUTED;
            };
            setState(state.isEmpty() ? "—" : state, stateColor);
            if ("WAITING".equals(state)) {
                // 对端可能还没启动；明确告诉用户是在等 Peer，而不是卡死。
                setHint("Waiting for peers to connect…", ACCENT);
                waitingHint = true;
            } else if (waitingHint && !"FAILED".equals(state) && !"FINISHED".equals(state)) {
                waitingHint = false;
                setHint(" ", MUTED);
            }
            if ("PAUSED".equals(state)) {
                if (!paused) {
                    paused = true;
                    pauseBtn.setText("Resume");
                }
            } else if (paused) {
                paused = false;
                pauseBtn.setText("Pause");
            }
            elapsedLabel.setText(formatElapsed(s.elapsedMs));
            applyTraffic(s);
            listenValue.setText(s.listen == null || s.listen.isBlank() ? "—" : s.listen);
            udpLocalValue.setText(s.udpLocal == null || s.udpLocal.isBlank() ? "—" : s.udpLocal);
            long ready = s.peers.stream().filter(p -> "ready".equals(p.state())
                    || "connected".equals(p.state())).count();
            peersSummary.setText(s.peers.isEmpty() ? "—"
                    : ready + "/" + s.peers.size() + " ready");
            endpointsLabel.setText((s.listen == null ? "" : s.listen)
                    + (s.udpLocal == null ? "" : "  ↔  " + s.udpLocal));

            // Stop 之后不要再让残余状态帧把 peer 刷回 ready/reconnecting。
            bridgePanel.applyStatus(s, running && !stopping);

            if (!s.message.isBlank() && ("FAILED".equals(state) || "WAITING".equals(state))) {
                setHint(s.message, "FAILED".equals(state) ? STATE_FAIL : ACCENT);
            }
            if ("FINISHED".equals(state) || "FAILED".equals(state)) {
                finishRun(state, s.message);
            }
        }

        private void applyTraffic(UiStatus s) {
            long now = System.nanoTime();
            if (lastStatusNanos > 0 && now > lastStatusNanos) {
                double secs = (now - lastStatusNanos) / 1_000_000_000.0;
                if (secs > 0.05) {
                    upPps = Math.max(0, s.udpToTcpPackets - lastUp) / secs;
                    downPps = Math.max(0, s.tcpToUdpPackets - lastDown) / secs;
                }
            }
            lastStatusNanos = now;
            lastUp = s.udpToTcpPackets;
            lastDown = s.tcpToUdpPackets;

            udpToTcpValue.setText(formatCount(s.udpToTcpPackets) + " pkt");
            udpToTcpDetail.setText(formatBytes(s.udpToTcpBytes) + " · " + formatRate(upPps));
            tcpToUdpValue.setText(formatCount(s.tcpToUdpPackets) + " pkt");
            tcpToUdpDetail.setText(formatBytes(s.tcpToUdpBytes) + " · " + formatRate(downPps));
            droppedValue.setText(formatCount(s.dropped) + " pkt · " + formatDropRate(s.dropped, s.udpIn));
        }

        /**
         * 子进程上报 FINISHED/FAILED 后的收尾：只关闭 stdin，**保持 running=true**，
         * 等进程真正退出（onProcessExit）后才允许再次 Start —— 否则旧进程还占着端口，
         * 新进程会直接 Address already in use。
         */
        private void finishRun(String state, String message) {
            if (!running || stopping) {
                return;
            }
            stopping = true;
            terminalState = state;
            terminalMessage = message;
            paused = false;
            waitingHint = false;
            bridgePanel.setPeerState("stopped");
            pauseBtn.setText("Pause");
            pauseBtn.setEnabled(false);
            stopStartWatchdog();
            startStopWatchdog();
            startStopBtn.setEnabled(false);
            updateStartStop();
            if ("FAILED".equals(state) && message != null && !message.isBlank()) {
                setHint(message, STATE_FAIL);
            } else if ("FINISHED".equals(state)) {
                setHint("Forwarder stopped.", MUTED);
            }
            closeChildStdin();
        }

        private void closeChildStdin() {
            ForwarderProcess p = process;
            if (p != null) {
                p.closeStdin();
            }
        }

        private void onProcessExit(int code) {
            process = null;
            stopStopWatchdog();
            if (!running) {
                return;
            }
            boolean userStop = stopping;
            String finalState = terminalState;
            String finalMessage = terminalMessage;
            running = false;
            stopping = false;
            terminalState = null;
            terminalMessage = null;
            paused = false;
            waitingHint = false;
            bridgePanel.setPeerState("stopped");
            pauseBtn.setText("Pause");
            stopStartWatchdog();
            setParamsEnabled(true);
            startStopBtn.setEnabled(true);
            pauseBtn.setEnabled(false);
            updateStartStop();
            if ("FAILED".equals(finalState)) {
                setState("FAILED", STATE_FAIL);
                if (finalMessage != null && !finalMessage.isBlank()) {
                    setHint(finalMessage, STATE_FAIL);
                }
            } else if ("FINISHED".equals(finalState) || userStop || code == 0) {
                setState("FINISHED", STATE_OK);
                setHint("Forwarder stopped.", MUTED);
            } else {
                setState("FAILED", STATE_FAIL);
                setHint("Forwarder process exited with code " + code + " — see the Log tab.", STATE_FAIL);
            }
            if (closing) {
                dispose();
            }
        }

        private void stopForwarder() {
            if (!running || process == null || stopping) {
                return;
            }
            stopping = true;
            bridgePanel.setPeerState("stopped");
            setState("STOPPING", ACCENT);
            startStopBtn.setEnabled(false);
            pauseBtn.setEnabled(false);
            updateStartStop();
            // 进程迟迟不退时强制结束，随后 onProcessExit 统一收尾。
            startStopWatchdog();
            if (!startSent) {
                // 子进程还没收到 start（仍在 STARTING）：直接结束。
                setHint("Stopping…", ACCENT);
                process.kill();
                return;
            }
            send("stop");
            setHint("Stopping peers and closing sockets…", ACCENT);
            // 关掉 stdin：控制循环处理完 stop 后读到 EOF，会自行退出 → onProcessExit 收尾。
            closeChildStdin();
        }

        private void togglePause() {
            if (!running || process == null) {
                return;
            }
            if (paused) {
                send("resume");
                paused = false;
                pauseBtn.setText("Pause");
                setHint("Resumed.", MUTED);
            } else {
                send("pause");
                paused = true;
                pauseBtn.setText("Resume");
                setHint("Paused; kept connections, forwarding stopped.", ACCENT);
            }
        }

        private void send(String cmd) {
            ForwarderProcess p = process;
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
                    setHint("Forwarder child did not become ready within 15s — see the Log tab.", STATE_FAIL);
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

        private void startStopWatchdog() {
            stopStopWatchdog();
            stopWatchdog = new Timer(6_000, e -> {
                if (running) {
                    log("[ui] child did not exit within 6s; killing it");
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

        private void setParamsEnabled(boolean enabled) {
            bridgePanel.setEnabledAll(enabled);
            themeBox.setEnabled(enabled);
        }

        private void setState(String text, Color color) {
            stateLabel.setText(text);
            stateLabel.setForeground(color);
            stateChip.setText(text);
            stateChip.setForeground(color);
            stateChip.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(color, 1),
                    BorderFactory.createEmptyBorder(4, 10, 4, 10)));
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
                closing = true;
                if (process != null) {
                    process.kill();
                }
                dispose();
                return;
            }
            int rc = JOptionPane.showConfirmDialog(this,
                    "The forwarder is running. Stop it and close?",
                    "JShark Forwarder", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (rc != JOptionPane.OK_OPTION) {
                return;
            }
            closing = true;
            stopForwarder();
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
            running = false;
            stopping = false;
            // 任何情况下都别把子进程留成孤儿（它会一直占着监听端口）。
            ForwarderProcess p = process;
            process = null;
            if (p != null) {
                p.kill();
            }
            super.dispose();
            if (userClosing) {
                new Timer(300, e -> System.exit(0)).start();
            }
        }
    }

    // ==================== 共用控件 ====================

    private static DefaultTableModel tableModel(String firstColumn) {
        DefaultTableModel model = new DefaultTableModel(
                new Object[]{firstColumn, "TCP", "Since"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        return model;
    }

    private static JScrollPane tableScroll(JTable table) {
        table.setRowHeight(22);
        table.setShowGrid(false);
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.setDefaultRenderer(Object.class, new PeerRenderer());
        table.getTableHeader().setReorderingAllowed(false);
        DefaultTableCellRenderer header = new DefaultTableCellRenderer();
        header.setHorizontalAlignment(SwingConstants.LEFT);
        header.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        table.getTableHeader().setDefaultRenderer(header);
        TableColumn first = table.getColumnModel().getColumn(0);
        first.setPreferredWidth(160);
        first.setMinWidth(90);
        TableColumn status = table.getColumnModel().getColumn(1);
        status.setPreferredWidth(105);
        status.setMinWidth(95);
        status.setMaxWidth(180);
        TableColumn since = table.getColumnModel().getColumn(2);
        since.setPreferredWidth(75);
        since.setMinWidth(65);
        since.setMaxWidth(140);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(BORDER));
        return scroll;
    }

    private static void applyPeers(DefaultTableModel model, List<Peer> peers,
                                   List<ForwarderArgs.Endpoint> endpoints) {
        for (int i = 0; i < endpoints.size() && i < model.getRowCount(); i++) {
            ForwarderArgs.Endpoint ep = endpoints.get(i);
            Peer match = peers.stream().filter(p -> endpointMatches(p.address(), ep)).findFirst().orElse(null);
            if (match != null) {
                model.setValueAt(match.state(), i, 1);
                model.setValueAt(formatSince(match.sinceMs()), i, 2);
            } else {
                model.setValueAt("connecting", i, 1);
                model.setValueAt("—", i, 2);
            }
        }
    }

    /** status 用解析后的 IP，UI 里可能填的是主机名；按端口 + 解析地址匹配。 */
    private static boolean endpointMatches(String address, ForwarderArgs.Endpoint ep) {
        if (address.equals(ep.text())) {
            return true;
        }
        int idx = address.lastIndexOf(':');
        if (idx <= 0 || !address.substring(idx + 1).equals(Integer.toString(ep.port()))) {
            return false;
        }
        try {
            return java.net.InetAddress.getByName(ep.host()).getHostAddress()
                    .equals(address.substring(0, idx));
        } catch (Exception e) {
            return false;
        }
    }

    private static final class PeerRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            setHorizontalAlignment(column == 0 ? SwingConstants.LEFT : SwingConstants.LEFT);
            String state = String.valueOf(table.getModel().getValueAt(row, 1));
            if (!isSelected) {
                if (column == 1) {
                    setForeground(switch (state) {
                        case "ready", "connected" -> STATE_OK;
                        case "reconnecting" -> ACCENT;
                        default -> MUTED;
                    });
                } else if (column == 2) {
                    setForeground(MUTED);
                } else {
                    setForeground(FG);
                }
            }
            return c;
        }
    }

    /** 开关滑块：左侧为 pill 形状的开关，右侧为说明文字（基于 JToggleButton，点击切换稳定）。 */
    private static final class ToggleSwitch extends JToggleButton {
        ToggleSwitch(String label) {
            super(label);
            setContentAreaFilled(false);
            setFocusPainted(false);
            setOpaque(true);
            setBorderPainted(false);
            setFont(getFont().deriveFont(Font.BOLD, 12.5f));
            setHorizontalAlignment(SwingConstants.LEFT);
            setMargin(new Insets(0, 0, 0, 0));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setMinimumSize(new Dimension(130, 42));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            // 背景
            g2.setColor(getBackground());
            g2.fillRect(0, 0, getWidth(), getHeight());

            boolean on = isSelected();
            int trackW = 44;
            int trackH = 22;
            int y = Math.max(0, (getHeight() - trackH) / 2);
            int x = 10;
            // 轨道
            Color trackColor = on ? ACCENT : (isEnabled() ? PANEL : DISABLED_BG);
            RoundRectangle2D track = new RoundRectangle2D.Float(x, y, trackW, trackH, trackH, trackH);
            g2.setColor(trackColor);
            g2.fill(track);
            g2.setColor(BORDER);
            g2.draw(track);
            // 滑块
            int knob = trackH - 6;
            int knobX = on ? x + trackW - knob - 3 : x + 3;
            g2.setColor(on ? ON_ACCENT : FG);
            g2.fillOval(knobX, y + 3, knob, knob);
            // 文字
            String label = getText();
            if (label != null && !label.isEmpty()) {
                g2.setColor(isEnabled() ? FG : MUTED);
                g2.setFont(getFont());
                int ty = y + trackH / 2 + g2.getFontMetrics().getAscent() / 2 - 1;
                g2.drawString(label, x + trackW + 14, ty);
            }
            g2.dispose();
        }

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(220, 42);
        }
    }

    /**
     * UDP group 输入过滤器：只接受 ASCII 数字和点、最长 15 字符。含其它字符（逗号、空格、
     * 主机名等）的整段输入直接丢弃，保证字段里始终只有“一个 IPv4 地址”。
     */
    private static final class Ipv4Document extends PlainDocument {
        @Override
        public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
            if (str == null || str.isEmpty()) {
                return;
            }
            for (int i = 0; i < str.length(); i++) {
                char ch = str.charAt(i);
                if (ch < '0' || ch > '9') {
                    if (ch != '.') {
                        return;
                    }
                }
            }
            if (getLength() + str.length() > 15) {
                return;
            }
            super.insertString(offs, str, a);
        }
    }

    /** 只允许输入数字的文档过滤器（Port 输入框用）。 */
    private static final class DigitDocument extends PlainDocument {        @Override
        public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
            if (str == null) {
                return;
            }
            StringBuilder sb = new StringBuilder(str.length());
            for (int i = 0; i < str.length(); i++) {
                char ch = str.charAt(i);
                if (Character.isDigit(ch)) {
                    sb.append(ch);
                }
            }
            super.insertString(offs, sb.toString(), a);
        }
    }

    // ==================== 小工具 ====================

                    /** 一栏（两列网格）的容器；{@code ui.column} 供布局回归测试定位。 */
    private static JPanel column(String name) {
        JPanel col = new JPanel(new GridBagLayout());
        col.putClientProperty("ui.column", name);
        return col;
    }

    private static int addSection(JPanel col, int row, String text) {
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(0, 0, 6, 0);
        col.add(sectionLabel(text), c);
        return row + 1;
    }

    private static int addFieldLabel(JPanel col, int row, String text) {
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(0, 0, 2, 0);
        col.add(smallMuted(text), c);
        return row + 1;
    }

    private static int addRow(JPanel col, int row, Component component) {
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        col.add(component, c);
        return row + 1;
    }

    private static int addToggle(JPanel col, int row, JToggleButton toggle) {
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(10, 0, 0, 0);
        col.add(toggle, c);
        return row + 1;
    }

    private static int addHint(JPanel col, int row, String text) {
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(6, 0, 0, 0);
        col.add(hintText(text), c);
        return row + 1;
    }

    /** 固定高度的纵向间距。注意：空的 JLabel 不会被 GridBagLayout 布局，必须用 JPanel。 */
    private static int addSpacer(JPanel col, int row, int height) {
        JPanel spacer = new JPanel();
        spacer.setOpaque(false);
        spacer.setPreferredSize(new Dimension(1, height));
        spacer.setMinimumSize(new Dimension(1, height));
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        col.add(spacer, c);
        return row + 1;
    }

    /** 栏底剩余空间：让内容顶部对齐。 */
    private static void addFiller(JPanel col, int row) {
        JPanel filler = new JPanel();
        filler.setOpaque(false);
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        col.add(filler, c);
    }

    private static int addStatusRow(JPanel col, int row, String name, JLabel value) {
        JPanel line = new JPanel(new BorderLayout(8, 0));
        line.setOpaque(false);
        line.add(labelMuted(name), BorderLayout.WEST);
        value.setFont(new Font("Consolas", Font.PLAIN, 11));
        value.setHorizontalAlignment(SwingConstants.RIGHT);
        line.add(value, BorderLayout.EAST);
        GridBagConstraints c = gbc(0, row);
        c.gridwidth = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        col.add(line, c);
        return row + 1;
    }

    private static JLabel smallMuted(String text) {
        JLabel l = labelMuted(text);
        l.setFont(l.getFont().deriveFont(Font.PLAIN, 11f));
        return l;
    }

    private static void addItem(JComboBox<String> combo) {
        for (String s : localSubnets()) {
            combo.addItem(s);
        }
        // 默认选中第一项（本地子网）。空列表时留空。
        if (combo.getItemCount() > 0) {
            combo.setSelectedIndex(0);
        } else {
            combo.setSelectedItem("");
        }
    }

    static List<String> localSubnets() {
        List<String> out = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    if (!(ia.getAddress() instanceof Inet4Address) || ia.getNetworkPrefixLength() < 1) {
                        continue;
                    }
                    byte[] addr = ia.getAddress().getAddress();
                    int ip = ((addr[0] & 0xff) << 24) | ((addr[1] & 0xff) << 16)
                            | ((addr[2] & 0xff) << 8) | (addr[3] & 0xff);
                    int prefix = ia.getNetworkPrefixLength();
                    int mask = prefix == 0 ? 0 : (-1 << (32 - prefix));
                    int network = ip & mask;
                    String cidr = ((network >>> 24) & 0xff) + "." + ((network >>> 16) & 0xff)
                            + "." + ((network >>> 8) & 0xff) + "." + (network & 0xff) + "/" + prefix;
                    if (!out.contains(cidr)) {
                        out.add(cidr);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        out.sort(java.util.Comparator.naturalOrder());
        return out;
    }

                    /** 本地丢弃率：未就绪丢弃 / 本地 UDP 入包。 */
        }
