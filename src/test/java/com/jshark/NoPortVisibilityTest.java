package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.stream.Stream;

/**
 * D6 验收测试：缺少端口信息的 TCP/UDP 包**不再静默丢弃**。
 *
 * <h3>要解决的问题</h3>
 * <p>
 * 当传输层头没能解析出端口时（典型成因：抓包被 snaplen 截断，或数据报的分片组未补齐），
 * 早期实现只打一行 {@code debug} 日志就跳过——等于<b>静默丢掉这些包的内容</b>：
 * 既不入库、也不重放、还没有任何计数。
 * </p>
 * <p>
 * 现在这类包会计数、首次出现时告警、写进 manifest 的 {@code dropped.noPort}，
 * 并在退出时汇报。本测试用<b>手工构造的 pcap</b>精确制造"IP 头完整但传输层头被截断"的帧
 * （caplen 只覆盖以太网 + IP 头），从而稳定命中该分支。
 * </p>
 */
public class NoPortVisibilityTest {

    private static final Logger logger = LoggerFactory.getLogger(NoPortVisibilityTest.class);

    private static final Path WORK_DIR = Paths.get("target", "noport-test");
    private static final Path PCAP_FILE = WORK_DIR.resolve("trunc.pcap");
    private static final String DB_PATH = WORK_DIR.resolve("noport.db").toString();
    private static final long INTERVAL_MS = 3_600_000L;   // 1 小时：本次运行不会轮转

    /**
     * 注入的固定时钟（本地 2026-02-02 10:03:20）。
     * <p>
     * 本用例只关心"截断包是否被明确计数"，与分卷轮转无关。用真实时钟 + 1 小时窗口时，
     * 如果这次运行恰好跨过整点，就会多出一个空的窗口卷，而校验阶段按文件名无序
     * {@code findFirst()} 选中空卷的概率不为零 → {@code rows == 1} 假失败（跨整点才复现，
     * 极难排查）。固定时钟后窗口永不推进，卷数恒为 1，整点与否都稳定。
     * </p>
     */
    private static final long FIXED_CLOCK_MS = java.time.LocalDateTime.of(2026, 2, 2, 10, 3, 20)
            .atZone(java.time.ZoneId.systemDefault())
            .toInstant()
            .toEpochMilli();

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void noPortVisibilityRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  D6 验收：无端口 TCP/UDP 包的可见性");
        logger.info("=================================================");

        prepare();
        writePcap();
        runCapture();
        verify();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    private static void prepare() throws Exception {
        if (Files.exists(WORK_DIR)) {
            try (Stream<Path> stream = Files.walk(WORK_DIR)) {
                stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                        // 清理失败不影响结论
                    }
                });
            }
        }
        Files.createDirectories(WORK_DIR);
    }

    /**
     * 手工写 pcap：这样可以精确控制 {@code incl_len}（caplen）与 {@code orig_len}，
     * 造出"线上是个完整 TCP 报文、但只抓到了前 34 字节"的帧。
     */
    private static void writePcap() throws Exception {
        // 1) 一个完整的 UDP 帧（应当被正常记录）
        byte[] udpFrame = buildUdpFrame();
        // 2) 一个被截断的 TCP 帧：只保留以太网(14) + IP 头(20) = 34 字节，
        //    IP 头里的 protocol 仍是 TCP，但传输层头整个缺失 → 端口解析为 null
        byte[] fullTcpFrame = buildTcpFrame();
        int truncatedLen = 34;
        check(fullTcpFrame.length > truncatedLen,
                "构造的 TCP 帧确实被截断（完整 " + fullTcpFrame.length + " 字节，只写 " + truncatedLen + "）");
        byte[] truncatedTcpFrame = java.util.Arrays.copyOf(fullTcpFrame, truncatedLen);

        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(PCAP_FILE))) {
            // pcap 全局头（小端）
            out.writeInt(0xa1b2c3d4);
            out.writeShort(2);
            out.writeShort(4);
            out.writeInt(0);          // thiszone
            out.writeInt(0);          // sigfigs
            out.writeInt(65535);      // snaplen
            out.writeInt(1);          // network = LINKTYPE_ETHERNET

            writeRecord(out, 1_700_000_000L, udpFrame, udpFrame.length);
            writeRecord(out, 1_700_000_001L, truncatedTcpFrame, fullTcpFrame.length);
        }
        logger.info("  已写入 pcap：1 个完整 UDP 帧 + 1 个截断 TCP 帧（caplen={}，orig_len={}）",
                truncatedTcpFrame.length, fullTcpFrame.length);
    }

    private static void writeRecord(DataOutputStream out, long tsSec, byte[] data, int origLen)
            throws Exception {
        out.writeInt((int) tsSec);
        out.writeInt(0);
        out.writeInt(data.length);   // incl_len
        out.writeInt(origLen);       // orig_len
        out.write(data);
    }

    private static void runCapture() throws Exception {
        logger.info("---- [1] 采集（启用分卷，以便检查 manifest 里的 dropped 计数）----");
        PacketCapture capture = new PacketCapture();
        // 固定时钟：保证窗口不随真实时间推进，卷数恒为 1（见 FIXED_CLOCK_MS 的说明）
        capture.setClockForTest(() -> FIXED_CLOCK_MS);
        capture.setSplit(INTERVAL_MS);
        capture.setLogDb(DB_PATH);
        capture.startCaptureFromFile(PCAP_FILE.toString());
        logger.info("  采集完成");
    }

    private static void verify() throws Exception {
        logger.info("---- [2] 校验：截断包未入库，但被明确计数 ----");

        // 启用分卷后数据落在**窗口文件名**上（noport_{时间戳}.db），不是基准名。
        // 这里刻意排序 + 断言"恰好一个卷"，把原来隐式的无序 findFirst() 变成一个真实检查。
        List<Path> dbFiles;
        try (Stream<Path> stream = Files.list(WORK_DIR)) {
            dbFiles = stream.filter(p -> p.getFileName().toString().endsWith(".db"))
                    .sorted()
                    .collect(java.util.stream.Collectors.toList());
        }
        check(dbFiles.size() == 1,
                "固定时钟下应恰好只有 1 个窗口 db（实际 " + dbFiles.size() + " 个: " + dbFiles + "）");
        if (dbFiles.isEmpty()) {
            return;
        }
        Path dbFile = dbFiles.get(0);
        logger.info("  窗口 db 文件: {}", dbFile.getFileName());

        int rows = 0;
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + dbFile);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("Select count(*) From JSharkLog")) {
            rows = rs.next() ? rs.getInt(1) : 0;
        }
        check(rows == 1, "只有完整的那一帧入库（实际 " + rows + " 行，期望 1）");

        // manifest 已写入该窗口 db 的 JSharkManifest 表，dropped.noPort 必须如实记录那个截断包
        String droppedJson = null;
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + dbFile);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "Select dropped, completeWindow, packetCount From JSharkManifest Order By volumeSeq")) {
            if (rs.next()) {
                droppedJson = rs.getString("dropped");
            }
        }
        check(droppedJson != null, "JSharkManifest 表里有 dropped 记录（" + droppedJson + "）");
        if (droppedJson == null) {
            return;
        }
        JSONObject dropped = JSON.parseObject(droppedJson);
        check(dropped != null, "manifest 的 dropped 是合法 JSON");
        int noPort = dropped.getIntValue("noPort", -1);
        check(noPort == 1, "manifest 的 dropped.noPort 记录了那个截断包（实际 " + noPort + "，期望 1）");
    }

    // ==================== 帧构造 ====================

    private static byte[] buildUdpFrame() {
        byte[] payload = new byte[8];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }
        byte[] udp = new byte[8 + payload.length];
        ByteBuffer ub = ByteBuffer.wrap(udp).order(ByteOrder.BIG_ENDIAN);
        ub.putShort((short) 3000).putShort((short) 8200)
                .putShort((short) udp.length).putShort((short) 0);
        System.arraycopy(payload, 0, udp, 8, payload.length);
        return ethernetIpFrame((byte) 17, udp);   // 17 = UDP
    }

    private static byte[] buildTcpFrame() {
        byte[] tcp = new byte[20];
        ByteBuffer tb = ByteBuffer.wrap(tcp).order(ByteOrder.BIG_ENDIAN);
        tb.putShort((short) 40001).putShort((short) 80);
        tb.putInt(1000);          // seq
        tb.putInt(0);             // ack
        tb.put((byte) 0x50);      // dataOffset = 5
        tb.put((byte) 0x18);      // PSH|ACK
        tb.putShort((short) 65535).putShort((short) 0).putShort((short) 0);
        return ethernetIpFrame((byte) 6, tcp);    // 6 = TCP
    }

    /** 以太网 + IPv4 + 传输层载荷；校验和留 0（离线解析不校验） */
    private static byte[] ethernetIpFrame(byte transportProtocol, byte[] transport) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            DataOutputStream out = new DataOutputStream(buf);
            // Ethernet
            out.write(new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55});   // dst
            out.write(new byte[]{0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb}); // src
            out.writeShort(0x0800);                                       // IPv4
            // IPv4
            out.writeByte(0x45);                                          // version 4, IHL 5
            out.writeByte(0x00);
            out.writeShort(20 + transport.length);
            out.writeShort(0x0001);                                       // id
            out.writeShort(0x0000);                                       // flags/frag
            out.writeByte(64);                                            // ttl
            out.writeByte(transportProtocol);
            out.writeShort(0);                                            // header checksum（不校验）
            out.write(new byte[]{(byte) 192, (byte) 168, 1, 100});        // src ip
            out.write(new byte[]{(byte) 192, (byte) 168, 1, (byte) 200}); // dst ip
            out.write(transport);
        } catch (Exception e) {
            throw new IllegalStateException("帧构造失败", e);
        }
        return buf.toByteArray();
    }

    /** 断言成功（失败即测试失败）：保留原夹具的调用形态与中文消息，内部改用 JUnit 断言。 */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
