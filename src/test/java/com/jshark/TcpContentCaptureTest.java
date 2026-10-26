package com.jshark;

import com.jshark.parser.CaptureKind;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * D3 验收测试：TCP 内容采集（重组 + 统一消息切分 + 每行可重放）。
 *
 * <h3>这个测试要证明什么</h3>
 * <ol>
 *   <li><b>跨段消息能拼完整</b>：一条 HTTP 消息被拆到两个 TCP 段，
 *       最终必须有一行记录里出现<b>完整</b>消息（早期实现在交付时丢弃字节，永远拼不起来）。</li>
 *   <li><b>乱序也按序列号拼</b>：第二段先到、第一段后到，
 *       拼出来的内容必须与原始字节<b>逐字节相同</b>（而不是按到达顺序倒着拼）。</li>
 *   <li><b>重传不产生重复字节</b>：重复的段不得让内容出现 "HELLOHELLO"。</li>
 *   <li><b>每一行都可重放</b>：TCP 内容行一律携带触发它的真实帧
 *       （{@code captureKind = WIRE_FRAME} 且 {@code frameData} 非空）。
 *       早期实现把合并行写成 {@code frameData = null} + {@code TCP_REASSEMBLED}，
 *       而重放只放行 kind 0/1，那些字节就永久不可重放。</li>
 * </ol>
 *
 * <p>全程离线：构造 pcap → {@code startCaptureFromFile} → 查 DuckDB 断言。</p>
 */
public class TcpContentCaptureTest {

    private static final Logger logger = LoggerFactory.getLogger(TcpContentCaptureTest.class);

    private static final Path WORK_DIR = Paths.get("target", "tcp-content-test");
    private static final Path PCAP_FILE = WORK_DIR.resolve("tcp.pcap");
    private static final String DB_FILE = WORK_DIR.resolve("tcp.duckdb").toString();

    private static final int PORT_IN_ORDER = 40001;
    private static final int PORT_OUT_OF_ORDER = 40002;
    private static final int PORT_RETRANSMIT = 40003;
    private static final int SERVER_PORT = 80;

    private static int totalChecks;
    private static int failedChecks;

    /** 被拆成两段的 HTTP 消息 */
    private static byte[] message;
    /** 拆分点：落在头部中间，确保第一段自己凑不出完整消息 */
    private static byte[] part1;
    private static byte[] part2;

    @org.junit.jupiter.api.Test
    void tcpContentCaptureRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  D3 验收：TCP 内容采集（重组 / 切分 / 可重放）");
        logger.info("=================================================");

        prepare();
        buildPcapAndCapture();
        verify();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    private static void prepare() throws Exception {
        if (Files.exists(WORK_DIR)) {
            try (var stream = Files.walk(WORK_DIR)) {
                stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                        // 清理失败不影响测试结论
                    }
                });
            }
        }
        Files.createDirectories(WORK_DIR);

        // 消息长度与拆分点都在运行时算出，避免手算字节数出错
        message = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
                .getBytes(StandardCharsets.ISO_8859_1);
        int split = 20;
        part1 = Arrays.copyOfRange(message, 0, split);
        part2 = Arrays.copyOfRange(message, split, message.length);

        logger.info("  消息 {} 字节，拆成 {} + {} 字节", message.length, part1.length, part2.length);
    }

    private static void buildPcapAndCapture() throws Exception {
        logger.info("---- [1] 构造 TCP 报文并写入 pcap ----");

        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");

        List<Packet> packets = new ArrayList<>();
        long ts = 1_700_000_000_000L;

        // 流 1：顺序到达（SYN, part1, part2）
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_IN_ORDER, 1000L, null, true, false, false, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_IN_ORDER, 1001L, part1, false, true, false, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_IN_ORDER, 1021L, part2, false, true, true, false));

        // 流 2：乱序到达（SYN, part2 先到, part1 后到）——必须仍按序列号拼
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_OUT_OF_ORDER, 2000L, null, true, false, false, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_OUT_OF_ORDER, 2021L, part2, false, true, false, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_OUT_OF_ORDER, 2001L, part1, false, true, true, false));

        // 流 3：带重传（SYN, part1, part2, part2 重传）
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_RETRANSMIT, 3000L, null, true, false, false, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_RETRANSMIT, 3001L, part1, false, true, false, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_RETRANSMIT, 3021L, part2, false, true, true, false));
        packets.add(tcpFrame(srcMac, dstMac, srcIp, dstIp, PORT_RETRANSMIT, 3021L, part2, false, true, true, false));

        try (PcapHandle h = Pcaps.openDead(DataLinkType.EN10MB, 65536);
             PcapDumper dumper = h.dumpOpen(PCAP_FILE.toString())) {
            for (int i = 0; i < packets.size(); i++) {
                dumper.dump(packets.get(i), new Timestamp(ts + i * 1000L));
            }
            dumper.flush();
        }
        logger.info("  已写入 {} 个报文到 {}", packets.size(), PCAP_FILE);

        logger.info("---- [2] 经 PacketCapture（离线模式）采集到 DuckDB ----");
        PacketCapture capture = new PacketCapture();
        capture.setLogDb(DB_FILE);
        capture.startCaptureFromFile(PCAP_FILE.toString());
        logger.info("  采集完成");
    }

    private static void verify() throws Exception {
        logger.info("---- [3] 校验入库结果 ----");

        Map<Integer, List<byte[]>> byClientPort = new LinkedHashMap<>();
        List<byte[]> allRaw = new ArrayList<>();
        int totalRows = 0;
        int unreplayableRows = 0;

        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + DB_FILE);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("Select captureKind, frameData, rawData, sourcePort "
                     + "From JSharkLog Order By ID")) {
            while (rs.next()) {
                totalRows++;
                int kind = rs.getInt("captureKind");
                byte[] frameData = readBlob(rs, "frameData");
                byte[] rawData = readBlob(rs, "rawData");
                int srcPort = rs.getInt("sourcePort");

                // 4) 每行都必须可重放
                boolean replayable = frameData != null && frameData.length > 0
                        && kind == CaptureKind.WIRE_FRAME.code();
                if (!replayable) {
                    unreplayableRows++;
                    logger.error("[失败] 存在不可重放的行: captureKind={}, frameData={} 字节",
                            kind, frameData == null ? "null" : frameData.length);
                }

                if (srcPort == PORT_IN_ORDER || srcPort == PORT_OUT_OF_ORDER
                        || srcPort == PORT_RETRANSMIT) {
                    byClientPort.computeIfAbsent(srcPort, k -> new ArrayList<>())
                            .add(rawData == null ? new byte[0] : rawData);
                    if (rawData != null) {
                        allRaw.add(rawData);
                    }
                }
            }
        }

        check(totalRows == 10, "共入库 10 行（实际 " + totalRows + "）");
        check(unreplayableRows == 0,
                "所有行都可按帧原样重放（不可重放行数 " + unreplayableRows + "）");

        // 1) 顺序到达：最终拼出完整消息
        verifyFlow(byClientPort.get(PORT_IN_ORDER), 3, "顺序到达");

        // 2) 乱序到达：仍按序列号拼出与原始字节完全相同的内容
        verifyFlow(byClientPort.get(PORT_OUT_OF_ORDER), 3, "乱序到达");

        // 3) 重传：拼出完整消息，且不得出现重复字节
        verifyFlow(byClientPort.get(PORT_RETRANSMIT), 4, "带重传");

        // 3b) 全局不得出现 "HELLOHELLO"（重传被去重的证据）
        byte[] doubled = "HELLOHELLO".getBytes(StandardCharsets.ISO_8859_1);
        boolean sawDoubled = false;
        for (byte[] raw : allRaw) {
            if (indexOf(raw, doubled) >= 0) {
                sawDoubled = true;
                break;
            }
        }
        check(!sawDoubled, "重传段被去重，内容中没有出现重复的 HELLO");
    }

    /**
     * 校验一条流：行数、以及"必须存在一行内容与原始消息逐字节相同"。
     * <p>
     * 用逐字节比较而不是"包含"，是为了同时证明拼接<b>顺序</b>正确——
     * 按到达顺序拼接的实现在乱序流上会得到 part2+part1，无法通过。
     * </p>
     */
    private static void verifyFlow(List<byte[]> rows, int expectedRows, String label) {
        if (rows == null) {
            check(false, label + "：没有任何记录");
            return;
        }
        check(rows.size() == expectedRows,
                label + "：入库 " + expectedRows + " 行（实际 " + rows.size() + "）");

        boolean exact = false;
        int maxLen = 0;
        for (byte[] raw : rows) {
            maxLen = Math.max(maxLen, raw.length);
            if (Arrays.equals(raw, message)) {
                exact = true;
            }
        }
        check(exact, label + "：存在一行内容与原始消息逐字节相同（最长内容 " + maxLen
                + " 字节，期望 " + message.length + " 字节）");
    }

    // ==================== 工具 ====================

    private static Packet tcpFrame(MacAddress srcMac, MacAddress dstMac,
                                   Inet4Address srcIp, Inet4Address dstIp,
                                   int srcPort, long seq, byte[] payload,
                                   boolean syn, boolean ack, boolean psh, boolean rst) {
        TcpPacket.Builder tcp = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) srcPort))
                .dstPort(TcpPort.getInstance((short) SERVER_PORT))
                .srcAddr(srcIp)
                .dstAddr(dstIp)
                .sequenceNumber((int) seq)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .syn(syn).ack(ack).psh(psh).fin(false).rst(rst)
                .urg(false)
                .window((short) 65535)
                .urgentPointer((short) 0)
                .options(new ArrayList<>())
                .payloadBuilder(payload == null || payload.length == 0
                        ? null
                        : new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(srcIp)
                .dstAddr(dstIp)
                .payloadBuilder(tcp)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return new EthernetPacket.Builder()
                .srcAddr(srcMac)
                .dstAddr(dstMac)
                .type(EtherType.IPV4)
                .payloadBuilder(ip)
                .paddingAtBuild(true)
                .build();
    }

    private static byte[] readBlob(ResultSet rs, String column) throws SQLException {
        // DuckDB JDBC 不支持 ResultSet.getBytes()，必须走 getObject()
        Object obj = rs.getObject(column);
        if (obj == null) {
            return null;
        }
        if (obj instanceof byte[] bytes) {
            return bytes;
        }
        if (obj instanceof java.sql.Blob blob) {
            try {
                return blob.getBytes(1, (int) blob.length());
            } catch (SQLException e) {
                throw new SQLException("读取 BLOB 失败: " + column, e);
            }
        }
        return obj.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * 断言成功（失败即测试失败）。
     * <p>保留原夹具的调用形态与中文消息，内部改成 JUnit 断言。</p>
     */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
