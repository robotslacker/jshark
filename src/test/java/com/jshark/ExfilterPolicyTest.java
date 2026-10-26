package com.jshark;

import com.jshark.parser.CaptureKind;
import com.jshark.parser.PacketDBEventHandler;
import com.jshark.parser.PacketParser;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code --exfilter} 验收：不匹配的包一律丢弃（计数并汇报），匹配的包入库。
 *
 * <h3>要解决的问题</h3>
 * <p>
 * {@code --exfilter} 的失败模式不是"过滤得太严"，而是<b>静默</b>：
 * 表达式写错（键名拼错、协议没识别出来）时所有包都不匹配、全部被丢，
 * 使用者面对一个空库，无法区分"确实没流量"和"条件写错了"。
 * 因此被丢弃的数量必须可查；没有 additionalInfo 的包永远不可能匹配任何表达式，
 * 它们被丢弃与过滤条件无关，属于"必然丢弃"，需要单独计数。
 * </p>
 */
public class ExfilterPolicyTest {

    private static final Logger logger = LoggerFactory.getLogger(ExfilterPolicyTest.class);

    private static final Path WORK_DIR = Paths.get("target", "exfilter-test");
    private static final Path PCAP_FILE = WORK_DIR.resolve("udp.pcap");
    private static final Path DB_NEVER = WORK_DIR.resolve("never.duckdb");
    private static final Path DB_MATCH = WORK_DIR.resolve("match.duckdb");

    /** 一个不会有任何包匹配的表达式：载荷里没有 DIS */
    private static final String NEVER_MATCH = "application.protocol=DIS";
    /** 一个能匹配构造出的 UDP 包的表达式（依赖 additionalInfo 详细字段） */
    private static final String MATCH_UDP = "ip.protocol.name=UDP";

    private static final int FRAME_COUNT = 2;

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void exfilterRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  --exfilter 验收（不匹配即丢弃）");
        logger.info("=================================================");

        checkDecision();
        checkEndToEnd();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    // ==================== [1] 决策与计数（不需要数据库） ====================

    private static void checkDecision() {
        logger.info("---- [1] 过滤决策与计数 ----");

        // 不匹配 → 不入队，且"无 additionalInfo"单独计数
        PacketDBEventHandler dropped = new PacketDBEventHandler();
        dropped.setExfilter(NEVER_MATCH);
        dropped.addPacket(dummyPacket(Map.of()), Map.of());
        check(dropped.filteredOut() == 1,
                "不匹配的包被计数（实际 " + dropped.filteredOut() + "）");
        check(dropped.filteredOutWithoutInfo() == 1,
                "无 additionalInfo 单独计数（实际 " + dropped.filteredOutWithoutInfo() + "）");
        check(dropped.pendingQueueSize() == 0, "不匹配的包不入库");

        // 有 additionalInfo 但不匹配：计入 filteredOut，但不计入"无信息"
        Map<String, Object> udpInfo = Map.of("application.protocol", "UDP");
        PacketDBEventHandler unmatchedWithInfo = new PacketDBEventHandler();
        unmatchedWithInfo.setExfilter(NEVER_MATCH);
        unmatchedWithInfo.addPacket(dummyPacket(udpInfo), udpInfo);
        check(unmatchedWithInfo.filteredOut() == 1 && unmatchedWithInfo.filteredOutWithoutInfo() == 0,
                "有信息但不匹配：只计入 filteredOut");
        check(unmatchedWithInfo.pendingQueueSize() == 0, "有信息但不匹配的包同样不入库");

        // 匹配的包：不计数、正常入库
        PacketDBEventHandler hit = new PacketDBEventHandler();
        hit.setExfilter(NEVER_MATCH);
        Map<String, Object> disInfo = Map.of("application.protocol", "DIS");
        hit.addPacket(dummyPacket(disInfo), disInfo);
        check(hit.filteredOut() == 0, "匹配的包不计入 filteredOut（实际 " + hit.filteredOut() + "）");
        check(hit.pendingQueueSize() == 1, "匹配的包正常入库");

        // 未设置表达式：完全不过滤
        PacketDBEventHandler none = new PacketDBEventHandler();
        none.addPacket(dummyPacket(Map.of()), Map.of());
        check(none.filteredOut() == 0 && none.pendingQueueSize() == 1,
                "未设置 --exfilter 时不过滤");
    }

    // ==================== [2] 端到端 ====================

    private static void checkEndToEnd() throws Exception {
        logger.info("---- [2] 端到端：不匹配丢弃、匹配入库并保留 additionalInfo ----");

        if (Files.exists(WORK_DIR)) {
            try (var stream = Files.walk(WORK_DIR)) {
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
        buildPcap();

        CaptureOutcome never = captureAndCount(DB_NEVER, NEVER_MATCH);
        check(never.rows() == 0, "不匹配的包一行都不入库（实际 " + never.rows() + " 行）");
        check(never.accountingResidual() == 0,
                "停机账目闭合，被过滤且未入库的包必须计入（残差 " + never.accountingResidual() + "）");

        CaptureOutcome match = captureAndCount(DB_MATCH, MATCH_UDP);
        check(match.rows() == FRAME_COUNT,
                "匹配的包全部入库（实际 " + match.rows() + " 行，期望 " + FRAME_COUNT + "）");
        check(match.accountingResidual() == 0,
                "停机账目闭合（残差 " + match.accountingResidual() + "）");
        // --exfilter 自动开启 additionalInfo：匹配行必须保留协议字段，供事后查询与重放过滤
        check(match.additionalInfoRows() == FRAME_COUNT,
                "匹配行保留 additionalInfo（实际 " + match.additionalInfoRows() + "/" + FRAME_COUNT + "）");
    }

    /** 一次采集的结果：入库行数 + 非空 additionalInfo 行数 + 停机对账残差 */
    private record CaptureOutcome(int rows, int additionalInfoRows, long accountingResidual) {}

    /**
     * 用同一份 pcap 跑一次采集，返回入库行数、additionalInfo 行数与停机对账残差。
     * <p>残差必须在 {@code startCaptureFromFile} 返回（即收尾完成）之后读取。</p>
     */
    private static CaptureOutcome captureAndCount(Path dbFile, String exfilter) throws Exception {
        PacketCapture capture = new PacketCapture();
        capture.setLogDb(dbFile.toString());
        // 不显式开启 additionalInfo：--exfilter 应当自动开启并落库
        capture.setExfilter(exfilter);
        capture.startCaptureFromFile(PCAP_FILE.toString());
        long residual = capture.accountingResidual();

        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + dbFile);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "Select count(*) n, count(additionalInfo) info_n From JSharkLog")) {
            rs.next();
            return new CaptureOutcome(rs.getInt("n"), rs.getInt("info_n"), residual);
        }
    }

    private static void buildPcap() throws Exception {
        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");

        List<Packet> packets = new ArrayList<>();
        for (int i = 0; i < FRAME_COUNT; i++) {
            byte[] payload = new byte[32];
            for (int j = 0; j < payload.length; j++) {
                payload[j] = (byte) (i * 31 + j);
            }
            packets.add(udpFrame(srcMac, dstMac, srcIp, dstIp, 3000 + i, 8200, payload));
        }

        long ts = 1_700_000_000_000L;
        try (PcapHandle h = Pcaps.openDead(DataLinkType.EN10MB, 65536);
             PcapDumper dumper = h.dumpOpen(PCAP_FILE.toString())) {
            for (int i = 0; i < packets.size(); i++) {
                dumper.dump(packets.get(i), new Timestamp(ts + i * 1000L));
            }
            dumper.flush();
        }
        logger.info("  已写入 {} 个 UDP 报文到 {}", packets.size(), PCAP_FILE);
    }

    // ==================== 工具 ====================

    private static PacketParser.ParsedPacket dummyPacket(Map<String, Object> info) {
        return new PacketParser.ParsedPacket(
                1L, Instant.now(), 64,
                "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                "10.0.0.1", "10.0.0.2",
                IpNumber.UDP, 3000, 4000,
                info, "test",
                new byte[]{1, 2, 3}, new byte[]{9, 9}, 64, 64,
                CaptureKind.WIRE_FRAME);
    }

    private static Packet udpFrame(MacAddress srcMac, MacAddress dstMac,
                                   Inet4Address srcIp, Inet4Address dstIp,
                                   int srcPort, int dstPort, byte[] payload) {
        UdpPacket.Builder udp = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) srcPort))
                .dstPort(UdpPort.getInstance((short) dstPort))
                .srcAddr(srcIp)
                .dstAddr(dstIp)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(srcIp)
                .dstAddr(dstIp)
                .payloadBuilder(udp)
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

    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
