package com.jshark;

import com.jshark.parser.CaptureKind;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A1 验收测试：完整帧入库 + 长度自洽。
 *
 * <h3>验证项</h3>
 * <ol>
 *   <li>{@code frameData} 与 pcap 中的原始帧**逐字节相同**</li>
 *   <li>{@code captureKind}：普通帧为 WIRE_FRAME，IP 分片重组后为 IP_DEFRAG_SYNTH</li>
 *   <li>时间戳取自 pcap 首部（可精确复现写入时的时间戳）</li>
 *   <li>{@code wireLen} / {@code capLen} 自洽，且分片记录不再出现"长度与内容不一致"</li>
 * </ol>
 *
 * <p>运行：{@code java -cp target/classes:target/test-classes:<deps> com.jshark.FrameStorageTest}</p>
 */
public class FrameStorageTest {

    private static final Logger logger = LoggerFactory.getLogger(FrameStorageTest.class);

    private static final Path WORK_DIR = Path.of("target", "test-a1");
    private static final Path PCAP_FILE = WORK_DIR.resolve("frames.pcap");
    private static final String DB_FILE = WORK_DIR.resolve("frames.duckdb").toString();

    /** 普通 UDP 帧的期望帧字节，按写入顺序排列 */
    private static final List<byte[]> EXPECTED_FRAMES = new ArrayList<>();
    /** 分片数据报的期望重组 payload（传输层头 + 数据） */
    private static final Map<Integer, byte[]> EXPECTED_DEFRAG = new LinkedHashMap<>();
    /** 分片数据报的期望应用层 payload（不含 UDP 头），即 rawData 的期望值 */
    private static final Map<Integer, byte[]> EXPECTED_DEFRAG_APP = new LinkedHashMap<>();
    /** 分片数据报的期望线上长度：首片线上长度(1514) + 后续分片增量(8) */
    private static final int EXPECTED_DEFRAG_WIRE_LEN = 1514 + 8;

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void frameStorageRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  A1 验收：完整帧入库 + 长度自洽");
        logger.info("=================================================");

        step0_prepare();
        step1_buildAndRecordPcap();
        step2_captureFromPcap();
        step3_verify();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    // ==================== 步骤 ====================

    private static void step0_prepare() throws Exception {
        logger.info("---- [0] 准备目录 ----");
        if (Files.exists(WORK_DIR)) {
            Files.walk(WORK_DIR)
                    .sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignore) {
                        }
                    });
        }
        Files.createDirectories(WORK_DIR);
        logger.info("  工作目录: {}", WORK_DIR.toAbsolutePath());
    }

    private static void step1_buildAndRecordPcap() throws Exception {
        logger.info("---- [1] 构造报文并写入 pcap ----");
        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");

        List<Packet> packets = new ArrayList<>();
        List<Long> timestamps = new ArrayList<>();

        long baseTs = 1_700_000_000_000L;

        // 1) 三个普通 UDP 帧（大小不一，含边界值）
        int[] payloadSizes = {16, 512, 1472};
        int[] srcPorts = {3000, 3001, 3002};
        for (int i = 0; i < payloadSizes.length; i++) {
            byte[] payload = new byte[payloadSizes[i]];
            for (int j = 0; j < payload.length; j++) {
                payload[j] = (byte) (i * 31 + j);
            }
            Packet pkt = buildUdpFrame(srcMac, dstMac, srcIp, dstIp, srcPorts[i], 8200, payload);
            packets.add(pkt);
            timestamps.add(baseTs + i * 1000L);
            EXPECTED_FRAMES.add(pkt.getRawData());
        }

        // 2) 一个 IP 分片的 UDP 数据报（1480 字节 UDP payload，分两片）
        byte[] bigPayload = new byte[1480];
        for (int j = 0; j < bigPayload.length; j++) {
            bigPayload[j] = (byte) (0x5A ^ j);
        }
        short ipId = (short) 0x1234;
        List<Packet> frags = buildFragmentedUdpFrames(srcMac, dstMac, srcIp, dstIp,
                3003, 8200, bigPayload, ipId);
        for (int i = 0; i < frags.size(); i++) {
            packets.add(frags.get(i));
            timestamps.add(baseTs + 10_000L + i * 100L);
        }
        // 期望的重组 payload = UDP 头(8) + 1480
        byte[] expectedDefrag = new byte[8 + bigPayload.length];
        ByteBuffer ub = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        ub.putShort((short) 3003).putShort((short) 8200).putShort((short) (8 + bigPayload.length)).putShort((short) 0);
        System.arraycopy(ub.array(), 0, expectedDefrag, 0, 8);
        System.arraycopy(bigPayload, 0, expectedDefrag, 8, bigPayload.length);
        EXPECTED_DEFRAG.put(1, expectedDefrag);
        // rawData 存的是应用层 payload（不含 UDP 头）
        EXPECTED_DEFRAG_APP.put(1, bigPayload);

        // 写入 pcap（离线 dead handle）
        try (PcapHandle h = Pcaps.openDead(org.pcap4j.packet.namednumber.DataLinkType.EN10MB, 65536);
             org.pcap4j.core.PcapDumper dumper = h.dumpOpen(PCAP_FILE.toString())) {
            for (int i = 0; i < packets.size(); i++) {
                dumper.dump(packets.get(i), new Timestamp(timestamps.get(i)));
            }
            dumper.flush();
        }

        logger.info("  已写入 {} 个报文（普通 {} + 分片 {}），文件 {}",
                packets.size(), EXPECTED_FRAMES.size(), frags.size(), PCAP_FILE);
    }

    private static void step2_captureFromPcap() throws Exception {
        logger.info("---- [2] 经 PacketCapture（离线模式）采集到 DuckDB ----");
        PacketCapture capture = new PacketCapture();
        capture.setLogDb(DB_FILE);
        // 本用例校验 additionalInfo 的完整性，显式打开（CLI 默认 false 时该列为 NULL）
        capture.setEnableAdditionalInfo(true);
        capture.setOutputFile(WORK_DIR.resolve("copy.pcap").toString());
        capture.setVerbose("true".equalsIgnoreCase(System.getProperty("jshark.a1.verbose", "false")));
        capture.startCaptureFromFile(PCAP_FILE.toString());
        logger.info("  采集完成");
    }

    private static void step3_verify() throws Exception {
        logger.info("---- [3] 校验入库结果 ----");

        int wireFrameCount = 0;
        int synthCount = 0;
        int totalRows = 0;
        List<String> seenFrames = new ArrayList<>();
        Map<Long, String> synthBySeq = new TreeMap<>();

        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + DB_FILE);
             Statement st = conn.createStatement()) {

            // 3.1 逐行读取，按 ID 顺序核对
            try (ResultSet rs = st.executeQuery(
                    "Select ID, frameData, rawData, wireLen, capLen, captureKind, length, sourcePort, destinationPort "
                            + "From JSharkLog Order By ID")) {
                while (rs.next()) {
                    totalRows++;
                    long id = rs.getLong("ID");
                    byte[] frameData = readBlob(rs, "frameData");
                    byte[] rawData = readBlob(rs, "rawData");
                    int wireLen = rs.getInt("wireLen");
                    int capLen = rs.getInt("capLen");
                    int kind = rs.getInt("captureKind");
                    int length = rs.getInt("length");
                    int srcPort = rs.getInt("sourcePort");

                    if (kind == CaptureKind.WIRE_FRAME.code()) {
                        wireFrameCount++;
                        seenFrames.add(hex(frameData));

                        check(frameData != null, "ID=" + id + " WIRE_FRAME 必须有 frameData");
                        check(Arrays.equals(frameData, EXPECTED_FRAMES.get(wireFrameCount - 1)),
                                "ID=" + id + " frameData 与原始帧逐字节相同（源端口 " + srcPort + "）");
                        check(capLen == frameData.length,
                                "ID=" + id + " capLen == frameData.length (" + capLen + ")");
                        check(wireLen == frameData.length,
                                "ID=" + id + " wireLen == capLen（未被截断，无填充）(" + wireLen + ")");
                        check(length == wireLen,
                                "ID=" + id + " length == wireLen (" + length + ")");
                    } else if (kind == CaptureKind.IP_DEFRAG_SYNTH.code()) {
                        synthCount++;
                        synthBySeq.put(id, "synth");
                        byte[] expectedApp = EXPECTED_DEFRAG_APP.get(synthCount);
                        check(frameData != null, "ID=" + id + " IP_DEFRAG_SYNTH 必须有合成帧");
                        boolean appMatch = rawData != null && expectedApp != null
                                && Arrays.equals(rawData, expectedApp);
                        check(appMatch,
                                "ID=" + id + " rawData == 应用层 payload（不含 UDP 头）"
                                        + " actual=" + (rawData == null ? "null" : rawData.length)
                                        + " expect=" + (expectedApp == null ? "null" : expectedApp.length)
                                        + " match=" + appMatch);
                        check(capLen == frameData.length,
                                "ID=" + id + " 合成帧 capLen == frameData.length (" + capLen + ")");
                        check(wireLen == EXPECTED_DEFRAG_WIRE_LEN,
                                "ID=" + id + " 合成帧 wireLen == 首片线上长度 + 后续增量 ("
                                        + wireLen + " vs " + EXPECTED_DEFRAG_WIRE_LEN + ")");
                        // 关键：不再出现"长度与内容不一致"
                        check(length == wireLen,
                                "ID=" + id + " 分片记录 length == wireLen（修复前取自首片帧长）("
                                        + length + " vs " + wireLen + ")");
                        // 合成帧是合法 UDP：端口可解析
                        check(srcPort == 3003, "ID=" + id + " 合成帧源端口可解析 (" + srcPort + ")");
                    } else {
                        check(false, "ID=" + id + " 出现非预期 captureKind=" + kind);
                    }
                }
            }

            // 3.2 统计计数
            check(totalRows == EXPECTED_FRAMES.size() + EXPECTED_DEFRAG.size(),
                    "入库记录数 == 普通帧数 + 重组数 (" + totalRows + ")");
            check(wireFrameCount == EXPECTED_FRAMES.size(),
                    "WIRE_FRAME 记录数 == " + EXPECTED_FRAMES.size() + " (" + wireFrameCount + ")");
            check(synthCount == EXPECTED_DEFRAG.size(),
                    "IP_DEFRAG_SYNTH 记录数 == " + EXPECTED_DEFRAG.size() + " (" + synthCount + ")");

            // 3.3 无重复帧（防止同一帧被多次入库）
            check(seenFrames.size() == seenFrames.stream().distinct().count(),
                    "WIRE_FRAME 帧内容无重复");

            // 3.4 时间戳来自 pcap 首部（第一帧应为写入时的 baseTs）
            try (ResultSet rs = st.executeQuery(
                    "Select TimeStamp From JSharkLog Order By ID Limit 1")) {
                if (rs.next()) {
                    long actual = rs.getTimestamp("TimeStamp").getTime();
                    check(actual == 1_700_000_000_000L,
                            "首帧时间戳取自 pcap 首部 (" + actual + ")");
                }
            }

            // 3.5 volumeSeq 有效（未启用分卷时为 0）
            try (ResultSet rs = st.executeQuery(
                    "Select count(*) As c From JSharkLog Where volumeSeq Is Not Null")) {
                rs.next();
                check(rs.getInt("c") == totalRows, "volumeSeq 全部非空");
            }

            // 3.7 协议解析结果确实落库（回归防护：曾因 ProtocolParser 误用 withFrame 组装
            //     而把新解析出的 additionalInfo 整包丢弃，表现为 appProtocol 全空）
            try (ResultSet rs = st.executeQuery(
                    "Select count(*) As c From JSharkLog Where additionalInfo Is Not Null")) {
                rs.next();
                check(rs.getInt("c") == totalRows,
                        "additionalInfo 全部非空（协议解析结果未被丢弃）(" + rs.getInt("c") + "/" + totalRows + ")");
            }
            try (ResultSet rs = st.executeQuery(
                    "Select count(*) As c From JSharkLog Where additionalInfo Like '%application.protocol%'")) {
                rs.next();
                check(rs.getInt("c") == totalRows,
                        "additionalInfo 含 application.protocol (" + rs.getInt("c") + "/" + totalRows + ")");
            }
        }

        // 3.6 副本 pcap 与源 pcap 字节数一致（PCAP 输出未被本次改造破坏）
        Path copy = WORK_DIR.resolve("copy.pcap");
        check(Files.exists(copy) && Files.size(copy) > 0, "输出的 pcap 文件已生成且非空");
    }

    // ==================== 报文构造 ====================

    private static Packet buildUdpFrame(MacAddress srcMac, MacAddress dstMac,
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
                .tos(org.pcap4j.packet.IpV4Rfc791Tos.newInstance((byte) 0))
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

    /**
     * 构造一个分两片的 UDP 数据报（首片 offset=0/MF=1，次片 offset=1480/MF=0）。
     */
    private static List<Packet> buildFragmentedUdpFrames(MacAddress srcMac, MacAddress dstMac,
                                                         Inet4Address srcIp, Inet4Address dstIp,
                                                         int srcPort, int dstPort,
                                                         byte[] udpPayload, short ipId) {
        byte[] full = new byte[8 + udpPayload.length];
        ByteBuffer ub = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        ub.putShort((short) srcPort).putShort((short) dstPort)
                .putShort((short) full.length).putShort((short) 0);
        System.arraycopy(ub.array(), 0, full, 0, 8);
        System.arraycopy(udpPayload, 0, full, 8, udpPayload.length);

        int split = 1480; // 8 字节对齐
        byte[] frag1 = Arrays.copyOfRange(full, 0, split);
        byte[] frag2 = Arrays.copyOfRange(full, split, full.length);

        List<Packet> out = new ArrayList<>();
        out.add(buildIpFragment(srcMac, dstMac, srcIp, dstIp, ipId, frag1, 0, true));
        out.add(buildIpFragment(srcMac, dstMac, srcIp, dstIp, ipId, frag2, split, false));
        return out;
    }

    private static Packet buildIpFragment(MacAddress srcMac, MacAddress dstMac,
                                          Inet4Address srcIp, Inet4Address dstIp,
                                          short ipId, byte[] data, int offsetBytes, boolean moreFragments) {
        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(org.pcap4j.packet.IpV4Rfc791Tos.newInstance((byte) 0))
                .totalLength((short) (20 + data.length))
                .identification(ipId)
                .reservedFlag(false)
                .dontFragmentFlag(false)
                .moreFragmentFlag(moreFragments)
                .fragmentOffset((short) (offsetBytes / 8))
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(srcIp)
                .dstAddr(dstIp)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .paddingAtBuild(false)
                .payloadBuilder(new UnknownPacket.Builder().rawData(data));

        return new EthernetPacket.Builder()
                .srcAddr(srcMac)
                .dstAddr(dstMac)
                .type(EtherType.IPV4)
                .payloadBuilder(ip)
                .paddingAtBuild(true)
                .build();
    }

    // ==================== 工具 ====================

    private static byte[] readBlob(ResultSet rs, String column) throws Exception {
        Object obj = rs.getObject(column);
        if (obj == null) {
            return null;
        }
        if (obj instanceof byte[] bytes) {
            return bytes;
        }
        if (obj instanceof java.sql.Blob blob) {
            return blob.getBytes(1, (int) blob.length());
        }
        return obj.toString().getBytes();
    }

    private static String hex(byte[] data) {
        if (data == null) {
            return "<null>";
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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
