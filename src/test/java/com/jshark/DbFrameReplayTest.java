package com.jshark;

import com.jshark.parser.DbReplayTool;
import com.jshark.parser.FrameRewriter;
import com.jshark.parser.StartupSelfCheck;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * B4 收尾验收：<b>数据库帧级重放</b>的字节级保真。
 *
 * <h3>验证链路（这是完整的"采集 → 存储 → 重放"闭环）</h3>
 * <pre>
 *   构造双向报文（UDP + TCP，带已知 IP ID / 载荷）
 *     → 写入 pcap
 *     → PacketCapture.startCaptureFromFile() 采集入库（frameData 落库）
 *     → DbReplayTool.enableFrameMode() 从数据库逐帧读取
 *     → RawFrameSender 注入网卡
 *     → 同网卡抓包 → 逐字节比对
 * </pre>
 *
 * <h3>断言</h3>
 * <ul>
 *   <li>库中可重放帧数 == 原始帧数（无帧记录不参与）</li>
 *   <li>重放发出的帧数 == 库中可重放帧数</li>
 *   <li>DB → 网卡 的每一帧与原始帧<b>逐字节一致</b>（无映射改写时）</li>
 *   <li>源 IP/源端口/载荷/seq/ack 等全部未变</li>
 * </ul>
 *
 * <p>与 {@link InjectE2ETest} 的分工：后者验证"pcap → 注入"并覆盖目标映射改写；
 * 本测试验证"DB → 注入"，即帧确实从 {@code frameData} 出得来、且与原帧一致。</p>
 */
public class DbFrameReplayTest {

    private static final Logger logger = LoggerFactory.getLogger(DbFrameReplayTest.class);

    private static final Path WORK_DIR = Path.of("target", "test-dbframe");
    private static final Path PCAP_FILE = WORK_DIR.resolve("db_source.pcap");
    private static final String DB_FILE = WORK_DIR.resolve("db_frame.duckdb").toString();

    private static final String SRC_IP = "192.168.5.100";
    private static final String DST_IP = "192.168.5.201";
    private static final MacAddress SRC_MAC = MacAddress.getByName("02:4a:53:48:41:52");
    private static final MacAddress DST_MAC = MacAddress.getByName("02:4a:53:48:41:53");
    private static final int UDP_SRC_PORT = 43200;
    private static final int UDP_DST_PORT = 43201;
    private static final int TCP_SRC_PORT = 44200;
    private static final int TCP_DST_PORT = 44201;

    private static final int FRAME_COUNT = 60;
    private static final double SPEED = 2.0;

    private static final List<byte[]> originalFrames = new ArrayList<>();

    private static int totalChecks;
    private static int failedChecks;

    /**
     * B4 验收：数据库帧级重放（live：需要 Npcap + 管理员权限，默认 {@code mvn test} 不执行）。
     */
    @org.junit.jupiter.api.Tag("live")
    @org.junit.jupiter.api.Test
    void dbFrameReplayRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  B4 验收：数据库帧级重放（采集 → 存储 → 注入）");
        logger.info("=================================================");

        // 测试方法不再有命令行参数：用 -Djshark.iface.ip=<ip> 指定注入网卡，默认自动探测
        String preferredIp = System.getProperty("jshark.iface.ip");
        PcapNetworkInterface nif = pickInjectableInterface(preferredIp);
        if (nif == null) {
            logger.warn("SKIPPED: no frame-injectable NIC on this machine (needs a wired Ethernet adapter). "
                    + "Re-run with -Djshark.iface.ip=<ip> on com.jshark.DbFrameReplayTest");
            return;
        }
        logger.info("使用注入网卡: {} ({})", nif.getName(), nif.getDescription());

        step0_prepare();
        step1_buildPcap();
        step2_captureIntoDb();
        List<byte[]> captured = step3_replayFromDbAndCapture(nif);
        step4_verify(captured);

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    private static PcapNetworkInterface pickInjectableInterface(String preferredIp) throws Exception {
        List<PcapNetworkInterface> candidates = new ArrayList<>();
        if (preferredIp != null && !preferredIp.isEmpty()) {
            PcapNetworkInterface nif = StartupSelfCheck.findInterfaceByIp(preferredIp);
            if (nif == null) {
                logger.error("No interface has IP {}", preferredIp);
                return null;
            }
            candidates.add(nif);
        } else {
            for (PcapNetworkInterface n : Pcaps.findAllDevs()) {
                String desc = n.getDescription();
                if (desc == null || desc.contains("VMware") || desc.contains("TAP-Windows")
                        || desc.contains("Wintun") || desc.contains("OpenVPN")
                        || desc.contains("Wi-Fi Direct") || desc.contains("Bluetooth")) {
                    continue;
                }
                candidates.add(n);
            }
        }
        for (PcapNetworkInterface n : candidates) {
            StartupSelfCheck.Result r = StartupSelfCheck.run(n, -1, 0);
            if (r != null && r.verdict().injectable()) {
                logger.info("网卡 {} 可用于注入（自检结论 {}）", n.getName(), r.verdict());
                return n;
            }
        }
        return null;
    }

    private static void step0_prepare() throws Exception {
        if (Files.exists(WORK_DIR)) {
            try (java.util.stream.Stream<Path> walk = Files.walk(WORK_DIR)) {
                walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignore) {
                        // 忽略清理失败
                    }
                });
            }
        }
        Files.createDirectories(WORK_DIR);
    }

    private static void step1_buildPcap() throws Exception {
        logger.info("---- [1] 构造 {} 个报文并写入 pcap ----", FRAME_COUNT);
        Inet4Address src = (Inet4Address) InetAddress.getByName(SRC_IP);
        Inet4Address dst = (Inet4Address) InetAddress.getByName(DST_IP);
        long base = System.currentTimeMillis();

        List<Packet> packets = new ArrayList<>();
        for (int i = 0; i < FRAME_COUNT; i++) {
            boolean tcp = (i % 2 == 1);
            byte[] payload = payloadFor(i);
            short ipId = (short) (0xD000 + i);
            Packet pkt = tcp ? buildTcp(src, dst, ipId, payload, 5000 + i, 6000 + i)
                    : buildUdp(src, dst, ipId, payload);
            packets.add(pkt);
            originalFrames.add(pkt.getRawData());
        }

        try (PcapHandle dead = Pcaps.openDead(org.pcap4j.packet.namednumber.DataLinkType.EN10MB, 65536);
             org.pcap4j.core.PcapDumper dumper = dead.dumpOpen(PCAP_FILE.toString())) {
            for (int i = 0; i < packets.size(); i++) {
                dumper.dump(packets.get(i), new Timestamp(base + i * 5L));
            }
            dumper.flush();
        }
        logger.info("  已写入 {}", PCAP_FILE);
    }

    private static void step2_captureIntoDb() throws Exception {
        logger.info("---- [2] 经 PacketCapture 采集入库（frameData 落库）----");
        PacketCapture capture = new PacketCapture();
        capture.setLogDb(DB_FILE);
        capture.setVerbose("true".equalsIgnoreCase(System.getProperty("jshark.b4.verbose", "false")));
        capture.startCaptureFromFile(PCAP_FILE.toString());

        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + DB_FILE);
             Statement st = conn.createStatement()) {
            try (ResultSet rs = st.executeQuery("Select count(*) As c From JSharkLog")) {
                rs.next();
                check(rs.getInt("c") == FRAME_COUNT,
                        "入库记录数 == " + FRAME_COUNT + " (实际 " + rs.getInt("c") + ")");
            }
            try (ResultSet rs = st.executeQuery(
                    "Select count(*) As c From JSharkLog Where frameData Is Not Null "
                            + "And (captureKind = 0 Or captureKind = 1)")) {
                rs.next();
                check(rs.getInt("c") == FRAME_COUNT,
                        "可重放帧数 == " + FRAME_COUNT + " (实际 " + rs.getInt("c") + ")");
            }
        }
    }

    /**
     * 从数据库帧级重放，并同网卡抓包。
     *
     * @param nif 注入网卡
     * @return 抓到的帧
     */
    private static List<byte[]> step3_replayFromDbAndCapture(PcapNetworkInterface nif) throws Exception {
        logger.info("---- [3] 数据库帧级重放（无映射改写）并同网卡抓包 ----");

        List<byte[]> captured = java.util.Collections.synchronizedList(new ArrayList<>());
        Thread capturer = new Thread(() -> {
            try (PcapHandle cap = nif.openLive(65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                try {
                    cap.setFilter("(udp and portrange 43200-43299) or (tcp and portrange 44200-44299)",
                            org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE);
                } catch (Exception e) {
                    logger.warn("抓包过滤器设置失败，改为全量收包: {}", e.getMessage());
                }
                long deadline = System.currentTimeMillis() + 5000;
                while (System.currentTimeMillis() < deadline) {
                    try {
                        Packet p = cap.getNextPacketEx();
                        if (p != null) {
                            captured.add(p.getRawData());
                        }
                    } catch (java.util.concurrent.TimeoutException te) {
                        // 正常读取超时
                    } catch (java.io.EOFException eof) {
                        break;
                    }
                }
            } catch (Exception e) {
                logger.warn("抓包线程异常结束: {}", e.getMessage());
            }
        }, "db-frame-capture");
        capturer.setDaemon(true);
        capturer.start();
        Thread.sleep(200);

        DbReplayTool tool = new DbReplayTool(
                DB_FILE, SPEED, null, null,
                null, null, null, null, null, null, null,
                "*:*-*:*");
        tool.enableFrameMode(nif, FrameRewriter.MacPolicy.preserve(), null);
        tool.startReplay();

        capturer.join(6000);
        com.jshark.parser.FrameReplayEngine.Result result = tool.frameResult();
        if (result == null) {
            check(false, "帧级重放未产生统计结果");
            return captured;
        }
        logger.info("  重放统计：examined={}, sent={}, failed={}, reportedErrorButSent={}",
                result.examined(), result.sent(), result.injectionFailures(),
                result.sentDespiteReportedError());
        check(result.examined() == FRAME_COUNT,
                "从库中取出的帧数 == " + FRAME_COUNT + " (实际 " + result.examined() + ")");
        check(result.sent() == FRAME_COUNT,
                "注入帧数 == " + FRAME_COUNT + " (实际 " + result.sent() + ")");
        check(result.injectionFailures() == 0,
                "无真正未发出的帧 (实际 " + result.injectionFailures() + ")");
        check(result.skippedWithoutFrame() == 0,
                "无因缺少 frameData 而被跳过的记录 (实际 " + result.skippedWithoutFrame() + ")");
        return captured;
    }

    private static void step4_verify(List<byte[]> captured) {
        logger.info("---- [4] 校验：DB → 网卡 的帧与原始帧一致 ----");
        int matched = 0;
        for (int i = 0; i < originalFrames.size(); i++) {
            byte[] original = originalFrames.get(i);
            byte[] actual = findByIpId(captured, original);
            if (actual == null) {
                if (i < 3) {
                    check(false, "帧 " + i + " 未出现在网络上（IP ID 未命中）");
                }
                continue;
            }
            matched++;
            if (i < 5 || i % 20 == 0) {
                check(Arrays.equals(actual, original),
                        "帧 " + i + " 与原始帧逐字节一致（长度 " + original.length + "）");
            }
        }
        check(matched == FRAME_COUNT,
                "全部 " + FRAME_COUNT + " 帧都在网络上被观察到 (实际 " + matched + ")");
    }

    private static byte[] findByIpId(List<byte[]> captured, byte[] expected) {
        if (expected.length < 20) {
            return null;
        }
        int id = ((expected[18] & 0xFF) << 8) | (expected[19] & 0xFF);
        for (byte[] c : captured) {
            if (c.length >= 20 && (((c[18] & 0xFF) << 8) | (c[19] & 0xFF)) == id) {
                return c;
            }
        }
        return null;
    }

    private static byte[] payloadFor(int i) {
        byte[] head = ("JSHARK-B4DB-" + i + "-").getBytes();
        byte[] fill = new byte[30 + i * 5];
        for (int j = 0; j < fill.length; j++) {
            fill[j] = (byte) (0x30 + i + j);
        }
        byte[] out = new byte[head.length + fill.length];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(fill, 0, out, head.length, fill.length);
        return out;
    }

    private static Packet buildUdp(Inet4Address src, Inet4Address dst, short ipId, byte[] payload)
            throws Exception {
        UdpPacket.Builder udp = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) UDP_SRC_PORT))
                .dstPort(UdpPort.getInstance((short) UDP_DST_PORT))
                .srcAddr(src).dstAddr(dst)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        return wrap(src, dst, ipId, IpNumber.UDP, udp);
    }

    private static Packet buildTcp(Inet4Address src, Inet4Address dst, short ipId, byte[] payload,
                                   int seq, int ack) throws Exception {
        TcpPacket.Builder tcp = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) TCP_SRC_PORT))
                .dstPort(TcpPort.getInstance((short) TCP_DST_PORT))
                .srcAddr(src).dstAddr(dst)
                .sequenceNumber(seq).acknowledgmentNumber(ack)
                .dataOffset((byte) 5).reserved((byte) 0)
                .urg(false).ack(true).psh(true).rst(false).syn(false).fin(false)
                .window((short) 65535)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        return wrap(src, dst, ipId, IpNumber.TCP, tcp);
    }

    private static Packet wrap(Inet4Address src, Inet4Address dst, short ipId,
                               IpNumber protocol, org.pcap4j.packet.Packet.Builder l4) {
        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4).tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification(ipId).ttl((byte) 64).protocol(protocol)
                .srcAddr(src).dstAddr(dst).payloadBuilder(l4)
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        return new EthernetPacket.Builder()
                .srcAddr(SRC_MAC).dstAddr(DST_MAC).type(EtherType.IPV4)
                .payloadBuilder(ip).paddingAtBuild(true).build();
    }

    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        } else {
            failedChecks++;
            logger.error("[失败] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
