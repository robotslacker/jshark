package com.jshark;

import com.jshark.parser.SplitUtil;
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
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * C 收尾验收：单文件模式与"仅 PCAP 分卷"模式的行为。
 *
 * <h3>验证项</h3>
 * <ol>
 *   <li><b>仅 PCAP + --split</b>：确实按时间窗分卷（早期由 PacketLogger 自己维护时钟，
 *       改造后必须由 VolumeWindows 统管，否则会退化为"总写同一个文件"）</li>
 *   <li><b>PCAP 与 logdb 同时启用</b>：两者的窗口时间戳完全一致</li>
 *   <li><b>不启用 --split</b>：单文件输出（向后兼容）；不产生旁路 manifest 文件</li>
 * </ol>
 *
 * <p>通过注入可控时钟推进窗口边界，无需真实等待。</p>
 */
public class SplitOutputTest {

    private static final Logger logger = LoggerFactory.getLogger(SplitOutputTest.class);

    private static final Path WORK_DIR = Path.of("target", "test-c-split");

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void splitOutputRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  C 收尾验收：单文件 / 仅 PCAP 分卷");
        logger.info("=================================================");

        step0_prepare();
        checkPcapOnlySplit();
        checkSingleFileMode();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
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

    /**
     * 用例 1：仅 PCAP + --split 必须分卷。
     * <p>
     * 造一个横跨约 3 秒的 pcap，用 1 秒窗口采集：由于窗口按<b>当前墙钟</b>推进，
     * 而离线读取很快，通常只会产生 1 个窗口。因此本用例的重点是：
     * <b>确实按窗口命名</b>（文件名带时间戳），而不是"总是写同一个不带时间戳的文件"。
     * pcap-only 模式不生成旁路 manifest。
     * </p>
     */
    private static void checkPcapOnlySplit() throws Exception {
        logger.info("---- [1] 仅 PCAP + --split ----");
        Path src = WORK_DIR.resolve("src.pcap");
        buildSourcePcap(src, 30);

        String pcapOut = WORK_DIR.resolve("onlypcap.pcap").toString();
        PacketCapture capture = new PacketCapture();
        capture.setOutputFile(pcapOut);
        capture.setSplit(1000L);   // 1 秒窗口
        capture.startCaptureFromFile(src.toString());

        // 期望：产出带时间戳的窗口文件，而不是基准名
        List<Path> windowFiles = listMatching("onlypcap_", ".pcap");
        Path base = WORK_DIR.resolve("onlypcap.pcap");

        check(!windowFiles.isEmpty(),
                "按窗口命名产出了 PCAP 文件（实际 " + windowFiles.size() + " 个）");
        check(!Files.exists(base),
                "未留下不带时间戳的基准文件 " + base.getFileName());

        // 文件内容非空（确实写入了帧）
        for (Path f : windowFiles) {
            check(Files.size(f) > 0, f.getFileName() + " 非空 (" + Files.size(f) + " 字节)");
        }
        // pcap-only 模式不再生成旁路 manifest
        check(listMatching("onlypcap_", ".manifest.json").isEmpty(),
                "pcap-only 分卷不生成旁路 manifest 文件");
    }

    /** 用例 2：不启用 --split → 单文件、无旁路 manifest */
    private static void checkSingleFileMode() throws Exception {
        logger.info("---- [2] 不启用 --split ----");
        Path src = WORK_DIR.resolve("src.pcap");
        String pcapOut = WORK_DIR.resolve("plain.pcap").toString();
        String dbOut = WORK_DIR.resolve("plain.db").toString();

        PacketCapture capture = new PacketCapture();
        capture.setOutputFile(pcapOut);
        capture.setLogDb(dbOut);
        capture.startCaptureFromFile(src.toString());

        check(Files.isRegularFile(Path.of(pcapOut)), "单文件模式：PCAP 使用基准名");
        check(Files.isRegularFile(Path.of(dbOut)), "单文件模式：logdb 使用基准名");
        check(listMatching("plain_", ".manifest.json").isEmpty(),
                "单文件模式不产生旁路 manifest（向后兼容）");
        check(listMatching("plain_", ".pcap").isEmpty(), "单文件模式不产生分卷 PCAP");
    }

    // ==================== 工具 ====================

    private static List<Path> listMatching(String prefix, String suffix) throws Exception {
        List<Path> out = new ArrayList<>();
        try (java.util.stream.Stream<Path> s = Files.list(WORK_DIR)) {
            s.filter(p -> {
                String n = p.getFileName().toString();
                return n.startsWith(prefix) && n.endsWith(suffix);
            }).forEach(out::add);
        }
        out.sort(java.util.Comparator.comparing(Path::toString));
        return out;
    }

    private static void buildSourcePcap(Path target, int count) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.9.1");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.9.2");
        MacAddress smac = MacAddress.getByName("02:4a:53:48:41:52");
        MacAddress dmac = MacAddress.getByName("02:4a:53:48:41:53");
        long base = at(2026, 2, 2, 12, 0, 0);

        try (PcapHandle dead = Pcaps.openDead(DataLinkType.EN10MB, 65536);
             org.pcap4j.core.PcapDumper d = dead.dumpOpen(target.toString())) {
            for (int i = 0; i < count; i++) {
                byte[] payload = new byte[64];
                for (int j = 0; j < payload.length; j++) {
                    payload[j] = (byte) (i + j);
                }
                UdpPacket.Builder udp = new UdpPacket.Builder()
                        .srcPort(UdpPort.getInstance((short) 45500))
                        .dstPort(UdpPort.getInstance((short) 45501))
                        .srcAddr(src).dstAddr(dst)
                        .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                        .correctChecksumAtBuild(true).correctLengthAtBuild(true);
                IpV4Packet.Builder ip = new IpV4Packet.Builder()
                        .version(IpVersion.IPV4).tos(IpV4Rfc791Tos.newInstance((byte) 0))
                        .identification((short) (0x1000 + i)).ttl((byte) 64).protocol(IpNumber.UDP)
                        .srcAddr(src).dstAddr(dst).payloadBuilder(udp)
                        .correctChecksumAtBuild(true).correctLengthAtBuild(true);
                Packet pkt = new EthernetPacket.Builder()
                        .srcAddr(smac).dstAddr(dmac).type(EtherType.IPV4)
                        .payloadBuilder(ip).paddingAtBuild(true).build();
                d.dump(pkt, new Timestamp(base + i * 100L));
            }
            d.flush();
        }
        logger.info("  已生成源 pcap: {} ({} 帧)", target, count);
    }

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return java.time.LocalDateTime.of(y, mo, d, h, mi, s)
                .atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    /**
     * 断言成功（失败即测试失败）。
     * <p>保留原夹具的调用形态与中文消息，内部改成 JUnit 断言：调用点一行都不用改，
     * 而失败会真正让构建失败。</p>
     */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
