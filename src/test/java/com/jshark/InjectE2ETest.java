package com.jshark;

import com.jshark.parser.FrameRewriter;
import com.jshark.parser.IpChecksum;
import com.jshark.parser.PcapReplayTool;
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
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * B5 验收测试：帧级注入的字节级保真。
 *
 * <h3>验证链路</h3>
 * <pre>
 *   构造双向报文（UDP + TCP，带已知 IP ID / 端口 / 序号 / 载荷）
 *     → 写入 pcap
 *     → PcapReplayTool（FRAME 模式，目标映射为"改目的端口"）
 *     → 注入网卡
 *     → 同一网卡抓包
 *     → 逐字段与逐字节比对
 * </pre>
 *
 * <h3>断言</h3>
 * <ul>
 *   <li>注入的帧确实出现在网络上（按 IP ID 匹配）</li>
 *   <li>目的端口按映射被改写；<b>源 IP/源端口/载荷逐字节不变</b></li>
 *   <li>改写后 IP 头与传输层校验和均通过（独立实现交叉验证）</li>
 *   <li>TCP 帧的序号/确认号/flags/window 逐字节不变</li>
 * </ul>
 *
 * <h3>网卡选择</h3>
 * <p>
 * 并非所有网卡都支持注入（实测：本机 Intel Wi-Fi 不支持）。因此本测试会先用
 * {@link StartupSelfCheck} 判定各网卡的注入能力，选一张可注入的网卡运行；
 * 若本机没有任何可注入网卡，则跳过并给出明确提示（退出码 0，不算失败）。
 * </p>
 *
 * <p>用法：{@code java ... com.jshark.InjectE2ETest [injectInterfaceIp]}</p>
 */
public class InjectE2ETest {

    private static final Logger logger = LoggerFactory.getLogger(InjectE2ETest.class);

    private static final Path WORK_DIR = Path.of("target", "test-inject");
    private static final Path PCAP_FILE = WORK_DIR.resolve("inject_source.pcap");

    /** 原始报文使用的地址与端口 */
    private static final String SRC_IP = "192.168.5.100";
    private static final String DST_IP = "192.168.5.200";
    private static final MacAddress SRC_MAC = MacAddress.getByName("02:4a:53:48:41:52");
    private static final MacAddress DST_MAC = MacAddress.getByName("02:4a:53:48:41:53");
    private static final int UDP_SRC_PORT = 43100;
    private static final int UDP_DST_PORT = 43101;
    private static final int TCP_SRC_PORT = 44100;
    private static final int TCP_DST_PORT = 44101;
    /** 映射后的目的端口（改端口路径） */
    private static final int MAPPED_DST_PORT = 43199;

    private static final int FRAME_COUNT = 100;
    private static final double SPEED = 2.0;

    /** 期望注入的帧（改写后） */
    private static final List<byte[]> expectedFrames = new ArrayList<>();
    /** 原始帧（改写前） */
    private static final List<byte[]> originalFrames = new ArrayList<>();

    private static int totalChecks;
    private static int failedChecks;
    private static int skippedChecks;

    /**
     * B5 验收：帧级注入字节级保真（live：需要 Npcap + 管理员权限，默认 {@code mvn test} 不执行）。
     */
    @org.junit.jupiter.api.Tag("live")
    @org.junit.jupiter.api.Test
    void injectE2ERegression() throws Exception {
        logger.info("=================================================");
        logger.info("  B5 验收：帧级注入字节级保真");
        logger.info("=================================================");

        // 测试方法不再有命令行参数：用 -Djshark.iface.ip=<ip> 指定注入网卡，默认自动探测
        String preferredIp = System.getProperty("jshark.iface.ip");
        PcapNetworkInterface nif = pickInjectableInterface(preferredIp);
        if (nif == null) {
            logger.warn("SKIPPED: no frame-injectable NIC on this machine. "
                    + "Frame injection needs a wired Ethernet adapter (Wi-Fi on Windows commonly cannot inject). "
                    + "Re-run with -Djshark.iface.ip=<ip> on com.jshark.InjectE2ETest");
            return;
        }
        logger.info("使用注入网卡: {} ({})", nif.getName(), nif.getDescription());

        step0_prepare();
        step1_buildPcap();
        List<byte[]> captured = step2_replayAndCapture(nif);
        step3_verify(captured);

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败, {} 跳过",
                totalChecks - failedChecks, totalChecks, failedChecks, skippedChecks);
    }

    // ==================== 网卡选择 ====================

    /**
     * 选择一张可注入的网卡。
     *
     * @param preferredIp 优先使用的网卡 IP；null 表示自动探测
     * @return 可注入的网卡；没有则返回 null
     */
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
            // 自动模式：挑本机地址可用于注入的以太网卡，避免动到默认路由所在网卡
            for (PcapNetworkInterface n : Pcaps.findAllDevs()) {
                String desc = n.getDescription();
                if (desc == null) {
                    continue;
                }
                if (desc.contains("VMware") || desc.contains("TAP-Windows") || desc.contains("Wintun")
                        || desc.contains("OpenVPN") || desc.contains("Wi-Fi Direct")
                        || desc.contains("Bluetooth")) {
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
            logger.info("网卡 {} 自检结论 = {}（尝试下一个）", n.getName(), r == null ? "null" : r.verdict());
        }
        return null;
    }

    // ==================== 步骤 ====================

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

    /** 构造 UDP/TCP 双向报文并写入 pcap；同时算出期望的注入帧 */
    private static void step1_buildPcap() throws Exception {
        logger.info("---- [1] 构造 {} 个报文并写入 pcap ----", FRAME_COUNT);

        Inet4Address src = (Inet4Address) InetAddress.getByName(SRC_IP);
        Inet4Address dst = (Inet4Address) InetAddress.getByName(DST_IP);
        long base = System.currentTimeMillis();

        List<Packet> packets = new ArrayList<>();
        for (int i = 0; i < FRAME_COUNT; i++) {
            boolean tcp = (i % 2 == 1);
            byte[] payload = payloadFor(i);
            short ipId = (short) (0xC000 + i);
            Packet pkt;
            if (tcp) {
                pkt = buildTcp(src, dst, ipId, payload, 1000 + i, 2000 + i);
            } else {
                pkt = buildUdp(src, dst, ipId, payload);
            }
            packets.add(pkt);
            originalFrames.add(pkt.getRawData());

            // 期望帧：仅目的端口改为 MAPPED_DST_PORT（地址不变，目的 MAC 保留）
            FrameRewriter rewriter = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);
            FrameRewriter.RewriteResult expected = rewriter.rewrite(pkt.getRawData(), DST_IP, MAPPED_DST_PORT);
            check(expected.status() == FrameRewriter.Status.REWRITTEN,
                    "帧 " + i + " 期望状态为 REWRITTEN（实际 " + expected.status() + "）");
            expectedFrames.add(expected.bytes());
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

    /**
     * 执行帧级重放，并在同一网卡上抓包。
     *
     * @param nif 注入网卡
     * @return 抓到的帧
     */
    private static List<byte[]> step2_replayAndCapture(PcapNetworkInterface nif) throws Exception {
        logger.info("---- [2] 帧级重放并同网卡抓包 ----");

        List<byte[]> captured = java.util.Collections.synchronizedList(new ArrayList<>());
        Thread capturer = new Thread(() -> {
            try (PcapHandle cap = nif.openLive(65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                try {
                    // 只收我们关心的协议，减少噪音
                    cap.setFilter("(udp and portrange 43100-43199) or (tcp and portrange 44100-44199)",
                            org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE);
                } catch (Exception e) {
                    logger.warn("抓包过滤器设置失败，改为全量收包: {}", e.getMessage());
                }
                long deadline = System.currentTimeMillis() + 4000;
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
        }, "inject-capture");
        capturer.setDaemon(true);
        capturer.start();
        Thread.sleep(200);

        PcapReplayTool tool = new PcapReplayTool(
                PCAP_FILE.toString(), SPEED, PcapReplayTool.Mode.FRAME,
                null, null, null, null, null,
                "*:*-" + DST_IP + ":" + MAPPED_DST_PORT,
                nif, FrameRewriter.MacPolicy.preserve(), null);
        tool.startReplay();

        capturer.join(5000);
        logger.info("  重放结束：examined={}, sent={}, 驱动报错但已发出={}, 失败={}, 抓到 {} 帧",
                tool.examinedCount(), tool.sentPackets(), tool.sentDespiteReportedError(),
                tool.injectionFailures(), captured.size());
        check(tool.sentPackets() == FRAME_COUNT,
                "注入帧数 == " + FRAME_COUNT + " (实际 " + tool.sentPackets() + ")");
        check(tool.injectionFailures() == 0,
                "无真正未发出的帧 (实际 " + tool.injectionFailures() + ")");
        return captured;
    }

    /** 逐字段、逐字节校验抓到的帧 */
    private static void step3_verify(List<byte[]> captured) {
        logger.info("---- [3] 校验注入结果 ----");

        int matched = 0;
        for (int i = 0; i < expectedFrames.size(); i++) {
            byte[] expected = expectedFrames.get(i);
            byte[] actual = findByIpId(captured, expected);
            if (actual == null) {
                check(false, "帧 " + i + " 未在网络/抓包中出现（IP ID 未命中）");
                continue;
            }
            matched++;

            // 1) 逐字节完全一致（目的端口改写 + 校验和重算后的期望值）
            check(Arrays.equals(actual, expected),
                    "帧 " + i + " 与期望帧逐字节一致（长度 " + expected.length + "）");

            // 2) 目的端口已改写
            int ihl = (actual[14] & 0x0F) * 4;
            int l4 = 14 + ihl;
            int dstPort = ((actual[l4 + 2] & 0xFF) << 8) | (actual[l4 + 3] & 0xFF);
            check(dstPort == MAPPED_DST_PORT, "帧 " + i + " 目的端口 = " + MAPPED_DST_PORT + " (实际 " + dstPort + ")");

            // 3) 源地址/源端口/载荷与原始帧一致
            byte[] original = originalFrames.get(i);
            check(Arrays.equals(Arrays.copyOfRange(original, 14 + 12, 14 + 16),
                            Arrays.copyOfRange(actual, 14 + 12, 14 + 16)),
                    "帧 " + i + " 源 IP 未变");
            check(original[l4] == actual[l4] && original[l4 + 1] == actual[l4 + 1],
                    "帧 " + i + " 源端口未变");
            int l4HeaderLen = (original[14 + 9] & 0xFF) == 17 ? 8 : 20;
            check(Arrays.equals(
                            Arrays.copyOfRange(original, l4 + l4HeaderLen, original.length),
                            Arrays.copyOfRange(actual, l4 + l4HeaderLen, actual.length)),
                    "帧 " + i + " 载荷逐字节未变");

            // 4) 校验和（独立交叉验证）
            check(IpChecksum.verify(actual, 14, ihl), "帧 " + i + " IPv4 头校验和通过");
            check(transportChecksumValid(actual), "帧 " + i + " 传输层校验和通过");

            // 5) TCP 帧的流状态字段未变
            if ((original[14 + 9] & 0xFF) == 6) {
                check(Arrays.equals(Arrays.copyOfRange(original, l4 + 4, l4 + 8),
                                Arrays.copyOfRange(actual, l4 + 4, l4 + 8)),
                        "帧 " + i + " TCP 序号未变");
                check(Arrays.equals(Arrays.copyOfRange(original, l4 + 8, l4 + 12),
                                Arrays.copyOfRange(actual, l4 + 8, l4 + 12)),
                        "帧 " + i + " TCP 确认号未变");
                check(original[l4 + 12] == actual[l4 + 12] && original[l4 + 13] == actual[l4 + 13],
                        "帧 " + i + " TCP flags 未变");
                check(Arrays.equals(Arrays.copyOfRange(original, l4 + 14, l4 + 16),
                                Arrays.copyOfRange(actual, l4 + 14, l4 + 16)),
                        "帧 " + i + " TCP 窗口未变");
            }
        }

        check(matched == FRAME_COUNT,
                "全部 " + FRAME_COUNT + " 帧都在网络上被观察到 (实际 " + matched + ")");
    }

    // ==================== 辅助 ====================

    /** 用 IP ID 在抓包结果中查找对应帧 */
    private static byte[] findByIpId(List<byte[]> captured, byte[] expected) {
        if (expected.length < 20) {
            return null;
        }
        int id = ((expected[18] & 0xFF) << 8) | (expected[19] & 0xFF);
        for (byte[] c : captured) {
            if (c.length >= 20) {
                int cid = ((c[18] & 0xFF) << 8) | (c[19] & 0xFF);
                if (cid == id) {
                    return c;
                }
            }
        }
        return null;
    }

    /** 校验传输层校验和（UDP 校验和为 0 时视为不校验） */
    private static boolean transportChecksumValid(byte[] frame) {
        int ihl = (frame[14] & 0x0F) * 4;
        int l4 = 14 + ihl;
        int protocol = frame[14 + 9] & 0xFF;
        int totalLen = ((frame[16] & 0xFF) << 8) | (frame[17] & 0xFF);
        int l4Len = totalLen - ihl;
        if (l4Len <= 0) {
            return false;
        }
        if (protocol == 17) {
            int stored = ((frame[l4 + 6] & 0xFF) << 8) | (frame[l4 + 7] & 0xFF);
            if (stored == 0) {
                return true;
            }
        }
        byte[] pseudo = new byte[12];
        System.arraycopy(frame, 14 + 12, pseudo, 0, 8);
        pseudo[9] = (byte) protocol;
        pseudo[10] = (byte) ((l4Len >> 8) & 0xFF);
        pseudo[11] = (byte) (l4Len & 0xFF);
        int sum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, l4, l4Len);
        return sum == 0;
    }

    private static byte[] payloadFor(int i) {
        // 带可识别前缀 + 序号 + 填充，便于人工排查
        byte[] head = ("JSHARK-B5-" + i + "-").getBytes();
        byte[] fill = new byte[40 + i * 7];
        for (int j = 0; j < fill.length; j++) {
            fill[j] = (byte) (0xA0 + i + j);
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
                .sequenceNumber(seq)
                .acknowledgmentNumber(ack)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .urg(false).ack(true).psh(true).rst(false).syn(false).fin(false)
                .window((short) 65535)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        return wrap(src, dst, ipId, IpNumber.TCP, tcp);
    }

    private static Packet wrap(Inet4Address src, Inet4Address dst, short ipId,
                               IpNumber protocol, org.pcap4j.packet.Packet.Builder l4) {
        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification(ipId)
                .ttl((byte) 64)
                .protocol(protocol)
                .srcAddr(src).dstAddr(dst)
                .payloadBuilder(l4)
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
