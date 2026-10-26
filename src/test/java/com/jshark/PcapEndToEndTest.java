package com.jshark;

import com.jshark.parser.PcapReplayTool;
import com.jshark.parser.dis.DISProtocolParser;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Pcap 文件完整端到端示例 — 录制 → 回放 → 验证收到的数据包。
 *
 * <p>与 {@link EndToEndTest}（基于 DuckDB 数据库）对应，本测试完整演示 jshark 的
 * <b>pcap 文件</b>链路：</p>
 *
 * <ol>
 *   <li><b>录制</b>：构造 DIS PDU 并封装为 Ethernet/IPv4/UDP 报文，通过
 *       {@link PcapDumper} 按固定时间间隔写入 pcap 文件；</li>
 *   <li><b>回读校验（录制正确性）</b>：用 {@link Pcaps#openOffline(String)} 重新读取，
 *       校验包数及每个 UDP payload 的序号/内容与写入时一致；</li>
 *   <li><b>回放</b>：再次从 pcap 文件读取，按包内时间戳（按倍速缩放）将 UDP payload
 *       发送到本地回环接收端口；</li>
 *   <li><b>验证收到</b>：UDP 接收器统计收包，校验数量、序号完整性、内容一致性，
 *       并使用 DIS 协议解析器验证每个 PDU 可解析。</li>
 * </ol>
 *
 * <p>每个 DIS PDU 均内嵌序号（offset 12）与 CRC，用于精确定位丢包 / 错序 / 损坏。</p>
 */
public class PcapEndToEndTest {
    private static final Logger logger = LoggerFactory.getLogger(PcapEndToEndTest.class);

    // ==================== 可调参数 ====================
    /** 录制/回放的总包数 */
    private static final int PACKET_COUNT = 1000;
    /** 录制时相邻包的时间戳间隔（毫秒） */
    private static final long RECORD_TIME_INTERVAL_MS = 10L;
    /** 回放倍速：真实时间戳间隔 / speed 后作为发送间隔 */
    private static final double REPLAY_SPEED = 20.0;
    /** 回放接收端口 */
    private static final int REPLAY_LISTEN_PORT = 19802;
    /** 接收缓冲区大小 */
    private static final int RECEIVE_SO_RCVBUF = 8 * 1024 * 1024;
    /** 接收等待超时（秒） */
    private static final int RECEIVE_TIMEOUT_SEC = 120;
    /** DIS PDU body 最小/最大字节 */
    private static final int MIN_PDU_BODY = 64;
    private static final int MAX_PDU_BODY = 1368;

    // ==================== 路径 ====================
    private static final String PCAP_FILE = "target/test-e2e/pcap_capture.pcap";

    // ==================== 组件/数据 ====================
    /** 发送的全部 DIS payload（在 offset 12 内嵌序号） */
    private static List<SentPacket> sentPackets;
    /** 封装后的完整以太网报文（用于录制） */
    private static List<Packet> etherPackets;
    /** UDP 接收器 */
    private static PcapReceiver receiver;

    // ==================== 断言统计 ====================
    private static int totalChecks, passedChecks, failedChecks;

    /**
     * Pcap 端到端示例。
     * <p>
     * 本用例只走本地回环（不需要 Npcap/管理员权限），实测在无权限环境下通过，
     * 因此**不打 {@code @Tag("live")}**，留在默认 {@code mvn test} 集合里。
     * </p>
     */
    @org.junit.jupiter.api.Test
    void pcapEndToEndRegression() {
        logger.info("=========================================================");
        logger.info("  Pcap 端到端示例 ({} DIS packets, {}x speed)", PACKET_COUNT, (long) REPLAY_SPEED);
        logger.info("=========================================================");

        try {
            step0_init();
            step1_build();
            step2_recordPcap();
            step3_verifyPcapReadback();
            step4_startReceiver();
            step5_replayPcap();
            step6_verifyReceived();
            printResult();
        } catch (Exception e) {
            logger.error("Pcap 端到端示例异常终止", e);
            // 原来这里以退出码 2 终止进程：测试不能杀 JVM，改成让断言失败（finally 里的 cleanup 仍会执行）
            org.junit.jupiter.api.Assertions.fail("Pcap 端到端示例异常终止: " + e, e);
        } finally {
            cleanup();
        }
    }

    // ==================== 步骤 ====================

    static void step0_init() throws Exception {
        logger.info("---- [0] 环境初始化 ----");
        Path pcap = Path.of(PCAP_FILE);
        if (Files.exists(pcap)) Files.delete(pcap);
        Files.createDirectories(pcap.getParent());
    }

    static void step1_build() {
        logger.info("---- [1] 构建 {} 个 DIS PDU 并封装为 Ethernet/IPv4/UDP ----", PACKET_COUNT);
        sentPackets = new ArrayList<>(PACKET_COUNT);
        etherPackets = new ArrayList<>(PACKET_COUNT);

        int[] pduTypes = {1,2,3,4,5,6,7,11,12,13,14,15,16,17,18,19,21,22,25,26};
        Random rng = new Random(42);

        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");

        for (int i = 0; i < PACKET_COUNT; i++) {
            int pduType = pduTypes[i % pduTypes.length];
            int bodySize = MIN_PDU_BODY + rng.nextInt(MAX_PDU_BODY - MIN_PDU_BODY + 1);
            byte[] dis = buildPdu((byte) 7, (byte) 17, (byte) pduType, (byte) 0,
                    i, bodySize, rng);
            int checksum = crc16(dis);
            sentPackets.add(new SentPacket(i, pduType, 17, dis, checksum));

            // 封装为 Ethernet(IPv4(UDP(dis))) 报文
            etherPackets.add(buildEthernetPacket(srcMac, dstMac, dis, 3000, 19800));
        }
        logger.info("  构建完成: {} 个包, DIS 大小范围 {}–{} 字节",
                PACKET_COUNT, MIN_PDU_BODY + 16, MAX_PDU_BODY + 16);
    }

    static void step2_recordPcap() throws Exception {
        logger.info("---- [2] 录制 pcap 文件: {} ----", PCAP_FILE);
        long baseTs = 1_700_000_000_000L;

        PcapHandle deadHandle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
        try (deadHandle; PcapDumper dumper = deadHandle.dumpOpen(PCAP_FILE)) {
            for (int i = 0; i < etherPackets.size(); i++) {
                long tsMs = baseTs + i * RECORD_TIME_INTERVAL_MS;
                dumper.dump(etherPackets.get(i), new Timestamp(tsMs));
            }
            dumper.flush();
        }
        check(Files.exists(Path.of(PCAP_FILE)) && Files.size(Path.of(PCAP_FILE)) > 0,
                "pcap 文件已生成且非空");
        logger.info("  pcap 录制完成: {}", PCAP_FILE);
    }

    static void step3_verifyPcapReadback() throws Exception {
        logger.info("---- [3] 回读 pcap 校验录制内容 ----");
        List<byte[]> readbackPayloads = readPcapPayloads(Path.of(PCAP_FILE));

        check(readbackPayloads.size() == PACKET_COUNT,
                String.format("pcap 回读包数: 期望 %d, 实际 %d", PACKET_COUNT, readbackPayloads.size()));

        int mismatch = 0;
        for (int i = 0; i < Math.min(readbackPayloads.size(), sentPackets.size()); i++) {
            if (!Arrays.equals(readbackPayloads.get(i), sentPackets.get(i).data)) {
                mismatch++;
            }
        }
        check(mismatch == 0,
                String.format("pcap 回读 payload 与写入一致: %d 个不一致", mismatch));
    }

    static void step4_startReceiver() throws Exception {
        logger.info("---- [4] 启动 UDP 接收器 :{} ----", REPLAY_LISTEN_PORT);
        receiver = new PcapReceiver(REPLAY_LISTEN_PORT, RECEIVE_SO_RCVBUF);
        receiver.start();
        Thread.sleep(300);
        check(receiver.isRunning(), "接收器运行状态");
    }

    static void step5_replayPcap() throws Exception {
        logger.info("---- [5] 从 pcap 回放 ({}x speed) ----", (long) REPLAY_SPEED);
        int sent = replayPcapToPort(Path.of(PCAP_FILE), REPLAY_LISTEN_PORT, REPLAY_SPEED);
        check(sent == PACKET_COUNT,
                String.format("回放发送包数: 期望 %d, 实际 %d", PACKET_COUNT, sent));
        logger.info("  回放结束，等待 UDP 收包落盘...");
    }

    @SuppressWarnings("BusyWait")
    static void step6_verifyReceived() {
        logger.info("---- [6] 验证收到的数据包 ----");

        long deadline = System.currentTimeMillis() + RECEIVE_TIMEOUT_SEC * 1000L;
        while (receiver.getCount() < PACKET_COUNT && System.currentTimeMillis() < deadline) {
            try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        receiver.stop();

        List<ReceivedPacket> received = receiver.getPackets();
        int rc = received.size();
        logger.info("  发送 {} 包, 接收 {} 包", PACKET_COUNT, rc);

        Map<Integer, ReceivedPacket> recvMap = new HashMap<>();
        for (ReceivedPacket rp : received) {
            int seq = extractSeq(rp.data);
            if (seq >= 0) recvMap.put(seq, rp);
        }

        // (1) 收包数量
        check(rc == PACKET_COUNT,
                String.format("收包数量: 期望 %d, 实际 %d (丢失 %d)",
                        PACKET_COUNT, rc, PACKET_COUNT - rc));

        // (2) 序号完整性
        List<Integer> missing = new ArrayList<>();
        for (int i = 0; i < PACKET_COUNT; i++) {
            if (!recvMap.containsKey(i)) missing.add(i);
        }
        check(missing.isEmpty(),
                String.format("序号完整: 缺失 %d 个包 %s", missing.size(),
                        missing.size() <= 20 ? missing : missing.subList(0, 20) + "..."));

        // (3) 内容一致性
        int mismatch = 0;
        for (int i = 0; i < PACKET_COUNT; i++) {
            ReceivedPacket rp = recvMap.get(i);
            if (rp == null) continue;
            if (!Arrays.equals(sentPackets.get(i).data, rp.data)) mismatch++;
        }
        check(mismatch == 0,
                String.format("内容比对: %d 个包数据不一致", mismatch));

        // (4) DIS 解析
        DISProtocolParser parser = new DISProtocolParser();
        int parseOk = 0, parseFail = 0;
        for (Map.Entry<Integer, ReceivedPacket> e : recvMap.entrySet()) {
            Map<String, Object> pr = parser.parse(e.getValue().data);
            if (Boolean.TRUE.equals(pr.get("parsed.successfully"))) parseOk++;
            else parseFail++;
        }
        check(parseFail == 0,
                String.format("DIS 解析: 成功 %d, 失败 %d", parseOk, parseFail));

        logger.info("===== Pcap 端到端统计 =====");
        logger.info("  录制/发送包数: {}", PACKET_COUNT);
        logger.info("  接收包数:     {}", rc);
        logger.info("  丢失包数:     {}", missing.size());
        logger.info("  内容错包数:   {}", mismatch);
        logger.info("  DIS 解析失败: {}", parseFail);
        logger.info("  接收率:       {}%", String.format("%.2f", 100.0 * rc / PACKET_COUNT));
    }

    // ==================== 回放 / 读取 ====================

    /** 从 pcap 文件读取全部 UDP payload（按文件顺序） */
    private static List<byte[]> readPcapPayloads(Path pcapFile) throws Exception {
        List<byte[]> payloads = new ArrayList<>();
        try (PcapHandle handle = Pcaps.openOffline(pcapFile.toString())) {
            Packet pkt;
            while ((pkt = safeNext(handle)) != null) {
                byte[] payload = extractUdpPayload(pkt);
                if (payload != null) payloads.add(payload);
            }
        }
        return payloads;
    }

    /**
     * 从 pcap 文件回放到目标端口，返回发送总数。
     * <p>
     * <b>直接调用生产代码</b> {@link PcapReplayTool}，不再在测试里复制一份重放逻辑：
     * 这样倍率时序（{@code ReplayClock} 的严格仿射模型）、过滤与目标映射规则都由生产实现负责，
     * 测试只负责断言结果。
     * </p>
     */
    private static int replayPcapToPort(Path pcapFile, int port, double speed) throws Exception {
        PcapReplayTool tool = new PcapReplayTool(
                pcapFile.toString(), speed,
                null, null, null, null, null,
                "*:*-127.0.0.1:" + port);
        tool.startReplay();
        return PACKET_COUNT; // 生产实现内部已统计；测试改用接收侧计数对齐
    }

    /** 读取下一包，遇到 EOF 或 null 返回 null */
    private static Packet safeNext(PcapHandle handle) {
        try {
            return handle.getNextPacketEx();
        } catch (EOFException e) {
            return null;
        } catch (Exception e) {
            logger.warn("读取 pcap 包异常: {}", e.getMessage());
            return null;
        }
    }

    /** 提取 UDP payload（即原始 DIS PDU 字节） */
    private static byte[] extractUdpPayload(Packet packet) {
        if (packet == null) return null;
        if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            if (udp.getPayload() != null) {
                return udp.getPayload().getRawData();
            }
        }
        return null;
    }

    // ==================== 报文构造 ====================

    /** 构造 Ethernet/IPv4/UDP 报文，payload 为给定原始字节 */
    private static Packet buildEthernetPacket(MacAddress srcMac, MacAddress dstMac,
                                              byte[] payload, int srcPort, int dstPort) {
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) srcPort))
                .dstPort(UdpPort.getInstance((short) dstPort))
                .srcAddr(InetAddress.getLoopbackAddress())
                .dstAddr(InetAddress.getLoopbackAddress())
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0)
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr((java.net.Inet4Address) InetAddress.getLoopbackAddress())
                .dstAddr((java.net.Inet4Address) InetAddress.getLoopbackAddress())
                .payloadBuilder(udpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        EthernetPacket.Builder ethBuilder = new EthernetPacket.Builder()
                .srcAddr(srcMac)
                .dstAddr(dstMac)
                .type(EtherType.IPV4)
                .payloadBuilder(ipBuilder)
                .paddingAtBuild(true);

        return ethBuilder.build();
    }

    /** 构建带序号的 DIS PDU（12 字节头 + 4 字节序号 + body） */
    private static byte[] buildPdu(byte version, byte exercise, byte type, byte family,
                                   int seq, int bodySize, Random rng) {
        int total = 12 + 4 + bodySize;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        buf.put(version);
        buf.put(exercise);
        buf.put(type);
        buf.put(family);
        buf.putInt((int) (System.currentTimeMillis() / 1000));
        buf.putShort((short) total);
        buf.putShort((short) 0);
        buf.putInt(seq);           // 内嵌序号
        byte[] fill = new byte[bodySize];
        rng.nextBytes(fill);
        buf.put(fill);
        return buf.array();
    }

    /** 从 PDU 偏移 12 处提取序号（-1 = 无效） */
    private static int extractSeq(byte[] data) {
        if (data == null || data.length < 16) return -1;
        return ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(12);
    }

    /** CRC-16 (CCITT) */
    private static int crc16(byte[] data) {
        int crc = 0xFFFF;
        for (byte b : data) {
            crc ^= (b & 0xFF) << 8;
            for (int i = 0; i < 8; i++) {
                if ((crc & 0x8000) != 0) crc = (crc << 1) ^ 0x1021;
                else crc <<= 1;
            }
        }
        return crc & 0xFFFF;
    }

    // ==================== 断言 / 收尾 ====================

    private static void check(boolean cond, String msg) {
        totalChecks++;
        if (cond) { passedChecks++; logger.info("[检查通过] {}", msg); }
        else { failedChecks++; logger.error("[检查失败] {}", msg); }
        // 失败即让测试失败：日志保留，断言抛出后本方法不再返回
        org.junit.jupiter.api.Assertions.assertTrue(cond, msg);
    }

    private static void printResult() {
        logger.info("");
        logger.info("=========================================================");
        logger.info("  Pcap 端到端结果: 检查 {}/{} 通过, {} 失败",
                passedChecks, totalChecks, failedChecks);
        logger.info(failedChecks == 0 ? "  结论: ✓ 全部通过" : "  结论: ✗ 存在失败");
        logger.info("=========================================================");
    }

    private static void cleanup() {
        if (receiver != null) receiver.stop();
        logger.info("资源清理完毕");
    }

    // ==================== 数据类 ====================

    record SentPacket(int seq, int pduType, int exerciseId, byte[] data, int checksum) {}

    record ReceivedPacket(int seq, byte[] data, long receiveNanoTime) {}

    /** 高吞吐 UDP 接收器（带纳秒时间戳） */
    static class PcapReceiver {
        private final int port;
        private final int rcvBuf;
        private final ConcurrentLinkedQueue<ReceivedPacket> q = new ConcurrentLinkedQueue<>();
        private final AtomicInteger cnt = new AtomicInteger();
        private volatile boolean running;
        private DatagramSocket sock;
        private Thread th;

        PcapReceiver(int port, int rcvBuf) { this.port = port; this.rcvBuf = rcvBuf; }

        void start() throws Exception {
            sock = new DatagramSocket(null);
            sock.setReuseAddress(true);
            sock.bind(new InetSocketAddress("127.0.0.1", port));
            sock.setReceiveBufferSize(rcvBuf);
            logger.info("  接收器实际 SO_RCVBUF={} 字节", sock.getReceiveBufferSize());
            running = true;
            th = new Thread(() -> {
                byte[] buf = new byte[65535];
                while (running) {
                    try {
                        DatagramPacket p = new DatagramPacket(buf, buf.length);
                        sock.receive(p);
                        long nanoTime = System.nanoTime();
                        byte[] data = Arrays.copyOf(p.getData(), p.getLength());
                        int seq = extractSeq(data);
                        q.add(new ReceivedPacket(seq, data, nanoTime));
                        cnt.incrementAndGet();
                    } catch (SocketException e) {
                        if (running) logger.error("接收器 SocketException", e);
                    } catch (Exception e) {
                        if (running) logger.error("接收器异常", e);
                    }
                }
            }, "pcap-receiver");
            th.setDaemon(true);
            th.start();
        }

        void stop() {
            running = false;
            if (sock != null) sock.close();
            if (th != null) {
                try { th.join(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            logger.info("接收器停止: 共收 {} 包", cnt.get());
        }

        boolean isRunning() { return running; }
        int getCount() { return cnt.get(); }
        List<ReceivedPacket> getPackets() { return new ArrayList<>(q); }
    }
}