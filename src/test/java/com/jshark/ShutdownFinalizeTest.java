package com.jshark;

import com.jshark.parser.SplitUtil;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.UdpPacket;
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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 停机收尾回归：<b>CTRL+C / SIGTERM 之后，最后一卷必须被 FORCE CHECKPOINT 并更名</b>。
 *
 * <h3>修的是什么</h3>
 * <p>
 * 旧实现把最后一卷的收尾丢给守护线程池，抓包线程立刻返回；而 shutdown hook 只等固定 30s
 * 就返回，JVM 随即 halt，守护线程被就地杀死。于是磁盘上留下
 * {@code xxx_<start>-capturing.db} + 一个未合并的 {@code xxx.db.wal}
 * ——库里只有 12KB 的头部，数据全在 WAL 里。
 * </p>
 * <p>
 * 现在：收尾在<b>被抓包线程</b>上同步做完，整段收尾有固定预算，并给
 * “FORCE CHECKPOINT → close → rename”预留尾段时间；即使抓包线程失效，
 * shutdown hook 还会调 {@link PacketCapture#forceFinalizeLastVolume()} 兜底。
 * </p>
 *
 * <h3>断言什么</h3>
 * <ol>
 *   <li>目录里不再有 {@code -capturing} 文件，也不再有 {@code .wal}；</li>
 *   <li>正常轮转的卷仍以<b>网格边界</b>结尾；被中断的最后一卷以<b>按下 CTRL+C 的时刻</b>结尾；</li>
 *   <li>manifest 的 {@code endMs/endTime/closedReason/completeWindow} 与文件名一致；</li>
 *   <li>更名后的库能被重新打开（WAL 已真正合并，而不是被删掉）。</li>
 * </ol>
 */
class ShutdownFinalizeTest {

    private static final Logger logger = LoggerFactory.getLogger(ShutdownFinalizeTest.class);

    private static final Path WORK_DIR = Paths.get("target", "shutdown-finalize-test");
    private static final long INTERVAL_MS = 60_000L;
    /** 窗口起点：整分钟（与网格对齐） */
    private static final long T = at(2026, 2, 2, 10, 0, 0);

    // ==================== 用例 1：真实采集路径（离线 pcap 驱动） ====================

    @org.junit.jupiter.api.Test
    void lastVolumeIsCheckpointedAndRenamedOnShutdown() throws Exception {
        Path dir = prepare("normal");
        Path pcap = buildPcap(dir, 2);

        // 假时钟：窗口初始化会取 3 次时间（setSplit 建窗、setLogDb 换基准重建、
        // 采集循环第一轮），这三次都停在 T；第二轮起才跳到 T+61s，跨过 1 分钟边界。
        AtomicInteger calls = new AtomicInteger();
        LongSupplier scripted = () -> calls.getAndIncrement() <= 2 ? T : T + INTERVAL_MS + 1_000L;

        PacketCapture capture = new PacketCapture();
        capture.setClockForTest(scripted);
        capture.setOutputFile(dir.resolve("cap.pcap").toString());
        capture.setSplit(INTERVAL_MS);
        capture.setLogDb(dir.resolve("cap.db").toString());
        capture.startCaptureFromFile(pcap.toString());

        // 采集已结束（EOF → stopCapture → finishCapture，与 Ctrl+C 走同一条收尾路径）
        List<String> files = fileNames(dir);
        logger.info("产物：{}", files);

        String gridEndName = "cap_" + stamp(T) + "-" + stamp(T + INTERVAL_MS) + ".db";
        String stopEndName = "cap_" + stamp(T + INTERVAL_MS) + "-" + stamp(T + INTERVAL_MS + 1_000L) + ".db";

        assertTrue(files.contains(gridEndName),
                "正常轮转的卷必须以网格边界结尾，期望 " + gridEndName + "，实际 " + files);
        assertTrue(files.contains(stopEndName),
                "被中断的最后一卷必须以停机时刻结尾，期望 " + stopEndName + "，实际 " + files);

        assertFalse(files.stream().anyMatch(n -> n.contains("-capturing")),
                "不允许残留 -capturing 卷，实际 " + files);
        assertFalse(files.stream().anyMatch(n -> n.endsWith(".wal")),
                "最后一卷的 WAL 必须已合并（目录里不允许残留 .wal），实际 " + files);

        // manifest：边界卷 = boundary/完整；停机卷 = shutdown/不完整 且 endMs 与文件名一致
        assertManifest(dir.resolve(gridEndName), T, T + INTERVAL_MS, true, "boundary");
        assertManifest(dir.resolve(stopEndName), T + INTERVAL_MS, T + INTERVAL_MS + 1_000L, false, "shutdown");

        // 更名后的库必须能重新打开：证明数据是"合并进 .db"而不是"把 WAL 删掉"
        assertEquals(1, countRows(dir.resolve(gridEndName)), "边界卷应保留它自己的 1 个包");
        assertEquals(1, countRows(dir.resolve(stopEndName)), "停机卷应保留它自己的 1 个包");

        // 回放端必须能发现这两卷（-capturing 会被跳过；这条断言把"可回放"钉死）
        List<String> replayable = SplitUtil.discoverVolumes(dir.resolve("cap.db").toString());
        assertEquals(2, replayable.size(), "回放端应发现两卷，实际 " + replayable);
        assertTrue(capture.isFinished(), "finishCapture 应已完整跑完（hook 不会走兜底路径）");
    }

    // ==================== 用例 2：抓包线程失效时的兜底 ====================

    @org.junit.jupiter.api.Test
    void forcedFinalizeHandlesTheCaseWhereNormalShutdownNeverRuns() throws Exception {
        Path dir = prepare("forced");
        Path base = dir.resolve("em.db");

        PacketCapture capture = new PacketCapture();
        capture.setClockForTest(() -> T);
        capture.setSplit(INTERVAL_MS);
        // setLogDb 已经连上并创建了 "-capturing" 卷文件；采集循环从未启动，
        // 等价于"hook 等到预算用尽，抓包线程仍卡在某处"。
        capture.setLogDb(base.toString());

        Path capturing = dir.resolve("em_" + stamp(T) + "-capturing.db");
        // 注意用 java.io.File.exists() 而不是 Files.exists()：
        // 此刻 DuckDB 仍持有该 -capturing 卷文件的写锁（open），Windows 上
        // Files.exists() 读取一个被占用的数据库文件的属性会失败而返回 false（假阴性），
        // 而 File.exists()/Files.list() 都能如实看到它。这是 Windows NIO 的一个怪癖。
        assertTrue(capturing.toFile().exists(), "前置条件：卷文件应已以 -capturing 形式创建");

        capture.requestStop();   // 停机时刻 = T
        assertTrue(capture.forceFinalizeLastVolume(), "兜底收尾应完成 CHECKPOINT + 更名");

        Path renamed = dir.resolve("em_" + stamp(T) + "-" + stamp(T + 1_000L) + ".db");
        assertTrue(Files.exists(renamed), "最后一卷应被更名，实际 " + fileNames(dir));
        assertFalse(Files.exists(capturing), "-capturing 文件不应再存在");
        assertFalse(Files.exists(Path.of(renamed + ".wal")),
                "WAL 必须已合并，实际 " + fileNames(dir));

        // 幂等：已经收完之后再兜底一次不应有任何副作用
        assertFalse(capture.forceFinalizeLastVolume(), "二次兜底应无事可做");

        // 兜底路径同样要写 manifest（否则归档里这一卷没有自证）
        assertManifest(renamed, T, T + 1_000L, false, "shutdown");
    }

    // ==================== 用例 3：end 计算的夹取规则 ====================

    @org.junit.jupiter.api.Test
    void computeEndMsRoundsUpAndClampsToTheWindow() {
        assertEquals(T + 1_000L, PacketCapture.computeEndMs(T, T, T + INTERVAL_MS),
                "同秒内起停：end 必须严格大于 start（否则文件名会是 start-start）");
        assertEquals(T + 61_000L, PacketCapture.computeEndMs(T, T + 60_500L, T + INTERVAL_MS * 2),
                "秒级文件名必须向上取整，保证覆盖停机瞬间");
        assertEquals(T + INTERVAL_MS, PacketCapture.computeEndMs(T, T + 999_999L, T + INTERVAL_MS),
                "end 不允许越过本窗口的网格边界");
        assertEquals(T + INTERVAL_MS, PacketCapture.computeEndMs(T, 0, T + INTERVAL_MS),
                "没有停机时刻时退化为当前时间，但仍不允许越过窗口边界");
    }

    // ==================== 工具 ====================

    private static Path prepare(String name) throws Exception {
        Path dir = WORK_DIR.resolve(name);
        if (Files.exists(dir)) {
            try (Stream<Path> stream = Files.walk(dir)) {
                stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                        // 清理失败不影响结论
                    }
                });
            }
        }
        Files.createDirectories(dir);
        return dir;
    }

    private static List<String> fileNames(Path dir) throws Exception {
        try (Stream<Path> stream = Files.list(dir)) {
            return stream.map(p -> p.getFileName().toString()).sorted().toList();
        }
    }

    private static void assertManifest(Path db, long startMs, long endMs,
                                       boolean complete, String reason) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + db);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "Select startMs, endMs, startTime, endTime, completeWindow, closedReason "
                             + "From JSharkManifest")) {
            assertTrue(rs.next(), db.getFileName() + " 必须有 manifest 行");
            assertEquals(startMs, rs.getLong("startMs"), db.getFileName() + " manifest.startMs");
            assertEquals(endMs, rs.getLong("endMs"), db.getFileName() + " manifest.endMs");
            assertEquals(SplitUtil.formatTimestamp(startMs), rs.getString("startTime"));
            assertEquals(SplitUtil.formatTimestamp(endMs), rs.getString("endTime"));
            assertEquals(complete, rs.getBoolean("completeWindow"), db.getFileName() + " completeWindow");
            assertEquals(reason, rs.getString("closedReason"), db.getFileName() + " closedReason");
        }
    }

    private static int countRows(Path db) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + db);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("Select count(*) From JSharkLog")) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }

    private static String stamp(long epochMs) {
        return SplitUtil.formatTimestamp(epochMs);
    }

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    /** 造一个只有 UDP 小包、时间戳互不相同的离线 pcap。 */
    private static Path buildPcap(Path dir, int frameCount) throws Exception {
        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");

        Path pcap = dir.resolve("in.pcap");
        long ts = T;
        try (PcapHandle h = Pcaps.openDead(DataLinkType.EN10MB, 65536);
             PcapDumper dumper = h.dumpOpen(pcap.toString())) {
            for (int i = 0; i < frameCount; i++) {
                byte[] payload = new byte[16];
                for (int j = 0; j < payload.length; j++) {
                    payload[j] = (byte) (i * 31 + j);
                }
                dumper.dump(udpFrame(srcMac, dstMac, srcIp, dstIp, 3000 + i, 8200, payload),
                        new Timestamp(ts + i * 1_000L));
            }
            dumper.flush();
        }
        return pcap;
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
}
