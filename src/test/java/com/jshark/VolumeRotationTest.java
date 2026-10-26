package com.jshark;

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
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.stream.Stream;

/**
 * D5 验收测试：**一次跨过多个时间窗**时的分卷轮转。
 *
 * <h3>为什么必须单独测</h3>
 * <p>
 * {@code VolumeWindows.advance()} 用 {@code while} 循环补齐被跨过的边界
 * （"一次卡顿可能跨过多个边界，必须逐个补齐，否则窗口会跳号"），
 * 因此 {@code advance().closed()} 可以是<b>多个</b>窗口。
 * 而轮转循环里最容易写错的一点是：关闭某个窗口之后，应该打开它的<b>后继</b>窗口，
 * 而不是循环外那个最终窗口。写错会导致：
 * </p>
 * <ul>
 *   <li>中间被跨过的窗口<b>没有自己的数据文件</b>（与"时间一到，哪怕零消息也要分段"相违背）；</li>
 *   <li>它们的 manifest <b>指向最终窗口的数据文件</b>——因为
 *       {@code currentLogDbPath} 已经被切到最终窗口了。</li>
 * </ul>
 * <p>
 * 这个路径在正常运行中几乎不会触发（只有进程卡顿/挂起跨过多个边界才出现），
 * 所以靠人工观察发现不了，必须用假时钟把它逼出来。
 * </p>
 */
public class VolumeRotationTest {

    private static final Logger logger = LoggerFactory.getLogger(VolumeRotationTest.class);

    private static final Path WORK_DIR = Paths.get("target", "volume-rotation-test");
    private static final Path PCAP_FILE = WORK_DIR.resolve("in.pcap");
    /** 分卷基准名：产物形如 base_{时间戳}.db / base_{时间戳}.manifest.json */
    private static final String BASE_NAME = "rot.db";

    private static final long INTERVAL_MS = 60_000L;
    private static final int FRAME_COUNT = 4;

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void volumeRotationRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  D5 验收：一次跨多个时间窗的分卷轮转");
        logger.info("=================================================");

        prepare();
        buildPcap();
        runWithScriptedClock();
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

    private static void buildPcap() throws Exception {
        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");

        List<Packet> packets = new ArrayList<>();
        for (int i = 0; i < FRAME_COUNT; i++) {
            byte[] payload = new byte[16];
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
        logger.info("  已写入 {} 个报文", packets.size());
    }

    /**
     * 用脚本化的假时钟跑一次采集：
     * 前面几个包都停在同一个窗口内，等到读文件末尾那一轮突然跳进 5 个间隔，
     * 从而逼出"一次关闭多个窗口"的路径。
     */
    private static void runWithScriptedClock() throws Exception {
        logger.info("---- [1] 假时钟驱动：最后一轮跳进 {} 个时间窗 ----", 5);

        long base = (System.currentTimeMillis() / INTERVAL_MS) * INTERVAL_MS;
        long jumped = base + 5 * INTERVAL_MS;

        // 时钟调用次序：initialize 1 次 + 每个包轮转 1 次 + 读末尾轮转 1 次
        // 最后一次调用（读末尾那一轮）跳到 jumped，触发多窗口关闭
        AtomicInteger call = new AtomicInteger();
        int jumpAtCall = FRAME_COUNT + 1;
        LongSupplier scripted = () -> call.getAndIncrement() >= jumpAtCall ? jumped : base;

        PacketCapture capture = new PacketCapture();
        // 顺序必须与 CLI 一致：时间源 → 输出文件 → split → logdb。
        // 关键原因是 setLogDb 会走 initializeLogDbVolumePath() 来建时间窗并连接到**窗口文件名**；
        // 若先 setLogDb 再 setSplit，窗口是后来才建的，而连接已经落在基准名文件上，
        // 于是首个窗口的数据在 rot.db、manifest 却指向 rot_{时间戳}.db。
        capture.setClockForTest(scripted);
        capture.setOutputFile(WORK_DIR.resolve("rot.pcap").toString());
        capture.setSplit(INTERVAL_MS);
        capture.setLogDb(WORK_DIR.resolve(BASE_NAME).toString());
        capture.startCaptureFromFile(PCAP_FILE.toString());
        logger.info("  采集完成（时钟共被询问 {} 次）", call.get());
    }

    private static void verify() throws Exception {
        logger.info("---- [2] 校验每个窗口的 db 文件都含一份自洽的 manifest 表 ----");

        List<Path> dbFiles = new ArrayList<>();
        try (Stream<Path> stream = Files.list(WORK_DIR)) {
            for (Path p : stream.toList()) {
                String name = p.getFileName().toString();
                if (name.endsWith(".db")) {
                    dbFiles.add(p);
                }
            }
        }
        dbFiles.sort(java.util.Comparator.comparing(Path::toString));

        logger.info("  产物：{} 个 db 文件", dbFiles.size());

        // 多窗口路径确实被触发了（否则本测试什么也没验证）
        check(dbFiles.size() >= 3,
                "一次跨多窗确实切出多个卷（db 数 " + dbFiles.size() + "，期望 >= 3）");

        // 核心断言：每个 db 文件的 JSharkManifest 表都有一条 manifest，且其 startTime
        // 与文件名里的窗口时间戳一致——即"manifest 属于它自己那个窗口"（窗口不错位）
        int badStartTime = 0;
        int missingManifest = 0;
        for (Path db : dbFiles) {
            String stamp = extractStamp(db.getFileName().toString());
            String startTime = null;
            boolean manifestRow = false;
            try (java.sql.Connection conn =
                         java.sql.DriverManager.getConnection("jdbc:duckdb:" + db);
                 java.sql.Statement st = conn.createStatement();
                 java.sql.ResultSet rs = st.executeQuery(
                         "Select startTime, completeWindow, packetCount From JSharkManifest")) {
                if (rs.next()) {
                    manifestRow = true;
                    startTime = rs.getString("startTime");
                }
            } catch (Exception e) {
                logger.error("[失败] db {} 无法读取 JSharkManifest: {}", db.getFileName(), e.getMessage());
                missingManifest++;
                continue;
            }
            if (!manifestRow) {
                missingManifest++;
                logger.error("[失败] db {} 没有 manifest 行", db.getFileName());
                continue;
            }
            if (!stamp.equals(startTime)) {
                badStartTime++;
                logger.error("[失败] db {} 的窗口是 {}，manifest.startTime 却是 {}（窗口错位）",
                        db.getFileName(), stamp, startTime);
            }
        }
        check(missingManifest == 0, "每个 db 文件都自带一条 manifest（缺失 " + missingManifest + "）");
        check(badStartTime == 0, "每个 manifest 都属于自己窗口的 db（错位 " + badStartTime + "）");

        // PCAP 与 logdb 必须共用同一个窗口时钟，且**扩展名不能串**。
        // 这条曾经真的错过：CLI 顺序是 setOutputFile → setSplit → setLogDb，
        // setSplit 时 logDb 还没设，窗口先按 PCAP 路径建好（连 .pcap 扩展名一起），
        // 结果 logdb 被写成 "rot_<时间戳>.pcap"，随后 PCAP 打开该路径报 Permission denied
        // （文件被 DuckDB 占着）。因此这里同时断言：db 文件真的能当库打开、也能查 JSharkLog。
        java.util.Set<String> stampFromDbs = new java.util.TreeSet<>();
        for (Path db : dbFiles) {
            stampFromDbs.add(extractStamp(db.getFileName().toString()));
        }
        List<Path> pcapFiles = new ArrayList<>();
        try (Stream<Path> stream = Files.list(WORK_DIR)) {
            for (Path p : stream.toList()) {
                String name = p.getFileName().toString();
                // 只看本工具产出的分卷（rot_<14位时间戳>.pcap），排除测试自己的输入文件 in.pcap
                if (name.startsWith("rot_") && name.endsWith(".pcap")) {
                    pcapFiles.add(p);
                }
            }
        }
        java.util.Set<String> stampFromPcaps = new java.util.TreeSet<>();
        for (Path pcap : pcapFiles) {
            stampFromPcaps.add(extractStamp(pcap.getFileName().toString()));
        }
        check(stampFromPcaps.equals(stampFromDbs),
                "PCAP 与 logdb 的窗口时间戳一一对应（pcap=" + stampFromPcaps + ", db=" + stampFromDbs + "）");

        boolean dbIsQueryable = false;
        String dbError = null;
        try (java.sql.Connection conn =
                     java.sql.DriverManager.getConnection("jdbc:duckdb:" + dbFiles.get(0));
             java.sql.Statement st = conn.createStatement();
             java.sql.ResultSet rs = st.executeQuery("Select count(*) From JSharkLog")) {
            dbIsQueryable = rs.next();
        } catch (Exception e) {
            dbError = e.getMessage();
        }
        check(dbIsQueryable, "窗口 db 文件确实是可查询的数据库（错误: " + dbError + "）");

        // 每个卷的 volumeSeq 列都必须 ≥1（0 的语义是"未启用分卷"）。
        // 历史上 openVolume() 的顺序是 resetCommittedCount → setVolumeSeq → setLogDb，
        // 而前两者对"已被上一卷关掉的 handler"是 no-op，于是卷 ≥2 的 volumeSeq 全部写成 0，
        // 归档数据里再也认不出卷号——这条断言把那个顺序钉死。
        int badVolumeSeq = 0;
        for (Path db : dbFiles) {
            try (java.sql.Connection conn =
                         java.sql.DriverManager.getConnection("jdbc:duckdb:" + db);
                 java.sql.Statement st = conn.createStatement();
                 java.sql.ResultSet rs = st.executeQuery(
                         "Select count(*) From JSharkLog Where volumeSeq = 0")) {
                if (rs.next() && rs.getInt(1) > 0) {
                    badVolumeSeq++;
                    logger.error("[失败] db {} 有 {} 行的 volumeSeq=0（分卷号丢失）",
                            db.getFileName(), rs.getInt(1));
                }
            } catch (Exception e) {
                badVolumeSeq++;
                logger.error("[失败] db {} 无法查询 volumeSeq: {}", db.getFileName(), e.getMessage());
            }
        }
        check(badVolumeSeq == 0, "所有卷的 volumeSeq 列都不为 0（异常卷数 " + badVolumeSeq + "）");

        // manifest 必须把"解析管线"的丢弃渠道也归档。
        // 这三项原先只出现在停机时那一行 INFO 汇总里：日志级别一调高、或日志被轮转掉，
        // 归档 db 里就再也查不到这笔账了——而 manifest 是归档数据唯一能自证完整性的地方。
        // 键名带单位语义：前两项是包数，第三项是事件数（不是包数）。
        String[] requiredDropKeys = {
                "parseStallDroppedCum", "parseTaskFailedCum", "parseBarrierTimeoutEventsCum"
        };
        int manifestRows = 0;
        int missingDropKeys = 0;
        for (Path db : dbFiles) {
            try (java.sql.Connection conn =
                         java.sql.DriverManager.getConnection("jdbc:duckdb:" + db);
                 java.sql.Statement st = conn.createStatement();
                 java.sql.ResultSet rs = st.executeQuery("Select dropped From JSharkManifest")) {
                while (rs.next()) {
                    manifestRows++;
                    String dropped = rs.getString(1);
                    for (String key : requiredDropKeys) {
                        if (dropped == null || !dropped.contains("\"" + key + "\"")) {
                            missingDropKeys++;
                            logger.error("[失败] db {} 的 manifest 缺少 dropped 键 {}（dropped={}）",
                                    db.getFileName(), key, dropped);
                        }
                    }
                }
            } catch (Exception e) {
                missingDropKeys++;
                logger.error("[失败] db {} 无法查询 manifest: {}", db.getFileName(), e.getMessage());
            }
        }
        check(manifestRows >= dbFiles.size(),
                "每个卷都写入了 manifest 行（行数 " + manifestRows + "，卷数 " + dbFiles.size() + "）");
        check(missingDropKeys == 0,
                "manifest 归档了解析管线的丢弃渠道 " + java.util.Arrays.toString(requiredDropKeys)
                        + "（缺失 " + missingDropKeys + " 处）");
    }

    /**
     * 从 {@code rot_20231114221320.db} / {@code rot_20231114221320-20231114231320.db} /
     * {@code rot_20231114221320.manifest.json} 里取出<b>起始</b>时间戳（第一个 14 位数字）。
     */
    private static String extractStamp(String fileName) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d{14})").matcher(fileName);
        return m.find() ? m.group(1) : fileName;
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
