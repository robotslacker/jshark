package com.jshark;

import com.jshark.parser.CaptureKind;
import com.jshark.parser.PacketParser;
import com.jshark.parser.ProtocolParser;
import org.pcap4j.packet.namednumber.IpNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * {@code --enable_additioninfo} 验收：关闭时 additionalInfo 列恒为 NULL、且不为该列解析载荷，
 * 但 appProtocol / frameData / rawData 与重放相关逻辑不受影响。
 */
public class EnableAdditionInfoTest {

    private static final Logger logger = LoggerFactory.getLogger(EnableAdditionInfoTest.class);

    private static final Path WORK_DIR = Path.of("target", "enable-additioninfo-test");
    private static final Path PCAP_FILE = WORK_DIR.resolve("dis.pcap");
    private static final Path DB_OFF = WORK_DIR.resolve("off.duckdb");
    private static final Path DB_ON = WORK_DIR.resolve("on.duckdb");
    private static final Path DB_FILTERED = WORK_DIR.resolve("filtered-off.duckdb");

    private static final int FRAME_COUNT = 3;

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void enableAdditionInfoRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  --enable_additioninfo 验收");
        logger.info("=================================================");

        checkProtocolParserSwitch();
        preparePcap();
        DbSnapshot off = capture(DB_OFF, false, null);
        DbSnapshot on = capture(DB_ON, true, null);
        checkDatabaseColumns(off, on);
        checkExfilterEnablesStorage();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    // ==================== [1] ProtocolParser 开关 ====================

    private static void checkProtocolParserSwitch() {
        logger.info("---- [1] ProtocolParser：关闭时不展开，开启时展开 ----");

        Map<String, Object> disOff = parse(disPayload(), false);
        check("DIS".equals(disOff.get("application.protocol")),
                "关闭时仍识别 application.protocol=DIS（重放过滤要用）");
        check(!hasPrefix(disOff, "dis."), "关闭时不产生任何 dis.* 字段（实际 " + keys(disOff) + "）");
        check(!hasPrefix(disOff, "ip.") && !hasPrefix(disOff, "udp."),
                "关闭时也不做 IP/传输层事实分析（实际 " + keys(disOff) + "）");

        Map<String, Object> disOn = parse(disPayload(), true);
        check(hasPrefix(disOn, "dis."), "开启时展开 dis.* 字段（实际 " + keys(disOn) + "）");

        byte[] http = "GET /hello?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
                .getBytes(StandardCharsets.ISO_8859_1);
        Map<String, Object> httpOff = parse(http, false, IpNumber.TCP);
        check("HTTP".equals(httpOff.get("application.protocol")), "关闭时仍识别 HTTP");
        check(!hasPrefix(httpOff, "http."), "关闭时不产生任何 http.* 字段（实际 " + keys(httpOff) + "）");
        check(hasPrefix(parse(http, true, IpNumber.TCP), "http."), "开启时展开 http.* 字段");

        byte[] pg = pgQuery("SELECT 1");
        Map<String, Object> pgOff = parse(pg, false, IpNumber.TCP);
        check("PG".equals(pgOff.get("application.protocol")), "关闭时仍识别 PG");
        check(pgOff.get("pg.consumed_bytes") instanceof Integer consumed && consumed == pg.length,
                "关闭时仍保留 pg.consumed_bytes（TCP 窗口切分依赖它，实际 "
                        + pgOff.get("pg.consumed_bytes") + "）");
        check(!hasPrefix(pgOff, "pg.query") && !pgOff.containsKey("pg.messages"),
                "关闭时不展开 pg.* 详细字段（实际 " + keys(pgOff) + "）");
        check(hasPrefix(parse(pg, true, IpNumber.TCP), "pg."), "开启时展开 pg.* 字段");
    }

    // ==================== [2] 入库验收 ====================

    private static void checkDatabaseColumns(DbSnapshot off, DbSnapshot on) throws Exception {
        logger.info("---- [2] 数据库：关闭时 additionalInfo 恒为 NULL ----");

        check(off.rows == FRAME_COUNT && on.rows == FRAME_COUNT,
                "开启/关闭入库行数一致（off=" + off.rows + ", on=" + on.rows + "）");
        check(off.additionalInfoRows == 0,
                "关闭时 additionalInfo 全部为 NULL（实际非空 " + off.additionalInfoRows + " 行）");
        check(on.additionalInfoRows == FRAME_COUNT,
                "开启时 additionalInfo 全部非空（" + on.additionalInfoRows + "/" + FRAME_COUNT + "）");

        check("DIS".equals(off.appProtocol) && "DIS".equals(on.appProtocol),
                "appProtocol 列不受开关影响（off=" + off.appProtocol + ", on=" + on.appProtocol + "）");
        check(off.frameHashes == on.frameHashes && off.rawHashes == on.rawHashes,
                "frameData/rawData 内容不变（frame " + off.frameHashes + "/" + on.frameHashes
                        + ", raw " + off.rawHashes + "/" + on.rawHashes + "）");
        check(off.totalLength == on.totalLength,
                "length 列不变（off=" + off.totalLength + ", on=" + on.totalLength + "）");
    }

    /**
     * 设置 --exfilter 时自动开启 additionalInfo 落盘：过滤依赖协议字段，
     * 匹配行也必须保留这些字段，供事后查询与重放过滤。
     */
    private static void checkExfilterEnablesStorage() throws Exception {
        logger.info("---- [3] --exfilter 自动开启 additionalInfo ----");

        DbSnapshot filtered = capture(DB_FILTERED, false, "dis.exercise.id=1");
        check(filtered.rows == 1,
                "exfilter 过滤生效（期望 1 行，实际 " + filtered.rows + " 行）");
        check(filtered.additionalInfoRows == 1,
                "exfilter 命中行写入 additionalInfo（实际非空 " + filtered.additionalInfoRows + " 行）");
        check("DIS".equals(filtered.appProtocol), "过滤命中行的 appProtocol 仍为 DIS");
    }

    // ==================== 采集 ====================

    private static DbSnapshot capture(Path db, boolean enable, String exfilter) throws Exception {
        PacketCapture capture = new PacketCapture();
        capture.setLogDb(db.toString());
        capture.setEnableAdditionalInfo(enable);
        if (exfilter != null) {
            capture.setExfilter(exfilter);
        }
        capture.startCaptureFromFile(PCAP_FILE.toString());

        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + db);
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT count(*) n, count(additionalInfo) info_n, min(appProtocol) ap, "
                             + "count(DISTINCT hash(frameData)) frame_h, "
                             + "count(DISTINCT hash(rawData)) raw_h, coalesce(sum(length),0) total_len "
                             + "FROM JSharkLog")) {
            rs.next();
            return new DbSnapshot(rs.getInt("n"), rs.getInt("info_n"), rs.getString("ap"),
                    rs.getInt("frame_h"), rs.getInt("raw_h"), rs.getLong("total_len"));
        }
    }

    private record DbSnapshot(int rows, int additionalInfoRows, String appProtocol,
                              int frameHashes, int rawHashes, long totalLength) {}

    // ==================== 载荷/报文构造 ====================

    private static Map<String, Object> parse(byte[] payload, boolean enable) {
        return parse(payload, enable, IpNumber.UDP);
    }

    private static Map<String, Object> parse(byte[] payload, boolean enable, IpNumber ipProtocol) {
        PacketParser.ParsedPacket packet = new PacketParser.ParsedPacket(
                1L, Instant.EPOCH, payload.length + 8,
                "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
                "10.0.0.1", "10.0.0.2", ipProtocol, 4000, 3000,
                Map.of(), "test", payload, payload, payload.length + 8, payload.length + 8,
                CaptureKind.WIRE_FRAME);
        return new HashMap<>(new ProtocolParser(enable).parseProtocolDetails(packet).additionalInfo());
    }

    private static byte[] disPayload() {
        int size = 144;
        byte[] p = new byte[size];
        p[0] = 7;                       // protocol version
        p[1] = 1;                       // exercise id
        p[2] = 1;                       // PDU type: Entity State
        p[3] = 1;
        p[8] = (byte) (size >> 8);      // declared length == actual length, otherwise not detected as DIS
        p[9] = (byte) size;
        p[12] = 1; p[13] = 1;
        p[14] = 0; p[15] = 1;
        p[16] = 0; p[17] = 1;
        p[18] = 1;
        p[20] = 1; p[21] = 1; p[22] = 0; p[23] = (byte) 225;
        p[24] = 1; p[25] = 1; p[26] = 1; p[27] = 0;
        System.arraycopy(p, 20, p, 28, 8);
        p[128] = 1;
        byte[] mark = "TANK-0001  ".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(mark, 0, p, 129, Math.min(11, mark.length));
        return p;
    }

    /** 构造一条最简单的 PG 前端 Query 消息：'Q' + Int32(length) + SQL\0 */
    private static byte[] pgQuery(String sql) {
        byte[] sqlBytes = sql.getBytes(StandardCharsets.UTF_8);
        int length = 4 + sqlBytes.length + 1;
        byte[] p = new byte[1 + length];
        p[0] = 'Q';
        ByteBuffer.wrap(p, 1, 4).order(ByteOrder.BIG_ENDIAN).putInt(length);
        System.arraycopy(sqlBytes, 0, p, 5, sqlBytes.length);
        p[p.length - 1] = 0;
        return p;
    }

    // ==================== pcap ====================

    private static void preparePcap() throws Exception {
        logger.info("---- [0] 构造 DIS pcap ----");
        if (Files.exists(WORK_DIR)) {
            try (var stream = Files.walk(WORK_DIR)) {
                stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                    }
                });
            }
        }
        Files.createDirectories(WORK_DIR);

        int frameSize = 186;              // 14 + 20 + 8 + 144
        int payloadLen = frameSize - 42;
        byte[] frame = new byte[frameSize];
        buildHeaders(frame, payloadLen);

        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(PCAP_FILE.toFile()), 1 << 16)) {
            os.write(pcapGlobalHeader());
            byte[] hdr = new byte[16];
            ByteBuffer hb = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN);
            for (int i = 0; i < FRAME_COUNT; i++) {
                byte[] dis = disPayload();
                dis[1] = (byte) i;        // exercise id = 0,1,2
                System.arraycopy(dis, 0, frame, 42, dis.length);
                hb.clear();
                hb.putInt(1_700_000_000);
                hb.putInt(i * 10);
                hb.putInt(frameSize);
                hb.putInt(frameSize);
                os.write(hdr);
                os.write(frame);
            }
        }
        logger.info("  已写入 {} 个 DIS 帧到 {}", FRAME_COUNT, PCAP_FILE);
    }

    private static byte[] pcapGlobalHeader() {
        byte[] gh = new byte[24];
        ByteBuffer b = ByteBuffer.wrap(gh).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0xa1b2c3d4);
        b.putShort((short) 2);
        b.putShort((short) 4);
        b.putInt(0);
        b.putInt(0);
        b.putInt(65535);
        b.putInt(1);
        return gh;
    }

    /** 以太网(14) + IPv4(20) + UDP(8) */
    private static void buildHeaders(byte[] f, int payloadLen) {
        f[0] = 0x01; f[1] = 0x00; f[2] = 0x5e; f[3] = 0x03; f[4] = 0x00; f[5] = 0x01;
        f[6] = 0x00; f[7] = 0x0c; f[8] = 0x29; f[9] = 0x11; f[10] = 0x22; f[11] = 0x33;
        f[12] = 0x08;
        f[13] = 0x00;
        int ip = 14;
        int total = 20 + 8 + payloadLen;
        f[ip] = 0x45;
        f[ip + 2] = (byte) (total >> 8); f[ip + 3] = (byte) total;
        f[ip + 8] = 64;
        f[ip + 9] = 17;
        f[ip + 12] = 10; f[ip + 13] = 1; f[ip + 14] = 1; f[ip + 15] = 10;
        f[ip + 16] = (byte) 224; f[ip + 17] = 3; f[ip + 18] = 0; f[ip + 19] = 1;
        int sum = 0;
        for (int i = ip; i < ip + 20; i += 2) {
            sum += ((f[i] & 0xff) << 8) | (f[i + 1] & 0xff);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        int ck = ~sum & 0xffff;
        f[ip + 10] = (byte) (ck >> 8); f[ip + 11] = (byte) ck;
        int u = ip + 20;
        f[u] = (byte) (4000 >> 8); f[u + 1] = (byte) 4000;
        f[u + 2] = (byte) (3000 >> 8); f[u + 3] = (byte) 3000;
        int ulen = 8 + payloadLen;
        f[u + 4] = (byte) (ulen >> 8); f[u + 5] = (byte) ulen;
    }

    // ==================== 断言工具 ====================

    private static boolean hasPrefix(Map<String, Object> map, String prefix) {
        return map.keySet().stream().anyMatch(k -> k.startsWith(prefix));
    }

    private static String keys(Map<String, Object> map) {
        return String.join(",", map.keySet());
    }

    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
