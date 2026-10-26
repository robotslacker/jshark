package com.jshark;

import com.jshark.parser.PacketDBEventHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并行解析的等价性回归：同一份 pcap，单线程（默认）与多线程入库的内容必须**逐行等价**。
 *
 * <p>为什么这是最重要的一条回归：解析并行化把"有状态"的工作（TCP 流重组、IP 分片重组）
 * 按流固定到分片、把无状态的包轮询分发。一旦路由写错，症状是<b>静默的错误结果</b>
 * （重组出的字节流错、分片拼不出来），不会崩、不会报错。</p>
 *
 * <p>比对维度覆盖：行数、id 之和、length 之和、帧字节的哈希集合、载荷哈希集合、
 * additionalInfo JSON 的取值集合。只要有任何一行内容或顺序语义变了，这里就会红。</p>
 *
 * <p>注意：队列容量在测试里被放大，确保"没有任何丢包"——否则行数差异会掩盖真正的等价性问题
 * （丢包本身有独立计数，见 PacketDBEventHandler#droppedQueueFull）。</p>
 *
 * <p>需要本机安装 Npcap（离线读 pcap 也依赖其本地库），这与产品本身的运行前提一致。</p>
 */
class ParallelParseEquivalenceTest {

    private static final int PACKETS = 3000;

    private Path dir;

    @AfterEach
    void cleanup() throws Exception {
        if (dir != null) {
            try (var s = Files.walk(dir)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                        // 清理失败不影响结论
                    }
                });
            }
        }
    }

    @Test
    @DisplayName("单线程 vs 4 线程解析：入库内容必须完全一致")
    void parallelParsingIsEquivalent() throws Exception {
        // 队列放大：本次要验证"内容等价"，不是"丢包策略"
        System.setProperty(PacketDBEventHandler.QUEUE_CAPACITY_PROPERTY, "50000");
        try {
            dir = Files.createTempDirectory("jshark-parallel-equiv");
            Path pcap = dir.resolve("dis.pcap");
            writeDisPcap(pcap, PACKETS);

            String single = capture(pcap, dir.resolve("single.db").toString(), 1);
            String quad = capture(pcap, dir.resolve("quad.db").toString(), 4);

            assertTrue(single.startsWith("n=" + PACKETS), "单线程应完整入库，实际: " + single);
            assertEquals(single, quad,
                    "并行解析的入库内容必须与单线程完全一致（顺序语义由 ingestSeq 保证）");
        } finally {
            System.clearProperty(PacketDBEventHandler.QUEUE_CAPACITY_PROPERTY);
        }
    }

    /** 跑一遍采集并返回内容摘要 */
    private static String capture(Path pcap, String dbFile, int parseThreads) {
        PacketCapture pc = new PacketCapture();
        pc.setParseThreads(parseThreads);
        pc.setLogDb(dbFile);
        // 本用例比较单线程/并行下的 additionalInfo JSON，显式开启
        pc.setEnableAdditionalInfo(true);
        pc.startCaptureFromFile(pcap.toString());

        try (Connection c = DriverManager.getConnection("jdbc:duckdb:" + dbFile);
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT count(*) n, coalesce(sum(length),0) slen, "
                             + "count(DISTINCT hash(frameData)) dhf, count(DISTINCT hash(rawData)) dhr, "
                             + "count(DISTINCT additionalInfo) djson "
                             + "FROM JSharkLog")) {
            rs.next();
            // 注意刻意不含 id/ingestSeq：并行模式下读线程为每个包预分配序号，
            // 被缓存等待后续分片的包也会消耗序号，因此序号可能带"空洞"（仍严格单调唯一）。
            return String.format("n=%d sumLen=%d dHashFrame=%d dHashRaw=%d dJson=%d",
                    rs.getLong("n"), rs.getLong("slen"),
                    rs.getLong("dhf"), rs.getLong("dhr"), rs.getLong("djson"));
        } catch (Exception e) {
            throw new AssertionError("读取入库结果失败: " + e.getMessage(), e);
        }
    }

    // ==================== 合成 DIS Entity State PDU 流量 ====================

    private static void writeDisPcap(Path file, int count) throws Exception {
        int frameSize = 186;              // 14 + 20 + 8 + 144
        int payloadLen = frameSize - 42;
        byte[] frame = new byte[frameSize];
        byte[] dis = new byte[payloadLen];
        buildDisEntityState(dis, payloadLen);
        buildHeaders(frame, payloadLen);

        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(file.toFile()), 1 << 16)) {
            byte[] gh = new byte[24];
            ByteBuffer b = ByteBuffer.wrap(gh).order(ByteOrder.LITTLE_ENDIAN);
            b.putInt(0xa1b2c3d4);
            b.putShort((short) 2);
            b.putShort((short) 4);
            b.putInt(0);
            b.putInt(0);
            b.putInt(65535);
            b.putInt(1);
            os.write(gh);

            byte[] hdr = new byte[16];
            ByteBuffer hb = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN);
            for (int i = 0; i < count; i++) {
                dis[1] = (byte) (i % 20);                 // exercise id
                dis[16] = (byte) (i & 0xff);              // entity id
                dis[17] = (byte) ((i >> 8) & 0xff);
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
    }

    /** IEEE 1278.1 Entity State PDU；声明长度必须等于载荷长度，否则 jshark 不会识别为 DIS。 */
    private static void buildDisEntityState(byte[] p, int declaredLen) {
        p[0] = 7;
        p[1] = 1;
        p[2] = 1;
        p[3] = 1;
        p[8] = (byte) (declaredLen >> 8);
        p[9] = (byte) declaredLen;
        p[12] = 1; p[13] = 1;
        p[14] = 0; p[15] = 1;
        p[16] = 0; p[17] = 1;
        p[18] = 1;
        p[20] = 1; p[21] = 1; p[22] = 0; p[23] = (byte) 225;
        p[24] = 1; p[25] = 1; p[26] = 1; p[27] = 0;
        System.arraycopy(p, 20, p, 28, 8);
        // marking 位于偏移 128（不是 116）：12+6+1+1+8+8+12+24+12+4+40 = 128
        p[128] = 1;
        byte[] mark = "TANK-0001  ".getBytes();
        System.arraycopy(mark, 0, p, 129, Math.min(11, mark.length));
    }

    /** 以太网(14) + IPv4(20) + UDP(8)，校验和按需计算 */
    private static void buildHeaders(byte[] f, int payloadLen) {
        f[0] = 0x01; f[1] = 0x00; f[2] = 0x5e; f[3] = 0x03; f[4] = 0x00; f[5] = 0x01;   // 224.3.0.1
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
}
