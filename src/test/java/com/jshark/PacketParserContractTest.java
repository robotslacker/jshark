package com.jshark;

import com.jshark.parser.PacketParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 锁定 {@link PacketParser} 的两处行为契约（这两处曾被性能改造动过）：
 *
 * <ol>
 *   <li><b>MAC 格式化</b>：从 {@code String.format("%02X")} 改成 16 进制查表（实测 6.69 → 0.199 µs/包）。
 *       输出必须仍是"大写、冒号分隔、负字节按无符号"。</li>
 *   <li><b>rawData 语义</b>：删掉了一次"赋完立刻被 payload 覆盖"的整帧拷贝。删拷贝不能改变语义：
 *       TCP 无载荷（如 SYN）必须仍是 {@code null}，UDP 取 payload，ICMP 与未被识别的 IP 协议
 *       （如 GRE 47）回退为整帧。</li>
 * </ol>
 *
 * <p>纯内存构造报文（不读 pcap 文件），因此不需要 Npcap 本地库。</p>
 */
class PacketParserContractTest {

    private static final byte[] SRC_MAC = {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF};
    private static final byte[] DST_MAC = {0x00, 0x0c, 0x29, 0x11, 0x22, 0x33};

    private final PacketParser parser = new PacketParser();

    @Test
    @DisplayName("MAC 格式化：大写、冒号分隔、大小写输入归一、00/FF 边界")
    void macFormatting() throws Exception {
        Packet syn = frame(SRC_MAC, DST_MAC, 6, tcp((short) 1234, (short) 80, true, null));
        PacketParser.ParsedPacket r = parser.parse(syn, 1, meta(syn));

        // 输入是混合大小写（AA..FF / 00:0c:29..），输出必须统一大写
        assertEquals("AA:BB:CC:DD:EE:FF", r.sourceMac());
        assertEquals("00:0C:29:11:22:33", r.destinationMac());
        assertTrue(r.summary().startsWith("Ethernet: AA:BB:CC:DD:EE:FF -> 00:0C:29:11:22:33"),
                "summary 前缀应含格式化后的 MAC，实际: " + r.summary());

        byte[] allZero = new byte[6];
        byte[] allOnes = new byte[6];
        Arrays.fill(allOnes, (byte) 0xFF);
        Packet edge = frame(allZero, allOnes, 6, tcp((short) 1, (short) 2, true, null));
        PacketParser.ParsedPacket e = parser.parse(edge, 2, meta(edge));
        assertEquals("00:00:00:00:00:00", e.sourceMac());
        assertEquals("FF:FF:FF:FF:FF:FF", e.destinationMac());
    }

    @Test
    @DisplayName("rawData：TCP 无载荷为 null，TCP/UDP 取 payload，未知 IP 协议回退整帧")
    void rawDataSemantics() throws Exception {
        // 1) TCP SYN 无应用层数据 -> rawData 必须为 null（processPacket 靠它区分控制段与数据段）
        Packet syn = frame(SRC_MAC, DST_MAC, 6, tcp((short) 1234, (short) 80, true, null));
        PacketParser.ParsedPacket p1 = parser.parse(syn, 1, meta(syn));
        assertNull(p1.rawData(), "TCP SYN 的 rawData 必须是 null");
        assertEquals("1234->80", p1.sourcePort() + "->" + p1.destinationPort());

        // 2) TCP 带载荷 -> rawData == payload
        byte[] tcpPayload = "HELLO".getBytes();
        Packet tcp = frame(SRC_MAC, DST_MAC, 6, tcp((short) 1234, (short) 80, false, tcpPayload));
        assertArrayEquals(tcpPayload, parser.parse(tcp, 2, meta(tcp)).rawData());

        // 3) UDP 带载荷 -> rawData == payload
        byte[] udpPayload = "DISDATA".getBytes();
        Packet udp = frame(SRC_MAC, DST_MAC, 17, udp((short) 4000, (short) 3000, udpPayload));
        assertArrayEquals(udpPayload, parser.parse(udp, 3, meta(udp)).rawData());

        // 4) 未被传输层识别的 IP 协议（GRE 47）-> 历史语义是整帧，删拷贝后必须保持
        byte[] inner = new byte[20];
        Arrays.fill(inner, (byte) 0x11);
        Packet gre = frame(SRC_MAC, DST_MAC, 47, inner);
        assertArrayEquals(gre.getRawData(), parser.parse(gre, 4, meta(gre)).rawData());

        // 5) ICMP -> 同样是整帧
        Packet icmp = frame(SRC_MAC, DST_MAC, 1, new byte[8]);
        assertArrayEquals(icmp.getRawData(), parser.parse(icmp, 5, meta(icmp)).rawData());
    }

    // ==================== 报文构造（纯字节，不依赖 pcap 文件） ====================

    private static PacketParser.WireMeta meta(Packet p) {
        return PacketParser.WireMeta.of(java.time.Instant.now(), p.length());
    }

    private static Packet frame(byte[] srcMac, byte[] dstMac, int ipProto, byte[] transport)
            throws org.pcap4j.packet.IllegalRawDataException {
        int total = 20 + transport.length;
        byte[] f = new byte[14 + total];
        System.arraycopy(dstMac, 0, f, 0, 6);
        System.arraycopy(srcMac, 0, f, 6, 6);
        f[12] = 0x08;
        f[13] = 0x00;
        int ip = 14;
        f[ip] = 0x45;
        f[ip + 2] = (byte) (total >> 8);
        f[ip + 3] = (byte) total;
        f[ip + 8] = 64;
        f[ip + 9] = (byte) ipProto;
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
        f[ip + 10] = (byte) (ck >> 8);
        f[ip + 11] = (byte) ck;
        System.arraycopy(transport, 0, f, ip + 20, transport.length);
        return EthernetPacket.newPacket(f, 0, f.length);
    }

    private static byte[] tcp(short srcPort, short dstPort, boolean syn, byte[] payload) {
        int pl = payload == null ? 0 : payload.length;
        byte[] t = new byte[20 + pl];
        t[0] = (byte) (srcPort >> 8); t[1] = (byte) srcPort;
        t[2] = (byte) (dstPort >> 8); t[3] = (byte) dstPort;
        t[12] = 0x50;
        t[13] = (byte) (syn ? 0x02 : 0x18);
        t[14] = 0x20; t[15] = 0x00;
        if (pl > 0) {
            System.arraycopy(payload, 0, t, 20, pl);
        }
        return t;
    }

    private static byte[] udp(short srcPort, short dstPort, byte[] payload) {
        int pl = payload == null ? 0 : payload.length;
        byte[] u = new byte[8 + pl];
        u[0] = (byte) (srcPort >> 8); u[1] = (byte) srcPort;
        u[2] = (byte) (dstPort >> 8); u[3] = (byte) dstPort;
        int len = 8 + pl;
        u[4] = (byte) (len >> 8); u[5] = (byte) len;
        if (pl > 0) {
            System.arraycopy(payload, 0, u, 8, pl);
        }
        return u;
    }
}
