package com.jshark;

import com.jshark.PacketCapture.Snapshot;
import com.jshark.PacketCapture.VolumeRow;
import org.junit.jupiter.api.Test;
import org.pcap4j.core.PcapDumper;
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

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 采集状态快照（UI / --control stdio 的数据源）的离线验收。
 *
 * <p>用 {@code --pcapinput} 等价的离线路径跑一遍 {@link PacketCapture#startCaptureFromFile}，
 * 不需要网卡、不需要管理员权限。校验：计数、单文件分卷行、终态不再有 "capturing" 行。</p>
 */
public class PacketCaptureSnapshotTest {

    private static final Path DIR = Path.of("target", "capture-snapshot-test");

    @Test
    void singleFileRunExposesFinishedSnapshot() throws Exception {
        resetDir();
        Path pcap = DIR.resolve("in.pcap");
        Path db = DIR.resolve("out.db");
        writeUdpPcap(pcap, 3, 10L);

        PacketCapture capture = new PacketCapture();
        capture.setLogDb(db.toString());
        capture.startCaptureFromFile(pcap.toString());

        Snapshot snap = capture.snapshot();
        assertNotNull(snap);
        assertEquals("FINISHED", snap.state(), "采集结束后快照状态应为 FINISHED");
        assertEquals(3, snap.captured(), "captured 应等于 pcap 中的包数");
        assertEquals(3, snap.stored(), "stored 应等于入库条数");
        assertFalse(snap.volumes().isEmpty(), "单文件模式也必须有一行分卷");

        VolumeRow row = snap.volumes().get(0);
        assertEquals(1, row.seq());
        assertTrue(row.file().endsWith("out.db"), "分卷行应指向 logdb 文件，实际 " + row.file());
        assertEquals(3, row.packets(), "分卷行包数应等于入库条数");
        assertTrue(row.bytes() > 0, "分卷文件大小应 > 0");
        assertEquals("complete", row.status(), "单文件结束后该卷应为 complete");
        assertTrue(snap.volumes().stream().noneMatch(v -> "capturing".equals(v.status())),
                "FINISHED 之后不应再有 capturing 行");
        assertTrue(snap.currentVolume() == null || snap.volumes().stream()
                        .anyMatch(v -> v.file().equals(snap.currentVolume())),
                "currentVolume 若存在应能在分卷表中找到");
    }

    @Test
    void pcapOnlyRunExposesPcapVolume() throws Exception {
        resetDir();
        Path pcap = DIR.resolve("in2.pcap");
        Path out = DIR.resolve("out.pcap");
        writeUdpPcap(pcap, 2, 10L);

        PacketCapture capture = new PacketCapture();
        capture.setOutputFile(out.toString());
        capture.startCaptureFromFile(pcap.toString());

        Snapshot snap = capture.snapshot();
        assertEquals(2, snap.captured());
        assertFalse(snap.volumes().isEmpty(), "仅 PCAP 模式也要有分卷行");
        VolumeRow row = snap.volumes().get(0);
        assertTrue(row.file().endsWith("out.pcap"), "分卷行应指向 pcap 文件，实际 " + row.file());
        assertEquals(2, row.packets());
        assertEquals("complete", row.status());
    }

    // ---------- fixtures ----------

    private static void writeUdpPcap(Path pcap, int packets, long spacingMs) throws Exception {
        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");
        long base = System.currentTimeMillis();
        try (PcapHandle dead = Pcaps.openDead(DataLinkType.EN10MB, 65536);
             PcapDumper dumper = dead.dumpOpen(pcap.toString())) {
            for (int i = 0; i < packets; i++) {
                Packet pkt = udpFrame(srcMac, dstMac, srcIp, dstIp, i);
                dumper.dump(pkt, new Timestamp(base + i * spacingMs));
            }
            dumper.flush();
        }
    }

    private static Packet udpFrame(MacAddress srcMac, MacAddress dstMac,
                                   Inet4Address srcIp, Inet4Address dstIp, int seq) {
        byte[] payload = ("jshark-" + seq).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        UdpPacket.Builder udp = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) 3000))
                .dstPort(UdpPort.getInstance((short) 8200))
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

    private static void resetDir() throws Exception {
        if (Files.exists(DIR)) {
            try (Stream<Path> walk = Files.walk(DIR)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                    }
                });
            }
        }
        Files.createDirectories(DIR);
    }
}
