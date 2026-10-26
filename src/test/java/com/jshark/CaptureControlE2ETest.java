package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.util.Comparator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code --control stdio} 端到端验收（离线 pcap，不需要管理员权限）。
 *
 * <p>把控制通道的 stdin/stdout 换成内存管道，直接跑 {@link CaptureControl}：
 * READY → start → RUNNING/FINISHED → terminal；校验状态推进、计数与分卷数据。</p>
 */
public class CaptureControlE2ETest {

    private static final Path DIR = Path.of("target", "capture-control-e2e");

    @Test
    void controlChannelRunsOfflineCaptureToCompletion() throws Exception {
        resetDir();
        Path pcap = DIR.resolve("in.pcap");
        Path db = DIR.resolve("out.db");
        writeUdpPcap(pcap, 3);

        CliShark cli = new CliShark();
        cli.parse(new String[]{"--pcapinput", pcap.toString(), "--logdb", db.toString()});

        PipedOutputStream cmdOut = new PipedOutputStream();
        PipedInputStream cmdIn = new PipedInputStream(cmdOut);
        PipedOutputStream protoOut = new PipedOutputStream();
        PipedInputStream protoIn = new PipedInputStream(protoOut);
        PrintStream protocol = new PrintStream(protoOut, true, StandardCharsets.UTF_8);

        BlockingQueue<String> lines = new LinkedBlockingQueue<>();
        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(protoIn, StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    lines.add(line);
                }
            } catch (Exception ignored) {
                // 流关闭即结束
            }
        }, "control-e2e-reader");
        reader.setDaemon(true);
        reader.start();

        CaptureControl control = CaptureControl.forTest(cli, cmdIn, protocol);
        Thread loop = new Thread(control::loop, "control-e2e");
        loop.setDaemon(true);
        loop.start();

        // 1) READY
        JSONObject ready = waitForState(lines, "READY", 5_000);
        assertNotNull(ready, "应收到 READY 状态");

        // 2) start
        cmdOut.write("{\"id\":1,\"cmd\":\"start\"}\n".getBytes(StandardCharsets.UTF_8));
        cmdOut.flush();

        // 3) 等到 FINISHED + terminal（离线 pcap 很小，通常 <1s）——
        //    两条消息的先后顺序不固定，必须一起收集。
        JSONObject finished = null;
        JSONObject terminal = null;
        long deadline = System.currentTimeMillis() + 15_000;
        while ((finished == null || terminal == null) && System.currentTimeMillis() < deadline) {
            long remain = Math.max(1, deadline - System.currentTimeMillis());
            String line = lines.poll(remain, TimeUnit.MILLISECONDS);
            if (line == null) {
                break;
            }
            JSONObject json = JSON.parseObject(line);
            if (json == null) {
                continue;
            }
            String type = json.getString("type");
            if ("terminal".equals(type)) {
                terminal = json;
            } else if ("status".equals(type) && "FINISHED".equals(json.getString("state"))) {
                finished = json;
            }
        }
        assertNotNull(finished, "应收到 FINISHED 状态");
        assertEquals(3L, finished.getLongValue("captured"), "captured 应等于 pcap 包数");
        assertEquals(3L, finished.getLongValue("stored"), "stored 应等于入库条数");
        JSONArray volumes = finished.getJSONArray("volumes");
        assertNotNull(volumes);
        assertFalse(volumes.isEmpty(), "FINISHED 快照应包含分卷");
        JSONObject firstVolume = volumes.getJSONObject(0);
        assertEquals(3L, firstVolume.getLongValue("packets"));
        assertEquals("complete", firstVolume.getString("status"));

        assertNotNull(terminal, "应收到 terminal");
        assertTrue(terminal.getBooleanValue("ok"), "正常结束 terminal.ok 应为 true");

        // 4) 关闭 stdin → 子进程循环退出
        cmdOut.close();
        loop.join(10_000);
        assertFalse(loop.isAlive(), "stdin EOF 后控制循环应退出");
    }

    // ---------- 协议读取 ----------

    private static JSONObject waitForState(BlockingQueue<String> lines, String state, long timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            long remain = deadline - System.currentTimeMillis();
            String line = lines.poll(Math.max(1, remain), TimeUnit.MILLISECONDS);
            if (line == null) {
                return null;
            }
            JSONObject json = JSON.parseObject(line);
            if (json != null && "status".equals(json.getString("type"))
                    && state.equals(json.getString("state"))) {
                return json;
            }
        }
        return null;
    }

    private static JSONObject waitForType(BlockingQueue<String> lines, String type, long timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            long remain = deadline - System.currentTimeMillis();
            String line = lines.poll(Math.max(1, remain), TimeUnit.MILLISECONDS);
            if (line == null) {
                return null;
            }
            JSONObject json = JSON.parseObject(line);
            if (json != null && type.equals(json.getString("type"))) {
                return json;
            }
        }
        return null;
    }

    // ---------- fixtures ----------

    private static void writeUdpPcap(Path pcap, int packets) throws Exception {
        MacAddress srcMac = MacAddress.getByName("66:77:88:99:aa:bb");
        MacAddress dstMac = MacAddress.getByName("00:11:22:33:44:55");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("192.168.1.100");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("192.168.1.200");
        long base = System.currentTimeMillis();
        try (PcapHandle dead = Pcaps.openDead(DataLinkType.EN10MB, 65536);
             PcapDumper dumper = dead.dumpOpen(pcap.toString())) {
            for (int i = 0; i < packets; i++) {
                dumper.dump(udpFrame(srcMac, dstMac, srcIp, dstIp, i),
                        new Timestamp(base + i * 10L));
            }
            dumper.flush();
        }
    }

    private static Packet udpFrame(MacAddress srcMac, MacAddress dstMac,
                                   Inet4Address srcIp, Inet4Address dstIp, int seq) {
        byte[] payload = ("e2e-" + seq).getBytes(StandardCharsets.US_ASCII);
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
