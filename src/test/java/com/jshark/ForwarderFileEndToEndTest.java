package com.jshark;

import com.jshark.forwarder.PeerConfig;
import com.jshark.forwarder.UdpBridgeNode;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 文件级端到端测试：UDP 组播 → 转发器A → TCP → 转发器B → 另一个端口的 UDP → 落盘。
 *
 * <pre>
 *  测试发送端 ──UDP 组播──▶ 转发器A ──TCP──▶ 转发器B ──UDP(127.0.0.1)──▶ 测试接收端 ──▶ 文件
 *  (50 MiB 随机数据)        (UDP→TCP)        (TCP→UDP)                  (MD5 校验)
 * </pre>
 *
 * <p>流格式：{@code 16B HEADER_MAGIC + 8B payloadLength + payload + 16B POISON}。
 * 毒丸用于让接收端在收完数据后主动收尾（TCP 是字节流，边界已经不存在，所以按字节流拼）。</p>
 *
 * <p><b>live 用例</b>（需要一块支持组播的 IPv4 网卡，不需要 Npcap/管理员权限）：</p>
 * <pre>
 * mvn test -Dgroups=live -DexcludedGroups= -Dtest=ForwarderFileEndToEndTest
 * # 快速自检（1 MiB）：
 * mvn test -Dgroups=live -DexcludedGroups= -Dtest=ForwarderFileEndToEndTest \
 *          -Djshark.forwarder.e2e.bytes=1048576
 * </pre>
 */
@Tag("live")
public class ForwarderFileEndToEndTest {

    private static final Logger logger = LoggerFactory.getLogger(ForwarderFileEndToEndTest.class);

    /** 默认 50 MiB；可用 -Djshark.forwarder.e2e.bytes=... 调整。 */
    private static final int PAYLOAD_BYTES =
            Integer.getInteger("jshark.forwarder.e2e.bytes", 50 * 1024 * 1024);

    /** 单次 UDP 发送量；默认 1400（小于 MTU），可用 -Ddatagram 覆盖以测包处理上限。 */
    private static final int DATAGRAM_BYTES =
            Integer.getInteger("jshark.forwarder.e2e.datagram", 1400);
    /** 每发送这么多包睡一会儿，避免把转发器的接收缓冲打爆；可用 -Dpace/-Dsleep 覆盖。 */
    private static final int PACE_EVERY_PACKETS =
            Integer.getInteger("jshark.forwarder.e2e.pace", 64);
    private static final int PACE_SLEEP_MS =
            Integer.getInteger("jshark.forwarder.e2e.sleep", 1);

    private static final int RECEIVE_TIMEOUT_MS = 180_000;

    private static final byte[] HEADER_MAGIC = "JSHARK-E2E-HDR1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] POISON = "JSHARK-E2E-END1".getBytes(StandardCharsets.US_ASCII);
    static final String GROUP = "239.255.42.99";

    @Test
    void fiftyMegabyteFileSurvivesUdpToTcpToUdp() throws Exception {
        Nic nic = pickMulticastNic();
        Assumptions.assumeTrue(nic != null, "需要一块支持组播的 IPv4 网卡才能跑此端到端测试");

        int bridgePort = freeTcpPort();
        int outPort = freeUdpPort();
        int multicastPort = 42000 + new Random().nextInt(2000);

        System.out.println("[E2E] payload=" + PAYLOAD_BYTES + " bytes, nic=" + nic.ni().getName()
                + " cidr=" + nic.cidr() + " group=" + GROUP + ":" + multicastPort
                + " tcp=" + bridgePort + " outUdp=" + outPort);

        byte[] payload = new byte[PAYLOAD_BYTES];
        new Random(0x5EEDL).nextBytes(payload);
        String sourceMd5 = md5Hex(payload);

        Path receivedFile = Files.createTempFile("jshark-fwd-e2e", ".bin");
        UdpBridgeNode a = null;
        UdpBridgeNode b = null;
        Receiver receiver = null;
        Thread aThread = null;
        try {
            // B：TCP:bridgePort → 127.0.0.1:outPort（只做 TCP→UDP；utot=false 不需要 peer）
            b = new UdpBridgeNode("127.0.0.1", outPort, nic.cidr(), bridgePort,
                    List.of(), false, true, logger);
            b.start();

            receiver = new Receiver(outPort, receivedFile);
            receiver.start();

            // A：组播:multicastPort → TCP(peer=B)（只做 UDP→TCP）
            a = new UdpBridgeNode(GROUP, multicastPort, nic.cidr(), 0,
                    List.of(new PeerConfig("127.0.0.1", bridgePort)), true, false, logger);
            UdpBridgeNode nodeA = a;
            AtomicReference<Throwable> aFailure = new AtomicReference<>();
            aThread = new Thread(() -> {
                try {
                    nodeA.start();
                    nodeA.startUdpListener();
                } catch (Throwable t) {
                    aFailure.set(t);
                }
            }, "fwd-e2e-a");
            aThread.setDaemon(true);
            aThread.start();

            assertTrue(await(a::ready, 10_000, aFailure), "A 应连上 B 的 TCP 端口: " + aFailure.get());
            Thread.sleep(1_000); // 等 A 的组播监听完成 join

            long sentAt = System.currentTimeMillis();
            sendStream(nic, payload, multicastPort);
            assertTrue(receiver.await(RECEIVE_TIMEOUT_MS), "接收端未在超时内收到毒丸: "
                    + receiver.describe());
            long elapsed = Math.max(1, System.currentTimeMillis() - sentAt);

            assertEquals(PAYLOAD_BYTES, receiver.payloadBytes(), "接收字节数不一致");
            assertEquals(sourceMd5, receiver.md5Hex(), "接收流 MD5 不一致");
            assertEquals(PAYLOAD_BYTES, Files.size(receivedFile), "落盘文件大小不一致");
            assertEquals(sourceMd5, md5Hex(receivedFile), "落盘文件 MD5 不一致");

            System.out.printf("[E2E] OK: %d bytes in %d ms (%.1f MiB/s), md5=%s%n",
                    PAYLOAD_BYTES, elapsed,
                    PAYLOAD_BYTES / 1024.0 / 1024.0 / (elapsed / 1000.0), sourceMd5);
        } finally {
            if (a != null) {
                a.stop();
            }
            if (b != null) {
                b.stop();
            }
            if (receiver != null) {
                receiver.close();
            }
            if (aThread != null) {
                aThread.join(5_000);
            }
            Files.deleteIfExists(receivedFile);
        }
    }

    // ==================== 发送 ====================

    static void sendStream(Nic nic, byte[] payload, int multicastPort) throws Exception {
        InetAddress group = InetAddress.getByName(GROUP);
        try (MulticastSocket socket = new MulticastSocket()) {
            try {
                socket.setNetworkInterface(nic.ni());
            } catch (SocketException e) {
                // Windows + 禁用 IPv6 时 JDK 的 setInterface6 会失败（同生产代码注释）；
                // 退化为由操作系统路由选择出口网卡。
                System.err.println("[E2E] setNetworkInterface failed (" + e.getMessage()
                        + "); falling back to OS multicast route");
            }
            socket.setTimeToLive(1);
            socket.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, true);
            socket.setSendBufferSize(4 * 1024 * 1024);

            byte[] header = ByteBuffer.allocate(HEADER_MAGIC.length + 8)
                    .put(HEADER_MAGIC)
                    .putLong(payload.length)
                    .array();
            socket.send(new DatagramPacket(header, header.length, group, multicastPort));

            int packets = 0;
            for (int off = 0; off < payload.length; off += DATAGRAM_BYTES) {
                int len = Math.min(DATAGRAM_BYTES, payload.length - off);
                socket.send(new DatagramPacket(payload, off, len, group, multicastPort));
                if (PACE_EVERY_PACKETS > 0 && ++packets % PACE_EVERY_PACKETS == 0) {
                    Thread.sleep(PACE_SLEEP_MS);
                }
            }

            // 毒丸：让接收端在收完 payload 后主动结束，而不是干等到超时。
            socket.send(new DatagramPacket(POISON, POISON.length, group, multicastPort));
        }
    }

    // ==================== 接收 / 拼流 ====================

    static final class Receiver implements Runnable {

        /** 测吞吐上限时用：只拼流/计数，不做 MD5 和落盘（-Dlight=true）。 */
        private static final boolean LIGHT = Boolean.getBoolean("jshark.forwarder.e2e.light");

        private final DatagramSocket socket;
        private final Path file;
        private final OutputStream out;
        private final MessageDigest md5;
        private final CountDownLatch done = new CountDownLatch(1);
        private final ByteArrayOutputStream header = new ByteArrayOutputStream();
        private final ByteArrayOutputStream tail = new ByteArrayOutputStream();

        private long expected = -1;
        private volatile long payloadBytes;
        private volatile boolean poisonSeen;
        private volatile Throwable failure;
        private volatile String md5Hex;

        Receiver(int port, Path file) throws Exception {
            this.file = file;
            this.socket = new DatagramSocket(null);
            // 压测会在同一端口上反复创建接收端（每次一份文件），要允许立即重新绑定。
            this.socket.setReuseAddress(true);
            this.socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
            this.socket.setReceiveBufferSize(8 * 1024 * 1024);
            this.socket.setSoTimeout(1_000);
            this.out = Files.newOutputStream(file);
            this.md5 = MessageDigest.getInstance("MD5");
        }

        void start() {
            Thread thread = new Thread(this, "fwd-e2e-receiver");
            thread.setDaemon(true);
            thread.start();
        }

        @Override
        public void run() {
            byte[] buffer = new byte[128 * 1024];
            long deadline = System.currentTimeMillis() + RECEIVE_TIMEOUT_MS;
            try {
                while (!poisonSeen && System.currentTimeMillis() < deadline) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        socket.receive(packet);
                    } catch (SocketTimeoutException e) {
                        continue;
                    }
                    feed(packet.getData(), packet.getOffset(), packet.getLength());
                }
                if (!poisonSeen) {
                    throw new IOException("timeout waiting for poison pill");
                }
                md5Hex = toHex(md5.digest());
            } catch (Throwable t) {
                failure = t;
            } finally {
                try {
                    out.close();
                } catch (IOException ignored) {
                }
                socket.close();
                done.countDown();
            }
        }

        /** 按 HEADER → PAYLOAD → POISON 三阶段消费任意切分的字节流。 */
        private void feed(byte[] data, int offset, int length) throws IOException {
            int pos = offset;
            int end = offset + length;
            while (pos < end) {
                if (expected < 0) {
                    int need = HEADER_MAGIC.length + 8 - header.size();
                    int n = Math.min(need, end - pos);
                    header.write(data, pos, n);
                    pos += n;
                    if (header.size() == HEADER_MAGIC.length + 8) {
                        byte[] raw = header.toByteArray();
                        if (!Arrays.equals(Arrays.copyOfRange(raw, 0, HEADER_MAGIC.length), HEADER_MAGIC)) {
                            throw new IOException("bad header magic");
                        }
                        expected = ByteBuffer.wrap(raw, HEADER_MAGIC.length, 8).getLong();
                        if (expected < 0) {
                            throw new IOException("bad payload length: " + expected);
                        }
                    }
                } else if (payloadBytes < expected) {
                    int n = (int) Math.min(expected - payloadBytes, end - pos);
                    if (!LIGHT) {
                        md5.update(data, pos, n);
                        out.write(data, pos, n);
                    }
                    payloadBytes += n;
                    pos += n;
                } else {
                    int need = POISON.length - tail.size();
                    int n = Math.min(need, end - pos);
                    tail.write(data, pos, n);
                    pos += n;
                    if (tail.size() == POISON.length) {
                        if (!Arrays.equals(tail.toByteArray(), POISON)) {
                            throw new IOException("bad poison pill");
                        }
                        poisonSeen = true;
                        return;
                    }
                }
            }
        }

        boolean await(long timeoutMs) throws InterruptedException {
            return done.await(timeoutMs, TimeUnit.MILLISECONDS) && failure == null && poisonSeen;
        }

        long payloadBytes() {
            return payloadBytes;
        }

        String md5Hex() {
            return md5Hex;
        }

        String describe() {
            return "payloadBytes=" + payloadBytes + " expected=" + expected
                    + " poison=" + poisonSeen + " failure=" + failure;
        }

        void close() {
            socket.close();
            try {
                out.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ==================== 环境 / 工具 ====================

    record Nic(NetworkInterface ni, String cidr) {
    }

    static Nic pickMulticastNic() throws SocketException {
        String requested = System.getProperty("nic", "").trim();
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!ni.isUp() || ni.isLoopback() || !ni.supportsMulticast()) {
                continue;
            }
            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                if (!(ia.getAddress() instanceof Inet4Address) || ia.getNetworkPrefixLength() < 1) {
                    continue;
                }
                if (!requested.isEmpty() && !requested.equals(ia.getAddress().getHostAddress())) {
                    continue;
                }
                int prefix = ia.getNetworkPrefixLength();
                byte[] bytes = ia.getAddress().getAddress();
                int ip = ((bytes[0] & 0xff) << 24) | ((bytes[1] & 0xff) << 16)
                        | ((bytes[2] & 0xff) << 8) | (bytes[3] & 0xff);
                int mask = prefix == 32 ? -1 : (-1 << (32 - prefix));
                int network = ip & mask;
                String cidr = ((network >>> 24) & 0xff) + "." + ((network >>> 16) & 0xff)
                        + "." + ((network >>> 8) & 0xff) + "." + (network & 0xff) + "/" + prefix;
                return new Nic(ni, cidr);
            }
        }
        return null;
    }

    static int freeTcpPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    static int freeUdpPort() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    static boolean await(BooleanSupplier condition, long timeoutMs,
                                 AtomicReference<Throwable> failure) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (failure.get() != null) {
                return false;
            }
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(50);
        }
        return condition.getAsBoolean();
    }

    static String md5Hex(byte[] data) throws Exception {
        return toHex(MessageDigest.getInstance("MD5").digest(data));
    }

    static String md5Hex(Path file) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] buffer = new byte[64 * 1024];
        try (InputStream in = Files.newInputStream(file)) {
            int n;
            while ((n = in.read(buffer)) > 0) {
                md5.update(buffer, 0, n);
            }
        }
        return toHex(md5.digest());
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
