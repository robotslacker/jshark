package com.jshark;

import com.jshark.forwarder.ForwarderFraming;
import com.jshark.forwarder.UdpBridgeNode;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * TCP→UDP 的报文封装：
 *
 * <ul>
 *   <li>默认 datagram：长度前缀的每个 frame 还原成<b>一个</b> UDP 包，边界/长度不变；</li>
 *   <li>magic 不匹配（旧/stream 客户端）：按原来的 8 KiB 字节流切片处理。</li>
 * </ul>
 *
 * <p>全部走 127.0.0.1，不需要组播/管理员权限。</p>
 */
public class ForwarderFramingTest {

    @Test
    void datagramFramesBecomeIndividualUdpPackets() throws Exception {
        int outPort = freeUdpPort();
        int listenPort = freeTcpPort();
        byte[] first = "hello".getBytes();
        byte[] second = new byte[1500];
        new Random(42).nextBytes(second);

        try (DatagramSocket receiver = new DatagramSocket(outPort)) {
            receiver.setSoTimeout(5_000);
            UdpBridgeNode node = new UdpBridgeNode("127.0.0.1", outPort, "127.0.0.0/8",
                    listenPort, List.of(), false, true,
                    LoggerFactory.getLogger("framing-test"));
            node.start();
            try (Socket tcp = new Socket()) {
                tcp.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), listenPort), 3_000);
                tcp.setSoTimeout(5_000);
                DataOutputStream out = new DataOutputStream(tcp.getOutputStream());
                out.write(ForwarderFraming.MAGIC);
                writeFrame(out, first);
                writeFrame(out, second);
                out.flush();

                byte[] a = receive(receiver, first.length);
                byte[] b = receive(receiver, second.length);
                assertArrayEquals(first, a, "第一个 frame 必须保持原长度/内容");
                assertArrayEquals(second, b, "第二个 frame 必须保持原长度/内容");
            } finally {
                node.stop();
            }
        }
    }

    @Test
    void magicMismatchFallsBackToLegacyByteStream() throws Exception {
        int outPort = freeUdpPort();
        int listenPort = freeTcpPort();
        byte[] payload = new byte[10 * 1024];
        new Random(7).nextBytes(payload);

        try (DatagramSocket receiver = new DatagramSocket(outPort)) {
            receiver.setSoTimeout(5_000);
            UdpBridgeNode node = new UdpBridgeNode("127.0.0.1", outPort, "127.0.0.0/8",
                    listenPort, List.of(), false, true,
                    LoggerFactory.getLogger("framing-test"));
            node.start();
            try (Socket tcp = new Socket()) {
                tcp.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), listenPort), 3_000);
                try (OutputStream out = tcp.getOutputStream()) {
                    out.write(payload);   // 无 magic：旧/stream 客户端
                    out.flush();
                }

                // TCP 读边界不等于写入边界：stream 模式按每次 read 切片，收齐后逐字节比对。
                java.io.ByteArrayOutputStream received = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[65535];
                while (received.size() < payload.length) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    receiver.receive(packet);
                    received.write(packet.getData(), packet.getOffset(), packet.getLength());
                }
                assertArrayEquals(payload, received.toByteArray(),
                        "stream 回退路径必须逐字节还原");
            } finally {
                node.stop();
            }
        }
    }

    private static void writeFrame(DataOutputStream out, byte[] payload) throws Exception {
        out.writeShort(payload.length);
        out.write(payload);
    }

    private static byte[] receive(DatagramSocket socket, int expectedLength) throws Exception {
        byte[] buffer = new byte[65535];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        socket.receive(packet);
        assertEquals(expectedLength, packet.getLength(), "UDP 包长度必须与原始 frame 一致");
        return Arrays.copyOfRange(packet.getData(), packet.getOffset(),
                packet.getOffset() + packet.getLength());
    }

    private static int freeUdpPort() throws Exception {
        try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static int freeTcpPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }
}
