package com.jshark;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 一次性基准（**不**是 JUnit）：纯 127.0.0.1 UDP 发送/接收，用来判断
 * “本机 UDP 路径”本身的上限，和转发器链路做对照。
 *
 * <pre>
 * java -Ddatagram=1400 -Dbytes=536870912 -cp ... com.jshark.UdpLoopbackBench
 * </pre>
 */
public final class UdpLoopbackBench {

    public static void main(String[] args) throws Exception {
        int datagram = Integer.getInteger("datagram", 1400);
        long total = Long.getLong("bytes", 512L * 1024 * 1024);
        int window = Integer.getInteger("window", 4 * 1024 * 1024);

        try (DatagramSocket rx = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0))) {
            rx.setReceiveBufferSize(8 * 1024 * 1024);
            int port = rx.getLocalPort();
            AtomicLong received = new AtomicLong();
            AtomicBoolean running = new AtomicBoolean(true);

            Thread receiver = new Thread(() -> {
                byte[] buf = new byte[datagram + 256];
                while (running.get()) {
                    try {
                        DatagramPacket packet = new DatagramPacket(buf, buf.length);
                        rx.receive(packet);
                        received.addAndGet(packet.getLength());
                    } catch (SocketException e) {
                        return;
                    } catch (Exception e) {
                        return;
                    }
                }
            }, "udp-bench-rx");
            receiver.setDaemon(true);
            receiver.start();

            try (DatagramSocket tx = new DatagramSocket()) {
                tx.setSendBufferSize(4 * 1024 * 1024);
                byte[] data = new byte[datagram];
                InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);

                long started = System.nanoTime();
                long sent = 0;
                while (sent < total) {
                    tx.send(new DatagramPacket(data, data.length, target));
                    sent += datagram;
                    while (sent - received.get() > window) {
                        Thread.sleep(1);
                    }
                }
                long deadline = System.currentTimeMillis() + 10_000;
                while (received.get() < sent && System.currentTimeMillis() < deadline) {
                    Thread.sleep(1);
                }
                long elapsedNanos = Math.max(1, System.nanoTime() - started);
                double secs = elapsedNanos / 1e9;
                long got = received.get();
                System.out.printf(
                        "[udp-bench] datagram=%d window=%dKB sent=%.1f MiB received=%.1f MiB "
                                + "in %.3fs -> %.1f MiB/s, drop=%.2f%%%n",
                        datagram, window / 1024, sent / 1048576.0, got / 1048576.0, secs,
                        got / 1048576.0 / secs,
                        sent == 0 ? 0 : 100.0 * (sent - got) / sent);
            } finally {
                running.set(false);
                rx.close();
                receiver.join(1000);
            }
        }
    }
}
