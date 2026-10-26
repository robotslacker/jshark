package com.jshark;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.StandardSocketOptions;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 一次性基准（**不**是 JUnit）：纯组播发送/接收（同一个网卡），用来把
 * “组播/网卡上限”与“转发器链路上限”分开。
 */
public final class MulticastLoopbackBench {

    public static void main(String[] args) throws Exception {
        ForwarderFileEndToEndTest.Nic nic = ForwarderFileEndToEndTest.pickMulticastNic();
        if (nic == null) {
            System.err.println("no multicast NIC");
            System.exit(2);
        }
        int datagram = Integer.getInteger("datagram", 1400);
        long total = Long.getLong("bytes", 512L * 1024 * 1024);
        int window = Integer.getInteger("window", 4 * 1024 * 1024);
        int port = 44000 + new Random().nextInt(1000);
        InetAddress group = InetAddress.getByName(ForwarderFileEndToEndTest.GROUP);

        MulticastSocket rx = new MulticastSocket(port);
        rx.setReuseAddress(true);
        try {
            rx.setNetworkInterface(nic.ni());
        } catch (java.net.SocketException e) {
            System.err.println("[mcast-bench] rx setNetworkInterface failed ("
                    + e.getMessage() + "); using OS multicast route");
        }
        rx.setReceiveBufferSize(8 * 1024 * 1024);
        rx.joinGroup(new InetSocketAddress(group, port), nic.ni());
        AtomicLong received = new AtomicLong();
        AtomicBoolean running = new AtomicBoolean(true);

        Thread receiver = new Thread(() -> {
            byte[] buf = new byte[datagram + 256];
            while (running.get()) {
                try {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    rx.receive(packet);
                    received.addAndGet(packet.getLength());
                } catch (Exception e) {
                    return;
                }
            }
        }, "mcast-bench-rx");
        receiver.setDaemon(true);
        receiver.start();

        try (MulticastSocket tx = new MulticastSocket()) {
            try {
                tx.setNetworkInterface(nic.ni());
            } catch (java.net.SocketException e) {
                System.err.println("[mcast-bench] setNetworkInterface failed ("
                        + e.getMessage() + "); using OS multicast route");
            }
            tx.setTimeToLive(1);
            tx.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, true);
            tx.setSendBufferSize(4 * 1024 * 1024);
            byte[] data = new byte[datagram];
            InetSocketAddress target = new InetSocketAddress(group, port);

            long started = System.nanoTime();
            long sent = 0;
            long lastReceived = 0;
            long lastProgress = System.currentTimeMillis();
            while (sent < total) {
                tx.send(new DatagramPacket(data, data.length, target));
                sent += datagram;
                while (sent - received.get() > window) {
                    if (received.get() > lastReceived) {
                        lastReceived = received.get();
                        lastProgress = System.currentTimeMillis();
                    } else if (System.currentTimeMillis() - lastProgress > 5_000) {
                        throw new IllegalStateException("no multicast progress: sent="
                                + sent + " received=" + received.get()
                                + " (interface/route cannot deliver multicast)");
                    }
                    Thread.sleep(1);
                }
            }
            long deadline = System.currentTimeMillis() + 10_000;
            while (received.get() < sent && System.currentTimeMillis() < deadline) {
                Thread.sleep(1);
            }
            double secs = Math.max(1, System.nanoTime() - started) / 1e9;
            long got = received.get();
            System.out.printf(
                    "[mcast-bench] nic=%s datagram=%d sent=%.1f MiB received=%.1f MiB "
                            + "in %.3fs -> %.1f MiB/s, drop=%.2f%%%n",
                    nic.ni().getName(), datagram, sent / 1048576.0, got / 1048576.0, secs,
                    got / 1048576.0 / secs, sent == 0 ? 0 : 100.0 * (sent - got) / sent);
        } finally {
            running.set(false);
            try {
                rx.leaveGroup(new InetSocketAddress(group, port), nic.ni());
            } catch (Exception ignored) {
            }
            rx.close();
            receiver.join(1000);
        }
    }
}
