package com.jshark;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.jshark.forwarder.PeerConfig;
import com.jshark.forwarder.UdpBridgeNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 一次性可靠性压测（**不**属于 {@code mvn test} 回归）：
 * 两个 {@link UdpBridgeNode} 常驻，连续发送 N 份随机文件（默认 20 × 50 MiB），
 * 每份都校验 MD5 与落盘文件，任何一次失败立即以非 0 退出。
 *
 * <p>启动方式：{@code pwsh tools/forwarder-soak.ps1 -Iterations 20}；
 * 也可以直接给 main 传 {@code -Diterations=... -Dsize=...}。</p>
 */
public final class ForwarderSoak {

    private static final Logger logger = LoggerFactory.getLogger(ForwarderSoak.class);

    public static void main(String[] args) throws Exception {
        // 发送节流/包长参数：-Dpace=64 -Dsleep=1 -Ddatagram=1400；pace<=0 表示不节流。
        System.setProperty("jshark.forwarder.e2e.pace", System.getProperty("pace", "64"));
        System.setProperty("jshark.forwarder.e2e.sleep", System.getProperty("sleep", "1"));
        System.setProperty("jshark.forwarder.e2e.datagram", System.getProperty("datagram", "1400"));
        System.setProperty("jshark.forwarder.e2e.light", System.getProperty("light", "false"));
        boolean light = Boolean.getBoolean("jshark.forwarder.e2e.light");

        int iterations = Integer.getInteger("iterations", 20);
        int size = Integer.getInteger("size", 50 * 1024 * 1024);
        if (iterations < 1 || size < 1) {
            System.err.println("iterations/size must be positive");
            System.exit(2);
        }

        // 压测只关心 OK/FAILED，把 bridge 的 INFO 日志压掉。
        if (LoggerFactory.getILoggerFactory() instanceof LoggerContext context) {
            context.getLogger(Logger.ROOT_LOGGER_NAME).setLevel(Level.WARN);
        }

        ForwarderFileEndToEndTest.Nic nic = ForwarderFileEndToEndTest.pickMulticastNic();
        if (nic == null) {
            System.err.println("[soak] no multicast-capable IPv4 NIC; skipped.");
            System.exit(2);
        }

        int bridgePort = ForwarderFileEndToEndTest.freeTcpPort();
        int outPort = ForwarderFileEndToEndTest.freeUdpPort();
        int multicastPort = 43000 + new Random().nextInt(2000);

        System.out.printf("[soak] %d x %d bytes (%.2f GiB), nic=%s cidr=%s group=%s:%d tcp=%d outUdp=%d%n",
                iterations, size, iterations * (double) size / 1024 / 1024 / 1024,
                nic.ni().getName(), nic.cidr(), ForwarderFileEndToEndTest.GROUP, multicastPort,
                bridgePort, outPort);
        System.out.printf("[soak] pace=%s packets/sleep, sleep=%sms, datagram=%s bytes, light=%s%n",
                System.getProperty("jshark.forwarder.e2e.pace"),
                System.getProperty("jshark.forwarder.e2e.sleep"),
                System.getProperty("jshark.forwarder.e2e.datagram"), light);

        UdpBridgeNode a = null;
        UdpBridgeNode b = null;
        Thread aThread = null;
        try {
            // B：TCP → 127.0.0.1:outPort（只做 TCP→UDP）
            b = new UdpBridgeNode("127.0.0.1", outPort, nic.cidr(), bridgePort,
                    List.of(), false, true, logger);
            b.start();

            // A：组播 → TCP(peer=B)（只做 UDP→TCP）
            a = new UdpBridgeNode(ForwarderFileEndToEndTest.GROUP, multicastPort, nic.cidr(), 0,
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
            }, "soak-a");
            aThread.setDaemon(true);
            aThread.start();

            if (!ForwarderFileEndToEndTest.await(a::ready, 10_000, aFailure)) {
                System.err.println("[soak] forwarder A failed to become ready: " + aFailure.get());
                System.exit(1);
            }
            Thread.sleep(1_000); // 等 A 加入组播组

            byte[] payload = new byte[size];
            long startedAll = System.currentTimeMillis();
            com.sun.management.OperatingSystemMXBean os =
                    (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            long cpuStartNanos = os.getProcessCpuTime();
            double loadSum = 0;
            int loadSamples = 0;
            long totalBytes = 0;

            for (int i = 1; i <= iterations; i++) {
                new Random(0x5EEDL + i).nextBytes(payload);
                String sourceMd5 = light ? null : ForwarderFileEndToEndTest.md5Hex(payload);

                Path file = Files.createTempFile("jshark-soak-", ".bin");
                ForwarderFileEndToEndTest.Receiver receiver =
                        new ForwarderFileEndToEndTest.Receiver(outPort, file);
                receiver.start();

                long started = System.currentTimeMillis();
                ForwarderFileEndToEndTest.sendStream(nic, payload, multicastPort);
                boolean ok = receiver.await(180_000);
                long elapsed = Math.max(1, System.currentTimeMillis() - started);

                if (!ok) {
                    System.err.printf("[soak] iteration %d/%d FAILED: %s%n",
                            i, iterations, receiver.describe());
                    receiver.close();
                    Files.deleteIfExists(file);
                    System.exit(1);
                }

                String receivedMd5 = light ? null : receiver.md5Hex();
                long fileSize = light ? size : Files.size(file);
                String fileMd5 = light ? null : ForwarderFileEndToEndTest.md5Hex(file);
                receiver.close();
                Files.deleteIfExists(file);

                if (receiver.payloadBytes() != size
                        || (!light && (!sourceMd5.equals(receivedMd5)
                        || fileSize != size || !sourceMd5.equals(fileMd5)))) {
                    System.err.printf("[soak] iteration %d/%d CORRUPT: bytes=%d/%d "
                                    + "streamMd5=%s fileMd5=%s sourceMd5=%s fileSize=%d%n",
                            i, iterations, receiver.payloadBytes(), size,
                            receivedMd5, fileMd5, sourceMd5, fileSize);
                    System.exit(1);
                }

                totalBytes += size;
                double load = os.getCpuLoad();
                if (load >= 0) {
                    loadSum += load;
                    loadSamples++;
                }
                System.out.printf("[soak] %2d/%d OK  %d bytes  %d ms  %.1f MiB/s  md5=%s%n",
                        i, iterations, size, elapsed, size / 1024.0 / 1024.0 / (elapsed / 1000.0),
                        sourceMd5);
            }

            long elapsedAll = Math.max(1, System.currentTimeMillis() - startedAll);
            System.out.printf("[soak] ALL OK: %d iterations, %.2f GiB in %d ms (%.1f MiB/s)%n",
                    iterations, totalBytes / 1024.0 / 1024.0 / 1024.0, elapsedAll,
                    totalBytes / 1024.0 / 1024.0 / (elapsedAll / 1000.0));
            long cpuNanos = os.getProcessCpuTime() - cpuStartNanos;
            if (cpuStartNanos > 0 && cpuNanos > 0) {
                double wallSec = elapsedAll / 1000.0;
                double cores = cpuNanos / 1e9 / wallSec;
                int processors = Runtime.getRuntime().availableProcessors();
                System.out.printf("[soak] CPU: %.2f cores busy (%.1f%% of %d logical CPUs), "
                                + "avg system load %.1f%%%n",
                        cores, 100.0 * cores / processors, processors,
                        loadSamples == 0 ? -1 : 100.0 * loadSum / loadSamples);
            }
        } catch (Throwable t) {
            System.err.println("[soak] aborted: " + t);
            t.printStackTrace(System.err);
            System.exit(1);
        } finally {
            if (a != null) {
                a.stop();
            }
            if (b != null) {
                b.stop();
            }
            if (aThread != null) {
                aThread.join(5_000);
            }
        }
        System.exit(0);
    }
}
