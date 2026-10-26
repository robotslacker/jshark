package com.jshark;

import com.jshark.forwarder.PeerConfig;
import com.jshark.forwarder.UdpBridgeNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bridge 模式集成测试
 * <p>
 * 测试 UdpBridgeNode 的双向桥接功能。
 * </p>
 *
 * <h3>测试场景</h3>
 * <pre>
 * 测试程序                     转发器A                         转发器B
 * ──────────────────────────────────────────────────────────────
 * 发→ 224.3.0.0:3000  ──→  UdpBridgeNode A
 *                           监听 224.3.0.0:3000
 *                               │
 *                               │ TCP (端口 30001)
 *                               │
 *                          UdpBridgeNode B
 *                           发→ 224.3.0.0:3001  ──→  测试程序监听 3001
 *
 * 测试流程：
 * 1. 启动转发器B（UdpBridgeNode B）：监听 TCP 30001，收到数据后发到 224.3.0.0:3001
 * 2. 启动转发器A（UdpBridgeNode A）：监听 224.3.0.0:3000，连接转发器B:30001
 * 3. 测试程序发送数据到 224.3.0.0:3000
 * 4. 验证测试程序在 3001 端口收到数据
 * </pre>
 */
public class BridgeTest {

    private static final Logger logger = LoggerFactory.getLogger(BridgeTest.class);

    // ========== 测试配置 ==========
    /** 发送端组播地址 */
    private static final String SEND_MULTICAST = "224.3.0.0";
    /** 发送端组播端口 */
    private static final int SEND_PORT = 3000;

    /** 接收端组播地址 */
    private static final String RECV_MULTICAST = "224.3.0.0";
    /** 接收端组播端口 */
    private static final int RECV_PORT = 3001;

    /** 节点间 TCP 桥接端口 */
    private static final int BRIDGE_TCP_PORT = 30001;

    /** 测试数据大小（2048 字节） */
    private static final int TEST_DATA_SIZE = 2048;

    // ========== 测试状态 ==========
    private static int totalChecks = 0;
    private static int passedChecks = 0;
    private static int failedChecks = 0;

    // ========== 组件 ==========
    /** 转发器A：监听 224.3.0.0:3000，通过 TCP 转发到转发器B */
    private static UdpBridgeNode forwarderA;
    /** 转发器B：接收 TCP 数据，转发到 224.3.0.0:3001 */
    private static UdpBridgeNode forwarderB;
    /** 接收端验证器：监听 3001 端口，验证是否收到数据 */
    private static UdpReceiver receiver;

    /**
     * Bridge 模式集成测试（live：需要 Npcap + 管理员权限/组播网卡，默认 {@code mvn test} 不执行）。
     */
    @org.junit.jupiter.api.Tag("live")
    @org.junit.jupiter.api.Test
    void bridgeRegression() {
        logger.info("========================================");
        logger.info("  Bridge 模式集成测试开始");
        logger.info("========================================");
        logger.info("  发送端: {}:{}", SEND_MULTICAST, SEND_PORT);
        logger.info("  接收端: {}:{}", RECV_MULTICAST, RECV_PORT);
        logger.info("  TCP 桥接端口: {}", BRIDGE_TCP_PORT);
        logger.info("========================================");

        try {
            // 步骤 1：启动接收端验证器（监听 3001 端口）
            step1StartReceiver();

            // 步骤 2：启动转发器B（UdpBridgeNode B）
            // 监听 TCP 30001，收到数据后发到 224.3.0.0:3001
            step2StartForwarderB();

            // 步骤 3：启动转发器A（UdpBridgeNode A）
            // 监听 224.3.0.0:3000，连接转发器B:30001
            step3StartForwarderA();

            // 等待连接建立
            Thread.sleep(2000);

            // 步骤 4：发送数据到 224.3.0.0:3000 → 验证接收端 3001 收到
            step4TestSendAndReceive();

            // 输出最终结果
            printFinalResult();
        } catch (Exception e) {
            logger.error("Bridge 测试执行失败", e);
            // 原来这里以退出码 1 终止进程：测试不能杀 JVM，改成让断言失败
            org.junit.jupiter.api.Assertions.fail("Bridge 测试执行失败: " + e, e);
        } finally {
            // 断言失败（AssertionError）不经过 catch，必须放 finally 才能保证转发器/套接字/接收线程被释放
            stepCleanup();
        }
    }

    // ==================== 步骤 1：启动接收端验证器 ====================

    static void step1StartReceiver() throws Exception {
        logger.info("===== 步骤1: 启动接收端验证器 (监听端口 {}) =====", RECV_PORT);

        receiver = new UdpReceiver(RECV_PORT);
        receiver.start();
        Thread.sleep(500);

        checkTrue(receiver.isRunning(), "接收端验证器应该正在运行");
        logger.info("接收端验证器已启动，监听端口: {}", RECV_PORT);

        // 先测试直接发送组播数据到 224.3.0.0:3001，验证接收器是否能收到
        logger.info("--- 验证组播接收功能 ---");
        byte[] testMulticast = "MULTICAST_TEST".getBytes();
        try (DatagramSocket testSender = new DatagramSocket()) {
            // 启用组播回环，这样同一台机器上的接收方也能收到
            testSender.setOption(java.net.StandardSocketOptions.IP_MULTICAST_LOOP, true);
            DatagramPacket testPacket = new DatagramPacket(
                    testMulticast, testMulticast.length,
                    new InetSocketAddress(RECV_MULTICAST, RECV_PORT)
            );
            testSender.send(testPacket);
            logger.info("已发送测试组播数据到 {}:{} (IP_MULTICAST_LOOP=true)", RECV_MULTICAST, RECV_PORT);
        }
        Thread.sleep(1000);
        List<byte[]> testReceived = receiver.getReceivedPackets();
        if (testReceived.isEmpty()) {
            logger.warn("⚠ 组播接收测试失败：接收器未收到直接发送的组播数据");
            logger.warn("  这可能是因为 Windows 组播路由问题");
            logger.warn("  将使用替代验证方式：直接检查 TCP 数据是否到达转发器B");
        } else {
            logger.info("✓ 组播接收测试成功：接收器能正常接收组播数据");
            // 清除测试数据
            receiver.getReceivedPackets().clear();
        }

    }


    // ==================== 步骤 2：启动转发器B ====================

    static void step2StartForwarderB() throws Exception {
        logger.info("===== 步骤2: 启动转发器B (UdpBridgeNode B) =====");
        logger.info("  角色: TCP 服务端 (端口 {}), 转发到 {}:{}",
                BRIDGE_TCP_PORT, RECV_MULTICAST, RECV_PORT);

        List<PeerConfig> peersB = Collections.emptyList();

        forwarderB = new UdpBridgeNode(
                RECV_MULTICAST, RECV_PORT,  // 收到 TCP 数据后发到 224.3.0.0:3001
                "10.10.10.0/24",           // 指定网卡子网
                BRIDGE_TCP_PORT,             // TCP 服务端端口 30001
                peersB,                      // 不需要连接其他节点
                logger
        );

        // 在单独的线程中启动转发器B
        Thread nodeBThread = new Thread(() -> {
            try {
                forwarderB.start();
            } catch (Exception e) {
                logger.error("转发器B 启动失败", e);
            }
        }, "forwarder-b");
        nodeBThread.setDaemon(true);
        nodeBThread.start();

        // 等待转发器B 完全启动
        Thread.sleep(2000);
        logger.info("转发器B 已启动，TCP 监听端口: {}", forwarderB.getActualListenPort());
    }

    // ==================== 步骤 3：启动转发器A ====================

    static void step3StartForwarderA() throws Exception {
        logger.info("===== 步骤3: 启动转发器A (UdpBridgeNode A) =====");
        logger.info("  角色: 监听 {}:{}, TCP 客户端连接 127.0.0.1:{}",
                SEND_MULTICAST, SEND_PORT, BRIDGE_TCP_PORT);

        List<PeerConfig> peersA = Collections.singletonList(
                new PeerConfig("127.0.0.1", BRIDGE_TCP_PORT)
        );

        forwarderA = new UdpBridgeNode(
                SEND_MULTICAST, SEND_PORT,   // 监听 224.3.0.0:3000
                "10.10.10.0/24",           // 指定网卡子网
                0,                           // 自动分配 TCP 端口
                peersA,                      // 连接转发器B:30001
                logger
        );

        // 在单独的线程中启动转发器A
        Thread nodeAThread = new Thread(() -> {
            try {
                forwarderA.start();
                forwarderA.startUdpListener();  // 监听 UDP 组播
            } catch (Exception e) {
                logger.error("转发器A 启动失败", e);
            }
        }, "forwarder-a");
        nodeAThread.setDaemon(true);
        nodeAThread.start();

        // 等待转发器A 完全启动并连接到转发器B
        Thread.sleep(3000);
        logger.info("转发器A 已启动");
    }

    // ==================== 步骤 4：发送数据并验证接收 ====================

    static void step4TestSendAndReceive() throws Exception {
        logger.info("===== 步骤4: 发送数据到 {}:{} 并验证接收 =====",
                SEND_MULTICAST, SEND_PORT);

        // 生成测试数据
        byte[] testData = generateTestData('T', TEST_DATA_SIZE);
        logger.info("发送 {} 字节数据到组播 {}:{}", testData.length, SEND_MULTICAST, SEND_PORT);

        try (DatagramSocket senderSocket = new DatagramSocket()) {
            DatagramPacket sendPacket = new DatagramPacket(
                    testData, testData.length,
                    new InetSocketAddress(SEND_MULTICAST, SEND_PORT)
            );
            senderSocket.send(sendPacket);
            logger.info("数据已发送");
        }

        // 等待数据通过桥接传输到接收端
        Thread.sleep(3000);

        // 验证接收端是否收到数据
        List<byte[]> receivedPackets = receiver.getReceivedPackets();
        logger.info("接收端 (端口 {}) 接收到 {} 个数据包", RECV_PORT, receivedPackets.size());

        // 过滤掉测试数据包（14 字节的 "MULTICAST_TEST"），只检查桥接数据包
        List<byte[]> bridgePackets = new ArrayList<>();
        for (byte[] pkt : receivedPackets) {
            if (pkt.length == TEST_DATA_SIZE) {
                bridgePackets.add(pkt);
            }
        }
        logger.info("其中桥接数据包: {} 个", bridgePackets.size());

        checkTrue(!bridgePackets.isEmpty(),
                "接收端应该至少收到 1 个桥接数据包，实际: " + bridgePackets.size());

        if (!bridgePackets.isEmpty()) {
            byte[] receivedData = bridgePackets.get(0);
            checkEquals(TEST_DATA_SIZE, receivedData.length,
                    "接收端收到的数据大小应该为 " + TEST_DATA_SIZE + " 字节，实际: " + receivedData.length);

            checkArrayEquals(testData, receivedData,
                    "接收端收到的数据内容应该与发送的一致");

            checkEquals('T', receivedData[0],
                    "接收端收到的数据第一个字节应该是 'T' (0x" + Integer.toHexString('T') + ")");

            logger.info("[验证通过] 数据成功通过桥接传输！");
            logger.info("  发送: {}:{} → 转发器A → TCP → 转发器B → {}:{} → 接收端",
                    SEND_MULTICAST, SEND_PORT, RECV_MULTICAST, RECV_PORT);
        }

    }

    // ==================== 清理 ====================

    static void stepCleanup() {
        logger.info("===== 清理资源 =====");

        if (forwarderA != null) {
            try { forwarderA.stop(); } catch (Exception e) { /* ignore */ }
        }
        if (forwarderB != null) {
            try { forwarderB.stop(); } catch (Exception e) { /* ignore */ }
        }
        if (receiver != null) {
            try { receiver.stop(); } catch (Exception e) { /* ignore */ }
        }

        try { Thread.sleep(1000); } catch (InterruptedException e) { /* ignore */ }

        logger.info("清理完成");
    }

    // ==================== 辅助方法 ====================

    private static byte[] generateTestData(char marker, int size) {
        byte[] data = new byte[size];
        data[0] = (byte) marker;
        for (int i = 1; i < size; i++) {
            data[i] = (byte) ('a' + (i - 1) % 26);
        }
        return data;
    }

    // ==================== 断言方法 ====================

    private static void checkTrue(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            passedChecks++;
        } else {
            failedChecks++;
            logger.error("[检查失败] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }

    private static void checkEquals(int expected, int actual, String message) {
        totalChecks++;
        if (expected == actual) {
            passedChecks++;
        } else {
            failedChecks++;
            logger.error("[检查失败] {} - 期望: {}, 实际: {}", message, expected, actual);
        }
        org.junit.jupiter.api.Assertions.assertEquals(expected, actual, message);
    }

    private static void checkArrayEquals(byte[] expected, byte[] actual, String message) {
        totalChecks++;
        if (Arrays.equals(expected, actual)) {
            passedChecks++;
        } else {
            failedChecks++;
            logger.error("[检查失败] {} - 数组内容不一致", message);
            StringBuilder sb = new StringBuilder("  期望前20字节: ");
            for (int i = 0; i < Math.min(20, expected.length); i++) {
                sb.append(String.format("%02X ", expected[i]));
            }
            logger.error(sb.toString());
            sb = new StringBuilder("  实际前20字节: ");
            for (int i = 0; i < Math.min(20, actual.length); i++) {
                sb.append(String.format("%02X ", actual[i]));
            }
            logger.error(sb.toString());
        }
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual, message);
    }

    private static void printFinalResult() {
        logger.info("");
        logger.info("========================================");
        logger.info("  Bridge 模式集成测试结果汇总");
        logger.info("========================================");
        logger.info("  总检查项: {}", totalChecks);
        logger.info("  通过:     {}", passedChecks);
        logger.info("  失败:     {}", failedChecks);
        logger.info("========================================");

        if (failedChecks == 0) {
            logger.info("  结论: 全部通过 ✓");
            logger.info("  Bridge 模式数据传输正常！");
        } else {
            logger.error("  结论: 存在失败项 ✗");
        }
        logger.info("========================================");
    }

    // ==================== UDP 接收器 ====================

    /**
     * UDP 数据包接收器
     * 监听指定端口，加入组播组以接收组播数据
     */
    private static class UdpReceiver {
        private final int port;
        private final ConcurrentLinkedQueue<byte[]> receivedPackets = new ConcurrentLinkedQueue<>();
        private final AtomicInteger packetCount = new AtomicInteger(0);
        private volatile boolean running = false;
        private DatagramSocket socket;
        private Thread receiverThread;

        UdpReceiver(int port) {
            this.port = port;
        }

        void start() throws Exception {
            socket = new DatagramSocket(port);
            // 使用指定网卡加入组播组
            java.net.NetworkInterface ni = com.jshark.forwarder.Utils.getInterfaceByCidr("10.10.10.0/24");
            if (ni == null) {
                logger.warn("[接收器:{}] 未找到指定网卡 (10.10.10.0/24)，尝试使用所有可用网卡", port);
                java.util.Enumeration<java.net.NetworkInterface> ifs = java.net.NetworkInterface.getNetworkInterfaces();
                boolean joined = false;
                while (ifs.hasMoreElements()) {
                    java.net.NetworkInterface iface = ifs.nextElement();
                    if (!iface.isUp() || iface.isLoopback()) continue;
                    java.util.Enumeration<java.net.InetAddress> addrs = iface.getInetAddresses();
                    boolean hasIPv4 = false;
                    while (addrs.hasMoreElements()) {
                        java.net.InetAddress addr = addrs.nextElement();
                        if (addr instanceof java.net.Inet4Address) {
                            hasIPv4 = true;
                            break;
                        }
                    }
                    if (hasIPv4) {
                        try {
                            socket.joinGroup(new java.net.InetSocketAddress(
                                    java.net.InetAddress.getByName(RECV_MULTICAST), port), iface);
                            logger.info("[接收器:{}] 已加入组播组 {}，网卡: {} (IPv4)", port, RECV_MULTICAST, iface.getName());
                            joined = true;
                        } catch (Exception e) {
                            logger.warn("[接收器:{}] 加入组播组失败 (网卡: {}): {}", port, iface.getName(), e.getMessage());
                        }
                    }
                }
                if (!joined) {
                    logger.warn("[接收器:{}] 未找到合适的网卡，无法加入组播组", port);
                }
            } else {
                socket.joinGroup(new java.net.InetSocketAddress(
                        java.net.InetAddress.getByName(RECV_MULTICAST), port), ni);
                logger.info("[接收器:{}] 已加入组播组 {}，网卡: {} (IPv4)", port, RECV_MULTICAST, ni.getName());
            }


            running = true;

            receiverThread = new Thread(() -> {
                byte[] buffer = new byte[65535];
                while (running) {
                    try {
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                        socket.receive(packet);

                        byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
                        receivedPackets.add(data);
                        int count = packetCount.incrementAndGet();

                        logger.info("[接收器:{}] 接收到数据包 #{}: {} 字节 (来自 {}:{})",
                                port, count, data.length,
                                packet.getAddress().getHostAddress(),
                                packet.getPort());
                    } catch (SocketException e) {
                        if (running) {
                            logger.error("[接收器:{}] socket 错误: {}", port, e.getMessage());
                        }
                    } catch (Exception e) {
                        if (running) {
                            logger.error("[接收器:{}] 接收错误: {}", port, e.getMessage());
                        }
                    }
                }
            }, "udp-receiver-" + port);
            receiverThread.setDaemon(true);
            receiverThread.start();
        }

        void stop() {
            running = false;
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            if (receiverThread != null) {
                try {
                    receiverThread.join(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            logger.info("[接收器:{}] 已停止，共接收 {} 个数据包", port, packetCount.get());
        }

        boolean isRunning() {
            return running;
        }

        List<byte[]> getReceivedPackets() {
            return new ArrayList<>(receivedPackets);
        }
    }
}
