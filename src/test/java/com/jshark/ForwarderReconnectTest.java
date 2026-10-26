package com.jshark;

import com.jshark.forwarder.PeerConfig;
import com.jshark.forwarder.UdpBridgeNode;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Peer 断线重连回归（只走 loopback TCP，不需要组播/管理员权限）。
 *
 * <h3>为什么需要它</h3>
 * <p>旧实现只在启动后的 60s 内重试连接，超时线程就退出；之后只有“有业务数据要发”时才顺带重连。
 * 于是两端启动有先后（或断线后没有流量）时，Peer 会永远停在 reconnecting/connecting。</p>
 */
public class ForwarderReconnectTest {

    @Test
    void reconnectsAfterPeerClosesWithoutAnyTraffic() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            BlockingQueue<Socket> accepted = new LinkedBlockingQueue<>();
            Thread acceptor = new Thread(() -> {
                try {
                    while (!server.isClosed()) {
                        accepted.add(server.accept());
                    }
                } catch (IOException ignored) {
                    // server closed
                }
            }, "accept-loop");
            acceptor.setDaemon(true);
            acceptor.start();

            UdpBridgeNode node = new UdpBridgeNode(
                    "224.3.0.0", 3000, "127.0.0.0/8", 0,
                    List.of(new PeerConfig("127.0.0.1", server.getLocalPort())),
                    true, false, LoggerFactory.getLogger("reconnect-test"));
            try {
                node.start();
                assertTrue(await(node::ready, 5_000), "首次连接后应进入就绪");
                assertEquals("ready", node.snapshot().peers().get(0).state());

                Socket first = accepted.poll(5, TimeUnit.SECONDS);
                assertNotNull(first, "节点应连上 loopback 监听");
                first.close();

                assertTrue(await(() -> !node.ready(), 5_000), "对端断开后应回到未就绪");
                assertEquals("reconnecting", node.snapshot().peers().get(0).state());

                // 没有任何业务流量：重连完全靠后台管理线程。
                Socket second = accepted.poll(10, TimeUnit.SECONDS);
                assertNotNull(second, "对端断开后应自动重连");
                assertTrue(await(node::ready, 5_000), "重连后应重新就绪");
                assertEquals("ready", node.snapshot().peers().get(0).state());
                second.close();
            } finally {
                node.stop();
            }
        }
    }

    @Test
    void latePeerStartIsConnectedEventually() throws Exception {
        int port;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = probe.getLocalPort();
        }

        UdpBridgeNode node = new UdpBridgeNode(
                "224.3.0.0", 3000, "127.0.0.0/8", 0,
                List.of(new PeerConfig("127.0.0.1", port)),
                true, false, LoggerFactory.getLogger("reconnect-test"));
        try {
            node.start();
            assertTrue(await(() -> !node.ready(), 2_000), "对端未启动时不应就绪");
            assertEquals("connecting", node.snapshot().peers().get(0).state(),
                    "从未连上过的 Peer 应显示 connecting，而不是 reconnecting");

            Thread.sleep(3_500); // 等它至少失败重试一次

            try (ServerSocket late = new ServerSocket(port, 5, InetAddress.getLoopbackAddress())) {
                assertTrue(await(node::ready, 10_000),
                        "对端晚启动后应自动连上（旧实现在 60s 后放弃）");
                assertEquals("ready", node.snapshot().peers().get(0).state());
            }
        } finally {
            node.stop();
        }
    }

    @Test
    void nodeWithoutOutboundDirectionIsReadyImmediately() throws Exception {
        // utot 关闭时不需要主动连 Peer；旧实现会让 working 永远为 false，UI 一直 WAITING。
        UdpBridgeNode node = new UdpBridgeNode(
                "224.3.0.0", 3000, null, 0, List.of(),
                false, false, LoggerFactory.getLogger("reconnect-test"));
        try {
            node.start();
            assertTrue(node.ready(), "没有出站方向时应直接就绪");
        } finally {
            node.stop();
        }
    }

    private static boolean await(BooleanSupplier condition, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(50);
        }
        return condition.getAsBoolean();
    }
}
