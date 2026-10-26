package com.jshark.parser;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.namednumber.IpNumber;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 入库队列的"容量护栏"与"丢包账目"回归。
 *
 * <p>为什么值得专门测：这一层的风险不是崩，而是<b>账目不闭合</b>——
 * 包确实丢了，但 manifest 和运行报告都显示"零丢弃"。历史上真实出现过：
 * {@code droppedAtShutdownBudget} 只有声明、从未赋值，于是 manifest 恒报
 * {@code queueAtShutdown=0}；{@code queueFull} 则干脆不在 manifest 里。
 * 因此这里锁定两件事：</p>
 *
 * <ol>
 *   <li>容量系统属性不得把有界队列放大成事实无界（历史上正是这样把堆吃光的）；</li>
 *   <li>"投递的包 == 入库 + 各条丢弃渠道"，任何一条渠道漏计都会让这个恒等式失败。</li>
 * </ol>
 */
class DbQueueAccountingTest {

    @AfterEach
    void clearProperty() {
        System.clearProperty(PacketDBEventHandler.QUEUE_CAPACITY_PROPERTY);
    }

    @Test
    @DisplayName("容量属性超上界：拒绝放大，回退默认（不允许把有界队列变成无界）")
    void oversizedCapacityPropertyFallsBackToDefault() {
        System.setProperty(PacketDBEventHandler.QUEUE_CAPACITY_PROPERTY, "2000000000");
        PacketDBEventHandler h = new PacketDBEventHandler();
        try {
            assertEquals(PacketDBEventHandler.DEFAULT_QUEUE_CAPACITY, h.queueCapacity(),
                    "超出上界的容量必须回退默认，否则队列事实上无界，堆会被吃光");
        } finally {
            h.shutdown();
        }
    }

    @Test
    @DisplayName("容量属性合法值：如实生效")
    void validCapacityPropertyIsHonoured() {
        System.setProperty(PacketDBEventHandler.QUEUE_CAPACITY_PROPERTY, "4096");
        PacketDBEventHandler h = new PacketDBEventHandler();
        try {
            assertEquals(4096, h.queueCapacity());
        } finally {
            h.shutdown();
        }
    }

    @Test
    @DisplayName("非法容量属性：回退默认且不抛异常")
    void invalidCapacityPropertyFallsBack() {
        System.setProperty(PacketDBEventHandler.QUEUE_CAPACITY_PROPERTY, "not-a-number");
        PacketDBEventHandler h = new PacketDBEventHandler();
        try {
            assertEquals(PacketDBEventHandler.DEFAULT_QUEUE_CAPACITY, h.queueCapacity());
        } finally {
            h.shutdown();
        }
    }

    @Test
    @DisplayName("丢包账目恒等式：投递 == 入库 + 队列满丢弃 + 停机遗弃 + 提交失败")
    void dropAccountingBalances() {
        final int total = 20;
        // 容量 1：绝大多数包会因队列满被丢弃，剩下的在停机时因无法提交而遗弃
        // （没有 DB 连接，提交必然失败——这正是要覆盖的失败路径）。
        PacketDBEventHandler h = new PacketDBEventHandler(1);
        for (int i = 0; i < total; i++) {
            h.addPacket(dummyPacket(), Collections.emptyMap());
        }

        assertTrue(h.droppedQueueFull() > 0, "容量 1 时应当有大量包因队列满被丢弃并计数（实际 "
                + h.droppedQueueFull() + "）");

        h.shutdown();

        long committed = h.committedPackets();
        long queueFull = h.droppedQueueFull();
        long abandoned = h.abandonedAtShutdown();
        long failedCommit = h.failedToCommit();
        assertEquals(total, committed + queueFull + abandoned + failedCommit,
                "账目必须闭合：committed=" + committed + ", queueFull=" + queueFull
                        + ", abandonedAtShutdown=" + abandoned + ", failedToCommit=" + failedCommit);
        assertTrue(abandoned > 0,
                "提交失败/预算用尽后留在队列里的包必须被计入 abandonedAtShutdown，"
                        + "否则 manifest 会一边写 queueAtShutdown=0 一边丢数据");
    }

    @Test
    @DisplayName("卷关闭后到达的包被计数（不再是静默丢弃），关闭后再记录也不抛 NPE")
    void packetsAfterVolumeCloseAreCountedAndCloseIsSafe() {
        PacketLogger logger = new PacketLogger();
        try {
            assertEquals(0, logger.droppedAfterVolumeClose());

            // 关闭当前卷（没有 DB 连接，shutdown 内部走空队列的快速路径）
            logger.flushAndCloseLogDb();

            // 屏障超时后掉队的 worker 仍会交付包：以前这里是静默跳过，必须变成计数
            logger.logPacket(dummyPacket(), false);
            logger.logPacket(dummyPacket(), false);
            assertEquals(2, logger.droppedAfterVolumeClose(),
                    "卷已关闭后到达的包必须计入 droppedAfterVolumeClose");

            // close() 之后再调用不得抛 NPE（曾因 logDb 未清空、packetHandler 已置空而 NPE，
            // 且 NPE 会被解析 worker 的 catch(Throwable) 吞掉 —— 表现成丢包且不计数）
            logger.close();
            assertDoesNotThrow(() -> logger.logPacket(dummyPacket(), false));
        } finally {
            logger.close();
        }
    }

    @Test
    @DisplayName("close() 之后到达的包被计数（未分卷模式的静默丢弃路径）")
    void packetsAfterCloseAreCounted() throws Exception {
        Path dir = Files.createTempDirectory("jshark-after-close");
        Path db = dir.resolve("after-close.duckdb");
        try {
            // 关键前置：本次运行必须"确实启用过 logdb"。未启用时不入库是预期行为，不该计数。
            try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + db)) {
                PacketLogger logger = new PacketLogger();
                try {
                    logger.setLogDb(conn);
                    assertEquals(0, logger.droppedAfterClose(), "尚未收尾时不应有该渠道的丢弃");

                    // 未分卷模式走 close()（分卷模式走 flushAndCloseLogDb()，它不置 closed）
                    logger.close();

                    // 卡死的解析 worker 之后才交付：早期实现既不计数、也没有任何日志，
                    // 只剩 worker join 超时那行 ERROR，丢了多少包完全不可查。
                    logger.logPacket(dummyPacket(), false);
                    logger.logPacket(dummyPacket(), false);
                    assertEquals(2, logger.droppedAfterClose(),
                            "close() 之后到达的包必须计数，否则这条路径上的丢包不可查");

                    // 反复记录不得抛异常（曾因 logDb 未清空、packetHandler 已置空而 NPE，
                    // 且 NPE 会被解析 worker 的 catch(Throwable) 吞掉 —— 表现成丢包且不计数）
                    assertDoesNotThrow(() -> logger.logPacket(dummyPacket(), false));
                    assertEquals(3, logger.droppedAfterClose(), "反复记录必须持续计数");
                } finally {
                    logger.close();
                }
            }

            // 反例：从未启用过 logdb（只写 pcap）时，close() 之后不入库是预期行为。
            // 那些包的帧早已由抓包线程写进 pcap 文件，把它算成丢包会污染对账。
            PacketLogger pcapOnly = new PacketLogger();
            try {
                pcapOnly.close();
                pcapOnly.logPacket(dummyPacket(), false);
                assertEquals(0, pcapOnly.droppedAfterClose(),
                        "未启用 logdb 时「不入库」是预期行为，不得计入丢包");
            } finally {
                pcapOnly.close();
            }
        } finally {
            try (var s = Files.walk(dir)) {
                s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignored) {
                        // 清理失败不影响结论
                    }
                });
            }
        }
    }

    // ==================== 工具 ====================

    private static PacketParser.ParsedPacket dummyPacket() {
        Map<String, Object> info = Collections.emptyMap();
        return new PacketParser.ParsedPacket(
                1L, Instant.now(), 64,
                "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66",
                "10.0.0.1", "10.0.0.2",
                IpNumber.UDP, 3000, 4000,
                info, "test",
                new byte[]{1, 2, 3}, new byte[]{9, 9}, 64, 64,
                CaptureKind.WIRE_FRAME);
    }
}
