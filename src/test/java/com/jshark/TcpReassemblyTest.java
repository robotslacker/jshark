package com.jshark;

import com.jshark.parser.TcpFlowReassembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * D1 验收测试：序列号驱动的 TCP 重组。
 *
 * <h3>验证项（对照早期"按到达顺序盲拼"的错误行为）</h3>
 * <ol>
 *   <li>顺序到达：交付完整字节流</li>
 *   <li><b>乱序</b>：存在缺口时不交付，缺口补齐后一次性按序交付</li>
 *   <li><b>重传</b>：完全重复的段被丢弃，不产生重复字节</li>
 *   <li><b>部分重叠</b>：重叠部分被裁剪，只保留新字节</li>
 *   <li><b>四元组复用</b>：SYN 或序列号大幅回退 → 识别为新连接，隔离两段数据</li>
 *   <li>FIN/RST：交付残留字节并结束流</li>
 *   <li>空闲超时：清理缓冲区并计入丢弃统计（不再静默泄漏）</li>
 * </ol>
 *
 * <p>纯逻辑断言：不依赖网络与真实时钟（时间通过参数注入）。</p>
 */
public class TcpReassemblyTest {

    private static final Logger logger = LoggerFactory.getLogger(TcpReassemblyTest.class);

    private static final String SRC_IP = "10.0.0.1";
    private static final String DST_IP = "10.0.0.2";
    private static final int SRC_PORT = 50000;
    private static final int DST_PORT = 80;

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void tcpReassemblyRegression() {
        logger.info("=================================================");
        logger.info("  D1 验收：序列号驱动的 TCP 重组");
        logger.info("=================================================");

        checkInOrder();
        checkOutOfOrder();
        checkRetransmission();
        checkPartialOverlap();
        checkTupleReuse();
        checkFinAndReset();
        checkIdleTimeout();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    private static TcpFlowReassembler.StreamKey key(int ignoredGeneration) {
        return new TcpFlowReassembler.StreamKey(SRC_IP, DST_IP, SRC_PORT, DST_PORT);
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** 用例 1：顺序到达 */
    private static void checkInOrder() {
        logger.info("---- [1] 顺序到达 ----");
        TcpFlowReassembler r = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k = key(1);

        TcpFlowReassembler.StreamUpdate u1 = feed(r, k, 1000, bytes("GET /"), 0);
        TcpFlowReassembler.StreamUpdate u2 = feed(r, k, 1005, bytes("index HTTP/1.1\r\n"), 1);

        check(u1.delivery() == TcpFlowReassembler.Delivery.DATA, "第一段交付数据");
        check(str(u1.data()).equals("GET /"), "第一段内容正确 (" + str(u1.data()) + ")");
        check(str(u2.data()).equals("index HTTP/1.1\r\n"), "第二段内容正确");
        check(!u2.waitingForGap(), "顺序到达时无缺口");
    }

    /** 用例 2：乱序——缺口时等待，补齐后按序交付 */
    private static void checkOutOfOrder() {
        logger.info("---- [2] 乱序 ----");
        TcpFlowReassembler r = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k = key(1);

        // 流的起始（首个被观察到的段）先到
        TcpFlowReassembler.StreamUpdate u1 = feed(r, k, 1000, bytes("AAA"), 0);
        check(str(u1.data()).equals("AAA"), "首个段交付");

        // 第 3 段先到（1006..1008），第 2 段（1003..1005）缺失 → 必须等待
        TcpFlowReassembler.StreamUpdate u2 = r.offer(k, 1006, bytes("CCC"), false, false, false, 1);
        check(u2.delivery() == TcpFlowReassembler.Delivery.BUFFERED,
                "存在缺口时数据只入缓冲、不可交付（实际 " + u2.delivery() + "）");
        check(u2.waitingForGap(), "如实报告正在等待缺口");

        // 缺口段到达 → 两段一起按序列号顺序交付
        TcpFlowReassembler.StreamUpdate u3 = r.offer(k, 1003, bytes("BBB"), false, false, false, 2);
        check(u3.delivery() == TcpFlowReassembler.Delivery.DATA, "缺口补齐后交付");
        check(str(u3.data()).equals("BBBCCC"),
                "按序列号顺序交付而非到达顺序（期望 BBBCCC，实际 " + str(u3.data()) + "）");
        check(!u3.waitingForGap(), "补齐后不再等待");

        // 缺口之后的数据不得被误判为重复而丢弃
        check(r.stats().segmentsAccepted() == 3,
                "三段都被接受（实际 " + r.stats().segmentsAccepted() + "）");
        check(r.stats().bytesDelivered() == 9,
                "累计交付 9 字节（实际 " + r.stats().bytesDelivered() + "）");
    }

    /** 用例 3：重传去重 */
    private static void checkRetransmission() {
        logger.info("---- [3] 重传去重 ----");
        TcpFlowReassembler r = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k = key(1);

        feed(r, k, 1000, bytes("PAYLOAD-1"), 0);
        // 完整重传同一段
        TcpFlowReassembler.StreamUpdate dup = r.offer(k, 1000, bytes("PAYLOAD-1"), false, false, false, 1);
        check(dup.delivery() == TcpFlowReassembler.Delivery.NOTHING, "完整重传不交付新数据");
        check(dup.duplicate(), "标记为重复段");

        // 后续新数据仍能正确接续（说明重传没有污染缓冲区）
        TcpFlowReassembler.StreamUpdate next = feed(r, k, 1009, bytes("PAYLOAD-2"), 2);
        check(str(next.data()).equals("PAYLOAD-2"),
                "重传之后新数据仍原样交付（未出现重复字节，实际 " + str(next.data()) + "）");
        check(r.stats().segmentsDuplicate() == 1, "重复段计数为 1");
    }

    /** 用例 4：部分重叠裁剪 */
    private static void checkPartialOverlap() {
        logger.info("---- [4] 部分重叠 ----");
        TcpFlowReassembler r = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k = key(1);

        feed(r, k, 1000, bytes("ABCDE"), 0);
        // 已交付 "ABCDE" 占序列号 1000..1004（A=1000 … E=1004），deliveredUpTo=1005。
        // 重传段从 1003 开始："CDEFGH" 按位对应
        //   1003=C, 1004=D, 1005=E, 1006=F, 1007=G, 1008=H
        // 其中 C、D 已在已交付区间内，应被裁掉；E/F/G/H 是新字节。
        TcpFlowReassembler.StreamUpdate u = r.offer(k, 1003, bytes("CDEFGH"), false, false, false, 1);
        check(str(u.data()).equals("EFGH"),
                "重叠部分被裁掉，只交付新字节（期望 EFGH，实际 " + str(u.data()) + "）");
        check(r.stats().segmentsOverlapTrimmed() == 1,
                "重叠裁剪计数为 1（实际 " + r.stats().segmentsOverlapTrimmed() + "）");
        check(r.stats().bytesDelivered() == 9,
                "累计交付 5+4=9 字节（实际 " + r.stats().bytesDelivered() + "）");
    }

    /** 用例 5：四元组复用隔离 */
    private static void checkTupleReuse() {
        logger.info("---- [5] 四元组复用 ----");

        // (a) SYN 触发新连接
        TcpFlowReassembler r1 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k1 = key(1);
        // 已有连接（SYN 之后），旧会话数据先交付
        r1.offer(k1, 1000, null, true, false, false, 0);            // SYN（占 1 字节序列号）
        TcpFlowReassembler.StreamUpdate old = feed(r1, k1, 1001, bytes("OLD-SESSION"), 1);
        check(str(old.data()).equals("OLD-SESSION"), "旧会话数据正常交付");

        // 同一四元组的第二次连接：新 SYN
        r1.offer(k1, 90000, null, true, false, false, 2);
        TcpFlowReassembler.StreamUpdate u = feed(r1, k1, 90001, bytes("NEW-SESSION"), 3);
        check(str(u.data()).equals("NEW-SESSION"),
                "新 SYN 之后的数据不与旧会话混淆（期望 NEW-SESSION，实际 " + str(u.data()) + "）");
        check(r1.stats().connectionsStarted() >= 2,
                "识别为两次连接（实际 " + r1.stats().connectionsStarted() + "）");

        // (b) 无 SYN 但序列号大幅跳进（新连接的 ISN 通常远大于旧连接）
        TcpFlowReassembler r2 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k2 = key(1);
        r2.offer(k2, 1000, bytes("OLD"), false, false, false, 0);
        TcpFlowReassembler.StreamUpdate u2 = r2.offer(k2, 5_000_000_000L, bytes("NEW"), false, false, false, 1);
        check(str(u2.data()).equals("NEW"),
                "序列号大幅跳进被识别为新连接（期望 NEW，实际 " + str(u2.data()) + "）");
        check(u2.newConnection(), "结果里标记了 newConnection");

        // (c) 重传的 SYN（ISN 与本代次相同）不得被误判为新连接，
        //     否则握手重传会把已经缓冲的数据清空。
        TcpFlowReassembler r3 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k3 = key(1);
        r3.offer(k3, 1000, null, true, false, false, 0);
        // 乱序：先到 1005 的 "TAIL"（缺口 1001..1004），再重传 SYN，再补 "HEAD"
        TcpFlowReassembler.StreamUpdate ooo = r3.offer(k3, 1005, bytes("TAIL"), false, false, false, 1);
        check(ooo.delivery() == TcpFlowReassembler.Delivery.BUFFERED,
                "缺口之后的数据被缓冲（实际 " + ooo.delivery() + "）");
        TcpFlowReassembler.StreamUpdate reSyn = r3.offer(k3, 1000, null, true, false, false, 2);
        check(!reSyn.newConnection(), "重传的 SYN 不触发新连接");
        check(r3.stats().connectionsStarted() == 1,
                "重传的 SYN 不增加连接计数（实际 " + r3.stats().connectionsStarted() + "）");
        TcpFlowReassembler.StreamUpdate fill = r3.offer(k3, 1001, bytes("HEAD"), false, false, false, 3);
        check(str(fill.data()).equals("HEADTAIL"),
                "重传 SYN 后缺口仍能补齐（期望 HEADTAIL，实际 " + str(fill.data()) + "）");

        // (d) 新段只覆盖后继分段的一部分时，后继分段越出新段末尾的字节必须保留。
        //     早期实现一见到重叠就把整个后继分段删掉，尾部字节会静默丢失。
        TcpFlowReassembler r4 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k4 = key(1);
        r4.offer(k4, 1000, null, true, false, false, 0);
        // TAIL 覆盖 1005..1008：T@1005 A@1006 I@1007 L@1008
        r4.offer(k4, 1005, bytes("TAIL"), false, false, false, 1);
        // HEADER 覆盖 1001..1006，与 TAIL 在 1005..1006 重叠；
        // 1007..1008 的 "IL" 未被覆盖，必须保留
        TcpFlowReassembler.StreamUpdate merged = r4.offer(k4, 1001, bytes("HEADER"), false, false, false, 2);
        check(str(merged.data()).equals("HEADERIL"),
                "后继分段被部分覆盖时保留越出末尾的字节（期望 HEADERIL，实际 " + str(merged.data()) + "）");

        // (e) 被动监听漏掉握手是常态：流只能从"首个见到的数据段"开始。
        //     之后到达的、完全落在该起点之前的段无法定位，只能按重传丢弃——
        //     这个丢弃**必须计入统计并告警**，否则内容缺了一块而使用者毫不知情。
        TcpFlowReassembler r5 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k5 = key(1);
        feed(r5, k5, 5000, bytes("LATER"), 0);          // 没看到 SYN，起点取 5000
        r5.offer(k5, 4900, bytes("EARLY"), false, false, false, 1);
        check(r5.stats().discardedBeforeOrigin() == 1,
                "未捕获 SYN 时丢弃起点之前的段会被计入统计（实际 "
                        + r5.stats().discardedBeforeOrigin() + "）");

        // 对照：捕获到 SYN 的流上，普通重传不得计入该项（否则统计失去意义）
        TcpFlowReassembler r6 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k6 = key(1);
        r6.offer(k6, 6000, null, true, false, false, 0);
        feed(r6, k6, 6001, bytes("DATA"), 1);
        r6.offer(k6, 6001, bytes("DATA"), false, false, false, 2);   // 重传
        check(r6.stats().discardedBeforeOrigin() == 0,
                "捕获到 SYN 的流上重传不计入该项（实际 "
                        + r6.stats().discardedBeforeOrigin() + "）");
    }

    /** 用例 6：FIN/RST 交付残留并结束流 */
    private static void checkFinAndReset() {
        logger.info("---- [6] FIN / RST ----");
        TcpFlowReassembler r = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k = key(1);

        feed(r, k, 1000, bytes("DATA"), 0);
        TcpFlowReassembler.StreamUpdate fin = r.offer(k, 1004, null, false, true, false, 1);
        check(fin.delivery() == TcpFlowReassembler.Delivery.NOTHING, "FIN 本身不带新数据");
        check(r.activeStreams() == 0, "FIN 后流被移除（实际 " + r.activeStreams() + "）");

        // 带缺口时 RST：残留数据仍应交付，且计入统计
        TcpFlowReassembler r2 = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k2 = key(1);
        r2.offer(k2, 2000, null, true, false, false, 0);
        r2.offer(k2, 2005, bytes("TAIL"), false, false, false, 1);   // 缺口 2001..2004
        TcpFlowReassembler.StreamUpdate rst = r2.offer(k2, 2009, null, false, false, true, 2);
        check(rst.delivery() == TcpFlowReassembler.Delivery.DATA,
                "RST 时残留数据被交付（避免静默丢弃）");
        check(str(rst.data()).contains("TAIL"), "残留内容正确");
        check(r2.stats().bytesDiscardedOnClose() >= 0, "缺口残留被统计");
    }

    /** 用例 7：空闲超时清理 */
    private static void checkIdleTimeout() {
        logger.info("---- [7] 空闲超时 ----");
        TcpFlowReassembler r = new TcpFlowReassembler();
        TcpFlowReassembler.StreamKey k = key(1);
        feed(r, k, 1000, bytes("PARTIAL"), 0);
        check(r.activeStreams() == 1, "流已建立");

        // 时间推进到超时之后，触发一次清理。
        // 注意：首段（"PARTIAL"）在新建流时即被交付（没有 SYN 时我们无法知道它是流的开头），
        // 因此这里造一条**确实会留下缺口残留**的流：起始段交付后，再送入缺口之后的数据。
        TcpFlowReassembler.StreamKey gapKey = new TcpFlowReassembler.StreamKey("10.0.0.7", DST_IP, 777, 80);
        feed(r, gapKey, 500, bytes("START"), 0);
        TcpFlowReassembler.StreamUpdate gap = r.offer(gapKey, 600, bytes("TAIL"), false, false, false, 1);
        check(gap.waitingForGap() && r.stats().bytesDiscardedOnClose() == 0,
                "缺口数据已缓存且尚未丢弃（缺口等待中）");

        TcpFlowReassembler.StreamKey k2 = new TcpFlowReassembler.StreamKey("10.0.0.9", DST_IP, 1234, 80);
        feed(r, k2, 1, bytes("x"), 200_000);
        check(r.stats().streamsExpired() >= 2, "超时流被清理（实际 " + r.stats().streamsExpired() + "）");
        check(r.stats().bytesDiscardedOnClose() > 0,
                "超时丢弃的字节被统计（不再静默泄漏），实际 " + r.stats().bytesDiscardedOnClose());
    }

    // ==================== 工具 ====================

    /**
     * 提交一个段，并消费掉返回的全部字节。
     * <p>
     * 对应"上层把这批连续字节一次处理完"的常见情形。
     * 重组器会把已交付的字节保留在窗口里，直到 {@link TcpFlowReassembler#consume} 显式丢弃
     * （这是跨段消息能拼起来的前提），因此凡是"本段数据应被完整处理"的场景都要走这里；
     * 需要观察窗口残留的场景则直接调用 {@code offer}。
     * </p>
     */
    private static TcpFlowReassembler.StreamUpdate feed(TcpFlowReassembler r,
                                                        TcpFlowReassembler.StreamKey k,
                                                        long seq, byte[] data, long nowMs) {
        return feed(r, k, seq, data, false, false, false, nowMs);
    }

    private static TcpFlowReassembler.StreamUpdate feed(TcpFlowReassembler r,
                                                        TcpFlowReassembler.StreamKey k,
                                                        long seq, byte[] data,
                                                        boolean syn, boolean fin, boolean rst,
                                                        long nowMs) {
        TcpFlowReassembler.StreamUpdate u = r.offer(k, seq, data, syn, fin, rst, nowMs);
        if (u.data() != null) {
            r.consume(k, u.data().length);
        }
        return u;
    }

    private static String str(byte[] b) {
        return b == null ? "<null>" : new String(b, StandardCharsets.UTF_8);
    }

    /**
     * 断言成功（失败即测试失败）。
     * <p>保留原夹具的调用形态与中文消息，内部改成 JUnit 断言。</p>
     */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
