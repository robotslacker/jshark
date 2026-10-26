package com.jshark;

import com.jshark.parser.MessageFramer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * D2 验收测试：统一消息切分（{@link MessageFramer}）。
 *
 * <h3>为什么必须测"不完整"这种情况</h3>
 * <p>
 * 这个组件唯一的职责是回答"多少字节构成完整消息"。它的危险失败模式不是漏切，
 * 而是<b>把不完整的消息也算成完整的</b>——上层据此丢弃字节，半条消息就永久丢了。
 * 因此每个协议都要覆盖：完整 / 不完整 / 多个 / 畸形。
 * </p>
 *
 * <p>纯逻辑断言：不依赖网络与磁盘。</p>
 */
public class MessageFramerTest {

    private static final Logger logger = LoggerFactory.getLogger(MessageFramerTest.class);

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void messageFramerRegression() {
        logger.info("=================================================");
        logger.info("  D2 验收：统一消息切分");
        logger.info("=================================================");

        checkDis();
        checkHttpContentLength();
        checkHttpChunked();
        checkHttpNoBody();
        checkUnknownProtocol();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    // ==================== DIS ====================

    private static void checkDis() {
        logger.info("---- [1] DIS：按 PDU 长度累加 ----");

        byte[] one = disPdu(64);
        check(MessageFramer.completeMessageBytes("DIS", one) == 64,
                "单个完整 PDU 全部算完整（实际 " + MessageFramer.completeMessageBytes("DIS", one) + "）");

        byte[] two = concat(disPdu(64), disPdu(48));
        check(MessageFramer.completeMessageBytes("DIS", two) == 112,
                "两个 PDU 累加（期望 112，实际 " + MessageFramer.completeMessageBytes("DIS", two) + "）");

        // 一个完整 + 半个：只应算第一个
        byte[] oneAndHalf = concat(disPdu(64), java.util.Arrays.copyOf(disPdu(48), 20));
        check(MessageFramer.completeMessageBytes("DIS", oneAndHalf) == 64,
                "尾部半个 PDU 不算完整，留给后续段（期望 64，实际 "
                        + MessageFramer.completeMessageBytes("DIS", oneAndHalf) + "）");

        // 版本号不在 5..7：不是 PDU 边界
        byte[] badVersion = disPdu(64);
        badVersion[0] = (byte) 3;
        check(MessageFramer.completeMessageBytes("DIS", badVersion) == 0,
                "版本号非法时保守返回 0（实际 " + MessageFramer.completeMessageBytes("DIS", badVersion) + "）");

        // 长度字段谎报巨大：不能无限等待，也不能越界
        byte[] huge = disPdu(64);
        huge[8] = (byte) 0x7F;
        huge[9] = (byte) 0xFF;
        check(MessageFramer.completeMessageBytes("DIS", huge) == 0,
                "长度字段超出实际上限时返回 0（实际 " + MessageFramer.completeMessageBytes("DIS", huge) + "）");
    }

    /** 构造一个合法的 DIS PDU（头部 12 字节，version=7） */
    private static byte[] disPdu(int totalLen) {
        byte[] pdu = new byte[totalLen];
        pdu[0] = 7;                                     // version
        pdu[1] = 1;                                     // exercise id
        pdu[2] = 1;                                     // pdu type
        pdu[3] = 1;                                     // protocol family
        pdu[8] = (byte) ((totalLen >> 8) & 0xFF);       // length (big-endian)
        pdu[9] = (byte) (totalLen & 0xFF);
        for (int i = 12; i < totalLen; i++) {
            pdu[i] = (byte) i;
        }
        return pdu;
    }

    // ==================== HTTP ====================

    private static void checkHttpContentLength() {
        logger.info("---- [2] HTTP：Content-Length ----");

        String msg = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";
        byte[] full = msg.getBytes(StandardCharsets.ISO_8859_1);
        check(MessageFramer.completeMessageBytes("HTTP", full) == full.length,
                "头部 + 完整主体（期望 " + full.length + "，实际 "
                        + MessageFramer.completeMessageBytes("HTTP", full) + "）");

        // 主体缺 2 字节：整条消息都不完整，必须返回 0
        byte[] shortBody = java.util.Arrays.copyOf(full, full.length - 2);
        check(MessageFramer.completeMessageBytes("HTTP", shortBody) == 0,
                "主体未收全时整条消息都不算完整（实际 "
                        + MessageFramer.completeMessageBytes("HTTP", shortBody) + "）");

        // 头部本身不完整
        byte[] shortHeader = java.util.Arrays.copyOf(full, 20);
        check(MessageFramer.completeMessageBytes("HTTP", shortHeader) == 0,
                "头部未收全时返回 0（实际 "
                        + MessageFramer.completeMessageBytes("HTTP", shortHeader) + "）");

        // 两条消息首尾相接
        byte[] twice = concat(full, full);
        check(MessageFramer.completeMessageBytes("HTTP", twice) == 2 * full.length,
                "两条消息累加（期望 " + (2 * full.length) + "，实际 "
                        + MessageFramer.completeMessageBytes("HTTP", twice) + "）");

        // 一条完整 + 一条不完整
        byte[] oneAndHalf = concat(full, java.util.Arrays.copyOf(full, 30));
        check(MessageFramer.completeMessageBytes("HTTP", oneAndHalf) == full.length,
                "第二条不完整时只算第一条（期望 " + full.length + "，实际 "
                        + MessageFramer.completeMessageBytes("HTTP", oneAndHalf) + "）");

        // 头部大小写不敏感
        String lower = "HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nABC";
        byte[] lowerBytes = lower.getBytes(StandardCharsets.ISO_8859_1);
        check(MessageFramer.completeMessageBytes("HTTP", lowerBytes) == lowerBytes.length,
                "头部名大小写不敏感（实际 "
                        + MessageFramer.completeMessageBytes("HTTP", lowerBytes) + "）");
    }

    private static void checkHttpChunked() {
        logger.info("---- [3] HTTP：chunked ----");

        String msg = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n";
        byte[] full = msg.getBytes(StandardCharsets.ISO_8859_1);
        check(MessageFramer.completeMessageBytes("HTTP", full) == full.length,
                "chunked 完整（期望 " + full.length + "，实际 "
                        + MessageFramer.completeMessageBytes("HTTP", full) + "）");

        // 缺结束块：不算完整
        int withoutEnd = full.length - 5;
        byte[] incomplete = java.util.Arrays.copyOf(full, withoutEnd);
        check(MessageFramer.completeMessageBytes("HTTP", incomplete) == 0,
                "chunked 缺结束块时返回 0（实际 "
                        + MessageFramer.completeMessageBytes("HTTP", incomplete) + "）");

        // 最后一个 chunk 的数据没收全
        byte[] missingChunkData = java.util.Arrays.copyOf(full, full.length - 10);
        check(MessageFramer.completeMessageBytes("HTTP", missingChunkData) == 0,
                "chunked 末块数据未收全时返回 0（实际 "
                        + MessageFramer.completeMessageBytes("HTTP", missingChunkData) + "）");
    }

    private static void checkHttpNoBody() {
        logger.info("---- [4] HTTP：无实体主体 ----");

        String msg = "HTTP/1.1 204 No Content\r\n\r\n";
        byte[] full = msg.getBytes(StandardCharsets.ISO_8859_1);
        check(MessageFramer.completeMessageBytes("HTTP", full) == full.length,
                "无主体响应以头部结束为界（期望 " + full.length + "，实际 "
                        + MessageFramer.completeMessageBytes("HTTP", full) + "）");

        String req = "GET /x HTTP/1.1\r\nHost: a\r\n\r\n";
        byte[] reqBytes = req.getBytes(StandardCharsets.ISO_8859_1);
        check(MessageFramer.completeMessageBytes("HTTP", reqBytes) == reqBytes.length,
                "无主体的请求同样以头部结束为界（实际 "
                        + MessageFramer.completeMessageBytes("HTTP", reqBytes) + "）");
    }

    private static void checkUnknownProtocol() {
        logger.info("---- [5] 未知协议：保守返回 0 ----");

        byte[] data = "some opaque bytes that are not a known protocol".getBytes(StandardCharsets.UTF_8);
        check(MessageFramer.completeMessageBytes("UNKNOWN", data) == 0,
                "未知协议返回 0，字节留在窗口里（实际 "
                        + MessageFramer.completeMessageBytes("UNKNOWN", data) + "）");
        check(MessageFramer.completeMessageBytes(null, data) == 0, "协议为 null 时返回 0");
        check(MessageFramer.completeMessageBytes("HTTP", null) == 0, "数据为 null 时返回 0");
        check(MessageFramer.completeMessageBytes("HTTP", new byte[0]) == 0, "空数据返回 0");
    }

    // ==================== 工具 ====================

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
