package com.jshark.parser;

import java.nio.charset.StandardCharsets;

/**
 * 统一消息切分：回答"这段连续字节里有多少字节构成完整消息"。
 *
 * <h3>为什么需要它</h3>
 * <p>
 * TCP 流重组把多个段的载荷拼成一段连续字节后，上层需要知道<b>从哪里可以安全地丢弃</b>：
 * 只有真正构成完整消息的那部分才能被消费，剩下的半条消息必须留在窗口里等后续段。
 * 早期实现按协议分别硬编码，且对非 PG 协议直接写
 * {@code consumedBytes = rawData.length}（把整个缓冲区都当成完整消息），
 * 于是消息一跨段就丢字节（A-13）。
 * </p>
 *
 * <h3>保守原则</h3>
 * <p>
 * 无法可靠判断时一律返回 <b>0</b>（"还没有完整消息"），让字节留在窗口里。
 * 宁可晚一点记录、也不能把半条消息当作完整消息消费掉——后者是静默丢数据。
 * </p>
 *
 * <p>本类只做长度切分，不做字段解析。</p>
 */
public final class MessageFramer {

    /** DIS 头部固定 12 字节 */
    private static final int DIS_HEADER_LEN = 12;
    /** DIS PDU 长度字段在头部内的偏移 */
    private static final int DIS_LENGTH_OFFSET = 8;
    /** 单个消息的合理长度上限，防止畸形长度字段导致无界等待 */
    private static final int MAX_MESSAGE_LEN = 10 * 1024 * 1024;

    private MessageFramer() {
    }

    /**
     * 计算前缀中有多少字节构成完整消息。
     *
     * @param protocol 已识别的应用层协议名（{@code DIS} / {@code HTTP} / ...）
     * @param data     连续字节（窗口内容）
     * @return 完整消息占用的字节数；0 表示还凑不出一个完整消息
     */
    public static int completeMessageBytes(String protocol, byte[] data) {
        if (protocol == null || data == null || data.length == 0) {
            return 0;
        }
        return switch (protocol) {
            case "DIS" -> disBytes(data);
            case "HTTP" -> httpBytes(data);
            // PG 由 pg.consumed_bytes 单独处理（它要按消息类型区分），其余协议保守返回 0
            default -> 0;
        };
    }

    // ==================== DIS ====================

    /**
     * DIS：按 PDU 长度字段逐个累加完整 PDU。
     * <p>
     * 一个 TCP 段里可能装多个 PDU，也可能只装半个。
     * 早期实现要求 {@code pduLength == data.length}，两种情况都会漏识别（A-15）。
     * </p>
     */
    static int disBytes(byte[] data) {
        int off = 0;
        while (data.length - off >= DIS_HEADER_LEN) {
            int version = data[off] & 0xFF;
            if (version < 5 || version > 7) {
                // 版本不在合理范围：不是 PDU 边界，停止累加
                break;
            }
            int pduLength = ((data[off + DIS_LENGTH_OFFSET] & 0xFF) << 8)
                    | (data[off + DIS_LENGTH_OFFSET + 1] & 0xFF);
            if (pduLength < DIS_HEADER_LEN || pduLength > MAX_MESSAGE_LEN) {
                break;
            }
            if (data.length - off < pduLength) {
                // 尾部 PDU 不完整：留给后续段
                break;
            }
            off += pduLength;
        }
        return off;
    }

    // ==================== HTTP ====================

    /**
     * HTTP：按"头部块 + 实体主体"逐个累加完整消息。
     * <p>
     * 主体长度来源优先级：{@code Transfer-Encoding: chunked} &gt; {@code Content-Length} &gt; 无主体。
     * 头部块结束（{@code \r\n\r\n}）但主体未收全时，整条消息都算不完整。
     * </p>
     */
    static int httpBytes(byte[] data) {
        int off = 0;
        while (true) {
            int headerEnd = indexOfDoubleCrlf(data, off);
            if (headerEnd < 0) {
                // 头部块本身不完整
                return off;
            }
            int bodyStart = headerEnd + 4;
            String headers = new String(data, off, headerEnd - off, StandardCharsets.ISO_8859_1);

            if (isChunked(headers)) {
                int end = chunkedBodyEnd(data, bodyStart);
                if (end < 0) {
                    return off;
                }
                off = end;
                continue;
            }

            long contentLength = parseContentLength(headers);
            if (contentLength < 0) {
                // 无实体主体（如 204 / 304 / HEAD 响应）
                off = bodyStart;
                continue;
            }
            if (contentLength > MAX_MESSAGE_LEN) {
                return off;
            }
            if (data.length - bodyStart < contentLength) {
                return off;
            }
            off = (int) (bodyStart + contentLength);
        }
    }

    /** 查找 {@code \r\n\r\n} 的起始位置；未找到返回 -1 */
    private static int indexOfDoubleCrlf(byte[] data, int from) {
        for (int i = Math.max(0, from); i + 3 < data.length; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    /** 查找 {@code \r\n} 的起始位置；未找到返回 -1 */
    private static int indexOfCrlf(byte[] data, int from) {
        for (int i = Math.max(0, from); i + 1 < data.length; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    /** @return Content-Length 值；不存在或非法返回 -1 */
    private static long parseContentLength(String headers) {
        for (String line : headers.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            if (line.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
                try {
                    return Long.parseLong(line.substring(colon + 1).trim());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    /** @return 是否声明了 chunked 传输编码 */
    private static boolean isChunked(String headers) {
        for (String line : headers.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            if (line.substring(0, colon).trim().equalsIgnoreCase("Transfer-Encoding")) {
                return line.substring(colon + 1).toLowerCase().contains("chunked");
            }
        }
        return false;
    }

    /**
     * 计算 chunked 主体的结束位置。
     *
     * @param data 完整窗口
     * @param pos  主体起始位置
     * @return 主体结束后的位置；尚未收全返回 -1
     */
    private static int chunkedBodyEnd(byte[] data, int pos) {
        int cursor = pos;
        while (true) {
            int lineEnd = indexOfCrlf(data, cursor);
            if (lineEnd < 0) {
                return -1;
            }
            String sizeLine = new String(data, cursor, lineEnd - cursor, StandardCharsets.ISO_8859_1).trim();
            int semi = sizeLine.indexOf(';');
            if (semi >= 0) {
                sizeLine = sizeLine.substring(0, semi).trim();
            }
            long size;
            try {
                size = Long.parseLong(sizeLine, 16);
            } catch (NumberFormatException e) {
                return -1;
            }
            if (size < 0 || size > MAX_MESSAGE_LEN) {
                return -1;
            }
            int dataStart = lineEnd + 2;
            if (size == 0) {
                // 结束块：其后是可选 trailer，最后以空行收尾
                if (data.length < dataStart + 2) {
                    return -1;
                }
                if (data[dataStart] == '\r' && data[dataStart + 1] == '\n') {
                    return dataStart + 2;
                }
                int trailerEnd = indexOfDoubleCrlf(data, dataStart);
                return trailerEnd < 0 ? -1 : trailerEnd + 4;
            }
            long next = dataStart + size;
            if (data.length < next + 2) {
                return -1;
            }
            if (data[(int) next] != '\r' || data[(int) next + 1] != '\n') {
                return -1;
            }
            cursor = (int) next + 2;
        }
    }
}
