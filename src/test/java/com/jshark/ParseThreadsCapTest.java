package com.jshark;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 解析线程数的上界护栏。
 *
 * <p>每个解析 worker 都是一条线程 + 一个 1024 深的队列。没有上界时
 * {@code --parse-threads 100000} 会直接造出 10 万条线程和 10 万个队列
 * （仅队列数组就约 0.8GB），表现为原生线程耗尽/OOM，而不是一条清晰的参数错误。
 * 这里锁定"越界按上界生效"，避免将来有人把 clamp 去掉。</p>
 */
class ParseThreadsCapTest {

    @Test
    @DisplayName("超过上界的解析线程数按上界生效，而不是照单全收")
    void oversizedParseThreadsAreClamped() {
        PacketCapture capture = new PacketCapture();
        capture.setParseThreads(100_000);
        assertEquals(PacketCapture.maxParseThreads(), capture.parseThreads(),
                "100000 个解析线程会耗尽原生线程/堆，必须被压到上界");
        assertTrue(PacketCapture.maxParseThreads() >= 4, "上界至少为 4");
    }

    @Test
    @DisplayName("合法值与 <=0 的语义：原样生效 / 退回单线程")
    void validAndNonPositiveValues() {
        PacketCapture capture = new PacketCapture();
        capture.setParseThreads(3);
        assertEquals(3, capture.parseThreads());
        capture.setParseThreads(1);
        assertEquals(1, capture.parseThreads());
        capture.setParseThreads(0);
        assertEquals(1, capture.parseThreads(), "<=0 表示单线程原地解析（与历史行为一致）");
        capture.setParseThreads(-5);
        assertEquals(1, capture.parseThreads());
    }
}
