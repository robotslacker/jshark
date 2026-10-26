package com.jshark.parser;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PcapFrameSource} 的 seek 跳过阶段必须可中断。
 *
 * <p>背景：seek 后需要“只读不发送”地把目标时间戳之前的包丢掉；大文件上这一步可能持续数秒。
 * 如果跳过过程中不看 stop/seek，UI 的“停止”就会静默卡住（P1）。</p>
 *
 * <p>用例用最小合法 pcap（手写文件头，不依赖发包/网卡）构造 1000 个包。</p>
 */
public class PcapFrameSourceSkipTest {

    private static final long T0 = 1_700_000_000_000L;

    @TempDir
    Path dir;

    @Test
    void skippingToStartCanBeAborted() throws Exception {
        Path pcap = dir.resolve("big.pcap");
        writePcap(pcap, T0, 1000);

        PcapFrameSource source = new PcapFrameSource(pcap.toString());
        source.setStartAtMs(T0 + 900);
        AtomicInteger checks = new AtomicInteger();
        source.setAbortCondition(() -> checks.incrementAndGet() >= 1);
        source.open();
        try {
            assertNull(source.next(), "跳过前导帧时应能响应 stop/seek（返回 null 表示放弃本段）");
            assertTrue(checks.get() >= 1, "中断判据必须在跳过过程中被调用，实际=" + checks.get());
        } finally {
            source.close();
        }
    }

    @Test
    void withoutAbortReturnsFirstFrameInWindow() throws Exception {
        Path pcap = dir.resolve("big.pcap");
        writePcap(pcap, T0, 1000);

        PcapFrameSource source = new PcapFrameSource(pcap.toString());
        source.setStartAtMs(T0 + 900);
        source.open();
        try {
            FrameSource.Frame frame = source.next();
            assertTrue(frame != null, "未中断时应返回窗口内第一帧");
            assertEquals((T0 + 900) * 1_000_000L, frame.timestampNanos(),
                    "应精确落在 --start 对应的那一帧");
        } finally {
            source.close();
        }
    }

    /** 写一个最小合法 pcap：Ethernet + IPv4 + UDP，帧间隔 1ms。 */
    private static void writePcap(Path path, long firstMs, int count) throws Exception {
        byte[] frame = udpFrame();
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(0xa1b2c3d4)
                .putShort((short) 2)
                .putShort((short) 4)
                .putInt(0)
                .putInt(0)
                .putInt(65535)
                .putInt(1);
        try (OutputStream out = Files.newOutputStream(path)) {
            out.write(header.array());
            for (int i = 0; i < count; i++) {
                long ms = firstMs + i;
                ByteBuffer packetHeader = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                packetHeader.putInt((int) (ms / 1000))
                        .putInt((int) ((ms % 1000) * 1000))
                        .putInt(frame.length)
                        .putInt(frame.length);
                out.write(packetHeader.array());
                out.write(frame);
            }
        }
    }

    private static byte[] udpFrame() {
        byte[] f = new byte[14 + 20 + 8];
        byte[] dst = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        byte[] src = {0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb};
        System.arraycopy(dst, 0, f, 0, 6);
        System.arraycopy(src, 0, f, 6, 6);
        f[12] = 0x08;
        f[13] = 0x00;
        int ip = 14;
        f[ip] = 0x45;
        f[ip + 2] = 0x00;
        f[ip + 3] = 28; // total length
        f[ip + 8] = 64; // TTL
        f[ip + 9] = 17; // UDP
        f[ip + 12] = 127;
        f[ip + 15] = 1;
        f[ip + 16] = 127;
        f[ip + 19] = 1;
        int udp = 34;
        f[udp] = 0x04;
        f[udp + 1] = (byte) 0xd2; // src 1234
        f[udp + 2] = 0x00;
        f[udp + 3] = 9; // dst 9
        f[udp + 4] = 0x00;
        f[udp + 5] = 8;
        return f;
    }
}
