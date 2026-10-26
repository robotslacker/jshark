package com.jshark.parser;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 帧级引擎的控制面测试：pause/resume、seek（段中止）、运行中 set_speed。
 *
 * <p>用内存 {@link FrameSource}/{@link FrameSender}，不需要网卡或管理员权限。
 * 生产发送端 {@link RawFrameSender} 与测试发送端共享 {@link FrameSender} 契约。</p>
 */
public class FrameReplayEngineControlTest {

    @Test
    void pauseBlocksBeforeFirstFrameAndResumeContinues() throws Exception {
        FakeSource source = new FakeSource(0, 100, 200);
        FakeSender sender = new FakeSender();
        ReplayControl control = new ReplayControl(1.0);
        control.requestPause();

        FrameReplayEngine engine = newEngine(source, control);
        Thread worker = new Thread(() -> run(engine, sender), "frame-pause-test");
        worker.start();
        Thread.sleep(250);
        assertEquals(0, sender.frames.size(), "暂停中不应注入任何帧");

        control.requestResume();
        worker.join(4000);
        assertFalse(worker.isAlive(), "恢复后应正常跑完");
        assertEquals(3, sender.frames.size());
    }

    @Test
    void seekAbortsCurrentSegmentBeforeFirstFrame() throws Exception {
        FakeSource source = new FakeSource(0, 10, 20);
        FakeSender sender = new FakeSender();
        ReplayControl control = new ReplayControl(1.0);
        control.requestSeek(12345);

        FrameReplayEngine engine = newEngine(source, control);
        run(engine, sender);

        assertEquals(12345L, control.takeSeek(), "seek 目标应由控制面消费");
        assertEquals(0, sender.frames.size(), "seek 应在当前段注入前退出，由外层重开新段");
    }

    @Test
    void setSpeedDuringWaitTakesEffect() throws Exception {
        FakeSource source = new FakeSource(0, 5_000);
        FakeSender sender = new FakeSender();
        ReplayControl control = new ReplayControl(0.01);
        control.requestSpeed(0.01);

        FrameReplayEngine engine = newEngine(source, control);
        Thread worker = new Thread(() -> run(engine, sender), "frame-speed-test");
        worker.start();

        awaitFrames(sender, 1, 2_000);
        control.requestSpeed(1000.0);
        worker.join(3_000);

        assertFalse(worker.isAlive(), "调速后第二帧应立即发出并结束");
        assertEquals(2, sender.frames.size());
    }

    private static FrameReplayEngine newEngine(FakeSource source, ReplayControl control) {
        FrameReplayEngine engine = new FrameReplayEngine(
                source, null, null, null, null, null);
        engine.setControl(control);
        return engine;
    }

    private static void run(FrameReplayEngine engine, FrameSender sender) {
        try {
            engine.run(new ReplayClock(1.0, null, null),
                    new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null),
                    sender,
                    TargetMapping.parse("*:*-*:*"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void awaitFrames(FakeSender sender, int count, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline && sender.frames.size() < count) {
            Thread.sleep(10);
        }
        assertTrue(sender.frames.size() >= count, "等待第 " + count + " 帧超时");
    }

    private static final class FakeSender implements FrameSender {
        final List<byte[]> frames = new CopyOnWriteArrayList<>();
        final AtomicInteger failed = new AtomicInteger();

        @Override
        public boolean send(byte[] frame) {
            frames.add(frame);
            return true;
        }

        @Override
        public long framesSentDespiteError() {
            return 0;
        }

        @Override
        public long framesFailed() {
            return failed.get();
        }
    }

    private static final class FakeSource implements FrameSource {
        private final List<Frame> frames = new ArrayList<>();
        private int index;

        FakeSource(long... timestampsMs) {
            for (long ts : timestampsMs) {
                frames.add(new Frame(frameBytes(), ts * 1_000_000L,
                        "127.0.0.1", "127.0.0.1", 1234, 9, "UDP"));
            }
        }

        @Override
        public void open() {
            index = 0;
        }

        @Override
        public Frame next() {
            return index < frames.size() ? frames.get(index++) : null;
        }

        @Override
        public boolean isOrderedByTimestamp() {
            return true;
        }

        @Override
        public String describe() {
            return "fake";
        }

        @Override
        public long skippedWithoutFrame() {
            return 0;
        }

        @Override
        public void close() {
        }
    }

    /** 最小合法 IPv4/UDP 帧；identity 映射下 FrameRewriter 走 no-op 快路径。 */
    private static byte[] frameBytes() {
        byte[] f = new byte[14 + 20 + 8];
        // Ethernet: dst 00:11:22:33:44:55, src 66:77:88:99:aa:bb, IPv4
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
        f[ip + 13] = 0;
        f[ip + 14] = 0;
        f[ip + 15] = 1;
        f[ip + 16] = 127;
        f[ip + 17] = 0;
        f[ip + 18] = 0;
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
