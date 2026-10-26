package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.parser.ReplayControl;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * stdio 控制协议的状态机测试：hello/READY/start/status/ack/finished、pause、seek 重开段、stop。
 *
 * <p>用 fake Host 避免真的开网卡/发报文。覆盖三条 P1 约束：</p>
 * <ul>
 *   <li>没有 {@code start} 不得开播（READY 握手）；</li>
 *   <li>一条坏命令只换来错误 ack，不能终止 stdin 循环（否则会被当成 EOF 收掉会话）；</li>
 *   <li>stdout 卡住不得阻塞重放线程（独立 writer + 合并 status）。</li>
 * </ul>
 */
public class ControlServerTest {

    @Test
    void statusReflectsRealSpeedWarningsAndFailures() throws Exception {
        Harness h = new Harness(new ByteArrayOutputStream());
        try {
            ReplayControl control = h.host.control;
            control.setAdaptive(false);
            control.speedObserved(4.0, 1.5);
            control.minSpeedObserved(0.37);
            control.sendFailed();
            control.addWarning("OPTION_IGNORED", "default payload: --injectInterface is ignored");
            control.addWarning("OPTION_IGNORED", "default payload: --injectInterface is ignored");

            h.send("{\"id\":1,\"cmd\":\"status\"}");
            Thread.sleep(250);

            JSONObject ack = h.messages().stream()
                    .filter(m -> "ack".equals(m.getString("type")) && m.containsKey("status"))
                    .findFirst().orElse(null);
            assertNotNull(ack, "status 命令应返回快照: " + h.rawOutput());
            JSONObject status = ack.getJSONObject("status");

            JSONObject speed = status.getJSONObject("speed");
            assertEquals(4.0, speed.getDoubleValue("target"), 1e-9);
            assertEquals(1.5, speed.getDoubleValue("current"), 1e-9);
            assertEquals(0.37, speed.getDoubleValue("min"), 1e-9, "speed.min 必须是真实下限");
            assertFalse(speed.getBooleanValue("adaptive"), "adaptive 必须反映真实开关");
            assertEquals(1, status.getJSONObject("counters").getLongValue("failed"),
                    "counters.failed 必须反映真实发送失败");
            assertEquals(1, status.getJSONArray("warnings").size(), "同一告警应去重");
            assertEquals("OPTION_IGNORED",
                    status.getJSONArray("warnings").getJSONObject(0).getString("code"));
        } finally {
            h.shutdown();
        }
    }

    @Test
    void replayStartsOnlyAfterStartCommand() throws Exception {
        Harness h = new Harness(new ByteArrayOutputStream());
        try {
            Thread.sleep(400);
            assertEquals(0, h.host.starts.get(), "收到 start 之前不得开播");
            assertTrue(h.states().contains("READY"), "握手前应先进入 READY，实际=" + h.states());

            h.send("{\"id\":1,\"cmd\":\"start\"}");
            Thread.sleep(300);
            assertEquals(1, h.host.starts.get(), "start 之后应开播恰好一次");
        } finally {
            h.shutdown();
        }
    }

    @Test
    void pauseSeekAndStopRoundTrip() throws Exception {
        Harness h = new Harness(new ByteArrayOutputStream());
        try {
            h.send("{\"id\":0,\"cmd\":\"start\"}");
            h.send("{\"id\":1,\"cmd\":\"pause\"}");
            Thread.sleep(250);
            assertTrue(h.host.control.isPaused() || h.host.control.pauseRequested(),
                    "pause 命令应传给 ReplayControl");

            h.send("{\"id\":2,\"cmd\":\"seek\",\"positionMs\":12345}");
            Thread.sleep(500);
            assertTrue(h.host.restarts.contains(12345L),
                    "seek 应让 worker 返回并以目标重开一段，实际 restarts=" + h.host.restarts);

            h.send("{\"id\":3,\"cmd\":\"stop\"}");
            assertTrue(h.terminate(5000), "stop 后控制服务端应退出");

            List<JSONObject> messages = h.messages();
            assertEquals("hello", messages.get(0).getString("type"));
            assertTrue(messages.stream().anyMatch(m -> "status".equals(m.getString("type"))));
            assertTrue(messages.stream().anyMatch(m -> "ack".equals(m.getString("type"))));
            JSONObject terminal = h.terminal(messages);
            assertNotNull(terminal, "应发送 terminal 终态: " + h.rawOutput());
            assertEquals("terminal", terminal.getString("type"));
            assertTrue(terminal.getBooleanValue("ok"), "正常结束 ok 应为 true");
            assertEquals("FINISHED", terminal.getString("state"));
        } finally {
            h.shutdown();
        }
    }

    @Test
    void invalidSeekGetsErrorAck() throws Exception {
        Harness h = new Harness(new ByteArrayOutputStream());
        try {
            h.send("{\"id\":0,\"cmd\":\"start\"}");
            h.send("{\"id\":9,\"cmd\":\"seek\"}");
            Thread.sleep(250);
            h.send("{\"id\":10,\"cmd\":\"stop\"}");
            assertTrue(h.terminate(5000));

            JSONObject errAck = h.messages().stream()
                    .filter(m -> "ack".equals(m.getString("type")) && !m.getBooleanValue("ok"))
                    .findFirst().orElse(null);
            assertNotNull(errAck, "缺 positionMs 的 seek 应返回错误 ack: " + h.rawOutput());
            assertEquals("INVALID_ARGUMENT", errAck.getJSONObject("error").getString("code"));
        } finally {
            h.shutdown();
        }
    }

    @Test
    void malformedCommandDoesNotKillSession() throws Exception {
        Harness h = new Harness(new ByteArrayOutputStream());
        try {
            h.send("{\"id\":0,\"cmd\":\"start\"}");
            Thread.sleep(200);
            // fastjson2 对“结构不对”的值抛 JSONException（不是 IllegalArgumentException），曾逃出 handler
            h.send("{\"id\":1,\"cmd\":\"seek\",\"positionMs\":{\"x\":1}}");
            h.send("{\"id\":2,\"cmd\":\"set_speed\",\"speed\":true}");
            h.send("null");
            h.send("{\"id\":3,\"cmd\":\"ping\"}");
            Thread.sleep(300);
            h.send("{\"id\":4,\"cmd\":\"stop\"}");
            assertTrue(h.terminate(5000), "坏命令之后的 stop 仍应正常工作");

            List<JSONObject> messages = h.messages();
            long errorAcks = messages.stream()
                    .filter(m -> "ack".equals(m.getString("type")) && !m.getBooleanValue("ok"))
                    .count();
            assertTrue(errorAcks >= 2, "每条坏命令都应换来错误 ack，实际=" + errorAcks);
            assertTrue(messages.stream().anyMatch(m -> "ack".equals(m.getString("type"))
                            && m.getBooleanValue("ok") && Long.valueOf(3).equals(m.getLong("id"))),
                    "坏命令之后 ping 仍应被应答（说明 stdin 循环没退出）: " + h.rawOutput());

            JSONObject terminal = h.terminal(messages);
            assertNotNull(terminal);
            assertEquals("user_stop", terminal.getJSONObject("summary").getString("reason"),
                    "会话是被 stop 结束的，不能被误判成 stdin EOF");
        } finally {
            h.shutdown();
        }
    }

    @Test
    void stalledStdoutDoesNotBlockReplayWorker() throws Exception {
        GatedOutputStream sink = new GatedOutputStream();
        Harness h = new Harness(sink);
        try {
            Thread.sleep(300); // hello/首条 status 已入队，writer 被 sink 卡住
            h.send("{\"id\":1,\"cmd\":\"start\"}");

            long deadline = System.currentTimeMillis() + 2000;
            while (System.currentTimeMillis() < deadline && h.host.ticks.get() < 50) {
                Thread.sleep(20);
            }
            assertTrue(h.host.ticks.get() >= 50,
                    "stdout 卡住时重放线程不能被阻塞，ticks=" + h.host.ticks.get());
        } finally {
            sink.open();
            h.shutdown();
        }
    }

    private static List<JSONObject> parse(String ndjson) {
        List<JSONObject> result = new ArrayList<>();
        for (String line : ndjson.split("\\R")) {
            if (!line.isBlank()) {
                result.add(JSON.parseObject(line));
            }
        }
        return result;
    }

    /** 起一个控制服务端 + 一条管道，方便逐个用例驱动。 */
    private static final class Harness {
        final FakeHost host = new FakeHost();
        final PipedOutputStream commands = new PipedOutputStream();
        final PipedInputStream commandInput;
        final OutputStream sink;
        final PrintStream out;
        final ControlServer server;
        final Thread thread;

        Harness(OutputStream sink) throws Exception {
            this.commandInput = new PipedInputStream(commands, 64 * 1024);
            this.sink = sink;
            this.out = new PrintStream(sink, true, StandardCharsets.UTF_8);
            this.server = new ControlServer(commandInput, out, host);
            this.thread = new Thread(() -> {
                try {
                    server.run();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, "control-server-test");
            this.thread.setDaemon(true);
            this.thread.start();
        }

        void send(String json) throws Exception {
            commands.write((json + "\n").getBytes(StandardCharsets.UTF_8));
            commands.flush();
        }

        boolean terminate(long timeoutMs) throws Exception {
            thread.join(timeoutMs);
            return !thread.isAlive();
        }

        String rawOutput() {
            return sink instanceof ByteArrayOutputStream buf
                    ? buf.toString(StandardCharsets.UTF_8)
                    : "<non-buffered sink>";
        }

        List<JSONObject> messages() {
            return parse(rawOutput());
        }

        List<String> states() {
            return messages().stream()
                    .filter(m -> "status".equals(m.getString("type")))
                    .map(m -> m.getString("state"))
                    .toList();
        }

        JSONObject terminal(List<JSONObject> messages) {
            return messages.stream()
                    .filter(m -> "terminal".equals(m.getString("type"))
                            || "finished".equals(m.getString("type"))
                            || "failed".equals(m.getString("type")))
                    .reduce((a, b) -> b)
                    .orElse(null);
        }

        void shutdown() throws Exception {
            try {
                send("{\"id\":99,\"cmd\":\"stop\"}");
            } catch (Exception ignored) {
                // 管道已关闭
            }
            thread.join(5000);
            if (thread.isAlive()) {
                thread.interrupt();
            }
            commands.close();
            out.close();
        }
    }

    /** 卡住写的 stdout：验证 writer 阻塞时重放线程照常跑。 */
    private static final class GatedOutputStream extends OutputStream {
        private final CountDownLatch gate = new CountDownLatch(1);
        private final ByteArrayOutputStream captured = new ByteArrayOutputStream();

        void open() {
            gate.countDown();
        }

        private void await() {
            try {
                gate.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void write(int b) {
            await();
            captured.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            await();
            captured.write(b, off, len);
        }
    }

    private static final class FakeHost implements ControlServer.Host {
        final ReplayControl control = new ReplayControl(1.0);
        final List<Long> restarts = new CopyOnWriteArrayList<>();
        final AtomicInteger starts = new AtomicInteger();
        final AtomicInteger ticks = new AtomicInteger();
        volatile boolean running;

        @Override
        public ReplayControl control() {
            return control;
        }

        @Override
        public void start() {
            starts.incrementAndGet();
            running = true;
            try {
                while (!control.shouldStop() && !control.hasPendingSeek()) {
                    ticks.incrementAndGet();
                    Thread.sleep(5);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                running = false;
            }
        }

        @Override
        public void stop() {
            control.requestStop();
        }

        @Override
        public String requestedMode() {
            return "payload";
        }

        @Override
        public String effectiveMode() {
            return "payload";
        }

        @Override
        public String sourceKind() {
            return "db";
        }

        @Override
        public String sourcePath() {
            return "fake.db";
        }

        @Override
        public void prepareRestart(long targetMs) {
            restarts.add(targetMs);
            control.beginNewSegment(targetMs);
        }
    }
}
