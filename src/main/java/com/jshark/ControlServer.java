package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.parser.AdaptiveSpeedController;
import com.jshark.parser.ReplayControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * {@code --control stdio} 的 NDJSON 协议服务端。
 *
 * <p>命令从 stdin 读，事件/状态写 stdout，日志由调用方保证走 stderr。
 * 启动后立即在 worker 线程运行重放；stdin EOF / stop 请求会优雅停止。</p>
 *
 * <p>本类只依赖 {@link ReplayControl} 与 {@link Host}，不依赖 Swing/具体重放工具。</p>
 */
public final class ControlServer {

    /** 重放宿主（由 CliReplay 实现）。 */
    public interface Host {
        ReplayControl control();

        /** 阻塞运行一次重放，直到 EOF/stop。 */
        void start();

        /** 请求停止当前重放（同时置 control stop）。 */
        void stop();

        String requestedMode();

        String effectiveMode();

        String sourceKind();

        String sourcePath();

        /** 为 seek 重开新段做准备：清理段级标志、设置新起点。 */
        void prepareRestart(long targetMs);
    }

    private static final Logger logger = LoggerFactory.getLogger(ControlServer.class);

    /**
     * stdout 的写队列：{@code status} 是快照，队列里只保留最新一条；
     * {@code hello/ack/finished/failed} 不允许丢弃。
     *
     * <p>所有写法都走独立 writer 线程，重放线程永远不会被 stdout 反压卡住
     * （UI 卡死/管道写满时最坏只是状态跳变）。</p>
     */
    private static final Object STATUS_TOKEN = new Object();
    private static final Object WRITER_STOP = new Object();

    private final BufferedReader reader;
    private final PrintStream out;
    private final Host host;
    private final ReplayControl control;
    private final String sessionId = UUID.randomUUID().toString();
    private final String[] capabilities = {
            "start", "frame", "payload", "pause", "resume", "speed", "seek", "status"
    };

    private final LinkedBlockingQueue<Object> writeQueue = new LinkedBlockingQueue<>();
    private final AtomicReference<JSONObject> pendingStatus = new AtomicReference<>();
    private final AtomicBoolean statusTokenPending = new AtomicBoolean();
    private Thread writerThread;

    private final AtomicLong seq = new AtomicLong();
    private final AtomicBoolean terminalSent = new AtomicBoolean();
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final AtomicBoolean workerDone = new AtomicBoolean();
    private final AtomicBoolean started = new AtomicBoolean();
    private final CountDownLatch done = new CountDownLatch(1);
    /** {@code start} 或 stop/EOF 二选一，唤醒 {@link #run()}。 */
    private final CountDownLatch startOrAbort = new CountDownLatch(1);

    private volatile String state = "STARTING";
    private volatile String message = "Starting replay";
    private volatile long stateSinceMs = System.currentTimeMillis();
    private final long startedAtMs = System.currentTimeMillis();
    private volatile long lastStatusNanos = System.nanoTime();
    private volatile long lastSent;
    private volatile Throwable workerError;
    private volatile boolean stopTimedOut;
    private volatile boolean seeking;
    private volatile boolean seekKeepPaused;
    /** 最近一段是 seek 重开出来的，且整段没有任何数据（定位点之后无数据）。 */
    private volatile boolean seekSegmentEmpty;

    private long examinedAtSegmentStart;
    private boolean hasSeeked;

    private Thread worker;
    private Thread stdinReader;
    private ScheduledExecutorService statusTimer;

    public ControlServer(InputStream in, PrintStream out, Host host) {
        this.reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        this.out = out;
        this.host = host;
        this.control = host.control();
    }

    /**
     * 运行协议服务端，直到重放结束/被停止/输入 EOF。
     *
     * @return 进程退出码：0 正常/用户停止，1 失败/超时
     */
    public int run() throws Exception {
        startWriter();
        sendHello();
        setState("READY", "Ready; waiting for start command");

        statusTimer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jshark-control-status");
            t.setDaemon(true);
            return t;
        });
        statusTimer.scheduleAtFixedRate(this::tickStatus, 250, 250, TimeUnit.MILLISECONDS);

        stdinReader = new Thread(this::readCommands, "jshark-control-stdin");
        stdinReader.setDaemon(true);
        stdinReader.start();

        // 握手：等 start（或 stop/EOF）。子进程启动即开播会让 Start 失去“已就绪、待确认”的语义，
        // 也不给 UI 校验 hello/READY 的机会。
        startOrAbort.await();
        if (started.get() && !stopping.get()) {
            worker = new Thread(this::runWorker, "jshark-control-replay");
            worker.setDaemon(true);
            worker.start();
            done.await();
        } else {
            done.countDown();
        }

        if (statusTimer != null) {
            statusTimer.shutdownNow();
        }
        sendTerminal();
        stopWriter();
        return workerError == null && !stopTimedOut ? 0 : 1;
    }

    // ==================== stdout writer（不阻塞重放线程） ====================

    private void startWriter() {
        writerThread = new Thread(this::writeLoop, "jshark-control-writer");
        writerThread.setDaemon(true);
        writerThread.start();
    }

    private void writeLoop() {
        while (true) {
            Object item;
            try {
                item = writeQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (item == WRITER_STOP) {
                return;
            }
            if (item == STATUS_TOKEN) {
                statusTokenPending.set(false);
                JSONObject snapshot = pendingStatus.getAndSet(null);
                if (snapshot != null) {
                    emit(snapshot);
                }
            } else if (item instanceof JSONObject json) {
                emit(json);
            }
        }
    }

    private void emit(JSONObject json) {
        // PrintStream 不抛 IOException；写失败只体现在 checkError() 上，绝不打断重放。
        out.println(JSON.toJSONString(json));
        out.flush();
    }

    /** 排空队列后退出 writer：调用方保证终态消息已在它之前入队。 */
    private void stopWriter() {
        writeQueue.offer(WRITER_STOP);
        Thread t = writerThread;
        if (t == null) {
            return;
        }
        try {
            t.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (t.isAlive()) {
            t.interrupt();
        }
    }

    // ==================== worker / stdin ====================

    private void runWorker() {
        try {
            while (!stopping.get()) {
                examinedAtSegmentStart = control.examinedCount();
                seeking = false;
                setState("RUNNING", "Replaying");
                host.start();
                boolean segmentEmpty = control.examinedCount() == examinedAtSegmentStart;

                Long seek = control.takeSeek();
                if (seek != null && !stopping.get()) {
                    host.prepareRestart(seek);
                    if (stopping.get()) {
                        // stop 与 seek 同时到达：以 stop 为准
                        break;
                    }
                    hasSeeked = true;
                    seeking = true;
                    setState("SEEKING", "Seeking");
                    boolean keepPaused = seekKeepPaused;
                    seekKeepPaused = false;
                    if (keepPaused) {
                        control.requestPause();
                    }
                    continue;
                }
                // seek 重开出来的段一行数据都没有：这是“定位点之后没数据”，不是正常播完。
                if (hasSeeked && segmentEmpty && !stopping.get() && workerError == null) {
                    seekSegmentEmpty = true;
                }
                break;
            }
        } catch (Throwable t) {
            workerError = t;
            control.reportError(t);
            logger.error("Replay failed", t);
        } finally {
            workerDone.set(true);
            seeking = false;
            Throwable effectiveError = workerError != null ? workerError : control.error();
            if (effectiveError != null) {
                setState("FAILED", "Failed");
            } else if (stopping.get()) {
                setState("STOPPED", "Stopped");
            } else if (seekSegmentEmpty) {
                setState("FINISHED", "No data after seek position");
            } else {
                setState("FINISHED", "Completed");
            }
            done.countDown();
        }
    }

    private void readCommands() {
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    handleLine(line);
                } catch (RuntimeException e) {
                    // 兜底：任何一条命令的异常都不允许终止 stdin 循环 ——
                    // 循环一旦退出就会被当成 EOF，把整个重放会话收掉。
                    logger.warn("Control command failed: {}", e.toString());
                    ackError(null, "INVALID_COMMAND", describe(e));
                }
            }
        } catch (Exception e) {
            logger.warn("Control stdin read failed: {}", e.getMessage());
        } finally {
            // stdin EOF：UI 退出/管道断开时不要让子进程变成孤儿；
            // 若重放已自然结束则不要再把状态改成 STOPPING。
            if (!workerDone.get()) {
                requestStop("stdin-eof");
            }
        }
    }

    private void handleLine(String line) {
        JSONObject cmd;
        try {
            cmd = JSON.parseObject(line);
        } catch (RuntimeException e) {
            ackError(null, "INVALID_JSON", "invalid JSON command: " + describe(e));
            return;
        }
        if (cmd == null) {
            ackError(null, "INVALID_JSON", "command must be a JSON object");
            return;
        }
        Long id = null;
        try {
            id = cmd.getLong("id");
            String name = cmd.getString("cmd");
            if (name == null) {
                ackError(id, "INVALID_COMMAND", "missing cmd");
                return;
            }
            switch (name) {
                case "start" -> {
                    // 真正开播的唯一入口；重复 start 幂等。
                    if (started.compareAndSet(false, true)) {
                        startOrAbort.countDown();
                    }
                    ackOk(id);
                }
                case "pause" -> {
                    control.requestPause();
                    setState("PAUSED", "Paused");
                    ackOk(id);
                }
                case "resume" -> {
                    control.requestResume();
                    setState("RUNNING", "Replaying");
                    ackOk(id);
                }
                case "set_speed" -> {
                    Double speed = cmd.getDouble("speed");
                    if (speed == null) {
                        ackError(id, "INVALID_ARGUMENT", "set_speed requires speed");
                    } else {
                        control.requestSpeed(speed);
                        ackOk(id);
                    }
                }
                case "seek" -> {
                    Long positionMs = cmd.getLong("positionMs");
                    if (positionMs == null) {
                        String position = cmd.getString("position");
                        if (position != null) {
                            positionMs = parsePosition(position);
                        }
                    }
                    if (positionMs == null) {
                        ackError(id, "INVALID_ARGUMENT", "seek requires positionMs or position");
                    } else if (!started.get() || workerDone.get() || stopping.get()) {
                        ackError(id, "NOT_RUNNING", "replay is not running");
                    } else {
                        seekKeepPaused = control.isPaused() || control.pauseRequested();
                        control.requestSeek(positionMs);
                        seeking = true;
                        setState("SEEKING", "Seeking");
                        ackOk(id);
                    }
                }
                case "status" -> {
                    JSONObject resp = new JSONObject();
                    resp.put("type", "ack");
                    resp.put("id", id);
                    resp.put("ok", true);
                    resp.put("status", statusJson());
                    write(resp);
                }
                case "stop", "shutdown" -> {
                    ackOk(id);
                    requestStop("user");
                }
                case "ping" -> ackOk(id);
                default -> ackError(id, "INVALID_COMMAND", "unknown cmd: " + name);
            }
        } catch (RuntimeException e) {
            // 参数类型不对（{"positionMs":{}}）在 fastjson2 里抛 JSONException（不是 IAE）；
            // 一条坏命令只应该换来一个错误 ack，不能影响会话。
            logger.warn("Control command rejected: {}", e.toString());
            ackError(id, "INVALID_ARGUMENT", describe(e));
        }
    }

    private static String describe(Throwable t) {
        String msg = t.getMessage();
        return msg == null || msg.isBlank() ? t.getClass().getSimpleName() : msg;
    }

    private void requestStop(String reason) {
        // start 之前也可能收到 stop/EOF：先唤醒 run()，避免它一直等握手。
        startOrAbort.countDown();
        if (workerDone.get() || terminalSent.get()) {
            return;
        }
        if (!stopping.compareAndSet(false, true)) {
            return;
        }
        setState("STOPPING", "Stopping");
        control.requestStop();
        host.stop();

        // 看门狗：发送器背压/线程卡住时也要在有限时间内收尾。
        Thread watchdog = new Thread(() -> {
            try {
                if (!done.await(5, TimeUnit.SECONDS)) {
                    stopTimedOut = true;
                    done.countDown();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                done.countDown();
            }
        }, "jshark-control-stop-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    // ==================== status ====================

    private void tickStatus() {
        if (terminalSent.get() || done.getCount() == 0) {
            return;
        }
        try {
            sendStatus();
        } catch (RuntimeException e) {
            // scheduleAtFixedRate 一旦抛异常就会永久停掉后续推送：这里必须兜住。
            logger.warn("Status tick failed: {}", e.toString());
        }
    }

    private void sendHello() {
        JSONObject hello = new JSONObject();
        hello.put("type", "hello");
        hello.put("protocol", 1);
        hello.put("app", "jshark-replay");
        hello.put("version", "1.0.0");
        hello.put("session", sessionId);
        hello.put("capabilities", capabilities);
        hello.put("pid", ProcessHandle.current().pid());
        write(hello);
    }

    private void sendStatus() {
        if (terminalSent.get()) {
            return;
        }
        writeStatus(statusJson());
    }

    /**
     * 渲染一条 status。
     *
     * <p>{@code synchronized}：调用方有状态定时器、stdin 线程和 worker，而 {@code pps}
     * 依赖 {@code lastSent/lastStatusNanos} 这对可变状态；串行化后不会再出现两条消息交错
     * 计算出的乱跳 pps。快照本身来自 {@link ReplayControl#snapshot()}（一次读出）。</p>
     */
    private synchronized JSONObject statusJson() {
        ReplayControl.Snapshot snap = control.snapshot();
        long now = System.currentTimeMillis();
        long elapsedMs = Math.max(0, now - startedAtMs);
        long pausedMs = snap.pausedNanos() / 1_000_000L;
        long activeMs = Math.max(0, elapsedMs - pausedMs);
        long windowFrom = snap.windowFromMs();
        long windowTo = snap.windowToMs();
        long playhead = snap.playheadMs();

        long sent = snap.sent();
        long bytes = snap.bytes();
        long nowNano = System.nanoTime();
        long dt = Math.max(1, nowNano - lastStatusNanos);
        double pps = (sent - lastSent) * 1_000_000_000.0 / dt;
        lastSent = sent;
        lastStatusNanos = nowNano;

        Long etaMs = null;
        if (windowFrom != Long.MIN_VALUE && windowTo != Long.MAX_VALUE
                && playhead > 0 && snap.currentSpeed() > 0) {
            long remain = Math.max(0, windowTo - playhead);
            etaMs = Math.round(remain / snap.currentSpeed());
        }

        JSONObject status = new JSONObject();
        status.put("type", "status");
        status.put("seq", seq.incrementAndGet());
        status.put("session", sessionId);
        status.put("protocol", 1);
        status.put("appVersion", "1.0.0");

        String displayState = state;
        String displayMessage = message;
        if (!stopping.get() && !seeking
                && ("RUNNING".equals(state) || "PAUSED".equals(state))) {
            boolean paused = snap.paused() || snap.pauseRequested();
            displayState = paused ? "PAUSED" : "RUNNING";
            displayMessage = paused ? "Paused" : "Replaying";
        }
        status.put("state", displayState);
        status.put("stateSinceMs", stateSinceMs);
        status.put("message", displayMessage);
        status.put("requestedMode", host.requestedMode());
        status.put("effectiveMode", host.effectiveMode());

        JSONObject source = new JSONObject();
        source.put("kind", host.sourceKind());
        source.put("path", host.sourcePath());
        source.put("live", snap.live());
        source.put("follow", snap.follow());
        source.put("dataStartMs", snap.dataStartMs() == Long.MIN_VALUE ? null : snap.dataStartMs());
        source.put("dataEndMs", snap.dataEndMs() == Long.MAX_VALUE ? null : snap.dataEndMs());
        status.put("source", source);

        JSONObject window = new JSONObject();
        window.put("fromMs", windowFrom == Long.MIN_VALUE ? null : windowFrom);
        window.put("toMs", windowTo == Long.MAX_VALUE ? null : windowTo);
        window.put("availableEndMs", snap.dataEndMs() == Long.MAX_VALUE ? null : snap.dataEndMs());
        window.put("live", snap.live());
        status.put("window", window);

        status.put("playheadMs", playhead == 0 ? null : playhead);
        status.put("paused", snap.paused() || snap.pauseRequested());
        status.put("seeking", seeking);
        status.put("waitingForData", snap.waitingForData());
        status.put("probing", false);

        JSONObject speed = new JSONObject();
        speed.put("target", snap.targetSpeed());
        speed.put("current", snap.currentSpeed());
        speed.put("min", snap.minSpeed());
        speed.put("adaptive", snap.adaptive());
        speed.put("down", snap.adaptiveDown());
        speed.put("up", snap.adaptiveUp());
        speed.put("atFloor", snap.currentSpeed() <= AdaptiveSpeedController.SPEED_FLOOR);
        status.put("speed", speed);

        JSONObject counters = new JSONObject();
        counters.put("examined", snap.examined());
        counters.put("sent", sent);
        counters.put("bytes", bytes);
        counters.put("filtered", snap.filtered());
        counters.put("skipped", snap.skipped());
        counters.put("failed", snap.failures());
        status.put("counters", counters);

        JSONObject timing = new JSONObject();
        timing.put("startedAtMs", startedAtMs);
        timing.put("elapsedMs", elapsedMs);
        timing.put("pausedMs", pausedMs);
        timing.put("activeMs", activeMs);
        timing.put("etaMs", etaMs);
        timing.put("pps", Math.round(pps));
        status.put("timing", timing);

        JSONArray warningArray = new JSONArray();
        for (ReplayControl.Warning warning : snap.warnings()) {
            JSONObject item = new JSONObject();
            item.put("code", warning.code());
            item.put("message", warning.message());
            warningArray.add(item);
        }
        status.put("warnings", warningArray);
        status.put("lastError", snap.error() == null ? null : errorJson(snap.error()));
        status.put("capabilities", capabilities);
        status.put("pid", ProcessHandle.current().pid());
        return status;
    }

    private void sendTerminal() {
        if (!terminalSent.compareAndSet(false, true)) {
            return;
        }
        JSONObject terminal = new JSONObject();
        // 与采集/转发端统一的终态形状：type/ok/state/message
        terminal.put("type", "terminal");
        JSONObject status = statusJson();
        Throwable error = workerError != null ? workerError : control.error();
        if (error != null || stopTimedOut) {
            JSONObject err = error != null ? errorJson(error)
                    : errorObject("CONTROL_TIMEOUT", "replay did not stop within 5s");
            terminal.put("ok", false);
            terminal.put("state", "FAILED");
            terminal.put("message", err.getString("message"));
            terminal.put("error", err);
            terminal.put("status", status);
            terminal.put("exitCode", 1);
        } else {
            ReplayControl.Snapshot snap = control.snapshot();
            JSONObject summary = new JSONObject();
            summary.put("reason", stopping.get() || snap.stopRequested() ? "user_stop"
                    : (seekSegmentEmpty ? "seek_empty" : "eof"));
            summary.put("sent", snap.sent());
            summary.put("bytes", snap.bytes());
            summary.put("targetSpeed", snap.targetSpeed());
            summary.put("currentSpeed", snap.currentSpeed());
            summary.put("exitCode", 0);
            terminal.put("ok", true);
            terminal.put("state", "FINISHED");
            terminal.put("message", "");
            terminal.put("status", status);
            terminal.put("summary", summary);
            terminal.put("exitCode", 0);
        }
        write(terminal);
    }

    // ==================== JSON / state ====================

    private static Long parsePosition(String text) {
        try {
            return TimeArgs.parse(text);
        } catch (IllegalArgumentException e) {
            // seek 的 position 允许为空/非法：由调用方回 INVALID_ARGUMENT，不中断会话
            return null;
        }
    }
    private void setState(String newState, String newMessage) {
        this.state = newState;
        this.message = newMessage;
        this.stateSinceMs = System.currentTimeMillis();
        sendStatus();
    }

    /** 控制消息（hello/ack/finished/failed）：入队后必定写出，不合并、不丢弃。 */
    private void write(JSONObject json) {
        writeQueue.offer(json);
    }

    /** 状态快照：队列里只保留最新一条，绝不阻塞调用方（可能来自重放线程）。 */
    private void writeStatus(JSONObject status) {
        pendingStatus.set(status);
        if (statusTokenPending.compareAndSet(false, true)) {
            writeQueue.offer(STATUS_TOKEN);
        }
    }

    private void ackOk(Long id) {
        JSONObject ack = new JSONObject();
        ack.put("type", "ack");
        ack.put("id", id);
        ack.put("ok", true);
        write(ack);
    }

    private void ackError(Long id, String code, String message) {
        JSONObject ack = new JSONObject();
        ack.put("type", "ack");
        ack.put("id", id);
        ack.put("ok", false);
        ack.put("error", errorObject(code, message));
        write(ack);
    }

    private static JSONObject errorJson(Throwable t) {
        String msg = t.getMessage();
        return errorObject("REPLAY_FAILED", msg == null ? t.getClass().getSimpleName() : msg);
    }

    private static JSONObject errorObject(String code, String message) {
        JSONObject err = new JSONObject();
        err.put("code", code);
        err.put("message", message);
        return err;
    }
}
