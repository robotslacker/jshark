package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * 子进程 stdio 控制会话的公共骨架（采集端与转发端共用）。
 *
 * <h3>职责边界</h3>
 * <p>
 * 这里只放两份控制通道里<b>逐字相同</b>的部分：hello/状态轮询/命令读取/start-stop 状态机/
 * 终态只发一次/EOF 清理。具体的"启动什么、怎么停、status 带哪些字段"仍由子类实现。
 * </p>
 *
 * <p>状态机（与历史行为一致）：</p>
 * <pre>
 * READY --start--> STARTING --(run 返回)--> FINISHED
 *                                   \--(抛异常)--> FAILED
 * READY/STARTING/... --stop--> STOPPING --(run 返回)--> FINISHED
 * 任意非终态 --stdin EOF--> 停止并等待
 * </pre>
 */
abstract class ControlSession {

    private static final long STATUS_INTERVAL_MS = 250L;

    protected final NdjsonChannel channel;
    private final InputStream in;
    private final Logger logger;
    private final String threadPrefix;
    private final String logTag;

    private volatile String state = "READY";
    private volatile String message = "";
    private volatile boolean closed = false;
    private volatile Thread runThread;

    /**
     * @param in           命令输入（stdin 或测试内存流）
     * @param out          协议输出（stdout 或测试内存流）
     * @param logger       子类 logger（保留原有 logger 名称）
     * @param threadPrefix 线程名前缀，如 {@code capture-control}
     * @param logTag       日志前缀，如 {@code [JShark]} / {@code [SERVER]}
     */
    protected ControlSession(InputStream in, PrintStream out, Logger logger,
                             String threadPrefix, String logTag) {
        this.in = in;
        this.logger = logger;
        this.threadPrefix = threadPrefix;
        this.logTag = logTag;
        this.channel = new NdjsonChannel(out);
    }

    // ==================== 子类实现 ====================

    /** @return 协议版本（hello 里带） */
    protected abstract int protocolVersion();

    /** @return EOF/stop 之后等待工作线程收尾的预算（毫秒） */
    protected abstract long stopJoinMs();

    /**
     * 构造一条 status 消息（子类负责自己的负载字段）。
     *
     * @param seq     序号
     * @param state   当前状态
     * @param message 提示/错误
     * @return NDJSON 对象
     */
    protected abstract JSONObject statusJson(long seq, String state, String message);

    /**
     * 真正的工作体（阻塞到结束）。
     *
     * @throws Exception 失败原因会进入 FAILED 状态与 terminal 消息
     */
    protected abstract void runSource() throws Exception;

    /** 停止工作体（可重复调用；未开始时必须安全）。 */
    protected abstract void requestStopSource();

    /** @return start 被重复调用时的提示主语，如 {@code capture already started} */
    protected abstract String startRejectedMessage();

    /** @return 工作体异常时的日志文案，如 {@code capture failed} */
    protected abstract String failureLogMessage();

    /**
     * 命令循环之前的准备（转发端在这里构建转发器）。
     *
     * @return false 表示准备失败且已经发过终态，不再进入命令循环
     */
    protected boolean beforeCommandLoop() {
        return true;
    }

    /** 每次状态轮询前的钩子（转发端用它把 WAITING/RUNNING/PAUSED 同步出来）。 */
    protected void beforeStatus() {
    }

    /** start 被接受后的钩子（转发端用它记录起始时刻）。 */
    protected void onStart() {
    }

    // ==================== 公共流程 ====================

    /** 进入控制模式并阻塞到 stdin EOF（或工作体结束）。 */
    final void loop() {
        // hello 必须是第一条：先握手，再发状态/启动线程
        channel.hello(protocolVersion());
        if (!beforeCommandLoop()) {
            return;   // 准备阶段已经失败并发过状态/终态
        }
        emitStatus();

        Thread statusThread = new Thread(this::statusLoop, threadPrefix + "-status");
        statusThread.setDaemon(true);
        statusThread.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    handle(line);
                }
            }
        } catch (Exception e) {
            logger.warn("{} control channel read failed: {}", logTag, e.toString());
        } finally {
            closed = true;
            // 父进程没了：不能让工作进程变成孤儿
            requestStopSource();
            joinRun();
            emitStatus();
        }
    }

    private void handle(String line) {
        JSONObject cmd;
        try {
            cmd = JSON.parseObject(line);
        } catch (Exception e) {
            logger.warn("{} bad control command: {}", logTag, line);
            return;
        }
        if (cmd == null) {
            return;
        }
        onCommand(cmd.getString("cmd"), cmd.getLongValue("id"));
    }

    /**
     * 命令分派（子类可覆盖以增加 pause/resume，其余交给默认实现）。
     *
     * @param name 命令名
     * @param id   命令 id（ack 原样带回）
     */
    protected void onCommand(String name, long id) {
        switch (name == null ? "" : name) {
            case "start" -> start(id);
            case "stop" -> stop(id);
            default -> channel.ack(id, false, "unknown command: " + name);
        }
    }

    /** 处理 start：READY → STARTING，后台线程跑工作体。 */
    protected final void start(long id) {
        if (!"READY".equals(state)) {
            channel.ack(id, false, startRejectedMessage() + " (state=" + state + ")");
            return;
        }
        state = "STARTING";
        onStart();
        channel.ack(id, true, "");
        runThread = new Thread(() -> {
            try {
                runSource();
                if (!"FAILED".equals(state)) {
                    state = "FINISHED";
                }
            } catch (Throwable t) {
                message = t.getMessage() == null ? t.toString() : t.getMessage();
                state = "FAILED";
                logger.error("{} {}", logTag, failureLogMessage(), t);
            } finally {
                emitTerminal();
            }
        }, threadPrefix + "-main");
        runThread.start();
    }

    /** 处理 stop：请求停止并回 ack。 */
    protected final void stop(long id) {
        requestStopSource();
        if (!isTerminal()) {
            state = "STOPPING";
        }
        channel.ack(id, true, "");
    }

    private void joinRun() {
        Thread t = runThread;
        if (t == null) {
            return;
        }
        try {
            t.join(stopJoinMs());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void statusLoop() {
        while (!closed) {
            beforeStatus();
            emitStatus();
            if (isTerminal()) {
                emitTerminal();
            }
            try {
                Thread.sleep(STATUS_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /** 发送终态（只发一次）。 */
    protected final void emitTerminal() {
        if (!channel.claimTerminal()) {
            return;
        }
        channel.terminal(state, message);
        emitStatus();
    }

    /** 发送一条 status。 */
    protected final void emitStatus() {
        channel.write(statusJson(channel.nextSeq(), state, message));
    }

    /** @return 是否已进入终态（FINISHED/FAILED） */
    protected final boolean isTerminal() {
        return "FINISHED".equals(state) || "FAILED".equals(state);
    }

    /** @return 当前状态 */
    protected final String state() {
        return state;
    }

    /**
     * 设置状态（子类只在准备阶段/状态同步钩子里使用）。
     *
     * @param newState 新状态
     */
    protected final void setState(String newState) {
        this.state = newState;
    }

    /**
     * 设置终态/错误消息。
     *
     * @param newMessage 可读消息
     */
    protected final void setMessage(String newMessage) {
        this.message = newMessage;
    }
}
