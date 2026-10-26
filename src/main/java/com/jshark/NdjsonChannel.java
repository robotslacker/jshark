package com.jshark;

import com.alibaba.fastjson2.JSONObject;

import java.io.PrintStream;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 控制通道的 NDJSON 写端（采集/转发子进程共用）。
 *
 * <h3>为什么单独抽出来</h3>
 * <p>
 * {@link CaptureControl} 与 {@link ForwarderControl} 的 hello/ack/terminal 是三份逐字相同的
 * JSON 拼装，连"只有第一个 terminal 生效"的 CAS 都一样。协议字段一旦改错一处，父进程就会
 * 卡在等 hello 或收不到终态；集中到这里之后，两个子进程的线路格式只可能完全一致。
 * </p>
 *
 * <p>只负责"写"，不负责状态机：state/message 由各自的控制类维护，terminal 由调用方显式
 * {@link #claimTerminal()} 后再写，避免"终态写两次"。</p>
 */
final class NdjsonChannel {

    private final PrintStream out;
    private final Object outLock = new Object();
    private final String session = UUID.randomUUID().toString();
    private final AtomicLong seq = new AtomicLong();
    private final AtomicBoolean terminalSent = new AtomicBoolean();

    /**
     * @param out 协议输出流（stdout；测试可传内存流）
     */
    NdjsonChannel(PrintStream out) {
        this.out = out;
    }

    /** @return 下一个 status 序号（从 1 开始） */
    long nextSeq() {
        return seq.incrementAndGet();
    }

    /**
     * 写一条消息并 flush。
     *
     * @param message NDJSON 对象
     */
    void write(JSONObject message) {
        synchronized (outLock) {
            out.println(message.toJSONString());
            out.flush();
        }
    }

    /**
     * 发送握手消息（必须是第一条）。
     *
     * @param protocolVersion 协议版本
     */
    void hello(int protocolVersion) {
        JSONObject hello = new JSONObject();
        hello.put("type", "hello");
        hello.put("protocol", protocolVersion);
        hello.put("session", session);
        write(hello);
    }

    /**
     * 回复命令。
     *
     * @param id    命令 id（原样带回）
     * @param ok    是否成功
     * @param error 失败原因；成功时为 null/空
     */
    void ack(long id, boolean ok, String error) {
        JSONObject o = new JSONObject();
        o.put("type", "ack");
        o.put("id", id);
        o.put("ok", ok);
        if (!ok) {
            o.put("error", error);
        }
        write(o);
    }

    /**
     * 抢占"终态只发一次"的资格。
     *
     * @return true 表示本次调用应继续写 terminal；false 表示已经写过
     */
    boolean claimTerminal() {
        return terminalSent.compareAndSet(false, true);
    }

    /**
     * 写终态消息（调用前必须先 {@link #claimTerminal()}）。
     *
     * @param state   终态（FINISHED 表示成功，其它为失败）
     * @param message 失败原因；成功时为空
     */
    void terminal(String state, String message) {
        JSONObject o = new JSONObject();
        o.put("type", "terminal");
        o.put("ok", "FINISHED".equals(state));
        o.put("state", state);
        o.put("message", message);
        write(o);
    }
}
