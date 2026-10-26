package com.jshark;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.forwarder.ForwarderFactory;
import com.jshark.forwarder.ForwarderStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 转发器的 stdio 控制通道（{@code --control stdio}）。
 *
 * <p>协议与采集端一致：stdout 只走 NDJSON，日志走 stderr；状态每 250ms 推一次。
 * 额外字段：{@code mode / udpToTcp / tcpToUdp / peers}。状态机/hello/终态/EOF 清理
 * 在 {@link ControlSession}，本类只负责"构建转发器 / pause-resume / status 负载"。</p>
 */
final class ForwarderControl extends ControlSession {

    private static final Logger logger = LoggerFactory.getLogger(ForwarderControl.class);

    static final int PROTOCOL_VERSION = 1;

    private final Map<String, String> options;
    private volatile long startNanos;
    private volatile String mode;
    private volatile ForwarderStatus.Source source;

    private ForwarderControl(Map<String, String> options, InputStream in, PrintStream out) {
        super(in, out, logger, "forwarder-control", "[SERVER]");
        this.options = options;
    }

    static void run(Map<String, String> options) {
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true,
                StandardCharsets.UTF_8);
        new ForwarderControl(options, System.in, out).loop();
    }

    @Override
    protected int protocolVersion() {
        return PROTOCOL_VERSION;
    }

    @Override
    protected long stopJoinMs() {
        return 10_000L;
    }

    @Override
    protected boolean beforeCommandLoop() {
        try {
            ForwarderFactory.Built built = ForwarderFactory.create(options, logger);
            this.mode = built.mode();
            this.source = built.source();
            return true;
        } catch (RuntimeException e) {
            mode = "bridge";
            setMessage(e.getMessage() == null ? e.toString() : e.getMessage());
            setState("FAILED");
            logger.error("[SERVER] Forwarder config error: {}", e.getMessage());
            emitStatus();
            emitTerminal();
            return false;
        }
    }

    @Override
    protected void onStart() {
        startNanos = System.nanoTime();
    }

    @Override
    protected void runSource() throws Exception {
        source.run();
    }

    @Override
    protected void requestStopSource() {
        ForwarderStatus.Source src = source;
        if (src != null) {
            src.stop();
        }
    }

    @Override
    protected String startRejectedMessage() {
        return "forwarder already started";
    }

    @Override
    protected String failureLogMessage() {
        return "forwarder failed";
    }

    @Override
    protected void onCommand(String name, long id) {
        if ("pause".equals(name)) {
            source.pause();
            channel.ack(id, true, "");
            return;
        }
        if ("resume".equals(name)) {
            source.resume();
            channel.ack(id, true, "");
            return;
        }
        super.onCommand(name, id);
    }

    @Override
    protected void beforeStatus() {
        updateRunningState();
    }

    private void updateRunningState() {
        ForwarderStatus.Source src = source;
        String current = state();
        if (src == null || !("STARTING".equals(current) || "WAITING".equals(current)
                || "RUNNING".equals(current) || "PAUSED".equals(current))) {
            return;
        }
        if (src.paused()) {
            setState("PAUSED");
        } else {
            setState(src.ready() ? "RUNNING" : "WAITING");
        }
    }

    @Override
    protected JSONObject statusJson(long seq, String state, String message) {
        return statusJson(seq, state, mode, message, elapsedMs(),
                source == null ? null : safeSnapshot());
    }

    private long elapsedMs() {
        return startNanos == 0 ? 0 : (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private ForwarderStatus.Snapshot safeSnapshot() {
        try {
            return source.snapshot();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * 构造一条 status（包内可见：便于无头单测字段契约）。
     */
    static JSONObject statusJson(long seq, String state, String mode, String message,
                                 long elapsedMs, ForwarderStatus.Snapshot snap) {
        JSONObject o = new JSONObject();
        o.put("type", "status");
        o.put("seq", seq);
        o.put("state", state);
        o.put("mode", mode);
        o.put("message", message == null ? "" : message);
        o.put("elapsedMs", elapsedMs);
        if (snap == null) {
            o.put("udpToTcp", direction(0, 0));
            o.put("tcpToUdp", direction(0, 0));
            o.put("dropped", 0L);
            o.put("udpIn", 0L);
            o.put("dropRate", 0.0);
            o.put("listen", "");
            o.put("udpLocal", "");
            o.put("peers", new JSONArray());
        } else {
            o.put("udpToTcp", direction(snap.udpToTcp().packets(), snap.udpToTcp().bytes()));
            o.put("tcpToUdp", direction(snap.tcpToUdp().packets(), snap.tcpToUdp().bytes()));
            o.put("dropped", snap.dropped());
            o.put("udpIn", snap.ingress());
            o.put("dropRate", snap.ingress() > 0
                    ? (double) snap.dropped() / snap.ingress() : 0.0);
            o.put("listen", snap.listen());
            o.put("udpLocal", snap.udpLocal());
            JSONArray peers = new JSONArray();
            for (ForwarderStatus.Peer peer : snap.peers()) {
                JSONObject p = new JSONObject();
                p.put("address", peer.address());
                p.put("state", peer.state());
                p.put("sinceMs", peer.sinceMs());
                peers.add(p);
            }
            o.put("peers", peers);
        }
        o.put("paused", "PAUSED".equals(state));
        return o;
    }

    private static JSONObject direction(long packets, long bytes) {
        JSONObject d = new JSONObject();
        d.put("packets", packets);
        d.put("bytes", bytes);
        return d;
    }
}
