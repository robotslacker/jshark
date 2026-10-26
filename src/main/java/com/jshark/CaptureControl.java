package com.jshark;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.PacketCapture.Snapshot;
import com.jshark.PacketCapture.VolumeRow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * 采集端的 stdio 控制通道（{@code --control stdio}）。
 *
 * <h3>协议（NDJSON，一行一条）</h3>
 * <pre>
 * 子进程 → 父进程
 *   {"type":"hello","protocol":1,"session":"..."}
 *   {"type":"status","seq":1,"state":"READY|STARTING|RUNNING|STOPPING|FINISHED|FAILED",
 *    "elapsedMs":0,"captured":0,"stored":0,"filtered":0,"dropped":0,"bytes":0,
 *    "currentVolume":null,"volumes":[{"seq":1,"file":"...","startMs":0,"endMs":0,
 *    "packets":0,"bytes":0,"status":"capturing"}],"message":""}
 *   {"type":"ack","id":1,"ok":true}
 *   {"type":"terminal","ok":true,"message":""}
 *
 * 父进程 → 子进程
 *   {"id":1,"cmd":"start"}
 *   {"id":2,"cmd":"stop"}
 * </pre>
 *
 * <p>状态机/hello/终态/EOF 清理在 {@link ControlSession}；本类只提供"启动采集 / 停止采集 /
 * status 负载"三件事。</p>
 */
final class CaptureControl extends ControlSession {

    private static final Logger logger = LoggerFactory.getLogger(CaptureControl.class);

    /** 协议版本：字段只增不改；父进程不匹配时拒绝启动。 */
    static final int PROTOCOL_VERSION = 1;

    private final CliShark cli;

    private CaptureControl(CliShark cli, InputStream in, PrintStream out) {
        super(in, out, logger, "capture-control", "[JShark]");
        this.cli = cli;
    }

    /**
     * 进入控制模式并阻塞到父进程关闭 stdin（或采集结束）。
     */
    static void run(CliShark cli) {
        // 显式 UTF-8：Windows 控制台默认代码页会把非 ASCII 路径写坏
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), true,
                StandardCharsets.UTF_8);
        new CaptureControl(cli, System.in, out).loop();
    }

    /** 测试用：把 stdin/stdout 换成内存流，不触碰真实进程的 stdio。 */
    static CaptureControl forTest(CliShark cli, InputStream in, PrintStream out) {
        return new CaptureControl(cli, in, out);
    }

    @Override
    protected int protocolVersion() {
        return PROTOCOL_VERSION;
    }

    @Override
    protected long stopJoinMs() {
        return 9_000L;
    }

    @Override
    protected void runSource() {
        // 阻塞到采集结束；失败以异常形式抛出，由 ControlSession 置为 FAILED
        cli.startCapture();
    }

    @Override
    protected void requestStopSource() {
        cli.requestStop();
    }

    @Override
    protected String startRejectedMessage() {
        return "capture already started";
    }

    @Override
    protected String failureLogMessage() {
        return "capture failed";
    }

    @Override
    protected JSONObject statusJson(long seq, String state, String message) {
        return statusJson(seq, state, message, cli.captureSnapshot());
    }

    /**
     * 构造一条 status 消息（包内可见：便于无头单测协议字段）。
     *
     * @param seq     递增序号
     * @param state   状态
     * @param message 提示/错误
     * @param snap    快照，可为 null（尚未开始）
     * @return NDJSON 对象
     */
    static JSONObject statusJson(long seq, String state, String message, Snapshot snap) {
        JSONObject o = new JSONObject();
        o.put("type", "status");
        o.put("seq", seq);
        o.put("state", state);
        o.put("message", message == null ? "" : message);
        if (snap == null) {
            o.put("elapsedMs", 0L);
            o.put("captured", 0L);
            o.put("stored", 0L);
            o.put("filtered", 0L);
            o.put("dropped", 0L);
            o.put("bytes", 0L);
            o.put("currentVolume", null);
            o.put("volumes", new JSONArray());
        } else {
            o.put("elapsedMs", snap.elapsedMs());
            o.put("captured", snap.captured());
            o.put("stored", snap.stored());
            o.put("filtered", snap.filtered());
            o.put("dropped", snap.dropped());
            o.put("bytes", snap.bytes());
            o.put("currentVolume", snap.currentVolume());
            JSONArray volumes = new JSONArray();
            // 长跑时分卷可能成千上万：协议只带最近 200 条，避免每 250ms 一条巨大的消息。
            java.util.List<VolumeRow> rows = snap.volumes();
            int from = Math.max(0, rows.size() - 200);
            for (int i = from; i < rows.size(); i++) {
                VolumeRow row = rows.get(i);
                JSONObject v = new JSONObject();
                v.put("seq", row.seq());
                v.put("file", row.file());
                v.put("startMs", row.startMs());
                v.put("endMs", row.endMs());
                v.put("packets", row.packets());
                v.put("bytes", row.bytes());
                v.put("status", row.status());
                volumes.add(v);
            }
            o.put("volumes", volumes);
        }
        return o;
    }
}
