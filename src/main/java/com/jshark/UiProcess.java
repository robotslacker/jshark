package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 界面与 headless 子进程之间的 stdio 客户端（三个 UI 共用）。
 *
 * <h3>职责</h3>
 * <ul>
 *   <li>启动进程、建立 UTF-8 stdin，起 stdout/stderr/wait 三个守护线程；</li>
 *   <li>stdout 每行按 NDJSON 解析，交给 {@link Events#onEvent(JSONObject)}；坏 JSON 走日志；</li>
 *   <li>stderr 每行交给 {@link Events#onLog(String)}；</li>
 *   <li>带上自增 id 写命令、关闭 stdin、强制结束进程。</li>
 * </ul>
 *
 * <p>消息语义（hello/status/ack/terminal/...）由各 UI 在自己的 {@code Events} 里分派，
 * 这里不解释任何 type。</p>
 */
final class UiProcess {

    /** 子进程事件回调（均在读取线程上调用，UI 实现负责切回 EDT）。 */
    interface Events {
        void onEvent(JSONObject json);

        void onLog(String line);

        void onExit(int code);
    }

    private final Process process;
    private final BufferedWriter stdin;
    private final AtomicLong nextId = new AtomicLong(1);
    private final AtomicBoolean closed = new AtomicBoolean();

    private UiProcess(Process process) {
        this.process = process;
        this.stdin = new BufferedWriter(new OutputStreamWriter(
                process.getOutputStream(), StandardCharsets.UTF_8));
    }

    /**
     * 启动子进程并开始读取输出。
     *
     * @param command     完整命令行（由 {@link UiLauncher} 生成）
     * @param threadPrefix 读线程名前缀，如 {@code capture-ui}
     * @param events      事件回调
     * @return 客户端
     * @throws IOException 进程启动失败
     */
    static UiProcess start(List<String> command, String threadPrefix, Events events) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(false);
        pb.directory(new File(System.getProperty("user.dir")));
        Process process = pb.start();
        UiProcess client = new UiProcess(process);

        Thread out = new Thread(() -> client.readStdout(events), threadPrefix + "-stdout");
        out.setDaemon(true);
        out.start();
        Thread err = new Thread(() -> client.readStderr(events), threadPrefix + "-stderr");
        err.setDaemon(true);
        err.start();
        Thread wait = new Thread(() -> {
            try {
                int code = process.waitFor();
                events.onExit(code);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, threadPrefix + "-wait");
        wait.setDaemon(true);
        wait.start();
        return client;
    }

    private void readStdout(Events events) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                JSONObject json;
                try {
                    json = JSON.parseObject(line);
                } catch (Exception e) {
                    events.onLog("[protocol] bad JSON: " + line);
                    continue;
                }
                if (json == null) {
                    continue;
                }
                events.onEvent(json);
            }
        } catch (IOException e) {
            if (!closed.get()) {
                events.onLog("[protocol] read failed: " + e.getMessage());
            }
        }
    }

    private void readStderr(Events events) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                events.onLog(line);
            }
        } catch (IOException e) {
            if (!closed.get()) {
                events.onLog("[stderr] read failed: " + e.getMessage());
            }
        }
    }

    /**
     * 写一条不带参数的命令。
     *
     * @return 命令 id
     * @throws IOException 写失败
     */
    long send(String cmd) throws IOException {
        return send(cmd, null);
    }

    /**
     * 写一条控制命令。
     *
     * @param cmd  命令名
     * @param args 附加参数；null 表示没有
     * @return 命令 id（写失败时抛出）
     * @throws IOException 写失败
     */
    long send(String cmd, Map<String, Object> args) throws IOException {
        long id = nextId.getAndIncrement();
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("cmd", cmd);
        if (args != null) {
            args.forEach(json::put);
        }
        synchronized (stdin) {
            stdin.write(json.toJSONString());
            stdin.newLine();
            stdin.flush();
        }
        return id;
    }

    /** 关闭 stdin（让子进程读到 EOF 后自然退出）。 */
    void closeStdin() {
        try {
            stdin.close();
        } catch (IOException ignored) {
            // 已经关闭/进程已退出
        }
    }

    /** 立即强杀（用于看门狗超时/关窗兜底）。 */
    void kill() {
        closed.set(true);
        closeStdin();
        process.destroyForcibly();
    }

    /**
     * 先请求正常结束，超时后升级为强杀。
     *
     * @param waitMs 等待正常退出的毫秒数
     */
    void terminate(long waitMs) {
        closed.set(true);
        process.destroy();
        try {
            if (!process.waitFor(waitMs, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** @return 底层进程（停止/等待等特殊逻辑使用） */
    Process process() {
        return process;
    }

    /** @return 是否已被主动关闭 */
    boolean isClosed() {
        return closed.get();
    }
}
