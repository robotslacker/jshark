package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;

/**
 * 周期性吞吐量统计器：按固定间隔（默认 20 秒）打印"过去这一段"的平均流量。
 *
 * <h3>为什么统计"上一段"而不是"从一开始"的累计平均</h3>
 * <p>
 * 累计平均会把启动阶段的爬坡、以及中途的降速一起抹平，看上去永远是"还行"，
 * 掩盖真实问题（例如落库跟不上、内核开始丢包）。按段统计能直接看出趋势：
 * 上一段 120MB/s、这一段掉到 30MB/s 就是要出事了。
 * </p>
 *
 * <h3>口径</h3>
 * <ul>
 *   <li>字节数用<b>抓到的帧长</b>（capLen）累加，与 pcap 文件里实际写入的体积一致；
 *       混合口径（含线上被截断部分）会虚高。</li>
 *   <li>MB 按 1MB = 1048576 字节计算。</li>
 *   <li>包数/字节数与内核丢包数一起打印，便于区分"没流量"和"丢了流量"。</li>
 * </ul>
 *
 * <p><b>线程语义（不要误读）</b>：{@link #addPacket(long)} 可被任意线程调用（计数是原子量）；
 * 但 {@link #tick(String)} / {@link #flush(String)} 对窗口起点做的是"读-再赋值"，<b>必须由单一
 * 驱动线程调用</b>（抓包线程或某一条回放线程），否则窗口会被重复复位、打印出重叠区间。
 * 现行调用点都满足这条约束。</p>
 */
public final class ThroughputMeter {
    private static final Logger logger = LoggerFactory.getLogger(ThroughputMeter.class);

    /** MB 的口径：1MB = 1024*1024 字节 */
    public static final long MB = 1024L * 1024L;

    private final String label;
    private final long intervalMs;
    private final long startMs = System.currentTimeMillis();
    private final AtomicLong packets = new AtomicLong();
    private final AtomicLong bytes = new AtomicLong();

    /** 窗口起点（毫秒）；只由驱动线程读写，见类注释的线程语义 */
    private volatile long windowStartMs;
    private volatile long windowStartPackets;
    private volatile long windowStartBytes;

    /**
     * @param label      打印用的场景名（例如 "Capture" / "Replay"）
     * @param intervalMs 打印间隔（毫秒）；{@code <=0} 时使用默认 20 秒
     */
    public ThroughputMeter(String label, long intervalMs) {
        this.label = label;
        this.intervalMs = intervalMs > 0 ? intervalMs : 20_000L;
        this.windowStartMs = System.currentTimeMillis();
    }

    /**
     * 累加一个已处理的包。
     *
     * @param frameBytes 该包的帧字节数（capLen）
     */
    public void addPacket(long frameBytes) {
        packets.incrementAndGet();
        bytes.addAndGet(frameBytes);
    }

    /**
     * 兼容只需要计包的场景。
     * <p>注意：字节数按 0 计，<b>用在本类的 MB/s 输出上会显示成假的 0</b>。
     * 现行主代码不使用该重载。</p>
     */
    public void addPacket() {
        addPacket(0);
    }

    /**
     * 是否已到打印间隔（<b>无副作用</b>，只读时钟）。
     * <p>
     * 存在的唯一理由：{@code tick(suffix)} 的实参在调用前求值，若 suffix 的构造很贵
     * （例如 {@code pcap_stats} 这种原生调用），逐包调用就变成"每包一次系统调用"。
     * 调用方应先问 {@code shouldTick()}，为真时再去构造 suffix 并调用 {@code tick(suffix)}。
     * </p>
     *
     * @return true 表示此刻调用 {@link #tick(String)} 会真的打印
     */
    public boolean shouldTick() {
        return System.currentTimeMillis() - windowStartMs >= intervalMs;
    }

    /**
     * 到达间隔时打印"过去这一段"的平均流量。由调用方在循环里驱动（不额外起线程）。
     *
     * @param contextSuffix 追加在行尾的补充信息（可为 null），例如内核丢包数
     * @return true 表示本次真的打印了
     */
    public boolean tick(String contextSuffix) {
        long now = System.currentTimeMillis();
        long elapsed = now - windowStartMs;
        if (elapsed < intervalMs) {
            return false;
        }
        long p = packets.get();
        long b = bytes.get();
        printWindow(now - windowStartMs,
                p - windowStartPackets,
                b - windowStartBytes,
                p, b,
                contextSuffix);
        windowStartMs = now;
        windowStartPackets = p;
        windowStartBytes = b;
        return true;
    }

    /** 到达间隔时打印（无补充信息） */
    public boolean tick() {
        return tick(null);
    }

    /**
     * 打印并复位窗口。用于停机时输出最后一段。
     */
    public void flush() {
        flush(null);
    }

    /**
     * 打印并复位窗口。用于停机时输出最后一段。
     *
     * @param contextSuffix 追加信息（可为 null）
     */
    public void flush(String contextSuffix) {
        long now = System.currentTimeMillis();
        long p = packets.get();
        long b = bytes.get();
        long winMs = now - windowStartMs;
        if (winMs <= 0) {
            return;
        }
        printWindow(winMs, p - windowStartPackets, b - windowStartBytes, p, b, contextSuffix);
        windowStartMs = now;
        windowStartPackets = p;
        windowStartBytes = b;
    }

    private void printWindow(long winMs, long winPackets, long winBytes,
                             long allPackets, long allBytes, String contextSuffix) {
        double secs = winMs / 1000.0;
        if (secs <= 0) {
            secs = 0.001;
        }
        double windowMBps = winBytes / (double) MB / secs;
        double windowPps = winPackets / secs;
        double totalSecs = Math.max(0.001, (System.currentTimeMillis() - startMs) / 1000.0);
        double avgMBps = allBytes / (double) MB / totalSecs;
        logger.info("[JShark] {} rate: {} MB/s ({} pps) over last {}s | cumulative {} packets, {} MB, "
                        + "avg {} MB/s{}",
                label, fmt(windowMBps), fmt(windowPps), fmtSecs(secs),
                allPackets, fmt(allBytes / (double) MB), fmt(avgMBps),
                contextSuffix == null ? "" : contextSuffix);
    }

    private static String fmt(double v) {
        return String.format("%.2f", v);
    }

    /**
     * 秒数用 3 位小数：极短窗口（&lt;1ms）会被地板上限成 0.001s，
     * 若仍按 2 位小数打印就成了 "over last 0.00s" 配一个非零速率，看起来像坏了。
     */
    private static String fmtSecs(double v) {
        return String.format("%.3f", v);
    }

    /** @return 累计处理包数 */
    public long totalPackets() {
        return packets.get();
    }

    /** @return 累计字节数 */
    public long totalBytes() {
        return bytes.get();
    }
}
