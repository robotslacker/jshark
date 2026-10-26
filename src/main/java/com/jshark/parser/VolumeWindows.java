package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 时间分卷窗口：按<b>自然时间网格</b>把采集过程切成固定长度的归档窗口。
 *
 * <h3>语义（与文档承诺一致）</h3>
 * <pre>
 *   窗口 k： [startMs, endMs)，startMs 与 endMs 都落在时间网格上
 *   首窗  ： start = 采集启动时刻（可能落在网格中间），end = 下一个网格边界
 *   后续窗： 由前一个边界经 alignToGrid 推进 —— 每步都精确落在网格上，不累积漂移
 * </pre>
 * <ul>
 *   <li><b>零消息也出卷</b>：时间一到就切窗口，哪怕窗口内一条消息都没有。
 *       审计场景需要"时间段可寻址"，静默跳过空窗口会让下游按时间对齐时出现"缺卷"。</li>
 *   <li><b>跨多个边界补齐</b>：一次卡顿/时钟跳跃跨过 m 个边界时，补齐中间 m−1 个空窗口，
 *       窗口序列不跳号。</li>
 *   <li><b>文件名</b>：{@code <base>_<yyyyMMddHHmmss><ext>}，时间戳为窗口起始时刻。</li>
 * </ul>
 *
 * <h3>为什么单独抽一个类</h3>
 * <p>
 * 早期实现里 PCAP 与 logdb 各自维护一套"卷起始时间"（{@code PacketLogger} 与
 * {@code PacketCapture} 各一份），初始化时机不同就会整体错位一个周期，两个输出文件集合
 * 的时间戳对不上。现在两者共用同一个 {@code VolumeWindows} 实例，只有一个时钟。
 * </p>
 *
 * <h3>线程模型</h3>
 * <p>
 * 只被采集线程使用（{@link #advance(long)} 在抓包循环里调用），因此内部状态无需同步。
 * </p>
 */
public class VolumeWindows {

    private static final Logger logger = LoggerFactory.getLogger(VolumeWindows.class);

    /** 一个已关闭的窗口 */
    public record ClosedWindow(long volumeSeq, long startMs, long endMs, boolean complete,
                               String closedReason) {
    }

    /**
     * 一次推进的结果。
     *
     * @param closed      本次推进关闭掉的窗口（按时间顺序，可能多个；未跨边界时为空）
     * @param currentSeq  推进后当前窗口的序号
     * @param currentStart 推进后当前窗口的起始时刻
     * @param currentEnd  推进后当前窗口的结束边界（= 下一个网格边界）
     */
    public record Advance(List<ClosedWindow> closed, long currentSeq, long currentStart, long currentEnd) {
        /** @return 本次推进是否发生了窗口切换 */
        public boolean rotated() {
            return !closed.isEmpty();
        }
    }

    private final long intervalMs;
    private final String basePath;
    private final String base;
    private final String ext;

    /**
     * 时间来源（毫秒）。默认取系统时钟；测试可注入可控时钟，
     * 使"跨边界轮转/补齐空卷"这类行为无需真实等待即可验证。
     */
    private final java.util.function.LongSupplier clock;

    private boolean initialized = false;
    private long seq = 0;
    private long startMs = 0;
    private long endMs = 0;

    /**
     * 构造时间窗管理器（使用系统时钟）。
     *
     * @param basePath   基准输出路径（如 {@code /data/capture.db}）；null 表示只做时间推进、不产生文件名
     * @param intervalMs 窗口长度（毫秒），必须 &gt; 0
     */
    public VolumeWindows(String basePath, long intervalMs) {
        this(basePath, intervalMs, System::currentTimeMillis);
    }

    /**
     * 构造时间窗管理器（可注入时钟）。
     *
     * @param basePath   基准输出路径；null 表示只做时间推进
     * @param intervalMs 窗口长度（毫秒），必须 &gt; 0
     * @param clock      毫秒时间来源，必须非 null
     */
    public VolumeWindows(String basePath, long intervalMs, java.util.function.LongSupplier clock) {
        if (intervalMs <= 0) {
            throw new IllegalArgumentException("intervalMs must be greater than 0, got: " + intervalMs);
        }
        this.intervalMs = intervalMs;
        this.clock = clock != null ? clock : System::currentTimeMillis;
        this.basePath = basePath;
        if (basePath == null) {
            this.base = null;
            this.ext = "";
        } else {
            int dot = basePath.lastIndexOf('.');
            int slash = Math.max(basePath.lastIndexOf('/'), basePath.lastIndexOf('\\'));
            if (dot > slash && dot > 0) {
                this.base = basePath.substring(0, dot);
                this.ext = basePath.substring(dot);
            } else {
                this.base = basePath;
                this.ext = "";
            }
        }
    }

    /**
     * 初始化第一个窗口：起始于给定时刻，结束于其后的第一个网格边界。
     * <p>
     * 首窗可能短于一个完整间隔（例如 10:03 启动、间隔 5 分钟 → 首窗 10:03–10:05），
     * 这是"按自然时间归档"的必然结果：宁可首窗短，也不让窗口边界脱离网格。
     * </p>
     *
     * @param nowMs 采集启动时刻（毫秒）
     */
    public void initialize(long nowMs) {
        this.seq = 1;
        this.startMs = nowMs;
        this.endMs = nextBoundary(nowMs);
        this.initialized = true;
        logger.info("[JShark] Time windows: interval={} ms, first window [{} .. {}), volume seq=1",
                intervalMs, SplitUtil.formatTimestamp(startMs), SplitUtil.formatTimestamp(endMs));
    }

    /**
     * 按当前时间推进（使用构造时注入的时钟）。
     *
     * @return 推进结果
     */
    public Advance advance() {
        return advance(clock.getAsLong());
    }

    /**
     * 把当前时间推进到对应窗口。
     * <p>
     * 若 {@code nowMs} 已越过当前窗口的结束边界，则：
     * 依次关闭当前窗口、补齐中间被完整跨过的空窗口、开启新窗口。
     * 每个被关闭的窗口都会出现在返回值的 {@code closed} 列表中（时间顺序）。
     * </p>
     *
     * @param nowMs 当前时间（毫秒）
     * @return 推进结果
     */
    public Advance advance(long nowMs) {
        if (!initialized) {
            throw new IllegalStateException("VolumeWindows is not initialized; call initialize() first");
        }
        List<ClosedWindow> closed = new ArrayList<>();
        // 用 while 而非 if：一次卡顿可能跨过多个边界，必须逐个补齐，否则窗口会跳号
        while (nowMs >= endMs) {
            long closedSeq = seq;
            long closedStart = startMs;
            long closedEnd = endMs;
            // 中间窗口（不是被 nowMs 落入的那个）在关闭时就是"完整走完"的
            closed.add(new ClosedWindow(closedSeq, closedStart, closedEnd, true, "boundary"));

            long newStart = endMs;
            long newEnd = nextBoundary(newStart);
            seq = closedSeq + 1;
            startMs = newStart;
            endMs = newEnd;

            logger.info("[JShark] Time window boundary reached: closed volume seq={} [{} .. {}), "
                            + "opening seq={} [{} .. {})",
                    closedSeq, SplitUtil.formatTimestamp(closedStart), SplitUtil.formatTimestamp(closedEnd),
                    seq, SplitUtil.formatTimestamp(newStart), SplitUtil.formatTimestamp(newEnd));
        }
        return new Advance(closed, seq, startMs, endMs);
    }

    /**
     * 计算给定时刻之后的第一个网格边界。
     * <p>
     * 用<b>本地日历算术</b>直接求"下一个边界"，而不是"把当前时刻向下取整后当作边界"——
     * 后者在时刻不落在网格上时会返回一个早于输入的值。做法：
     * </p>
     * <ol>
     *   <li>取本地当日零点，算出当日已过的毫秒数；</li>
     *   <li>向下取整到间隔的整数倍，再加一个间隔，即为当日之内的下一个边界；</li>
     *   <li>若已越过当日末尾，则取次日零点的对应倍数（跨天时自动落到 00:00 起的网格）。</li>
     * </ol>
     * <p>
     * 全部计算都在本地时区进行，因此自然覆盖"整分/整点/本地零点"的对齐要求，
     * 且每步都相对当日网格计算，长时间运行不累积漂移。
     * </p>
     *
     * @param fromMs 起始时刻
     * @return 严格大于 fromMs 的最近网格边界
     */
    private long nextBoundary(long fromMs) {
        java.time.ZonedDateTime zdt = java.time.Instant.ofEpochMilli(fromMs)
                .atZone(java.time.ZoneId.systemDefault());
        java.time.ZonedDateTime startOfDay = zdt.toLocalDate()
                .atStartOfDay(java.time.ZoneId.systemDefault());
        long startOfDayMillis = startOfDay.toInstant().toEpochMilli();
        long millisOfDay = fromMs - startOfDayMillis;

        long next = (Math.floorDiv(millisOfDay, intervalMs) + 1) * intervalMs;
        long candidate = startOfDayMillis + next;

        // 跨天：next 可能超过当日长度（例如 1d 间隔正好等于一天），此时取次日零点对应倍数
        if (next >= 24L * 60 * 60 * 1000) {
            long dayIndex = Math.floorDiv(next, 24L * 60 * 60 * 1000);
            long remainder = next - dayIndex * 24L * 60 * 60 * 1000;
            candidate = startOfDay.plusDays(dayIndex).toInstant().toEpochMilli() + remainder;
        }

        // 兜底：确保严格前进（时钟回拨、夏令时跳变等极端情况）
        if (candidate <= fromMs) {
            candidate = fromMs + intervalMs;
        }
        return candidate;
    }

    /** @return 当前窗口序号（从 1 开始） */
    public long currentSeq() {
        return seq;
    }

    /** @return 当前窗口起始时刻（毫秒） */
    public long currentStartMs() {
        return startMs;
    }

    /** @return 当前窗口结束边界（毫秒，不含） */
    public long currentEndMs() {
        return endMs;
    }

    /** @return 窗口长度（毫秒） */
        /** @return 是否已初始化 */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * 生成指定窗口的<b>捕获中</b> logdb 文件名（完整路径）。
     *
     * <p>分卷模式下，数据库文件在采集过程中以 "{@code <base>_<start>-capturing<ext>}"
     * 命名（{@code start} 为窗口起始时刻的 YYYYMMDDHH24MISS），表示该卷仍在被写入。
     * 一卷完成（到达网格边界或被停机收尾）时，由调用方执行 FORCE CHECKPOINT + 关闭后，
     * 再通过 {@link #finalFileFor(long, long)} 更名为 "{@code <base>_<start>-<end><ext>}"。
     * </p>
     *
     * @param windowStartMs 窗口起始时刻
     * @return 该卷捕获中的 logdb 文件路径；未配置基准路径时返回 null
     */
    public String fileFor(long windowStartMs) {
        if (base == null) {
            return null;
        }
        return base + "_" + SplitUtil.formatTimestamp(windowStartMs) + "-capturing" + ext;
    }

    /**
     * 生成指定窗口的<b>最终（已关闭）</b> logdb 文件名（完整路径）。
     *
     * <p>该卷完成时由采集端把 {@link #fileFor(long)} 的捕获中文件更名为该名：
     * "{@code <base>_<start>-<end><ext>}"，{@code start}/{@code end} 均为窗口边界时刻的
     * YYYYMMDDHH24MISS。文件名携带完整的时间范围，使回放端在给定
     * {@code --start/--end} 时能仅凭文件名判断是否落在窗口内而无需打开数据库。</p>
     *
     * @param startMs 窗口起始时刻
     * @param endMs   窗口结束边界（与该卷 manifest 的 endMs 一致）
     * @return 该卷最终的 logdb 文件路径；未配置基准路径时返回 null
     */
    public String finalFileFor(long startMs, long endMs) {
        if (base == null) {
            return null;
        }
        return base + "_" + SplitUtil.formatTimestamp(startMs)
                + "-" + SplitUtil.formatTimestamp(endMs) + ext;
    }

    /**
     * 生成指定窗口的 PCAP 文件名（完整路径）。
     * <p>
     * 与 {@link #fileFor(long)} 使用同一个时间戳，因此 logdb 与 PCAP 的文件名一一对应 ——
     * 这是早期"两套独立时钟导致两个输出集合错位"问题的根本修法。
     * </p>
     *
     * @param windowStartMs 窗口起始时刻
     * @return pcap 文件路径；未配置基准路径时返回 null
     */
    public String pcapFor(long windowStartMs) {
        if (base == null) {
            return null;
        }
        return base + "_" + SplitUtil.formatTimestamp(windowStartMs) + ".pcap";
    }

    /** @return 基准路径（未配置时为 null） */
    public String basePath() {
        return basePath;
    }
}
