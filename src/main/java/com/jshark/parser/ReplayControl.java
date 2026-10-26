package com.jshark.parser;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

/**
 * 重放控制/进度通道：UI 或 stdio 协议线程写请求，重放线程消费；重放线程写进度，读取方无锁读取。
 *
 * <p>只由重放线程调用 {@link #takeSeek()}、{@link #takeSpeed()}、{@link #enterPaused()} 等
 * “消费型”方法；请求方法可被任意线程调用。</p>
 *
 * <p>本类不依赖 Swing、不依赖 JSON；CLI 控制协议与 UI 都通过它取状态。</p>
 */
public final class ReplayControl {

    /** 协议里的非致命告警（回退/参数被忽略等）；重复添加同一 code+message 会去重。 */
    public record Warning(String code, String message) {
    }

    /**
     * 渲染 {@code status} 用的不可变快照：所有字段在同一处读取一次。
     *
     * <p>status 的读取方是另一个线程（协议 writer / UI），如果逐字段去读 control，
     * 同一条消息里的 {@code window}、{@code playhead}、{@code counters} 可能来自不同的瞬间。
     * 这里把“读取一次”收敛成一个值对象，渲染只依赖它。</p>
     *
     * @param stopRequested 是否已请求停止
     * @param paused        是否已进入暂停
     * @param pauseRequested 是否收到了尚未被重放线程消费的暂停请求
     * @param playheadMs    播放头（未开始为 0）
     * @param examined      已检查记录数
     * @param sent          已发送包数
     * @param bytes         已发送字节数
     * @param filtered      被过滤规则排除数
     * @param skipped       无法发送/无法改写数
     * @param failures      已知发送失败数
     * @param windowFromMs  播放窗口起点
     * @param windowToMs    播放窗口终点
     * @param dataStartMs   数据范围起点
     * @param dataEndMs     数据范围终点
     * @param live          是否存在仍在写入的卷
     * @param follow        是否滚动跟随
     * @param waitingForData 是否在等新卷
     * @param targetSpeed   目标倍率（自适应上限）
     * @param currentSpeed  当前倍率
     * @param minSpeed      实际达到过的最低倍率
     * @param adaptive      是否启用自适应
     * @param adaptiveDown  自适应降速次数
     * @param adaptiveUp    自适应提速次数
     * @param pausedNanos   累计暂停时长（纳秒）
     * @param error         失败原因（无则 null）
     * @param warnings      告警快照
     */
    public record Snapshot(boolean stopRequested, boolean paused, boolean pauseRequested,
                           long playheadMs,
                           long examined, long sent, long bytes, long filtered, long skipped,
                           long failures, long windowFromMs, long windowToMs,
                           long dataStartMs, long dataEndMs, boolean live, boolean follow,
                           boolean waitingForData, double targetSpeed, double currentSpeed,
                           double minSpeed, boolean adaptive, int adaptiveDown, int adaptiveUp,
                           long pausedNanos, Throwable error, List<Warning> warnings) {
    }

    /**
     * 取当前状态快照（任意线程可调用）。
     *
     * @return 一次性读出的不可变快照
     */
    public Snapshot snapshot() {
        return new Snapshot(stopRequested, paused, pauseRequested, playheadMs(), examined.sum(),
                sent.sum(), bytes.sum(), filtered.sum(), skipped.sum(), failures.sum(),
                windowFromMs, windowToMs, dataStartMs, dataEndMs, live, follow, waitingForData,
                targetSpeed, currentSpeed, minSpeed, adaptive, adaptiveDown, adaptiveUp,
                pausedNanos, error, List.copyOf(warnings));
    }

    private volatile boolean stopRequested;
    private volatile boolean pauseRequested;
    private volatile boolean paused;

    private final AtomicReference<Double> pendingSpeed = new AtomicReference<>();
    private final AtomicLong pendingSeek = new AtomicLong(Long.MIN_VALUE);

    private final AtomicLong playheadMs = new AtomicLong(Long.MIN_VALUE);
    private final LongAdder examined = new LongAdder();
    private final LongAdder sent = new LongAdder();
    private final LongAdder bytes = new LongAdder();
    private final LongAdder filtered = new LongAdder();
    private final LongAdder skipped = new LongAdder();
    private final LongAdder failures = new LongAdder();

    private volatile long windowFromMs = Long.MIN_VALUE;
    private volatile long windowToMs = Long.MAX_VALUE;
    /** 用户给定的窗口终点上限（--end）；LIVE 可用终点只能在上限内增长。 */
    private volatile long limitWindowToMs = Long.MAX_VALUE;
    private volatile long dataStartMs = Long.MIN_VALUE;
    private volatile long dataEndMs = Long.MAX_VALUE;
    private volatile boolean live;
    private volatile boolean follow;
    private volatile boolean waitingForData;

    private volatile double targetSpeed;
    private volatile double currentSpeed;
    private volatile double minSpeed;
    private volatile boolean adaptive = true;
    private volatile int adaptiveDown;
    private volatile int adaptiveUp;
    private volatile long pausedNanos;

    private final List<Warning> warnings = new CopyOnWriteArrayList<>();

    private volatile boolean endReached;
    private volatile Throwable error;

    /**
     * @param initialSpeed 初始目标倍率（&gt; 0）
     */
    public ReplayControl(double initialSpeed) {
        if (!(initialSpeed > 0) || Double.isNaN(initialSpeed) || Double.isInfinite(initialSpeed)) {
            throw new IllegalArgumentException("speed must be a positive finite number, got: " + initialSpeed);
        }
        this.targetSpeed = initialSpeed;
        this.currentSpeed = initialSpeed;
        this.minSpeed = initialSpeed;
    }

    // ==================== 请求（任意线程） ====================

    public void requestStop() {
        stopRequested = true;
        paused = false;
        pauseRequested = false;
    }

    public void requestPause() {
        if (!stopRequested) {
            pauseRequested = true;
        }
    }

    public void requestResume() {
        paused = false;
        pauseRequested = false;
    }

    /**
     * 覆盖式调速：只保留最新值。
     *
     * @param speed 新目标倍率，必须 &gt; 0 且有限
     */
    public void requestSpeed(double speed) {
        if (!(speed > 0) || Double.isNaN(speed) || Double.isInfinite(speed)) {
            throw new IllegalArgumentException("speed must be a positive finite number, got: " + speed);
        }
        pendingSpeed.set(speed);
    }

    /**
     * 覆盖式定位：只保留最新目标。目标为绝对 epoch 毫秒。
     *
     * @param positionMs 目标捕获时间
     */
    public void requestSeek(long positionMs) {
        pendingSeek.set(positionMs);
    }

    // ==================== 重放线程消费 ====================

    public boolean shouldStop() {
        return stopRequested;
    }

    public boolean pauseRequested() {
        return pauseRequested;
    }

    public boolean isPaused() {
        return paused;
    }

    public boolean hasPendingSeek() {
        return pendingSeek.get() != Long.MIN_VALUE;
    }

    /** @return 最新 seek 目标并清空；没有返回 null */
    public Long takeSeek() {
        long v = pendingSeek.getAndSet(Long.MIN_VALUE);
        return v == Long.MIN_VALUE ? null : v;
    }

    /** @return 最新倍率并清空；没有返回 null */
    public Double takeSpeed() {
        return pendingSpeed.getAndSet(null);
    }

    public void enterPaused() {
        paused = true;
        pauseRequested = false;
    }

    public void leavePaused() {
        paused = false;
    }

    /**
     * 重放线程的统一定时检查点：消费运行中调速请求 → 处理暂停/恢复 → 返回“是否必须放弃当前段”。
     *
     * <p>DB payload、PCAP（payload/frame）、DB frame 三条路径原来各有一份几乎相同的实现，
     * 行为差异也开始分叉（是否清 waitingForData、中断后是否 leavePaused）。收到 seek/stop
     * 立即返回 true，由外层“重开新段”；暂停期间原地等待、恢复后把整条时间轴后移并重置自适应
     * 观测窗口，<b>绝不补发</b>。</p>
     *
     * <p>只由重放线程调用。</p>
     *
     * @param clock               重放时钟
     * @param speedController     自适应降速控制器；null 表示没有
     * @param clearWaitingForData 进入暂停时是否清掉 waitingForData（LIVE 跟随需要）
     * @return true 表示收到 stop/seek（或线程被中断），调用方应放弃当前段
     */
    public boolean checkpoint(ReplayClock clock, AdaptiveSpeedController speedController,
                              boolean clearWaitingForData) {
        Double requested = takeSpeed();
        if (requested != null) {
            clock.setSpeed(requested);
            if (speedController != null) {
                speedController.retarget(requested);
            }
            speedObserved(requested, clock.speed());
            minSpeedObserved(speedController != null ? speedController.minSpeed() : clock.minSpeed());
        }

        if (pauseRequested()) {
            long pauseStart = System.nanoTime();
            enterPaused();
            if (clearWaitingForData) {
                setWaitingForData(false);
            }
            while (isPaused() && !stopRequested && !hasPendingSeek()) {
                try {
                    Thread.sleep(50L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    stopRequested = true;
                    break;
                }
            }
            long pausedNanos = System.nanoTime() - pauseStart;
            if (!stopRequested && !hasPendingSeek()) {
                if (clock.isAnchored()) {
                    clock.shiftTimeline(pausedNanos);
                }
                if (speedController != null) {
                    speedController.resetWindow();
                }
                addPausedNanos(pausedNanos);
            }
            leavePaused();
        }
        return shouldStop() || hasPendingSeek();
    }

    // ==================== 进度上报（重放线程） ====================

    /** 单调推进播放头。 */
    public void position(long captureTimeMs) {
        playheadMs.accumulateAndGet(captureTimeMs, Math::max);
    }

    /** 直接设置播放头（seek 重开段时允许回退）。 */
    public void setPosition(long captureTimeMs) {
        playheadMs.set(captureTimeMs);
    }

    /**
     * 为 seek 重开的新段清理会话内的“段级”标志。
     *
     * <p>不清零累计计数/暂停时长；只清 stop/pause/pendingSeek/end 标志，并把播放头设到目标。</p>
     *
     * @param targetMs 新段起点（epoch ms）
     */
    public void beginNewSegment(long targetMs) {
        stopRequested = false;
        paused = false;
        pauseRequested = false;
        pendingSeek.set(Long.MIN_VALUE);
        endReached = false;
        waitingForData = false;
        setPosition(targetMs);
        // 注意：window 是“整段播放窗口”，不随 seek 重开段收缩；
        // 否则 UI 的拖动范围会越拖越小，“回到起点”也会退化成回到上一次 seek。
    }

    public void sent(long packetBytes) {
        sent.increment();
        bytes.add(packetBytes);
    }

    public void examined() {
        examined.increment();
    }

    public void filtered() {
        filtered.increment();
    }

    public void skipped() {
        skipped.increment();
    }

    public void sendFailed() {
        failures.increment();
    }

    public void speedObserved(double target, double current) {
        this.targetSpeed = target;
        this.currentSpeed = current;
    }

    /** 记录当前实际倍率的下限（自适应降过速后 UI 用来显示“最低降到 x”）。 */
    public void minSpeedObserved(double minSpeed) {
        if (minSpeed > 0) {
            this.minSpeed = minSpeed;
        }
    }

    /** 本次重放是否启用自适应降速（`--speed` 只是上限）。 */
    public void setAdaptive(boolean adaptive) {
        this.adaptive = adaptive;
    }

    /**
     * 记录一条非致命告警（参数被忽略等），供 UI 常驻显示。
     *
     * <p>同一 {@code code+message} 只保留一条：seek 重开段会重复执行同一段参数校验。</p>
     *
     * @param code    稳定的机器可读代码，例如 {@code OPTION_IGNORED}
     * @param message 一行人类可读说明
     */
    public void addWarning(String code, String message) {
        Warning warning = new Warning(code, message);
        if (!warnings.contains(warning)) {
            warnings.add(warning);
        }
    }

    public void adaptiveObserved(int down, int up) {
        this.adaptiveDown = down;
        this.adaptiveUp = up;
    }

    public void addPausedNanos(long nanos) {
        if (nanos > 0) {
            pausedNanos += nanos;
        }
    }

    /**
     * 会话级窗口起点：只在尚未建立时生效（first-wins）。
     *
     * <p>seek 的实现是“中止当前段 → 重建工具再跑一段”，新段会以新起点再次走到这里；
     * 若允许覆盖，窗口就会被逐次收缩到 seek 目标，UI 的拖动范围越拖越小，
     * “回到起点”也会退化成回到上一次 seek。</p>
     *
     * @param fromMs 窗口起点（epoch ms）
     */
    public void windowStartIfUnset(long fromMs) {
        if (windowFromMs == Long.MIN_VALUE) {
            windowFromMs = fromMs;
        }
    }

    /**
     * 会话级窗口终点上限（用户显式 {@code --end} 的终点）：只收紧、不放松。
     *
     * <p>seek 重开段可能会用 {@link Long#MAX_VALUE} 重设窗口，这里不能因此把用户的终点上限抹掉。</p>
     *
     * @param toMs 新上限（epoch ms）
     */
    public void limitWindowTo(long toMs) {
        limitWindowToMs = Math.min(limitWindowToMs, toMs);
    }

    /**
     * 设置会话级窗口：起点 first-wins，终点上限只收紧，终点本身取“已给出的最晚值”。
     *
     * <p>{@code toMs == Long.MAX_VALUE} 表示“没有显式终点”，此时只做上限裁剪，
     * 不会把已知的数据终点（{@link #setWindowTo(long)} 补进来的值）重置回未知状态。</p>
     *
     * @param fromMs 窗口起点（epoch ms）
     * @param toMs   窗口终点或终点上限（epoch ms）
     */
    public void setWindow(long fromMs, long toMs) {
        windowStartIfUnset(fromMs);
        limitWindowTo(toMs);
        if (toMs == Long.MAX_VALUE) {
            windowToMs = Math.min(limitWindowToMs, windowToMs);
        } else {
            windowToMs = Math.min(limitWindowToMs, Math.max(windowToMs, toMs));
        }
    }

    public void setDataRange(long startMs, long endMs) {
        this.dataStartMs = startMs;
        this.dataEndMs = endMs;
    }

    /** 只更新可用数据终点（LIVE：已关闭卷的最新数据时间）。 */
    public void setDataEnd(long endMs) {
        if (dataEndMs == Long.MAX_VALUE || endMs > dataEndMs) {
            dataEndMs = endMs;
        }
    }

    /**
     * 收窄窗口终点：只在当前未设置或更晚时更新，绝不越过用户给定的 --end。
     *
     * @param toMs 新终点（epoch ms）
     */
    public void setWindowTo(long toMs) {
        long current = windowToMs == Long.MAX_VALUE ? toMs : Math.max(windowToMs, toMs);
        windowToMs = Math.min(limitWindowToMs, current);
    }

    public void setLive(boolean live, boolean follow) {
        this.live = live;
        this.follow = follow;
    }

    public void setWaitingForData(boolean waiting) {
        this.waitingForData = waiting;
    }

    public void markEndReached() {
        this.endReached = true;
    }

    public void reportError(Throwable error) {
        this.error = error;
    }

    // ==================== 读取（任意线程） ====================

    public long playheadMs() {
        long v = playheadMs.get();
        return v == Long.MIN_VALUE ? 0 : v;
    }

    public long examinedCount() {
        return examined.sum();
    }

    public long sentBytes() {
        return bytes.sum();
    }

                public long windowFromMs() {
        return windowFromMs;
    }

    public long windowToMs() {
        return windowToMs;
    }

    public long dataStartMs() {
        return dataStartMs;
    }

    public long dataEndMs() {
        return dataEndMs;
    }

    public boolean live() {
        return live;
    }

    public boolean follow() {
        return follow;
    }

    public boolean waitingForData() {
        return waitingForData;
    }

    public double targetSpeed() {
        return targetSpeed;
    }

    public double currentSpeed() {
        return currentSpeed;
    }

    /** @return 本次重放实际达到过的最低倍率 */
    public double minSpeed() {
        return minSpeed;
    }

    /** @return 是否启用自适应降速 */
    public boolean adaptive() {
        return adaptive;
    }

    /** @return 当前告警快照（不可变副本，按首次出现顺序） */
    public List<Warning> warnings() {
        return List.copyOf(warnings);
    }

    public int adaptiveDown() {
        return adaptiveDown;
    }

    public int adaptiveUp() {
        return adaptiveUp;
    }

    public long pausedNanos() {
        return pausedNanos;
    }

    public boolean endReached() {
        return endReached;
    }

    public Throwable error() {
        return error;
    }
}
