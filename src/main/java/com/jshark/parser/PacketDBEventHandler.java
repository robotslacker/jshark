package com.jshark.parser;

import com.alibaba.fastjson2.JSON;
import org.duckdb.DuckDBAppender;
import org.duckdb.DuckDBConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 数据包数据库处理器，负责将数据包信息插入数据库
 * 使用DuckDB Appender进行批量插入，每5秒提交一次
 * 捕获的数据直接放入packetQueue中，由定时任务批量处理
 * <p>
 * 修复：
 * 1. 使用 ReentrantLock 替代 synchronized，避免定时任务与 shutdown 的竞态
 * 2. 修复 finally 块中 appender 资源清理逻辑
 * 3. 修复 closeAppender 中的重入问题
 * </p>
 */
public class PacketDBEventHandler {
    private static final Logger logger = LoggerFactory.getLogger(PacketDBEventHandler.class);
    
    // DuckDB Appender实例
    private Connection dbConn;
    private volatile DuckDBAppender appender;
    // 提交间隔（5秒）
    private static final long COMMIT_INTERVAL_MS = 5000;
    // 关闭（CTRL+C/SIGTERM）时允许用于最后一次冲刷队列的<b>上限</b>（毫秒）。
    //
    // 这只是一个上限：真正可用的时间由调用方传入的 deadline 决定（停机总预算里要留出
    // FORCE CHECKPOINT + close + rename 的尾段时间）。两个都取小，避免某一条路径
    // 把整段预算吃光、导致最后一卷来不及 checkpoint 就退出。
    private static final long SHUTDOWN_FLUSH_BUDGET_MS = 2000;
    /**
     * 是否把 {@code additionalInfo} 写进数据库列。
     * <p>
     * 关闭时该列<b>恒为 NULL</b>：仍然会取出 {@code appProtocol}/{@code tcpFlags} 两列
     * （它们有独立的数据库列，重放过滤要用），但不再做 JSON 序列化，也不再让队列持有 Map。
     * 由 CLI 参数 {@code --enable_additioninfo} 控制，默认 false。
     * </p>
     */
    private volatile boolean storeAdditionalInfo = false;

    /**
     * Additional info过滤表达式
     */
    private String exfilter = null;

    /** 因过滤表达式不匹配而被丢弃的包数 */
    private final java.util.concurrent.atomic.AtomicLong filteredOut =
            new java.util.concurrent.atomic.AtomicLong();
    /**
     * 上述被丢弃的包里，**没有 additionalInfo** 的数量。
     * 这类包永远不可能匹配任何表达式，属"必然丢弃"，与"按条件筛掉"不是一回事。
     */
    private final java.util.concurrent.atomic.AtomicLong filteredOutWithoutInfo =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * 当前 logdb 分卷序号（由采集端在轮转时设置）。未启用分卷时为 0。
     */
    private volatile int volumeSeq = 0;

    // 定时任务执行器
    //
    // 使用**守护线程**：本执行器只负责周期性把队列刷进数据库，属于纯后台辅助任务，
    // 绝不能阻止 JVM 退出。早期使用默认线程工厂（非守护），只要有任何一条关闭路径漏掉
    // scheduler.shutdown()，进程就会在"采集已结束"之后一直挂着不退出
    // （实测表现为测试跑完不返回、CLI 按了 Ctrl+C 也不退）。
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "jshark-db-flusher");
                t.setDaemon(true);
                return t;
            });

    // ========== 锁机制 ==========
    
    /** 使用 ReentrantLock 替代 synchronized，避免定时任务与 shutdown 的竞态 */
    private final ReentrantLock commitLock = new ReentrantLock();

    /**
     * 兜底收尾标志：置位后不再接受任何新的落库批次。
     * <p>
     * 由 {@link #forceClose(long)} 在"抓包线程没能在停机预算内收尾"时设置。
     * 目的只有一个：把可能仍在跑的 appender 批次刹住，好让另一个线程安全地执行
     * {@code FORCE CHECKPOINT} + {@code close}（这两步不能与 appender 并发）。
     * </p>
     */
    private volatile boolean forceClosed = false;

    /** shutdown 是否已经执行过（幂等保护） */
    private volatile boolean shutdownCompleted = false;

    /** 累计已写入 Appender 并提交的包数（用于分卷 manifest 与运行报告） */
    private final java.util.concurrent.atomic.AtomicLong committedPackets =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * @return 累计已提交入库的包数
     */
    public long committedPackets() {
        return committedPackets.get();
    }

    /**
     * 重置"已提交入库"计数（每个时间窗开始时调用，使 manifest 记录的是本卷包数）。
     */
    public void resetCommittedCount() {
        committedPackets.set(0);
    }

    /**
     * 把队列中"截止到调用时刻已经入队"的记录全部落库（停机快照语义）。
     * <p>
     * 与 {@link #commitAppender(long)} 的区别：本方法先取队列快照，只消费快照内的记录。
     * 快照之后新入队的记录会被丢弃并返回其数量——这正是"停机后直接停止后续捕获"的语义，
     * 同时保证"已经抓到的都入库、半截的丢弃、丢弃量可核对"。
     * </p>
     *
     * @param deadlineMs 兜底截止时间（epoch 毫秒）；{@link Long#MAX_VALUE} 表示不限
     * @return 被丢弃（快照之外）的包数
     */
    public long drainSnapshot(long deadlineMs) {
        int snapshot = packetQueue.size();
        if (snapshot == 0) {
            return 0;
        }
        commitAppender(deadlineMs, snapshot);
        // 快照之外新入队的记录：停机后不再采集，理论为 0；若非 0 说明有并发写入，如实丢弃并计数
        int remaining = packetQueue.size();
        if (remaining > 0) {
            packetQueue.clear();
        }
        return remaining;
    }

    public void setLogDb(Connection dbConn) {
        this.dbConn = dbConn;
    }

    /**
     * 设置是否把 {@code additionalInfo} 写入数据库列。
     *
     * @param storeAdditionalInfo false = 该列恒为 NULL（appProtocol/tcpFlags 等独立列不受影响）
     */
    public void setStoreAdditionalInfo(boolean storeAdditionalInfo) {
        this.storeAdditionalInfo = storeAdditionalInfo;
    }

    /**
     * 设置 additionalInfo 过滤表达式
     */
    public void setExfilter(String exfilter) {
        this.exfilter = exfilter;
        if (exfilter != null && !exfilter.isEmpty()) {
            logger.info("[JShark] PacketDBEventHandler: Additional info filter set: {}", exfilter);
        }
    }

    /** @return 因过滤表达式不匹配而被丢弃的包数 */
    public long filteredOut() {
        return filteredOut.get();
    }

    /** @return 被丢弃的包中"没有 additionalInfo、永远不可能匹配"的数量 */
    public long filteredOutWithoutInfo() {
        return filteredOutWithoutInfo.get();
    }

    /** @return 当前队列中待入库的包数（供测试与运行报告使用） */
    public int pendingQueueSize() {
        return packetQueue.size();
    }

    /** @return 停机冲刷预算用尽、被遗弃在队列中（未入库）的包数 */
    public long abandonedAtShutdown() {
        return abandonedAtShutdown.get();
    }

    /** @return 入队前处理失败（如 JSON 序列化异常）而被丢弃的包数 */
    public long failedToEnqueue() {
        return failedToEnqueue.get();
    }

    /** @return 已出队但批次提交失败（回滚）而丢失的包数 */
    public long failedToCommit() {
        return failedToCommit.get();
    }

    /**
     * 设置当前 logdb 分卷序号（分卷轮转时由采集端更新）。
     *
     * @param volumeSeq 分卷序号，从 1 开始；0 表示未启用分卷
     */
    public void setVolumeSeq(int volumeSeq) {
        this.volumeSeq = volumeSeq;
    }

    // Thread-safe FIFO queue for storing packets to be processed
    //
    // 有界队列（重要）：早期用的是无界 LinkedBlockingQueue，理由是"绝不丢包"。
    // 但采集端不做背压，无界队列在落库跟不上时只会把堆吃光：实测在真实 DIS 流量下
    // 堆顶到 -Xmx 上限后进入 GC 抖动，抓包速率从 4 万 pps 掉到约 550 pps（1.84ms/包），
    // 29 分钟只处理了 95 万/150 万包，最后仍未跑完。
    //
    // 现在的语义是：队列满 -> 立即丢弃并计数（丢弃量在退出时明确报告），
    // 内存因此有确定上限（capacity × 每条约 1~9KB），抓包速率不会被 GC 拖垮。
    // 这是"丢包可核对"而不是"不丢包"——高流量下后者不可实现。
    private final BlockingQueue<PacketData> packetQueue;

    /** 队列容量上限（条） */
    private final int queueCapacity;

    /** 因队列满而被丢弃的包数 */
    private final java.util.concurrent.atomic.AtomicLong droppedQueueFull =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * 停机时"冲刷预算用尽、仍然留在队列里"的包数。
     * <p>
     * 早期这里只有一个声明、从未被赋值，导致 manifest 恒报 {@code queueAtShutdown=0}——
     * 即"一边声称零丢弃、一边丢掉几万条"。现在 shutdown 的末尾如实统计剩余队列并清零，
     * 该数字会进运行报告与 manifest。</p>
     */
    private final java.util.concurrent.atomic.AtomicLong abandonedAtShutdown =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * 入队前处理失败（例如 {@code JSON.toJSONString} 抛异常）而被丢弃的包数。
     * <p>这类包既不入库、也不属于"队列满"，若不单独计数就会表现为
     * "queued 多、committed 少、各项 dropped 都是 0"的无法解释差额。</p>
     */
    private final java.util.concurrent.atomic.AtomicLong failedToEnqueue =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * 已从队列取出、但批次提交失败（rollback）而丢失的包数。
     * <p>这批包不会回到队列，属于真丢失，必须计数。</p>
     */
    private final java.util.concurrent.atomic.AtomicLong failedToCommit =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * 默认队列容量（条）。
     * <p>按真实 DIS 行每条约 8~9KB 堆占用估算，10 万条约 0.85GB 上限；
     * 非 DIS 行（小 additionalInfo）约 1~2KB/条，10 万条约 0.2GB。</p>
     */
    public static final int DEFAULT_QUEUE_CAPACITY = 100_000;

    /** 覆盖默认队列容量的系统属性：{@code -Djshark.db.queue.capacity=<条数>} */
    public static final String QUEUE_CAPACITY_PROPERTY = "jshark.db.queue.capacity";

    /**
     * 队列容量上限（条）。
     * <p>
     * 没有上限时，{@code -Djshark.db.queue.capacity=2000000000} 会让有界队列重新变成事实无界，
     * 正是上面的字段注释里记录过的历史故障（堆压满 → GC 抖动 → 抓包从 4 万 pps 掉到 550 pps）。
     * 默认 10 万条已经相当于 0.2~0.85GB，因此上界取 500 万条（约 1.2~4.5GB 的风险敞口），
     * 超过即回退默认并告警，不做静默放大。</p>
     */
    public static final int MAX_QUEUE_CAPACITY = 5_000_000;

    /**
     * 停机冲刷等待提交锁的上限（毫秒）。
     * <p>
     * 停机时若周期性提交正持有锁，必须等它做完再冲刷，否则会把整个队列丢掉。
     * 这里给一个上限，避免"等待"变成"挂死"。
     * </p>
     */
    private static final long DEFAULT_COMMIT_LOCK_WAIT_MS = 30_000L;

    /**
     * Inner class for storing packet information.
     * <p>
     * {@code json} / {@code appProtocol} / {@code tcpFlags} 都是<b>入队时就准备好</b>的：
     * 落库线程（单线程）因此不需要再碰 {@code additionalInfo} 这个 Map ——
     * 既省掉了每行的 {@code JSON.toJSONString}，也让队列不必再持有 61 键的大 Map。
     * </p>
     */
    private record PacketData(PacketParser.ParsedPacket parsedPacket, String json,
                              String appProtocol, String tcpFlags) {}

    /** 安全转字符串；null 原样返回 */
    private static String asString(Object v) {
        return v == null ? null : v.toString();
    }
    
    public PacketDBEventHandler() {
        this(resolveDefaultQueueCapacity());
    }

    /**
     * @param queueCapacity 队列容量（条）；{@code <=0} 表示使用默认值
     */
    public PacketDBEventHandler(int queueCapacity) {
        this.queueCapacity = queueCapacity > 0 ? queueCapacity : DEFAULT_QUEUE_CAPACITY;
        this.packetQueue = new LinkedBlockingQueue<>(this.queueCapacity);
        // Start scheduled commit task
        //
        // 必须套一层"自愈"包装：ScheduledExecutorService 的语义是——周期任务一旦抛出异常，
        // 该任务会被**永久取消**，此后再也不会提交（DB 静默停止接收，最终只表现为"队列满丢弃"）。
        // 这里把任何 Throwable 都吞在包装层内并记 ERROR，保证提交任务在单次失败后仍会继续。
        scheduler.scheduleAtFixedRate(this::safeCommitTick,
            COMMIT_INTERVAL_MS, COMMIT_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    /** 周期提交任务的包装：任何 Throwable 都不得逃逸，否则调度器会永久取消该任务 */
    private void safeCommitTick() {
        try {
            commitAppender();
        } catch (Throwable t) {
            logger.error("[JShark] Scheduled DB commit failed; the periodic task will keep running", t);
        }
    }

    /**
     * 解析队列容量：优先系统属性 {@value #QUEUE_CAPACITY_PROPERTY}，非法值回退默认。
     */
    private static int resolveDefaultQueueCapacity() {
        String raw = System.getProperty(QUEUE_CAPACITY_PROPERTY);
        if (raw == null || raw.trim().isEmpty()) {
            return DEFAULT_QUEUE_CAPACITY;
        }
        try {
            int v = Integer.parseInt(raw.trim());
            if (v > 0) {
                if (v > MAX_QUEUE_CAPACITY) {
                    // 无上界 = 有界队列退化成无界队列（历史上正是这么把堆吃光的），拒绝放大
                    logger.warn("[JShark] -D{}=\"{}\" exceeds the maximum of {}; using default {} instead",
                            QUEUE_CAPACITY_PROPERTY, raw, MAX_QUEUE_CAPACITY, DEFAULT_QUEUE_CAPACITY);
                    return DEFAULT_QUEUE_CAPACITY;
                }
                logger.info("[JShark] DB queue capacity set to {} by -D{}", v, QUEUE_CAPACITY_PROPERTY);
                return v;
            }
            logger.warn("[JShark] -D{}=\"{}\" must be positive; using default {}", QUEUE_CAPACITY_PROPERTY, raw,
                    DEFAULT_QUEUE_CAPACITY);
        } catch (NumberFormatException e) {
            logger.warn("[JShark] -D{}=\"{}\" is not a number; using default {}", QUEUE_CAPACITY_PROPERTY, raw,
                    DEFAULT_QUEUE_CAPACITY);
        }
        return DEFAULT_QUEUE_CAPACITY;
    }

    /** @return 队列容量（条） */
    public int queueCapacity() {
        return queueCapacity;
    }

    /** @return 因队列满而被丢弃的包数 */
    public long droppedQueueFull() {
        return droppedQueueFull.get();
    }
    
    /**
     * Add packet to processing queue
     * @param parsedPacket parsed packet
     * @param additionalInfo additional information
     */
    public void addPacket(PacketParser.ParsedPacket parsedPacket,
                         Map<String, Object> additionalInfo) {
        try {
            // 检查是否需要过滤：表达式不匹配的包直接丢弃（仍计数，退出时报告）
            if (exfilter != null && !exfilter.isEmpty()) {
                if (!matchesFilter(additionalInfo, exfilter)) {
                    boolean hadInfo = additionalInfo != null && !additionalInfo.isEmpty();
                    filteredOut.incrementAndGet();
                    if (!hadInfo) {
                        // 没有 additionalInfo 的包永远不可能匹配任何表达式：
                        // 单独计数，才能区分"按条件筛掉"与"本来就匹配不了"
                        filteredOutWithoutInfo.incrementAndGet();
                    }
                    return;
                }
            }

            // 在这里（解析线程）一次性完成 JSON 序列化与落库列的取值。
            //
            // 为什么挪到这里：落库线程是**单线程**，而 DIS 一行要做 JSON.toJSONString
            // 61 个键（实测约 6.6 µs/行，占真实 DIS 行总落库成本 58 µs/行的约 11%），
            // 全部压在它身上就把落库吞吐锁死了。放到解析线程后，这部分成本可以随
            // --parse-threads 并行摊开。
            //
            // 顺带的内存收益：序列化出的字符串取代了队列对 61 键 Map（约 8KB/包）的强引用，
            // 队列占用从"每包约 8-9KB"降到"每包约 2-3KB"，直接缓解高流量下的 GC 抖动。
            // 前提：入队之后没有任何人再读这个 Map —— 落库需要的两个列值
            // （application.protocol / tcp.flags）已在下面单独取出。
            String json = null;
            String appProtocol = null;
            String tcpFlags = null;
            if (additionalInfo != null && !additionalInfo.isEmpty()) {
                // appProtocol / tcpFlags 是独立列，必须始终取出：
                // 即使 additionalInfo 列被关闭，重放端的 --applicationProtocol 过滤也不能失效。
                appProtocol = asString(additionalInfo.get("application.protocol"));
                tcpFlags = asString(additionalInfo.get("tcp.flags"));
                if (storeAdditionalInfo) {
                    json = JSON.toJSONString(additionalInfo);
                }
            }

            // Put packet into thread-safe FIFO queue
            // queuedPacket 的 additionalInfo 被清空（数据已进 json 列），使队列不再持有大 Map。
            // 关闭 additionalInfo 列时同样清空：Map 里的详细字段反正不会入库，
            // 让它跟着队列排队只会白白占内存。
            PacketParser.ParsedPacket queuedPacket = (json != null || !storeAdditionalInfo)
                    ? parsedPacket.withAdditionalInfo(java.util.Collections.emptyMap())
                    : parsedPacket;
            PacketData packetData = new PacketData(queuedPacket, json, appProtocol, tcpFlags);

            // Add new data to queue.
            // 队列满 -> 丢弃并计数（不阻塞抓包线程）。队列有界是刻意的：
            // 无界队列在落库跟不上时会把堆吃光并拖垮整条采集链路，见字段注释。
            boolean added = packetQueue.offer(packetData);
            if (!added) {
                long dropped = droppedQueueFull.incrementAndGet();
                // 前 3 次与之后每 10000 次各打一条，避免丢包风暴时刷爆日志
                if (dropped <= 3 || dropped % 10000 == 0) {
                    logger.warn("[JShark] DB queue full (capacity={}), packet dropped. "
                                    + "Total dropped so far: {}. Sink cannot keep up with the capture rate.",
                            queueCapacity, dropped);
                }
            }
        } catch (Exception e) {
            // 入队前处理失败（最典型的是 additionalInfo 的 JSON 序列化抛异常）。
            // 这个包不会入库，必须计数，否则运行报告里只会留下一笔无法解释的差额。
            long failed = failedToEnqueue.incrementAndGet();
            if (failed <= 3 || failed % 10000 == 0) {
                logger.error("[JShark] Failed to enqueue packet (total failed so far: {}); it will NOT be stored",
                        failed, e);
            }
        }
    }
    
    /**
     * Append packet to Appender
     */
    private void appendPacketToAppender(PacketData packetData) throws SQLException {
        PacketParser.ParsedPacket parsedPacket = packetData.parsedPacket();
        try {
            // Start a row
            appender.beginRow();

            // ID
            appender.append(parsedPacket.packetSequence());

            // timestamp
            appender.append(Timestamp.from(parsedPacket.timestamp()).toLocalDateTime());

            // length（原始线上长度）
            appender.append(parsedPacket.length());

            // wireLen（原始线上长度，来自 pcap 首部）
            appender.append(parsedPacket.wireLen());

            // capLen（实际捕获长度；小于 wireLen 表示被 snaplen 截断）
            appender.append(parsedPacket.capLen());

            // sourceMac
            appender.append(parsedPacket.sourceMac());
            
            // destinationMac
            appender.append(parsedPacket.destinationMac());
            
            // sourceIp
            appender.append(parsedPacket.sourceIp());
            
            // destinationIp
            appender.append(parsedPacket.destinationIp());
            
            // ipProtocol
            if (parsedPacket.ipProtocol() != null) {
                appender.append(parsedPacket.ipProtocol().name());
            } else {
                appender.append((String) null);
            }
            
            // sourcePort
            if (parsedPacket.sourcePort() != null) {
                appender.append(parsedPacket.sourcePort());
            } else {
                appender.append((Integer) null);
            }
            
            // destinationPort
            if (parsedPacket.destinationPort() != null) {
                appender.append(parsedPacket.destinationPort());
            } else {
                appender.append((Integer) null);
            }
            
            // appProtocol / tcpFlags：入队时已取出（见 addPacket），这里直接落列
            if (packetData.appProtocol() != null) {
                appender.append(packetData.appProtocol());
            } else {
                appender.append((String) null);
            }

            if (packetData.tcpFlags() != null) {
                appender.append(packetData.tcpFlags());
            } else {
                appender.append((String) null);
            }

            // frameData（完整原始帧：帧级重放的唯一数据源）
            byte[] frameData = parsedPacket.frameData();
            if (frameData != null && frameData.length > 0) {
                appender.append(frameData);
            } else {
                appender.append((byte[]) null);
            }

            // rawData（传输层 payload，供解析与查询使用）
            byte[] rawData = parsedPacket.rawData();
            if (rawData != null && rawData.length > 0) {
                appender.append(rawData);
            } else {
                appender.append((byte[]) null);
            }

            // captureKind（记录来源类型，决定是否可重放）
            appender.append((short) parsedPacket.captureKind().code());

            // ingestSeq（进程内全局单调序号，跨卷唯一）
            appender.append(parsedPacket.packetSequence());

            // volumeSeq（分卷序号）
            appender.append(this.volumeSeq);

            // additionalInfo — JSON 文本列。序列化已在解析线程完成（见 addPacket），
            // 落库线程只做 append，不再逐行调用 JSON.toJSONString。
            appender.append(packetData.json());
            
            // 结束行
            appender.endRow();
        } catch (Exception e) {
            // 如果发生异常，尝试结束当前行以避免Appender处于不一致状态
            try {
                appender.endRow();
            } catch (Exception endRowEx) {
                // 忽略结束行异常
            }
            throw e;
        }
    }
    
    /**
     * 提交Appender中的数据（无截止时间，用于定时任务）
     * 从队列中获取数据并调用appendPacketToAppender
     * 使用 ReentrantLock 保证线程安全，同时使用局部变量 appender 避免并发问题
     */
    private void commitAppender() {
        // 周期性任务：抢不到锁就跳过（避免多个提交排队堆积）
        commitAppender(Long.MAX_VALUE, Integer.MAX_VALUE, false);
    }

    /**
     * 提交Appender中的数据
     * 从队列中获取数据并调用appendPacketToAppender
     * 使用 ReentrantLock 保证线程安全，同时使用局部变量 appender 避免并发问题
     *
     * @param deadlineMs 冲刷截止时间（epoch毫秒），超过该时间即使队列未清空也会停止并提交已处理的部分
     */
    private void commitAppender(long deadlineMs) {
        // 停机路径：必须等到锁，不能因为"别人正在提交"就放弃
        commitAppender(deadlineMs, Integer.MAX_VALUE, true);
    }

    /**
     * 提交Appender中的数据（可限定只消费前若干条，用于停机快照）。
     *
     * <p>使用 ReentrantLock 保证与定时任务的互斥；Appender 用局部变量避免并发共享。</p>
     *
     * @param deadlineMs  冲刷截止时间（epoch 毫秒），超过则停止并提交已处理的部分
     * @param maxRecords  本次最多消费的记录数；{@link Integer#MAX_VALUE} 表示不限制
     */
    private void commitAppender(long deadlineMs, int maxRecords) {
        // 停机快照：同样必须等锁。若这里因抢不到锁直接返回，drainSnapshot 会在随后的
        // 快照外清理中把**整个队列**丢掉（实测踩到：200000 包只入库 0，其余记为
        // droppedAfterSignal）。等锁的代价有 deadline 兜底，远小于静默丢数据的代价。
        commitAppender(deadlineMs, maxRecords, true);
    }

    /**
     * 提交Appender中的数据（完整实现）。
     *
     * @param deadlineMs  冲刷截止时间（epoch 毫秒）
     * @param maxRecords  本次最多消费的记录数
     * @param waitForLock true = 限时等待提交锁（停机路径，宁可等也不丢）；
     *                    false = 抢不到就跳过（周期性路径，避免堆积）
     */
    private void commitAppender(long deadlineMs, int maxRecords, boolean waitForLock) {
        // 注意：这里不再用 shuttingDown 提前返回。scheduler 会在 shutdown() 中被
        // shutdown/awaitTermination 妥善停止，之后才由 shutdown() 显式调用本方法做最终冲刷；
        // 若在此提前返回，会直接“跳过”最后的队列冲刷，导致 CTRL+C 时数据未落库。
        if (packetQueue.isEmpty()) {
            // 没有数据就直接返回
            return;
        }

        if (forceClosed) {
            // 兜底收尾（另一个线程）已经开始，不再写库：与 FORCE CHECKPOINT/close 并发写
            // 会直接损坏连接。队列里的记录留给 shutdown() 如实计入 abandonedAtShutdown。
            return;
        }

        if (waitForLock) {
            long waitMs = (deadlineMs == Long.MAX_VALUE)
                    ? DEFAULT_COMMIT_LOCK_WAIT_MS
                    : Math.max(1L, deadlineMs - System.currentTimeMillis());
            try {
                if (!commitLock.tryLock(waitMs, TimeUnit.MILLISECONDS)) {
                    logger.warn("[JShark] could not acquire the DB commit lock within {}ms; "
                            + "{} packets remain in the queue", waitMs, packetQueue.size());
                    return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        } else if (!commitLock.tryLock()) {
            logger.debug("commitAppender: another thread is already committing, skipping");
            return;
        }

        try {
            // 拿到锁之后再看一次：等锁期间兜底收尾可能已经开始（见 forceClose）
            if (forceClosed) {
                return;
            }
            DuckDBAppender localAppender = null;
            // 提到 try 之外：catch 里要用它统计"批次失败而丢失"的包数。
            // 刻意在"取到包"之后立刻自增（早于 append），这样 append 阶段抛异常的包
            // 也算在这一批里，不会被漏计。
            int polledCount = 0;
            try {
                localAppender = ((DuckDBConnection) this.dbConn).createAppender( "JSharkLog");
                this.appender = localAppender;

                // 处理队列中的数据包，直到达到记录上限、队列清空或到达截止时间
                while (!packetQueue.isEmpty() && polledCount < maxRecords) {
                    if (System.currentTimeMillis() >= deadlineMs) {
                        logger.warn("[JShark] Aborting DB flush due to shutdown budget, remaining queue: {}",
                                packetQueue.size());
                        break;
                    }
                    PacketData packetData = packetQueue.poll();
                    if (packetData == null) {
                        break;
                    }
                    polledCount++;
                    // 调用appendPacketToAppender处理数据包
                    appendPacketToAppender(packetData);
                }
                
                // 提交数据
                localAppender.close();
                localAppender = null; // 标记已关闭，避免 finally 中重复关闭
                this.appender = null;
                this.dbConn.commit();

                // 只有 commit 成功之后才计"已入库"。
                // 早期在 commit 之前累加，批次回滚时计数虚高，直接破坏 committed/queued 的对账。
                if (polledCount > 0) {
                    logger.info("[JShark] Committed {} packets in database. ", polledCount);
                    committedPackets.addAndGet(polledCount);
                }
            } catch (Exception e) {
                logger.error("Failed to commit DuckDB Appender", e);
                // 这一批已经从队列取出，回滚后不会回到队列 —— 属于真丢失，必须计数
                if (polledCount > 0) {
                    long lost = failedToCommit.addAndGet(polledCount);
                    logger.warn("[JShark] {} packets of the failed commit batch were lost "
                                    + "(total lost to failed commits: {})", polledCount, lost);
                }
                try {
                    this.dbConn.rollback();
                } catch (Throwable rollbackEx) {
                    // 必须捕获 Throwable：dbConn 可能为 null 或连接已关闭，
                    // 此时抛出的非 SQLException 会穿透到调度器，使周期提交任务被永久取消。
                    logger.error("Failed to rollback transaction", rollbackEx);
                }
            } finally {
                // 清理：如果 localAppender 不为 null，说明 close() 未成功执行
                if (localAppender != null) {
                    try {
                        localAppender.close();
                    } catch (Exception ignored) {}
                }
               if (this.appender != null) {
                    // 异常情况下，this.appender 可能还指向未关闭的 appender
                    try {
                        this.appender.close();
                    } catch (Exception ignored) {}
                    this.appender = null;
                }
            }
        } finally {
            commitLock.unlock();
        }
    }
    
    /**
     * 关闭Appender
     * 在关闭前按时间预算处理队列中剩余的数据，避免长时间阻塞
     */
    private void closeAppender(long deadlineMs) {
        // 先提交剩余数据（包括队列中的数据），受调用方 deadline 与本地上限的双重约束
        long deadline = Math.min(deadlineMs, System.currentTimeMillis() + SHUTDOWN_FLUSH_BUDGET_MS);
        commitAppender(deadline);

        // 再次检查队列是否还有数据（可能在commitAppender调用期间新加入的）
        if (!packetQueue.isEmpty()) {
            logger.info("Processing remaining {} packets in queue before closing", packetQueue.size());
            commitAppender(deadline);
        }
        
        // 关闭Appender
        DuckDBAppender localAppender = this.appender;
        if (localAppender != null) {
            try {
                localAppender.close();
            } catch (Exception e) {
                logger.error("Error closing appender", e);
            }
            this.appender = null;
        }
    }
    
    /**
     * 检查additionalInfo是否匹配过滤表达式
     * 使用FilterNinja表达式解析器，支持：
     * 1. 括号分组：()
     * 2. 逻辑运算：&& (AND), || (OR)
     * 3. 比较运算：=, !=, >, <, >=, <=
     * 4. 字符串匹配：like (支持通配符 * 和 ?)
     * 示例：
     *   dis.pdu.type=28 && dis.exercise.id=17
     *   (dis.pdu.type=28 || dis.pdu.type=1) && dis.exercise.id!=0
     *   dis.pdu.type>20 && dis.pdu.type<30
     *   dis.entity.name like "*tank*"
     */
    private boolean matchesFilter(Map<String, Object> additionalInfo, String filterExpr) {
        if (additionalInfo == null || additionalInfo.isEmpty()) {
            return false; // 没有additionalInfo，不匹配
        }
        
        try {
            // 使用FilterNinja表达式解析器
            return ExpressionParser.evaluate(filterExpr, additionalInfo);
        } catch (Exception e) {
            logger.error("Error evaluating filter expression: {}", filterExpr, e);
            return false; // 解析错误时默认不匹配
        }
    }

    /**
     * 清理资源
     * 在关闭前确保处理所有队列中的数据
     */
    public void shutdown() {
        // 默认预算：沿用历史语义（最多等 5 秒），供测试与"非停机"关闭路径使用
        shutdown(System.currentTimeMillis() + 5_000L);
    }

    /**
     * 预算化的关闭：在 {@code deadlineMs} 之前把能写的写完，然后释放 appender。
     * <p>
     * 为什么必须带 deadline：停机总预算里要给"FORCE CHECKPOINT + close + rename"留出尾段时间，
     * 写死的 5s/2s 会把整段预算吃光，最后一卷就来不及 checkpoint、只能以 {@code -capturing}
     * 加一个未合并的 {@code .wal} 留在磁盘上。
     * </p>
     *
     * @param deadlineMs 绝对截止时间（epoch 毫秒）；{@link Long#MAX_VALUE} 表示不限
     */
    public void shutdown(long deadlineMs) {
        // 幂等保护：防止多线程并发调用导致重复shutdown
        if (shutdownCompleted) {
            return;
        }
        shutdownCompleted = true;
        
        logger.info("Shutting down PacketDBEventHandler, queue size: {}", packetQueue.size());

        // 先停止定时任务：等待时间同时受 deadline 约束（不再无条件等 5 秒）
        long awaitMs = Math.min(5_000L, Math.max(1L, deadlineMs - System.currentTimeMillis()));
        try {
            scheduler.shutdown();
            if (!scheduler.awaitTermination(awaitMs, TimeUnit.MILLISECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        // 处理队列中剩余的数据（受时间预算约束，保证快速退出）
        if (!packetQueue.isEmpty() && !forceClosed) {
            long deadline = Math.min(deadlineMs, System.currentTimeMillis() + SHUTDOWN_FLUSH_BUDGET_MS);
            logger.info("Processing remaining {} packets in queue before shutdown", packetQueue.size());
            try {
                commitAppender(deadline);
            } catch (Exception e) {
                logger.error("Error processing remaining packets during shutdown", e);
            }
        }
        
        // 关闭Appender
        try {
            closeAppender(deadlineMs);
        } catch (Exception e) {
            logger.error("Error closing appender during shutdown", e);
        }

        // 预算用尽后仍留在队列里的记录：永远不会入库，必须如实计数并清空，
        // 否则 manifest 会出现"声称零丢弃、实际丢掉数万条"的谎报。
        int abandoned = packetQueue.size();
        if (abandoned > 0) {
            packetQueue.clear();
            abandonedAtShutdown.addAndGet(abandoned);
            logger.warn("[JShark] Shutdown flush budget exhausted: {} packets were abandoned in the queue and will "
                            + "NOT be stored (counted as droppedAtShutdownBudget)", abandoned);
        }

        // 队列满丢弃汇报：丢包必须可见，绝不静默
        long queueDropped = droppedQueueFull.get();
        if (queueDropped > 0) {
            logger.warn("[JShark] {} packets were dropped because the DB queue (capacity={}) was full; "
                            + "the storage sink could not keep up with the capture rate",
                    queueDropped, queueCapacity);
        }

        // 过滤结果汇报：不匹配的包绝不静默吞掉
        if (exfilter != null && !exfilter.isEmpty() && filteredOut.get() > 0) {
            logger.info("[JShark] --exfilter \"{}\" dropped {} unmatched packets", exfilter, filteredOut.get());
            if (filteredOutWithoutInfo.get() > 0) {
                logger.warn("[JShark] {} of those packets had no additionalInfo and could never match any "
                                + "expression; they are unrelated to this filter.",
                        filteredOutWithoutInfo.get());
            }
        }
    }

    /**
     * 兜底收尾：立刻刹住落库，让调用方可以安全地对连接做 {@code FORCE CHECKPOINT} + {@code close}。
     * <p>
     * 只在"抓包线程没能在停机预算内收尾"时由另一个线程调用（见
     * {@code PacketCapture#forceFinalizeLastVolume()}）。它<b>不</b>负责排空队列——
     * 那些记录会由随后的 {@link #shutdown(long)} 如实计入 {@code abandonedAtShutdown}；
     * 这里唯一的目标是：保证没有 appender 正在写，然后尽快返回。
     * </p>
     *
     * @param waitMs 等待"当前正在提交的那一批"结束的最长时间（毫秒）
     */
    public void forceClose(long waitMs) {
        forceClosed = true;
        try {
            scheduler.shutdownNow();
        } catch (Throwable ignored) {
            // 调度器可能已经被 shutdown() 停掉，这里失败不影响后续收尾
        }
        try {
            if (commitLock.tryLock(Math.max(1L, waitMs), TimeUnit.MILLISECONDS)) {
                try {
                    // 拿到锁即说明没有批次在写；立刻放掉，真正的 checkpoint/close 由调用方在锁外做
                    logger.warn("[JShark] Forced shutdown: {} packets remain in the DB queue and will NOT be stored",
                            packetQueue.size());
                } finally {
                    commitLock.unlock();
                }
            } else {
                logger.warn("[JShark] Forced shutdown could not acquire the DB commit lock within {}ms; "
                        + "a commit may still be in flight", waitMs);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
