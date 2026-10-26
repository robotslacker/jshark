package com.jshark.parser;

import org.duckdb.DuckDBDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * LIVE（分卷滚动跟随）的可用终点刷新器。
 *
 * <p>Start 之后每 2s 发现一次“最新已关闭卷”，只在出现<b>新的</b>已关闭卷时查一次它的
 * {@code MAX(TimeStamp)} 并缓存结果，随后更新 {@link ReplayControl#setDataEnd(long)} 与
 * {@link ReplayControl#setWindowTo(long)}。已关闭卷不会再变化，因此绝不重复聚合。</p>
 *
 * <p>暂停期间也继续刷新；只读已关闭卷，绝不打开 {@code -capturing} 卷。</p>
 */
public final class LiveEndWatcher {

    private static final Logger logger = LoggerFactory.getLogger(LiveEndWatcher.class);

    private final String dbFile;
    private final ReplayControl control;
    private final long intervalMs;
    private final AtomicBoolean running = new AtomicBoolean();
    /** 已经查询过的“最新已关闭卷”：同一个卷不再重复查。 */
    private volatile String lastQueriedVolume;
    /** 实际发起的 MAX(TimeStamp) 查询次数（诊断/测试用）。 */
    private final java.util.concurrent.atomic.AtomicInteger queries =
            new java.util.concurrent.atomic.AtomicInteger();
    private Thread thread;

    public LiveEndWatcher(String dbFile, ReplayControl control, long intervalMs) {
        this.dbFile = dbFile;
        this.control = control;
        this.intervalMs = Math.max(250L, intervalMs);
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        thread = new Thread(this::loop, "jshark-live-end-watcher");
        thread.setDaemon(true);
        thread.start();
    }

    public void stop() {
        running.set(false);
        Thread t = thread;
        thread = null;
        if (t != null) {
            t.interrupt();
        }
    }

    /** @return 已执行的 MAX(TimeStamp) 查询次数（诊断/测试用） */
    int queries() {
        return queries.get();
    }

    private void loop() {
        while (running.get()) {
            try {
                refreshOnce();
            } catch (Exception e) {
                logger.debug("[LIVE] end watcher failed: {}", e.getMessage());
            }
            try {
                Thread.sleep(intervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void refreshOnce() {
        List<String> volumes = SplitUtil.discoverVolumes(dbFile);
        if (volumes.isEmpty()) {
            return;
        }
        String latestClosed = volumes.get(volumes.size() - 1);
        if (latestClosed.equals(lastQueriedVolume)) {
            return;   // 已关闭卷不可变：同一卷不重复聚合
        }
        Long end;
        try {
            queries.incrementAndGet();
            end = queryMaxTimestamp(latestClosed);
        } catch (Exception e) {
            // 新卷刚关闭时 capture 端可能还没释放连接：保持上一次的 availableEnd，下轮再试
            logger.debug("[LIVE] cannot read max timestamp from {}: {}", latestClosed, e.getMessage());
            return;
        }
        // 查询成功（含“空卷”）：该卷不会再变，标记为已处理
        lastQueriedVolume = latestClosed;
        if (end == null || end <= 0) {
            logger.debug("[LIVE] no data in newly closed volume {}", latestClosed);
            return;
        }
        control.setDataEnd(end);
        control.setWindowTo(end);
        logger.debug("[LIVE] availableEnd={} from {}", end, latestClosed);
    }

    /**
     * 查询单个已关闭卷的 {@code MAX(TimeStamp)}。
     *
     * @param volume 已关闭卷路径
     * @return 最大时间戳（epoch ms）；空表返回 null
     * @throws IllegalStateException 三次重试后仍无法读取（瞬时锁冲突等）
     */
    private Long queryMaxTimestamp(String volume) {
        String url = "jdbc:duckdb:" + volume;
        Properties props = new Properties();
        props.setProperty("duckdb.read_only", "true");
        props.setProperty(DuckDBDriver.JDBC_STREAM_RESULTS, String.valueOf(true));
        // 新卷刚关闭时，capture 端的连接可能还没完全释放；重试几次，避免把
        // 一次瞬时 “different configuration” 错误当成“没有数据”。
        Exception last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try (Connection c = DriverManager.getConnection(url, props);
                 Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT MAX(TimeStamp) AS maxTs FROM JSharkLog")) {
                if (rs.next()) {
                    Timestamp ts = rs.getTimestamp("maxTs");
                    return ts == null ? null : ts.getTime();
                }
                return null;
            } catch (Exception e) {
                last = e;
                try {
                    Thread.sleep(50L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        throw new IllegalStateException("cannot read max timestamp from " + volume,
                last == null ? null : last);
    }
}
