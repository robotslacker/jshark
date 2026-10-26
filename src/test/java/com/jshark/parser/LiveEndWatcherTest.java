package com.jshark.parser;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * LIVE 可用终点刷新：只读最新已关闭卷的最大 TimeStamp，并更新 dataEnd/window.to。
 */
public class LiveEndWatcherTest {

    @TempDir
    Path dir;

    @Test
    void refreshesFromLatestClosedVolume() throws Exception {
        long t0 = at(2026, 8, 21, 8, 0, 0);
        long t1 = at(2026, 8, 21, 8, 10, 0);
        long t2 = at(2026, 8, 21, 8, 20, 0);
        Path v1 = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0)
                + "-" + SplitUtil.formatTimestamp(t1) + ".db");
        Path v2 = dir.resolve("cap_" + SplitUtil.formatTimestamp(t1)
                + "-" + SplitUtil.formatTimestamp(t2) + ".db");
        createDb(v1, t0 + 1_000, t1 - 1_000);
        createDb(v2, t1 + 1_000, t2 - 1_000);

        ReplayControl control = new ReplayControl(1.0);
        control.setWindow(t0, Long.MAX_VALUE);
        LiveEndWatcher watcher = new LiveEndWatcher(dir.resolve("cap.db").toString(), control, 250);
        watcher.start();
        try {
            Thread.sleep(900);
        } finally {
            watcher.stop();
        }

        assertEquals(t2 - 1_000, control.dataEndMs());
        assertEquals(t2 - 1_000, control.windowToMs());
        assertTrue(control.dataEndMs() >= control.windowFromMs());
    }

    @Test
    void queriesOnlyNewlyClosedVolumes() throws Exception {
        long t0 = at(2026, 8, 21, 10, 0, 0);
        long t1 = at(2026, 8, 21, 10, 10, 0);
        long t2 = at(2026, 8, 21, 10, 20, 0);
        Path v1 = dir.resolve("cache_" + SplitUtil.formatTimestamp(t0)
                + "-" + SplitUtil.formatTimestamp(t1) + ".db");
        createDb(v1, t0 + 1_000, t1 - 1_000);

        ReplayControl control = new ReplayControl(1.0);
        control.setWindow(t0, Long.MAX_VALUE);
        LiveEndWatcher watcher = new LiveEndWatcher(dir.resolve("cache.db").toString(), control, 250);
        watcher.start();
        try {
            Thread.sleep(900);
            assertEquals(1, watcher.queries(), "已关闭卷不会再变：同一个卷不应重复聚合");
            assertEquals(t1 - 1_000, control.windowToMs());

            // 先在临时名字下建好，再原子重命名成“已关闭卷”，避免 watcher 看到半成品
            Path building = dir.resolve("building.db");
            createDb(building, t1 + 1_000, t2 - 1_000);
            Path v2 = dir.resolve("cache_" + SplitUtil.formatTimestamp(t1)
                    + "-" + SplitUtil.formatTimestamp(t2) + ".db");
            java.nio.file.Files.move(building, v2);

            Thread.sleep(800);
            assertEquals(2, watcher.queries(), "出现新卷后应只多查一次");
            assertEquals(t2 - 1_000, control.windowToMs());
        } finally {
            watcher.stop();
        }
    }

    @Test
    void availableEndGrowsWhenNewClosedVolumeAppears() throws Exception {
        long t0 = at(2026, 8, 21, 9, 0, 0);
        long t1 = at(2026, 8, 21, 9, 10, 0);
        long t2 = at(2026, 8, 21, 9, 20, 0);
        long t3 = at(2026, 8, 21, 9, 30, 0);
        Path v1 = dir.resolve("grow_" + SplitUtil.formatTimestamp(t0)
                + "-" + SplitUtil.formatTimestamp(t1) + ".db");
        createDb(v1, t0 + 1_000, t1 - 1_000);

        ReplayControl control = new ReplayControl(1.0);
        control.setWindow(t0, Long.MAX_VALUE);
        LiveEndWatcher watcher = new LiveEndWatcher(dir.resolve("grow.db").toString(), control, 250);
        watcher.start();
        try {
            Thread.sleep(500);
            assertEquals(t1 - 1_000, control.windowToMs());

            Path v2 = dir.resolve("grow_" + SplitUtil.formatTimestamp(t1)
                    + "-" + SplitUtil.formatTimestamp(t2) + ".db");
            createDb(v2, t1 + 1_000, t2 - 1_000);
            Thread.sleep(700);
            assertEquals(t2 - 1_000, control.windowToMs(),
                    "LIVE 可用终点必须能增长，而不是只取第一次的值");
        } finally {
            watcher.stop();
        }
    }

    private static void createDb(Path path, long firstMs, long lastMs) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + path);
             Statement st = conn.createStatement()) {
            st.execute("Create Table JSharkLog (Id BIGINT, TimeStamp timestamp)");
            st.executeUpdate("Insert Into JSharkLog (Id, TimeStamp) Values (1, TIMESTAMP '"
                    + toDuckDbTs(firstMs) + "')");
            st.executeUpdate("Insert Into JSharkLog (Id, TimeStamp) Values (2, TIMESTAMP '"
                    + toDuckDbTs(lastMs) + "')");
        }
    }

    private static String toDuckDbTs(long epochMs) {
        return LocalDateTime.ofInstant(java.time.Instant.ofEpochMilli(epochMs), ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
    }

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s)
                .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }
}
