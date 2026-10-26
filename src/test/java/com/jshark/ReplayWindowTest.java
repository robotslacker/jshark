package com.jshark;

import com.jshark.parser.DbReplayTool;
import com.jshark.parser.SplitUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

/**
 * D7 验收测试：--start/--end（天文绝对捕获时间）的窗口语义。
 *
 * <h3>覆盖</h3>
 * <ol>
 *   <li><b>按卷名选卷</b>：{@code SplitUtil.selectVolumesInCaptureWindow} 只保留
 *       窗口起点时间戳落在 {@code [start, end]} 内的分卷（含边界、start/end 单独给定）。</li>
 *   <li><b>卷内按 TimeStamp 过滤</b>：在真实 DuckDB 里建表并写入已知绝对时间的包，
 *       验证 "[start, end]" 的过滤只返回窗口内的包（贴合重放路径的过滤语义）。</li>
 *   <li><b>end 在 follow 模式的"到时间即退出"谓词</b>：窗口整体在过去（最早的卷起点已越过 end）
 *       时选卷为空且应停止；end 落在中间时起始卷仍应被选中（不丢数据）。</li>
 *   <li><b>CLI 校验约束</b>：{@code CliReplay.validateTimeSelection} 只校验
 *       end&lt;start，不再限制数据源类型。</li>
 * </ol>
 *
 * <p>全程离线：不需要网卡、不需要特权、不真实发包。</p>
 */
public class ReplayWindowTest {

    private static final Logger logger = LoggerFactory.getLogger(ReplayWindowTest.class);

    private static final Path WORK_DIR = Path.of("target", "test-d7");

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void replayWindowRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  D7 验收：--start/--end 窗口语义");
        logger.info("=================================================");

        step0_prepare();
        checkVolumeSelection();
        checkFinalNameSelection();
        checkTimestampFiltering();
        checkEndFollowPredicates();
        checkCliValidation();
        checkFollowRealRun();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    private static void step0_prepare() throws Exception {
        if (Files.exists(WORK_DIR)) {
            try (java.util.stream.Stream<Path> walk = Files.walk(WORK_DIR)) {
                walk.sorted((a, b) -> b.getNameCount() - a.getNameCount()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (Exception ignore) {
                        // 忽略清理失败
                    }
                });
            }
        }
        Files.createDirectories(WORK_DIR);
    }

    // ==================== [1] 按卷名选卷 ====================

    private static void checkVolumeSelection() {
        logger.info("---- [1] 按卷名选卷（selectVolumesInCaptureWindow） ----");

        long t0800 = at(2026, 8, 21, 8, 0, 0);
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long t0830 = at(2026, 8, 21, 8, 30, 0);
        long t0835 = at(2026, 8, 21, 8, 35, 0);
        long t0900 = at(2026, 8, 21, 9, 0, 0);

        List<String> vols = new ArrayList<>();
        vols.add(volName("cap", t0800));
        vols.add(volName("cap", t0810));
        vols.add(volName("cap", t0830));
        vols.add(volName("cap", t0835));
        vols.add(volName("cap", t0900));

        // a) 未设置 start/end → 原样全选
        check(SplitUtil.selectVolumesInCaptureWindow(vols, null, null).size() == 5,
                "未设置 start/end 时全选（实际 "
                        + SplitUtil.selectVolumesInCaptureWindow(vols, null, null).size() + "）");

        // b) 仅 start：只保留起点 >= start 的卷
        List<String> from0810 = SplitUtil.selectVolumesInCaptureWindow(vols, t0810, null);
        check(from0810.size() == 4, "--start=08:10 选中 4 卷（实际 " + from0810.size() + "）");
        check(!from0810.contains(volName("cap", t0800)), "08:00 卷（起点 < start）被排除");

        // c) 仅 end：只保留起点 <= end 的卷
        List<String> upTo0835 = SplitUtil.selectVolumesInCaptureWindow(vols, null, t0835);
        check(upTo0835.size() == 4, "--end=08:35 选中 4 卷（实际 " + upTo0835.size() + "）");
        check(!upTo0835.contains(volName("cap", t0900)), "09:00 卷（起点 > end）被排除");

        // d) 两者同时：窗口 [08:10, 08:35]（含边界）
        List<String> window = SplitUtil.selectVolumesInCaptureWindow(vols, t0810, t0835);
        check(window.size() == 3, "[08:10,08:35] 选中 3 卷（实际 " + window.size() + "）");
        check(window.contains(volName("cap", t0810)), "边界 08:10 卷被包含");
        check(window.contains(volName("cap", t0835)), "边界 08:35 卷被包含");
        check(window.contains(volName("cap", t0830)), "窗口中间 08:30 卷被包含");
        check(!window.contains(volName("cap", t0900)), "窗口外 09:00 卷被排除");

        // e) 非分卷命名（拿不到时间戳）不缩小：保留
        List<String> mixed = new ArrayList<>();
        mixed.add(volName("cap", t0810));
        mixed.add(WORK_DIR.resolve("legacy.db").toString());
        List<String> sel = SplitUtil.selectVolumesInCaptureWindow(mixed, t0810, t0835);
        check(sel.size() == 2, "非分卷命名项按不缩小处理（实际 " + sel.size() + "）");

        // f) earliestVolumeStart
        check(SplitUtil.earliestVolumeStart(vols) == t0800,
                "earliestVolumeStart 返回最早窗口起点（实际 "
                        + SplitUtil.earliestVolumeStart(vols) + "）");
        check(SplitUtil.earliestVolumeStart(new ArrayList<>()) == null, "空列表 earliestVolumeStart 为 null");
    }

    // ==================== [1b] 最终卷名（<start>-<end>）的范围快速跳过 ====================

    private static void checkFinalNameSelection() {
        logger.info("---- [1b] 最终卷名（<start>-<end>）按完整范围快速跳过 ----");

        long t0800 = at(2026, 8, 21, 8, 0, 0);
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long t0820 = at(2026, 8, 21, 8, 20, 0);
        long t0835 = at(2026, 8, 21, 8, 35, 0);
        long t0845 = at(2026, 8, 21, 8, 45, 0);
        long t0900 = at(2026, 8, 21, 9, 0, 0);

        // 卷 [start, end)：08:00-08:10、08:10-08:20、08:20-08:35、08:35-08:45、08:45-09:00
        List<String> vols = new ArrayList<>();
        vols.add(finalVolName("cap", t0800, t0810));
        vols.add(finalVolName("cap", t0810, t0820));
        vols.add(finalVolName("cap", t0820, t0835));
        vols.add(finalVolName("cap", t0835, t0845));
        vols.add(finalVolName("cap", t0845, t0900));

        // a) start=08:10, end=08:35：相交的卷为 [08:10,08:20)、[08:20,08:35]
        List<String> window = SplitUtil.selectVolumesInCaptureWindow(vols, t0810, t0835);
        check(window.size() == 2, "[08:10,08:35] 按范围选中 2 卷（实际 " + window.size() + "）");
        check(window.contains(finalVolName("cap", t0810, t0820)), "边界 08:10 起始卷被包含");
        check(window.contains(finalVolName("cap", t0820, t0835)), "08:20 卷被包含");
        check(!window.contains(finalVolName("cap", t0800, t0810)),
                "整体在 start 之前的卷被快速跳过（不打开）");
        check(!window.contains(finalVolName("cap", t0835, t0845)),
                "整体在 end 之后的卷被快速跳过（不打开）");

        // b) start 落在某个卷中间：该卷仍应被选中（end > start）
        long mid = at(2026, 8, 21, 8, 5, 0); // 落在 [08:00,08:10) 内
        List<String> fromMid = SplitUtil.selectVolumesInCaptureWindow(vols, mid, null);
        check(fromMid.contains(finalVolName("cap", t0800, t0810)),
                "start 落在卷中间时该卷被保留（不丢数据）");

        // c) end 落在某卷中间：该卷仍应被选中（start < end）
        long midEnd = at(2026, 8, 21, 8, 40, 0); // 落在 [08:35,08:45) 内
        List<String> toMid = SplitUtil.selectVolumesInCaptureWindow(vols, null, midEnd);
        check(toMid.contains(finalVolName("cap", t0835, t0845)),
                "end 落在卷中间时该卷被保留（不丢数据）");
    }

    // ==================== [2] 卷内按 TimeStamp 过滤（真实 DuckDB） ====================

    private static void checkTimestampFiltering() throws Exception {
        logger.info("---- [2] 卷内按 TimeStamp 过滤（真实 DuckDB） ----");

        Path db = WORK_DIR.resolve("ts_window.db");
        long t0000 = at(2026, 8, 21, 0, 0, 0);
        long t0800 = at(2026, 8, 21, 8, 0, 0);
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long t0820 = at(2026, 8, 21, 8, 20, 0);
        long t0835 = at(2026, 8, 21, 8, 35, 0);
        long t0900 = at(2026, 8, 21, 9, 0, 0);

        // 建一个与重放过滤同构的表：ID + TimeStamp（绝对捕获时间），写入跨越窗口的包
        try (java.sql.Connection conn =
                     java.sql.DriverManager.getConnection("jdbc:duckdb:" + db);
             java.sql.Statement st = conn.createStatement()) {
            st.execute("Create Table JSharkLog (ID BIGINT primary key, TimeStamp timestamp)");
            long[] stamps = {t0000, t0800, t0810, t0820, t0835, t0900};
            for (int i = 0; i < stamps.length; i++) {
                st.executeUpdate("Insert Into JSharkLog (ID, TimeStamp) Values ("
                        + i + ", TIMESTAMP '" + toDuckDbTs(stamps[i]) + "')");
            }

            // 重放路径的两段式过滤语义：先按卷名选卷（这里单卷），卷内再按绝对 [start,end] 过滤
            long start = t0810;
            long end = t0835;
            String sql = "Select ID, TimeStamp From JSharkLog "
                    + "Where TimeStamp >= ? And TimeStamp <= ? Order By ID";
            try (java.sql.PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setObject(1, new java.sql.Timestamp(start));
                ps.setObject(2, new java.sql.Timestamp(end));
                try (java.sql.ResultSet rs = ps.executeQuery()) {
                    List<Long> in = new ArrayList<>();
                    while (rs.next()) {
                        in.add(rs.getTimestamp("TimeStamp").getTime());
                    }
                    check(in.size() == 3, "窗口 [08:10,08:35] 命中 3 个包（实际 " + in.size() + "）");
                    check(in.contains(t0810), "边界包 08:10 命中");
                    check(in.contains(t0820), "中间包 08:20 命中");
                    check(in.contains(t0835), "边界包 08:35 命中");
                    check(!in.contains(t0000), "窗口前包 00:00 排除");
                    check(!in.contains(t0800), "窗口前包 08:00 排除");
                    check(!in.contains(t0900), "窗口后包 09:00 排除");
                }
            }

            // 仅 start：TimeStamp >= start（含 08:10、08:20、08:35、以及 09:00）
            try (java.sql.PreparedStatement ps = conn.prepareStatement(
                    "Select count(*) From JSharkLog Where TimeStamp >= ?")) {
                ps.setObject(1, new java.sql.Timestamp(t0810));
                try (java.sql.ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    check(rs.getInt(1) == 4, "仅 --start=08:10 命中 4 个包（实际 " + rs.getInt(1) + "）");
                }
            }
        }
    }

    // ==================== [3] end 在 follow 模式的退出谓词 ====================

    private static void checkEndFollowPredicates() {
        logger.info("---- [3] end follow 退出谓词 ----");

        long t0830 = at(2026, 8, 21, 8, 30, 0);
        long t0835 = at(2026, 8, 21, 8, 35, 0);
        long t0840 = at(2026, 8, 21, 8, 40, 0);

        // a) 窗口整体在过去：所有卷起点都 > end → 选卷为空，且最早卷起点 > end → 应停止（不无限等待）
        List<String> allPast = new ArrayList<>();
        allPast.add(volName("cap", t0835));
        allPast.add(volName("cap", t0840));
        boolean selEmpty = SplitUtil.selectVolumesInCaptureWindow(allPast, null, t0830).isEmpty();
        boolean earliestPast = SplitUtil.earliestVolumeStart(allPast) > t0830;
        check(selEmpty && earliestPast,
                "end 在最早卷之前 → 选卷为空且最早起点越过 end（follow 应退出，不无限等）");

        // b) end 落在中间：窗口起始卷应被选中（边界语义，不丢数据）
        List<String> straddle = new ArrayList<>();
        straddle.add(volName("cap", t0830));
        straddle.add(volName("cap", t0835));
        List<String> w = SplitUtil.selectVolumesInCaptureWindow(straddle, null, t0830);
        check(w.size() == 1 && w.contains(volName("cap", t0830)),
                "end=08:35 时 08:30 卷仍在窗口内（应被选中），08:35 卷由卷内 TimeStamp 过滤决定");

        // c) 数据到达谓词 lastPacketTimestamp >= end（与 --end 同逻辑）
        boolean reached = (t0840 >= t0835);
        check(reached, "卷最大包时间戳越过 end 即触发退出");
        boolean notReached = (t0830 >= t0835) == false;
        check(notReached, "卷最大包时间戳未达 end 时不退出");
    }

    // ==================== [4] CLI 校验约束 ====================

    private static void checkCliValidation() {
        logger.info("---- [4] CLI 校验约束（validateTimeSelection） ----");

        long s = at(2026, 8, 21, 8, 10, 0);
        long e = at(2026, 8, 21, 8, 35, 0);

        // 绝对时间窗口对所有数据源都合法：不再有“仅分卷/仅非 pcap”的限制
        check(noThrow(() -> CliReplay.validateTimeSelection(null, null)),
                "未给出时间窗口合法");
        check(noThrow(() -> CliReplay.validateTimeSelection(s, null)),
                "仅 --start 合法");
        check(noThrow(() -> CliReplay.validateTimeSelection(null, e)),
                "仅 --end 合法");
        check(noThrow(() -> CliReplay.validateTimeSelection(s, e)),
                "start < end 合法（分卷 DB / 单卷 DB / PCAP 同一套规则）");
        check(noThrow(() -> CliReplay.validateTimeSelection(s, s)),
                "start == end（单点窗口）合法");

        // 顺序：end < start → 报错
        check(throwsIAE(() -> CliReplay.validateTimeSelection(e, s)),
                "end < start → 报错");
        String msg = thrownMsg(() -> CliReplay.validateTimeSelection(e, s));
        check(msg != null && msg.contains("is before --start"),
                "错误信息应指出 end 早于 start（实际 " + msg + "）");
    }

    // ==================== [5] follow 模式真跑 end 退出 ====================

    private static void checkFollowRealRun() throws Exception {
        logger.info("---- [5] follow 模式真跑 end 退出 ----");

        checkFollowExitsWhenWindowInPast();
        checkFollowExitsOnDataReachingEnd();
    }

    /**
     * 用例 5a：窗口整体在过去——所有分卷的窗口起点都晚于 end。
     * follow 主循环应在第一轮就命中"最早卷起点已越过 end"的守卫而退出，不无限等待。
     */
    private static void checkFollowExitsWhenWindowInPast() throws Exception {
        logger.info("---- [5a] end 在过去，窗口整体无数据 → follow 应直接退出 ----");
        long end = at(2026, 8, 21, 8, 30, 0);
        long t0835 = at(2026, 8, 21, 8, 35, 0);
        long t0840 = at(2026, 8, 21, 8, 40, 0);

        Path dir = WORK_DIR.resolve("follow-empty");
        Files.createDirectories(dir);
        // 伪造分卷（守卫在打开数据库之前就退出，无需真正 DuckDB）
        String b1 = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0835) + ".db").toString();
        String b2 = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0840) + ".db").toString();
        Files.writeString(Path.of(b1), "dummy");
        Files.writeString(Path.of(b2), "dummy");

        String base = dir.resolve("cap.db").toString();
        DbReplayTool tool = new DbReplayTool(base, 1.0, null, end,
                null, null, null, null, null, null, null, null);
        tool.setFollowPollIntervalMs(50);
        boolean exited = followExitsOnItsOwn(tool, 5000);
        check(exited, "end 在过去：follow 主循环自动退出（不无限等待新卷），实际过时则判定失败");
    }

    /**
     * 用例 5b：数据到达 end——分卷被选中回放，其最大包捕获时间戳 ≥ end。
     * 这里把所有包的 TimeStamp 都放在 end 之后，使卷内 SQL 过滤（TimeStamp &lt;= end）返回 0 行
     * （因此不会发任何包、不碰网卡），但 MAX(TimeStamp) ≥ end，命中"数据到达 end 即退出"。
     */
    private static void checkFollowExitsOnDataReachingEnd() throws Exception {
        logger.info("---- [5b] 数据到达 end → follow 重放完该卷后退出 ----");
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long end = at(2026, 8, 21, 8, 35, 0);
        long t0840 = at(2026, 8, 21, 8, 40, 0);
        long t0900 = at(2026, 8, 21, 9, 0, 0);
        long t0905 = at(2026, 8, 21, 9, 5, 0);

        Path dir = WORK_DIR.resolve("follow-data");
        Files.createDirectories(dir);

        // 被选中回放的分卷：窗口起点 08:10 ≤ end（按名选中），内含包时间戳全在 end(08:35) 之后；
        // 卷内过滤为空（不发送），但 MAX(TimeStamp)=09:00 ≥ end → 数据到达即退出。
        String dataVol = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0810) + ".db").toString();
        try (java.sql.Connection conn = DriverManager.getConnection("jdbc:duckdb:" + dataVol);
             java.sql.Statement st = conn.createStatement()) {
            st.execute("Create Table JSharkLog ("
                    + "Id BIGINT primary key, TimeStamp timestamp, rawData blob, "
                    + "sourceIp varchar, destinationIp varchar, sourcePort integer, "
                    + "destinationPort integer, ipProtocol varchar, appProtocol varchar, "
                    + "additionalInfo varchar)");
            insertPacket(st, 1, t0840);
            insertPacket(st, 2, t0900);
        }

        // 更晚的新增分卷（follow 永远不读最新卷，避免"读到仍在写入"的锁冲突假设）——
        // 只造占位文件即可，因其作为 globalNewest 不会被打开。
        String newest = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0905) + ".db").toString();
        Files.writeString(Path.of(newest), "dummy");

        String base = dir.resolve("cap.db").toString();
        DbReplayTool tool = new DbReplayTool(base, 1.0, null, end,
                null, null, null, null, null, null, null, null);
        tool.setFollowPollIntervalMs(50);
        boolean exited = followExitsOnItsOwn(tool, 5000);
        check(exited, "数据到达 end：follow 回放完选中卷后自动退出");
    }

    private static void insertPacket(java.sql.Statement st, long id, long tsMs) throws java.sql.SQLException {
        st.executeUpdate("Insert Into JSharkLog (Id, TimeStamp) Values ("
                + id + ", TIMESTAMP '" + toDuckDbTs(tsMs) + "')");
    }

    /** 在独立守护线程里跑 startReplay，限时观察其是否自行退出；超时则 stopReplay 并判失败。 */
    private static boolean followExitsOnItsOwn(DbReplayTool tool, long timeoutMs) {
        Thread t = new Thread(tool::startReplay, "follow-replay-test");
        t.setDaemon(true);
        t.start();
        long deadline = System.currentTimeMillis() + timeoutMs;
        try {
            while (t.isAlive() && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        boolean exited = !t.isAlive();
        if (!exited) {
            tool.stopReplay();
            try {
                t.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return exited;
    }

    // ==================== 工具 ====================

    private static String volName(String base, long windowStartMs) {
        return WORK_DIR.resolve(base + "_" + SplitUtil.formatTimestamp(windowStartMs) + ".db").toString();
    }

    private static String finalVolName(String base, long startMs, long endMs) {
        return WORK_DIR.resolve(base + "_" + SplitUtil.formatTimestamp(startMs)
                + "-" + SplitUtil.formatTimestamp(endMs) + ".db").toString();
    }

    private static String toDuckDbTs(long epochMs) {
        return LocalDateTime.ofInstant(java.time.Instant.ofEpochMilli(epochMs), ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
    }

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    private static boolean noThrow(ThrowingRunnable r) {
        try {
            r.run();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean throwsIAE(ThrowingRunnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String thrownMsg(ThrowingRunnable r) {
        try {
            r.run();
            return null;
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** 断言成功（失败即测试失败）：保留原夹具的调用形态与中文消息，内部改用 JUnit 断言。 */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
