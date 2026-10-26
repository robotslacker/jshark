package com.jshark;

import com.jshark.parser.SplitUtil;
import com.jshark.parser.VolumeWindows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

/**
 * C 阶段单元验收：时间窗与自然网格对齐。
 *
 * <h3>验证项</h3>
 * <ol>
 *   <li>边界落在自然网格上（5m → 整 5 分钟；1h → 整点；1d → 本地零点）</li>
 *   <li>首窗从启动时刻开始、结束于下一个网格边界（可能不足一个完整间隔）</li>
 *   <li>长期运行不累积漂移（连续推进 1 天，窗口数与理论值一致）</li>
 *   <li>一次跨越多个边界时补齐中间窗口，序列不跳号（"零消息也出卷"）</li>
 *   <li>文件名：logdb 与 PCAP 使用同一时间戳；manifest 路径成对</li>
 * </ol>
 *
 * <p>纯计算断言：通过注入"当前时间"驱动 {@link VolumeWindows#advance(long)}，
 * 不依赖真实时钟、不需要网络。</p>
 */
public class VolumeWindowsTest {

    private static final Logger logger = LoggerFactory.getLogger(VolumeWindowsTest.class);

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void volumeWindowsRegression() {
        logger.info("=================================================");
        logger.info("  C 验收：自然时间窗");
        logger.info("=================================================");

        checkGridAlignment();
        checkFirstWindow();
        checkNoDrift();
        checkCatchUpAcrossBoundaries();
        checkFileNaming();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    /** 用例 1：边界必须落在自然网格上 */
    private static void checkGridAlignment() {
        logger.info("---- [1] 自然网格对齐 ----");

        // 10:03:20 启动、间隔 5 分钟 → 首窗结束于 10:05:00
        long start = at(2026, 2, 2, 10, 3, 20);
        VolumeWindows w = new VolumeWindows(null, 5 * 60_000L);
        w.initialize(start);
        check(w.currentStartMs() == start, "首窗起点 == 启动时刻");
        check(w.currentEndMs() == at(2026, 2, 2, 10, 5, 0),
                "5m 首窗结束于整 5 分钟边界 (" + fmt(w.currentEndMs()) + ")");

        // 1 小时：结束于整点
        VolumeWindows hourly = new VolumeWindows(null, 60 * 60_000L);
        hourly.initialize(at(2026, 2, 2, 10, 3, 20));
        check(hourly.currentEndMs() == at(2026, 2, 2, 11, 0, 0),
                "1h 首窗结束于整点 (" + fmt(hourly.currentEndMs()) + ")");

        // 1 天：结束于本地次日零点
        VolumeWindows daily = new VolumeWindows(null, 24 * 60 * 60_000L);
        daily.initialize(at(2026, 2, 2, 10, 3, 20));
        check(daily.currentEndMs() == at(2026, 2, 3, 0, 0, 0),
                "1d 首窗结束于本地零点 (" + fmt(daily.currentEndMs()) + ")");

        // 单位规则：最小为分钟。不再支持秒，也不接受省略单位
        check(SplitUtil.parseSplit("5m") == 5 * 60_000L, "5m 解析为 5 分钟");
        check(SplitUtil.parseSplit("1h") == 60 * 60_000L, "1h 解析为 1 小时");
        check(SplitUtil.parseSplit("1d") == 24 * 60 * 60_000L, "1d 解析为 1 天");
        check(SplitUtil.parseSplit("1M") == 60_000L, "单位大小写不敏感（1M = 1 分钟）");
        checkThrows(() -> SplitUtil.parseSplit("300S"), "秒单位已取消：300S 应报错");
        checkThrows(() -> SplitUtil.parseSplit("1s"), "秒单位已取消：1s 应报错");
        checkThrows(() -> SplitUtil.parseSplit("300"),
                "省略单位应报错（否则 300 会从 5 分钟悄悄变成 300 分钟）");
        checkThrows(() -> SplitUtil.parseSplit("0m"), "0m 应报错（必须大于 0）");
        checkThrows(() -> SplitUtil.parseSplit("m"), "只有单位没有数字应报错");
        checkThrows(() -> SplitUtil.parseSplit("5x"), "非法单位应报错");

        // 说明：SplitUtil.alignToGrid 是"向下取整到网格"（10:03:20 → 10:00:00），
        // VolumeWindows.nextBoundary 在其基础上 +1 个间隔，因此得到 10:05:00。
        check(SplitUtil.alignToGrid(start, 5 * 60_000L) == at(2026, 2, 2, 10, 0, 0),
                "alignToGrid 向下取整到 10:00");
    }

    /** 用例 2：首窗可从网格中间开始（短于一个完整间隔） */
    private static void checkFirstWindow() {
        logger.info("---- [2] 首窗语义 ----");
        long start = at(2026, 2, 2, 10, 3, 20);
        VolumeWindows w = new VolumeWindows(null, 5 * 60_000L);
        w.initialize(start);
        long firstLen = w.currentEndMs() - w.currentStartMs();
        check(firstLen == 100_000L, "首窗长度 == 到下一个边界的距离 (100s，实际 " + firstLen / 1000 + "s)");
        check(w.currentSeq() == 1, "首窗序号为 1");

        // 恰好在边界上启动：首窗应为完整间隔，而不是零长度
        VolumeWindows onGrid = new VolumeWindows(null, 5 * 60_000L);
        onGrid.initialize(at(2026, 2, 2, 10, 5, 0));
        check(onGrid.currentEndMs() == at(2026, 2, 2, 10, 10, 0),
                "整点启动时首窗为完整间隔 (" + fmt(onGrid.currentEndMs()) + ")");
    }

    /** 用例 3：连续推进不累积漂移 */
    private static void checkNoDrift() {
        logger.info("---- [3] 无累积漂移 ----");
        long start = at(2026, 2, 2, 10, 3, 20);
        VolumeWindows w = new VolumeWindows(null, 5 * 60_000L);
        w.initialize(start);

        // 推进 24 小时，逐 10 秒 tick 一次（模拟抓包循环）
        long end = start + 24L * 60 * 60_000L;
        long closedCount = 0;
        long lastBoundary = w.currentEndMs();
        boolean allOnGrid = true;
        for (long t = start; t <= end; t += 10_000L) {
            VolumeWindows.Advance adv = w.advance(t);
            closedCount += adv.closed().size();
            for (VolumeWindows.ClosedWindow c : adv.closed()) {
                if (c.endMs() % (5 * 60_000L) != 0) {
                    allOnGrid = false;
                }
            }
            lastBoundary = w.currentEndMs();
        }

        // 首窗 10:03:20→10:05:00 之后，24 小时内还有 287 个完整 5 分钟窗（至次日 10:05）
        check(closedCount >= 287 && closedCount <= 289,
                "24 小时共关闭约 288 个窗口（实际 " + closedCount + "）");
        check(allOnGrid, "所有窗口边界都落在 5 分钟网格上（无漂移）");
        check(w.currentStartMs() % (5 * 60_000L) == 0,
                "当前窗口起点也在网格上 (" + fmt(w.currentStartMs()) + ")");
        check(w.currentEndMs() % (5 * 60_000L) == 0, "当前窗口终点在网格上");
    }

    /** 用例 4：跨多个边界时补齐中间窗口（零消息也出卷） */
    private static void checkCatchUpAcrossBoundaries() {
        logger.info("---- [4] 跨边界补齐 ----");
        long start = at(2026, 2, 2, 10, 0, 0);
        VolumeWindows w = new VolumeWindows(null, 5 * 60_000L);
        w.initialize(start);

        // 从 10:00 一次跳到 10:22:30（跨过 10:05/10:10/10:15/10:20 四个边界）
        VolumeWindows.Advance adv = w.advance(at(2026, 2, 2, 10, 22, 30));
        List<VolumeWindows.ClosedWindow> closed = adv.closed();

        check(closed.size() == 4, "一次跨越 4 个边界补齐 4 个窗口（实际 " + closed.size() + "）");
        check(closed.get(0).startMs() == at(2026, 2, 2, 10, 0, 0)
                        && closed.get(0).endMs() == at(2026, 2, 2, 10, 5, 0),
                "第 1 个被关闭窗口为 [10:00, 10:05)");
        check(closed.get(3).startMs() == at(2026, 2, 2, 10, 15, 0)
                        && closed.get(3).endMs() == at(2026, 2, 2, 10, 20, 0),
                "第 4 个被关闭窗口为 [10:15, 10:20)");
        check(w.currentStartMs() == at(2026, 2, 2, 10, 20, 0)
                        && w.currentEndMs() == at(2026, 2, 2, 10, 25, 0),
                "当前窗口为 [10:20, 10:25)");

        // 序列不跳号
        boolean sequential = true;
        for (int i = 0; i < closed.size(); i++) {
            if (closed.get(i).volumeSeq() != i + 1) {
                sequential = false;
            }
        }
        check(sequential, "窗口序号连续不跳号（1.." + closed.size() + "）");
        check(w.currentSeq() == 5, "当前窗口序号为 5（实际 " + w.currentSeq() + "）");

        // 未跨边界时不产生窗口
        VolumeWindows.Advance none = w.advance(at(2026, 2, 2, 10, 24, 0));
        check(none.closed().isEmpty() && !none.rotated(), "未跨边界时不切换窗口");
    }

    /** 用例 5：文件名配对 */
    private static void checkFileNaming() {
        logger.info("---- [5] 文件命名 ----");
        String base = java.nio.file.Path.of("target", "test-c", "capture.db").toString();
        VolumeWindows w = new VolumeWindows(base, 5 * 60_000L);
        long start = at(2026, 2, 2, 10, 5, 0);
        long end = at(2026, 2, 2, 10, 10, 0);
        w.initialize(start);

        String db = w.fileFor(start);          // 捕获中的 logdb
        String finalDb = w.finalFileFor(start, end); // 关闭后的最终 logdb
        String pcap = w.pcapFor(start);

        String stamp = SplitUtil.formatTimestamp(start);
        String endStamp = SplitUtil.formatTimestamp(end);
        check(db != null && db.endsWith("capture_" + stamp + "-capturing.db"),
                "捕获中 logdb 文件名带窗口时间戳（-capturing）("
                        + java.nio.file.Path.of(db).getFileName() + ")");
        check(finalDb != null && finalDb.endsWith("capture_" + stamp + "-" + endStamp + ".db"),
                "最终 logdb 文件名携带起止时间范围 ("
                        + java.nio.file.Path.of(finalDb).getFileName() + ")");
        check(pcap != null && pcap.endsWith("capture_" + stamp + ".pcap"),
                "PCAP 文件名使用同一时间戳 (" + java.nio.file.Path.of(pcap).getFileName() + ")");

        // 两个输出集合的时间戳必须一致（早期"两套独立时钟"就在这里出错）
        int dbStampStart = db.lastIndexOf("capture_") + "capture_".length();
        int dbStampEnd = db.indexOf('-', dbStampStart);
        String dbStamp = (dbStampEnd > dbStampStart) ? db.substring(dbStampStart, dbStampEnd) : "";
        String pcapStamp = pcap.substring(pcap.lastIndexOf("capture_") + 8, pcap.lastIndexOf('.'));
        check(dbStamp.equals(pcapStamp), "logdb 与 PCAP 的窗口时间戳完全一致 (" + dbStamp + ")");
    }

    // ==================== 工具 ====================

    /** 构造本地时间对应的 epoch 毫秒 */
    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s)
                .atZone(ZoneId.systemDefault())
                .toInstant()
                .toEpochMilli();
    }

    private static String fmt(long epochMs) {
        return LocalDateTime.ofInstant(java.time.Instant.ofEpochMilli(epochMs), ZoneId.systemDefault())
                .toString();
    }

    /**
     * 断言成功（失败即测试失败）。
     * <p>保留原夹具的调用形态与中文消息，内部改成 JUnit 断言：
     * 这样几百处 {@code check(...)} 调用点一行都不用改，而失败会真正让构建失败。</p>
     */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }

    /** 断言给定操作抛出 IllegalArgumentException（用于校验非法参数被拒绝） */
    private static void checkThrows(Runnable action, String message) {
        totalChecks++;
        IllegalArgumentException e = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class, action::run, message);
        logger.info("[通过] {}（{}）", message, e.getMessage());
    }
}
