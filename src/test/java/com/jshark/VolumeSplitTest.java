package com.jshark;

import com.jshark.parser.SplitUtil;
import com.jshark.parser.VolumeWindows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * C 阶段集成验收：时间分卷 + manifest + 停机快照。
 *
 * <h3>用可控时钟驱动，无需真实等待</h3>
 * <p>
 * 通过注入递增的假时钟推进采集循环，模拟"跨过多个时间边界"与"长时间无流量"，
 * 从而在秒级完成原本需要数分钟的验证。
 * </p>
 *
 * <h3>验证项</h3>
 * <ol>
 *   <li>窗口边界落在自然网格上；首窗从启动时刻到下一个边界</li>
 *   <li>一次跨越 m 个边界时补齐 m 个窗口（含"零消息也出卷"）</li>
 *   <li>有 logdb 时，每条 manifest 写入该卷 db 的 {@code JSharkManifest} 表，内容自洽（时间、序号、完整性、关闭原因）</li>
 *   <li>不产生旁路 {@code .manifest.json} 文件（pcap-only sidecar 特性已移除）</li>
 * </ol>
 */
public class VolumeSplitTest {

    private static final Logger logger = LoggerFactory.getLogger(VolumeSplitTest.class);

    private static final Path WORK_DIR = Path.of("target", "test-c");

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void volumeSplitRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  C 验收：时间分卷 + manifest");
        logger.info("=================================================");

        step0_prepare();
        checkRotationWithFakeClock();
        checkManifestContent();
        checkNoSidecarManifest();

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

    /** 用例 1：用假时钟推进，验证跨越多个边界时补齐窗口 */
    private static void checkRotationWithFakeClock() {
        logger.info("---- [1] 假时钟驱动的跨边界轮转 ----");

        AtomicLong fakeNow = new AtomicLong(at(2026, 2, 2, 10, 0, 0));
        String base = WORK_DIR.resolve("rot.db").toString();
        VolumeWindows w = new VolumeWindows(base, 60_000L, fakeNow::get);
        w.initialize(fakeNow.get());

        check(w.currentStartMs() == at(2026, 2, 2, 10, 0, 0), "首窗起点 == 初始化时刻");
        check(w.currentEndMs() == at(2026, 2, 2, 10, 1, 0), "1m 首窗结束于整分钟");

        // 正常推进：过 10:00:30，不应轮转
        fakeNow.set(at(2026, 2, 2, 10, 0, 30));
        check(!w.advance().rotated(), "未到边界时不轮转");

        // 越过 10:01 → 轮转一次
        fakeNow.set(at(2026, 2, 2, 10, 1, 5));
        VolumeWindows.Advance adv1 = w.advance();
        check(adv1.closed().size() == 1, "越过 1 个边界 → 关闭 1 个窗口（实际 " + adv1.closed().size() + "）");
        check(adv1.closed().get(0).startMs() == at(2026, 2, 2, 10, 0, 0)
                        && adv1.closed().get(0).endMs() == at(2026, 2, 2, 10, 1, 0),
                "被关闭窗口为 [10:00, 10:01)");
        check(w.currentStartMs() == at(2026, 2, 2, 10, 1, 0), "新窗口起点为 10:01");

        // 模拟长时间无流量：一次跳到 10:06:30，跨 5 个边界
        fakeNow.set(at(2026, 2, 2, 10, 6, 30));
        VolumeWindows.Advance adv2 = w.advance();
        List<VolumeWindows.ClosedWindow> closed = adv2.closed();
        check(closed.size() == 5, "跨越 5 个边界补齐 5 个窗口（实际 " + closed.size() + "）");
        check(closed.get(0).startMs() == at(2026, 2, 2, 10, 1, 0)
                        && closed.get(4).endMs() == at(2026, 2, 2, 10, 6, 0),
                "补齐区间覆盖 [10:01, 10:06)");
        check(w.currentStartMs() == at(2026, 2, 2, 10, 6, 0)
                        && w.currentEndMs() == at(2026, 2, 2, 10, 7, 0),
                "当前窗口为 [10:06, 10:07)");
        boolean sequential = true;
        for (int i = 0; i < closed.size(); i++) {
            if (closed.get(i).volumeSeq() != i + 2) {
                sequential = false;
            }
        }
        check(sequential, "序号连续（从 2 到 6）");

        // 每个窗口的文件名一一对应且时间戳一致
        boolean namesOk = true;
        for (VolumeWindows.ClosedWindow c : closed) {
            String db = w.fileFor(c.startMs());
            String finalDb = w.finalFileFor(c.startMs(), c.endMs());
            String pcap = w.pcapFor(c.startMs());
            String stamp = SplitUtil.formatTimestamp(c.startMs());
            if (!db.endsWith("rot_" + stamp + "-capturing.db")
                    || !finalDb.endsWith("rot_" + stamp + "-" + SplitUtil.formatTimestamp(c.endMs()) + ".db")
                    || !pcap.endsWith("rot_" + stamp + ".pcap")) {
                namesOk = false;
            }
        }
        check(namesOk, "所有窗口的 db（捕获中/最终）/pcap 文件名使用同一时间戳");
    }

    /** 用例 2：manifest 的写入与内容自洽（旁路文件回退 + 入库两种路径） */
    private static void checkManifestContent() throws Exception {
        logger.info("---- [2] manifest 入库（JSharkManifest 表） ----");

        long start = at(2026, 2, 2, 11, 0, 0);
        long end = at(2026, 2, 2, 11, 1, 0);

        Path manifestDb = WORK_DIR.resolve("manifest_table.db");
        try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:duckdb:" + manifestDb);
             java.sql.Statement st = conn.createStatement()) {
            st.execute("""
                    Create Table IF Not Exists JSharkManifest (
                        volumeSeq BIGINT, startMs BIGINT, endMs BIGINT, startTime text, endTime text,
                        packetCount BIGINT, completeWindow boolean, closedReason text,
                        dropped text, info text)
                    """);

            // 完整窗口
            com.jshark.parser.VolumeManifest complete =
                    new com.jshark.parser.VolumeManifest(7, start, end);
            complete.packetCount(1234);
            complete.closed(true, "boundary");
            complete.dropped("afterSnapshot", 0);
            complete.dropped("inFlight", 3);
            complete.put("splitIntervalMs", 60_000L);
            complete.writeToDb(conn);

            // 停机中断窗口：标为不完整
            com.jshark.parser.VolumeManifest interrupted =
                    new com.jshark.parser.VolumeManifest(8, end, end + 60_000L);
            interrupted.packetCount(99);
            interrupted.closed(false, "shutdown");
            interrupted.writeToDb(conn);

            try (java.sql.ResultSet rs = st.executeQuery(
                    "Select volumeSeq, startTime, packetCount, completeWindow, closedReason, dropped, info "
                            + "From JSharkManifest Order By volumeSeq")) {
                check(rs.next(), "JSharkManifest 表有第一条 manifest");
                check(rs.getLong("volumeSeq") == 7, "表里 volumeSeq=7（实际 " + rs.getLong("volumeSeq") + "）");
                check(rs.getLong("packetCount") == 1234, "表里 packetCount=1234（实际 " + rs.getLong("packetCount") + "）");
                check(rs.getBoolean("completeWindow"), "完整窗口 completeWindow=true");
                check(rs.getString("closedReason").contains("boundary"), "完整窗口 closedReason=boundary");
                check(rs.getString("startTime").endsWith("110000"), "startTime 为 yyyyMMddHHmmss（实际 "
                        + rs.getString("startTime") + "）");
                String dropped = rs.getString("dropped");
                check(dropped.contains("\"inFlight\": 3") || dropped.contains("\"inFlight\":3"),
                        "表里 dropped.inFlight=3（实际 " + dropped + "）");
                String info = rs.getString("info");
                check(info.contains("splitIntervalMs"), "表里 info 有 splitIntervalMs（实际 " + info + "）");

                check(rs.next(), "JSharkManifest 表有第二条 manifest");
                check(!rs.getBoolean("completeWindow"), "停机窗口 completeWindow=false");
                check(rs.getString("closedReason").contains("shutdown"), "停机窗口 closedReason=shutdown");
            }
        }
    }

    /** 用例 3：不再产生任何旁路 .manifest.json 文件（pcap-only sidecar 特性已移除） */
    private static void checkNoSidecarManifest() throws Exception {
        logger.info("---- [3] 无旁路 .manifest.json 文件 ----");
        long count = Files.list(WORK_DIR).filter(p -> p.toString().endsWith(".manifest.json")).count();
        check(count == 0, "工作目录中不存在任何 .manifest.json 旁路文件（实际 " + count + " 个）");
    }

    // ==================== 工具 ====================

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    /**
     * 断言成功（失败即测试失败）。
     * <p>保留原夹具的调用形态与中文消息，内部改成 JUnit 断言。</p>
     */
    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
