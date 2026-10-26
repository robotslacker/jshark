package com.jshark;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.jshark.parser.SourceInspector;
import com.jshark.parser.SplitUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 启动前源检查（--inspect）的回归测试。
 *
 * <p>用真实 DuckDB 时间分卷验证：文件列表、起止/时长、可回放计数、LIVE 标记、
 * selected 的绝对 start/end 裁剪。capturing 卷只按文件名识别，不被打开。</p>
 */
public class SourceInspectorTest {

    @TempDir
    Path dir;

    @Test
    void inspectsSplitVolumesWithoutOpeningCapturingFile() throws Exception {
        long t0800 = at(2026, 8, 21, 8, 0, 0);
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long t0820 = at(2026, 8, 21, 8, 20, 0);

        Path v1 = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0800)
                + "-" + SplitUtil.formatTimestamp(t0810) + ".db");
        Path v2 = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0810)
                + "-" + SplitUtil.formatTimestamp(t0820) + ".db");
        createDb(v1, t0800 + 1_000, t0810 - 1_000);
        createDb(v2, t0810 + 1_000, t0820 - 1_000);

        // 故意写成非 DuckDB 内容：SourceInspector 不应打开 capturing 卷，否则这里会失败。
        Path capturing = dir.resolve("cap_" + SplitUtil.formatTimestamp(t0820) + "-capturing.db");
        Files.writeString(capturing, "still being written, not a database");

        String base = dir.resolve("cap.db").toString();
        SourceInspector.Options options = new SourceInspector.Options(
                base, null, "payload", true, false,
                t0800 + 5 * 60_000L, t0810 + 5 * 60_000L);

        JSONObject result = SourceInspector.inspect(options, "s1", null);

        assertEquals("inspect-result", result.getString("type"));
        assertEquals("s1", result.getString("inspectSession"));
        JSONObject source = result.getJSONObject("source");
        assertEquals("db", source.getString("kind"));
        assertTrue(source.getBooleanValue("split"));
        assertTrue(source.getBooleanValue("live"));
        assertEquals(3, source.getIntValue("volumes"));
        assertEquals(2, source.getIntValue("replayableVolumes"));

        assertEquals(3, result.getJSONArray("files").size());

        JSONObject summary = result.getJSONObject("summary");
        assertEquals((long) (t0800 + 1_000), summary.getLongValue("dataStartMs"));
        assertEquals((long) (t0820 - 1_000), summary.getLongValue("dataEndMs"));
        assertEquals((long) (t0820 - 1_000 - (t0800 + 1_000)), summary.getLongValue("durationMs"));
        assertEquals(2, summary.getIntValue("replayableCount"));
        assertTrue(summary.getBooleanValue("live"));
        assertFalse(summary.getBooleanValue("waiting"));

        JSONObject selected = result.getJSONObject("selected");
        assertEquals("start/end", selected.getString("source"));
        assertEquals((long) (t0800 + 5 * 60_000L), selected.getLongValue("fromMs"));
        assertEquals((long) (t0810 + 5 * 60_000L), selected.getLongValue("toMs"));
        assertEquals((long) (10 * 60_000L), selected.getLongValue("durationMs"));

        // capturing 卷必须被标记为不可回放，且不参与数据范围。
        JSONObject captureRow = result.getJSONArray("files").stream()
                .map(o -> (JSONObject) o)
                .filter(o -> o.getString("name").contains("-capturing"))
                .findFirst().orElseThrow();
        assertFalse(captureRow.getBooleanValue("replayable"));
        assertEquals("capturing", captureRow.getString("status"));
        assertNull(captureRow.get("dataStartMs"));
    }

    @Test
    void absoluteStartEndAreSelectedAsIs() throws Exception {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 8, 10, 0);
        Path v1 = dir.resolve("abs_" + SplitUtil.formatTimestamp(start)
                + "-" + SplitUtil.formatTimestamp(end) + ".db");
        createDb(v1, start, end);

        SourceInspector.Options options = new SourceInspector.Options(
                dir.resolve("abs.db").toString(), null, "payload", true, false,
                start + 60_000L, end + 60_000L);

        JSONObject result = SourceInspector.inspect(options, "s2", null);
        JSONObject selected = result.getJSONObject("selected");
        assertEquals("start/end", selected.getString("source"));
        assertEquals(start + 60_000L, selected.getLongValue("fromMs"));
        assertEquals(end, selected.getLongValue("toMs"), "超出数据范围的 end 应被裁剪");
        assertTrue(selected.getBooleanValue("clamped"));
    }

    @Test
    void endBeforeStartIsRejected() throws Exception {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 8, 10, 0);
        Path v1 = dir.resolve("bad_" + SplitUtil.formatTimestamp(start)
                + "-" + SplitUtil.formatTimestamp(end) + ".db");
        createDb(v1, start, end);

        SourceInspector.Options options = new SourceInspector.Options(
                dir.resolve("bad.db").toString(), null, "payload", true, false,
                end, start);

        IllegalArgumentException error = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> SourceInspector.inspect(options, "s-bad", null));
        assertTrue(error.getMessage().contains("is before --start"));
    }

    @Test
    void noReplayableVolumeIsWaiting() throws Exception {
        long start = at(2026, 8, 21, 9, 0, 0);
        Path capturing = dir.resolve("wait_" + SplitUtil.formatTimestamp(start) + "-capturing.db");
        Files.writeString(capturing, "not a db");

        SourceInspector.Options options = new SourceInspector.Options(
                dir.resolve("wait.db").toString(), null, "payload", true, false,
                null, null);

        JSONObject result = SourceInspector.inspect(options, "s3", null);
        JSONObject summary = result.getJSONObject("summary");
        assertEquals(0, summary.getIntValue("replayableCount"));
        assertTrue(summary.getBooleanValue("waiting"));
        assertNull(result.getJSONObject("selected").get("fromMs"));
    }

    @Test
    void singleInstantDataRangeIsValid() throws Exception {
        long t = at(2026, 8, 21, 10, 0, 0);
        Path db = dir.resolve("instant.db");
        createDb(db, t, t);

        SourceInspector.Options options = new SourceInspector.Options(
                db.toString(), null, "payload", true, false,
                null, null);
        JSONObject result = SourceInspector.inspect(options, "s-instant", null);

        JSONObject summary = result.getJSONObject("summary");
        assertEquals(0L, summary.getLongValue("durationMs"));
        JSONObject selected = result.getJSONObject("selected");
        assertEquals(t, selected.getLongValue("fromMs"));
        assertEquals(t, selected.getLongValue("toMs"));
        assertEquals(0L, selected.getLongValue("durationMs"));
        JSONArray warnings = result.getJSONArray("warnings");
        assertTrue(warnings == null || warnings.stream()
                        .map(o -> ((JSONObject) o).getString("code"))
                        .noneMatch("EMPTY_SELECTED_RANGE"::equals),
                "单瞬时数据不应被判定为空范围: " + warnings);
    }

    @Test
    void rejectsBothSources() {
        SourceInspector.Options options = new SourceInspector.Options(
                "a.db", "b.pcap", "payload", true, false,
                null, null);
        try {
            SourceInspector.inspect(options, "s4", null);
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("exactly one data source"));
        } catch (Exception e) {
            throw new AssertionError("expected IllegalArgumentException, got " + e, e);
        }
    }

    // ==================== 帧能力（payload 捕获 vs 帧捕获） ====================

    @Test
    void payloadOnlyDatabaseCannotReplayFrames() throws Exception {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 8, 10, 0);
        Path db = dir.resolve("payload_only.db");
        // 旧库结构：只有 rawData，没有 frameData。这类库只能按载荷重放。
        createDb(db, start, end);

        // 显式 frame + inject：如果 UI 不拦，重放会先开网卡、再在第一个卷上失败。
        SourceInspector.Options options = new SourceInspector.Options(
                db.toString(), null, "frame", true, true, null, null);
        JSONObject result = SourceInspector.inspect(options, "s-frame", null);

        JSONObject source = result.getJSONObject("source");
        assertFalse(source.getBooleanValue("frameCapable"),
                "没有 frameData 的库必须判定为不能帧级重放");
        assertEquals(0, source.getIntValue("frameVolumes"));
        assertEquals(1, source.getIntValue("payloadOnlyVolumes"));

        JSONObject file = result.getJSONArray("files").getJSONObject(0);
        assertFalse(file.getBooleanValue("hasFrames"));

        assertTrue(warningCodes(result).contains("DB_PAYLOAD_ONLY"),
                "payload 捕获的库应给出 DB_PAYLOAD_ONLY 告警: " + result.getJSONArray("warnings"));
    }

    @Test
    void payloadOnlySplitDatabaseStillSupportsFollow() throws Exception {
        long t0800 = at(2026, 8, 21, 8, 0, 0);
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long t0820 = at(2026, 8, 21, 8, 20, 0);
        Path v1 = dir.resolve("pcap_" + SplitUtil.formatTimestamp(t0800)
                + "-" + SplitUtil.formatTimestamp(t0810) + ".db");
        Path v2 = dir.resolve("pcap_" + SplitUtil.formatTimestamp(t0810)
                + "-" + SplitUtil.formatTimestamp(t0820) + ".db");
        createDb(v1, t0800 + 1_000, t0810 - 1_000);
        createDb(v2, t0810 + 1_000, t0820 - 1_000);

        SourceInspector.Options options = new SourceInspector.Options(
                dir.resolve("pcap.db").toString(), null, "frame", true, true, null, null);
        JSONObject result = SourceInspector.inspect(options, "s-follow", null);

        JSONObject source = result.getJSONObject("source");
        assertTrue(source.getBooleanValue("split"));
        assertFalse(source.getBooleanValue("frameCapable"));
        assertTrue(source.getBooleanValue("followSupported"),
                "只能 payload 的分卷库同样应该支持 follow（payload 模式）");
    }

    @Test
    void frameDatabaseIsFrameCapable() throws Exception {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 8, 10, 0);
        Path db = dir.resolve("with_frames.db");
        createFrameDb(db, start, end);

        SourceInspector.Options options = new SourceInspector.Options(
                db.toString(), null, "frame", true, true, null, null);
        JSONObject result = SourceInspector.inspect(options, "s-frames", null);

        JSONObject source = result.getJSONObject("source");
        assertTrue(source.getBooleanValue("frameCapable"));
        assertEquals(1, source.getIntValue("frameVolumes"));
        assertEquals(0, source.getIntValue("payloadOnlyVolumes"));

        JSONObject file = result.getJSONArray("files").getJSONObject(0);
        assertTrue(file.getBooleanValue("hasFrames"));
        assertFalse(warningCodes(result).contains("DB_PAYLOAD_ONLY"));
    }

    @Test
    void mixedVolumesReportPartialFrameData() throws Exception {
        long t0800 = at(2026, 8, 21, 8, 0, 0);
        long t0810 = at(2026, 8, 21, 8, 10, 0);
        long t0820 = at(2026, 8, 21, 8, 20, 0);
        Path legacy = dir.resolve("mix_" + SplitUtil.formatTimestamp(t0800)
                + "-" + SplitUtil.formatTimestamp(t0810) + ".db");
        Path frames = dir.resolve("mix_" + SplitUtil.formatTimestamp(t0810)
                + "-" + SplitUtil.formatTimestamp(t0820) + ".db");
        createDb(legacy, t0800 + 1_000, t0810 - 1_000);
        createFrameDb(frames, t0810 + 1_000, t0820 - 1_000);

        SourceInspector.Options options = new SourceInspector.Options(
                dir.resolve("mix.db").toString(), null, "frame", true, true, null, null);
        JSONObject result = SourceInspector.inspect(options, "s-mixed", null);

        JSONObject source = result.getJSONObject("source");
        assertTrue(source.getBooleanValue("frameCapable"), "只要有一个卷带帧，frame 仍然可选");
        assertEquals(1, source.getIntValue("frameVolumes"));
        assertEquals(1, source.getIntValue("payloadOnlyVolumes"));
        assertTrue(warningCodes(result).contains("DB_PARTIAL_FRAMES"),
                "混合库应提示哪些卷在帧模式下会被跳过: " + result.getJSONArray("warnings"));
    }

    // ==================== 工具 ====================

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

    /** 带 frameData 的“帧捕获”库：帧级重放可用。 */
    private static void createFrameDb(Path path, long firstMs, long lastMs) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + path);
             Statement st = conn.createStatement()) {
            st.execute("Create Table JSharkLog (Id BIGINT, TimeStamp timestamp, frameData BLOB)");
        }
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + path);
             java.sql.PreparedStatement ps = conn.prepareStatement(
                     "Insert Into JSharkLog (Id, TimeStamp, frameData) "
                             + "Values (?, CAST(? AS TIMESTAMP), ?)")) {
            long[] timestamps = {firstMs, lastMs};
            for (int i = 0; i < timestamps.length; i++) {
                ps.setLong(1, i + 1);
                ps.setString(2, toDuckDbTs(timestamps[i]));
                ps.setBytes(3, new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF});
                ps.executeUpdate();
            }
        }
    }

    private static java.util.Set<String> warningCodes(JSONObject result) {
        java.util.Set<String> codes = new java.util.HashSet<>();
        JSONArray warnings = result.getJSONArray("warnings");
        if (warnings != null) {
            for (int i = 0; i < warnings.size(); i++) {
                String code = warnings.getJSONObject(i).getString("code");
                if (code != null) {
                    codes.add(code);
                }
            }
        }
        return codes;
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
