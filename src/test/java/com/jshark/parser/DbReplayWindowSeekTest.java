package com.jshark.parser;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 会话播放窗口的回归测试（payload + DB 单卷）。
 *
 * <p>背景：seek 的实现是“中止当前段 → 用新起点重建 {@link DbReplayTool} 再跑一段”，
 * 新段会再次执行 {@code startReplay()}。旧实现每次都会用 {@code --start} 无条件重设窗口，
 * 导致每 seek 一次窗口起点就跟着移动（UI 拖动范围越拖越小、“回到起点”退化成回到上一次 seek），
 * 未给 {@code --end} 时窗口终点还会一直是“未知”（{@code status.timing.etaMs} 恒为 null）。</p>
 *
 * <p>数据行被 {@code --sourceIp} 过滤掉（0 行命中 → 不发送任何报文、不碰网卡）；
 * 窗口信息来自未过滤的 {@code MIN/MAX(TimeStamp)}，因此本用例不需要 Npcap/管理员权限。</p>
 */
public class DbReplayWindowSeekTest {

    /** 故意不存在的源 IP：SQL 命中 0 行，重放循环不会发送任何报文。 */
    private static final String NO_MATCH_IP = "192.0.2.1";

    @TempDir
    Path dir;

    @Test
    @Timeout(60)
    void seekSegmentKeepsWindowStartAndFillsDataEnd() throws Exception {
        long t0 = at(2026, 8, 21, 8, 0, 0);
        long t1 = t0 + 10_000;
        Path db = dir.resolve("capture.db");
        createDb(db, t0, t1);

        ReplayControl control = new ReplayControl(1.0);

        // 段 1：--start=t0，未给 --end
        DbReplayTool first = tool(db, t0);
        first.setControl(control);
        first.startReplay();

        assertEquals(t0, control.windowFromMs(), "首段窗口起点应等于 --start");
        assertEquals(t1, control.windowToMs(),
                "未给 --end 时窗口终点必须补成真实末包时间，否则 status.timing.etaMs 恒为 null");

        // seek 到 t0+5s：等价于 CliReplay#prepareRestart + 用新起点重建工具
        long seekTarget = t0 + 5_000;
        control.beginNewSegment(seekTarget);
        DbReplayTool second = tool(db, seekTarget);
        second.setControl(control);
        second.startReplay();

        assertEquals(t0, control.windowFromMs(),
                "seek 重开段不得把窗口起点改成 seek 目标（否则“回到起点”会退化成回到上一次 seek）");
        assertEquals(t1, control.windowToMs(), "seek 重开段不得清空窗口终点");
        assertEquals(seekTarget, control.playheadMs(), "重开段应把播放头放到 seek 目标");
    }

    private static DbReplayTool tool(Path db, Long startAtMs) {
        return new DbReplayTool(db.toString(), 1.0,
                startAtMs, null,
                NO_MATCH_IP, null, null, null, null, null, null, null);
    }

    private static void createDb(Path db, long firstMs, long lastMs) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:duckdb:" + db);
             Statement st = conn.createStatement()) {
            st.execute("Create Table JSharkLog ("
                    + "Id BIGINT primary key, TimeStamp timestamp, rawData blob, "
                    + "sourceIp varchar, destinationIp varchar, sourcePort integer, "
                    + "destinationPort integer, ipProtocol varchar, appProtocol varchar, "
                    + "additionalInfo varchar)");
            insert(st, 1, firstMs);
            insert(st, 2, lastMs);
        }
    }

    private static void insert(Statement st, long id, long tsMs) throws Exception {
        st.executeUpdate("Insert Into JSharkLog (Id, TimeStamp, rawData, sourceIp, destinationIp, "
                + "sourcePort, destinationPort, ipProtocol) Values ("
                + id + ", TIMESTAMP '" + toDuckDbTs(tsMs) + "', NULL, "
                + "'10.0.0.1', '10.0.0.2', 1234, 9, 'UDP')");
    }

    private static String toDuckDbTs(long epochMs) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMs), ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
    }

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s)
                .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }
}
