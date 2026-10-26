package com.jshark.parser;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 分卷 manifest：与每个时间窗口一一对应的归档说明，写入该卷 db 的 {@code JSharkManifest} 表。
 *
 * <h3>记录什么</h3>
 * <ul>
 *   <li><b>卷是否已写完</b>：{@code completeWindow} / {@code closedReason}，
 *       让下游能判断该卷是"完整走完"还是"停机中断"。</li>
 *   <li><b>话务/审计元数据</b>：窗口起止时间、卷序号、落库包数、各类丢弃计数、
 *       采集参数（分卷间隔、PCAP/logdb 是否启用）等留痕。</li>
 * </ul>
 *
 * <h3>写入方式</h3>
 * <ul>
 *   <li><b>有 logdb 的窗口</b>：manifest 写入该窗口 db 文件的 {@code JSharkManifest} 表，
 *       与业务表同库、自成描述。</li>
 *   <li><b>纯 PCAP（无 logdb）的模式不再生成 manifest</b>：回放按分卷文件名发现卷、不读取 manifest，
 *       因此没有旁路文件需写。</li>
 * </ul>
 *
 * <h3>失败处理</h3>
 * <p>
 * manifest 写入失败只告警，<b>不影响采集</b>：它是一份旁路说明，
 * 不应因为写入问题而中断数据采集。
 * </p>
 */
public class VolumeManifest {

    private static final Logger logger = LoggerFactory.getLogger(VolumeManifest.class);

    private final long volumeSeq;
    private final long startMs;
    private final long endMs;
    private long packetCount;
    private boolean completeWindow = true;
    private String closedReason = "boundary";
    private final Map<String, Long> dropped = new LinkedHashMap<>();
    private final Map<String, Object> extras = new LinkedHashMap<>();

    /**
     * 构造 manifest。
     *
     * @param volumeSeq 卷序号
     * @param startMs   窗口起始时刻
     * @param endMs     窗口结束边界
     */
    public VolumeManifest(long volumeSeq, long startMs, long endMs) {
        this.volumeSeq = volumeSeq;
        this.startMs = startMs;
        this.endMs = endMs;
    }

    /** @param packetCount 该窗口内实际落库的包数 */
    public void packetCount(long packetCount) {
        this.packetCount = packetCount;
    }

    /**
     * @param complete     该窗口是否为完整窗口
     * @param closedReason 关闭原因：{@code boundary} / {@code shutdown}
     */
    public void closed(boolean complete, String closedReason) {
        this.completeWindow = complete;
        this.closedReason = closedReason;
    }

    /**
     * 记录一类被丢弃/跳过的数量。
     *
     * @param reason 原因标签
     * @param count  数量（0 也会被记录，便于下游确认"确实检查过"）
     */
    public void dropped(String reason, long count) {
        dropped.merge(reason, count, Long::sum);
    }

    /**
     * 记录附加信息（如采集参数、回放提示）。
     *
     * @param key   键
     * @param value 值
     */
    public void put(String key, Object value) {
        extras.put(key, value);
    }

    /**
     * 把 manifest 写入数据库的 {@code JSharkManifest} 表。
     * <p>
     * 调用方保证 {@code conn} 上 {@code JSharkManifest} 表已由
     * {@code initializeLogDbSchema} 创建。写入失败只告警，不影响采集。
     * </p>
     *
     * @param conn 到本卷 db 的已打开连接
     */
    public void writeToDb(Connection conn) {
        if (conn == null) {
            return;
        }
        String sql = """
                INSERT INTO JSharkManifest
                    (volumeSeq, startMs, endMs, startTime, endTime, packetCount,
                     completeWindow, closedReason, dropped, info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, volumeSeq);
            ps.setLong(2, startMs);
            ps.setLong(3, endMs);
            ps.setString(4, SplitUtil.formatTimestamp(startMs));
            ps.setString(5, SplitUtil.formatTimestamp(endMs));
            ps.setLong(6, packetCount);
            ps.setBoolean(7, completeWindow);
            ps.setString(8, closedReason);
            ps.setString(9, dropped.isEmpty() ? "{}"
                    : JSON.toJSONString(dropped, JSONWriter.Feature.WriteMapNullValue));
            ps.setString(10, extras.isEmpty() ? "{}"
                    : JSON.toJSONString(extras, JSONWriter.Feature.WriteMapNullValue));
            ps.executeUpdate();
            commitQuietly(conn);
        } catch (SQLException e) {
            logger.warn("[JShark] Failed to write manifest into db table {}: {}",
                    conn.toString(), e.getMessage());
        }
    }

    /**
     * 提交一个事务；若当前没有活动事务（如 DDL 后直接赶来），视为成功，
     * 因为重要的已由 executeUpdate 完成。与"manifest 写入失败只告警"的语义一致。
     */
    private static void commitQuietly(Connection conn) {
        try {
            conn.commit();
        } catch (SQLException e) {
            logger.debug("[JShark] Manifest commit skipped (no active transaction): {}",
                    e.getMessage());
        }
    }
}
