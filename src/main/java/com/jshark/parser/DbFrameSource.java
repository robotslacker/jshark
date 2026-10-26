package com.jshark.parser;

import com.jshark.PacketCaptureException;
import org.duckdb.DuckDBDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * 以数据库（{@code JSharkLog.frameData}）为数据源的帧来源。
 *
 * <h3>为什么可行</h3>
 * <p>
 * 阶段 A 已把<b>完整原始帧</b>写入 {@code frameData}（见 §3.2 的表结构），
 * 因此数据库里存的就是"线上那一帧"，不需要再去猜载荷与五元组。
 * 只有 {@code captureKind} 为"有帧"的记录（{@code WIRE_FRAME} / {@code IP_DEFRAG_SYNTH}）
 * 才会被取出；TCP 重组体与缓冲区冲刷体（无对应帧）会被跳过并计数。
 * </p>
 *
 * <h3>排序与时间的取舍（重要）</h3>
 * <p>
 * 查询按 {@code (TimeStamp, ID)} 排序。但数据库的 TIMESTAMP 是<b>微秒</b>精度，
 * 同一微秒内的多条记录其相对顺序由 {@code ID}（采集序）决定，而这个顺序未必与
 * 线上到达顺序完全一致。因此本数据源声明 {@link #isOrderedByTimestamp()} 为 {@code false}，
 * 引擎会按<b>实际的非递减时间轴</b>推进，而不会因为"时间戳没有严格递增"而算出负等待。
 * </p>
 * <p>
 * 时序精度的下限由此而来：同一微秒内（真实间隔 &lt; 1µs）的多帧会被视为同一时刻并发发出。
 * 对本工具的审计场景（DIS 报文间隔为毫秒级、TCP 会话间隔更大）不构成影响。
 * </p>
 *
 * <h3>数据源级别的过滤</h3>
 * <p>
 * 时间窗、IP、端口、协议过滤下推到 SQL，避免为了过滤而把整库读进内存。
 * 引擎还会再做一次同样的过滤，两者一致（幂等），因此不会产生语义分歧。
 * </p>
 */
public class DbFrameSource implements FrameSource {

    private static final Logger logger = LoggerFactory.getLogger(DbFrameSource.class);

    /** 默认最多读取的记录数，防止超大库把内存吃光（可在构造时覆盖） */
    public static final int DEFAULT_MAX_ROWS = 2_000_000;

    private final String dbFile;
    private final Long startAbsoluteMs;
    private final Long endAbsoluteMs;
    private final String sourceIpFilter;
    private final String destinationIpFilter;
    private final Integer sourcePortFilter;
    private final Integer destinationPortFilter;
    private final String ipProtocolFilter;
    private final int maxRows;

    private Connection connection;
    private PreparedStatement statement;
    private ResultSet resultSet;
    private long skippedWithoutFrame;
    private long rowsRead;

    /**
     * 构造数据库帧来源。
     *
     * @param dbFile                数据库文件（分卷请传单个分卷路径）
     * @param startAbsoluteMs       起始绝对时间（含）；null 表示不限
     * @param endAbsoluteMs         结束绝对时间（含）；null 表示不限
     * @param sourceIpFilter        源 IP 过滤；null/空表示不限
     * @param destinationIpFilter   目的 IP 过滤；null/空表示不限
     * @param sourcePortFilter      源端口过滤；null 表示不限
     * @param destinationPortFilter 目的端口过滤；null 表示不限
     * @param ipProtocolFilter      IP 协议过滤（如 UDP/TCP）；null/空表示不限
     * @param maxRows               最多读取记录数；&lt;=0 表示使用 {@link #DEFAULT_MAX_ROWS}
     */
    public DbFrameSource(String dbFile, Long startAbsoluteMs, Long endAbsoluteMs,
                         String sourceIpFilter, String destinationIpFilter,
                         Integer sourcePortFilter, Integer destinationPortFilter,
                         String ipProtocolFilter, int maxRows) {
        this.dbFile = dbFile;
        this.startAbsoluteMs = startAbsoluteMs;
        this.endAbsoluteMs = endAbsoluteMs;
        this.sourceIpFilter = sourceIpFilter;
        this.destinationIpFilter = destinationIpFilter;
        this.sourcePortFilter = sourcePortFilter;
        this.destinationPortFilter = destinationPortFilter;
        this.ipProtocolFilter = ipProtocolFilter;
        this.maxRows = maxRows > 0 ? maxRows : DEFAULT_MAX_ROWS;
    }

    @Override
    public void open() throws Exception {
        String url = "jdbc:duckdb:" + dbFile;
        Properties props = new Properties();
        props.setProperty("duckdb.read_only", "true");
        props.setProperty(DuckDBDriver.JDBC_STREAM_RESULTS, String.valueOf(true));
        try {
            connection = DriverManager.getConnection(url, props);
        } catch (SQLException e) {
            throw new PacketCaptureException("Failed to open database " + dbFile, e);
        }

        // payload 捕获的旧库根本没有 frameData 列：帧级重放不可能成功。
        // 这里提前失败并说清原因（而不是等 SQL 编译报“列不存在”，让人以为库坏了）。
        try {
            if (!hasFrameColumn(connection)) {
                close();
                throw new PacketCaptureException("Database " + dbFile + " has no frameData column "
                        + "(payload-only capture), so it cannot be replayed frame by frame; "
                        + "use --replayMode=payload.");
            }
        } catch (SQLException e) {
            close();
            throw new PacketCaptureException("Failed to read database " + dbFile, e);
        }

        StringBuilder sql = new StringBuilder(
                "Select Id, TimeStamp, frameData, captureKind, sourceIp, destinationIp, "
                        + "sourcePort, destinationPort, ipProtocol "
                        + "From JSharkLog Where frameData Is Not Null And (captureKind = 0 Or captureKind = 1)");

        List<Object> params = new ArrayList<>();
        if (startAbsoluteMs != null) {
            sql.append(" And TimeStamp >= ?");
            params.add(new java.sql.Timestamp(startAbsoluteMs));
        }
        if (endAbsoluteMs != null) {
            sql.append(" And TimeStamp <= ?");
            params.add(new java.sql.Timestamp(endAbsoluteMs));
        }
        if (sourceIpFilter != null && !sourceIpFilter.isEmpty()) {
            sql.append(" And sourceIp = ?");
            params.add(sourceIpFilter);
        }
        if (destinationIpFilter != null && !destinationIpFilter.isEmpty()) {
            sql.append(" And destinationIp = ?");
            params.add(destinationIpFilter);
        }
        if (sourcePortFilter != null) {
            sql.append(" And sourcePort = ?");
            params.add(sourcePortFilter);
        }
        if (destinationPortFilter != null) {
            sql.append(" And destinationPort = ?");
            params.add(destinationPortFilter);
        }
        if (ipProtocolFilter != null && !ipProtocolFilter.isEmpty()) {
            sql.append(" And upper(ipProtocol) = upper(?)");
            params.add(ipProtocolFilter);
        }
        sql.append(" Order By TimeStamp Asc, Id Asc");
        sql.append(" Limit ").append(maxRows);

        logger.info("[JShark] Frame source: database {} (max {} records, filters pushed down)",
                dbFile, maxRows);

        statement = connection.prepareStatement(sql.toString());
        for (int i = 0; i < params.size(); i++) {
            statement.setObject(i + 1, params.get(i));
        }
        resultSet = statement.executeQuery();
    }

    /**
     * 表里是否有 {@code frameData} 列。
     *
     * <p>旧版采集只写 {@code rawData}（payload）；没有这一列就说明这条数据源不含任何帧，
     * 帧级重放不可能成功。</p>
     */
    private static boolean hasFrameColumn(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT * FROM JSharkLog LIMIT 0");
             ResultSet rs = statement.executeQuery()) {
            java.sql.ResultSetMetaData meta = rs.getMetaData();
            for (int i = 1; i <= meta.getColumnCount(); i++) {
                if ("frameData".equalsIgnoreCase(meta.getColumnLabel(i))) {
                    return true;
                }
            }
            return false;
        }
    }

    @Override
    public Frame next() throws Exception {
        if (resultSet == null) {
            return null;
        }
        while (resultSet.next()) {
            rowsRead++;
            byte[] frameData = readFrameData(resultSet);
            if (frameData == null || frameData.length == 0) {
                skippedWithoutFrame++;
                continue;
            }

            java.sql.Timestamp ts = resultSet.getTimestamp("TimeStamp");
            long timestampNanos = ts != null
                    ? ReplayClock.PacketTime.of(ts).toEpochNanos()
                    : System.currentTimeMillis() * 1_000_000L;

            // 地址元数据以**帧内容**为准：目标映射按源 IP:源端口匹配，
            // 而 sourceIp/sourcePort 这些列正是从同一帧解析出来的，用帧内容可避免列与帧不一致的历史数据。
            FrameSource.FrameMeta meta = PcapFrameSource.extractMeta(frameData);
            String srcIp = meta.srcIp();
            String dstIp = meta.dstIp();
            String protocol = meta.ipProtocol();
            Integer srcPort = meta.srcPort();
            Integer dstPort = meta.dstPort();

            // 帧内没有地址时（极少见，例如非 IP 帧）回退到库列，保证过滤与映射仍可用
            if (srcIp == null) {
                srcIp = resultSet.getString("sourceIp");
            }
            if (dstIp == null) {
                dstIp = resultSet.getString("destinationIp");
            }
            if (srcPort == null) {
                srcPort = (Integer) resultSet.getObject("sourcePort");
            }
            if (dstPort == null) {
                dstPort = (Integer) resultSet.getObject("destinationPort");
            }
            if (protocol == null || protocol.isEmpty()) {
                protocol = resultSet.getString("ipProtocol");
            }

            return new Frame(frameData, timestampNanos, srcIp, dstIp, srcPort, dstPort,
                    protocol != null ? protocol : "");
        }

        if (rowsRead >= maxRows) {
            logger.warn("[JShark] Reached the record limit ({}); the rest of the database was NOT replayed. "
                    + "Narrow the time window with --start/--end or raise the limit.", maxRows);
        }
        return null;
    }

    /**
     * 读取 {@code frameData} 列，兼容驱动返回 byte[] 或 Blob 两种情况。
     *
     * @param rs 结果集
     * @return 帧字节；为空返回 null
     */
    private static byte[] readFrameData(ResultSet rs) throws SQLException {
        Object obj = rs.getObject("frameData");
        if (obj == null) {
            return null;
        }
        if (obj instanceof byte[] bytes) {
            return bytes;
        }
        if (obj instanceof java.sql.Blob blob) {
            return blob.getBytes(1, (int) blob.length());
        }
        return null;
    }

    @Override
    public boolean isOrderedByTimestamp() {
        // 见类注释：TIMESTAMP 微秒精度 + ID 次序，不保证等于线上到达顺序
        return false;
    }

    @Override
    public String describe() {
        return "database " + dbFile;
    }

    @Override
    public long skippedWithoutFrame() {
        return skippedWithoutFrame;
    }

    @Override
    public void close() {
        closeQuietly(resultSet);
        closeQuietly(statement);
        closeQuietly(connection);
        resultSet = null;
        statement = null;
        connection = null;
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception e) {
                logger.debug("Error closing {}: {}", c.getClass().getSimpleName(), e.getMessage());
            }
        }
    }
}
