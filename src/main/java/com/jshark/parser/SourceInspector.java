package com.jshark.parser;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Properties;

/**
 * 启动前只读源检查：列出 DB 分卷 / PCAP 文件，给出每卷/文件的起止时间、时长、大小，
 * 以及全局数据范围与当前选定的播放范围。
 *
 * <p>本类不启动重放、不打开网卡、不要求 inject；只读 DuckDB / 离线 pcap。
 * 输出结构由 {@link #inspect(Options, String, ProgressListener)} 返回，CLI 负责打印 JSON。</p>
 *
 * <p><b>不读正在写入的卷</b>：{@code -capturing} 只展示文件名/大小，不执行 SQL。</p>
 */
public final class SourceInspector {

    /** 检查输入。{@code startMs/endMs} 为绝对捕获时间（epoch 毫秒）。 */
    public record Options(String dbFile,
                          String pcapFile,
                          String replayMode,
                          boolean replayModeExplicit,
                          boolean hasInjectInterface,
                          Long startMs,
                          Long endMs) {
    }

    /** 进度回调。 */
    public record Progress(String phase,
                           int current,
                           int total,
                           long bytes,
                           long packets,
                           String message) {
    }

    /** 进度监听器。 */
    @FunctionalInterface
    public interface ProgressListener {
        void onProgress(Progress progress);
    }

    private SourceInspector() {
    }

    /**
     * 执行检查。
     *
     * @param options 输入
     * @param session 本次检查的会话号（写入结果，供 UI 丢弃旧结果）
     * @param progress 进度回调，可为 null
     * @return {@code inspect-result} JSON
     * @throws IllegalArgumentException 参数/源不合法
     * @throws Exception 读取失败
     */
    public static JSONObject inspect(Options options, String session, ProgressListener progress)
            throws Exception {
        if (options == null) {
            throw new IllegalArgumentException("inspect options must not be null");
        }
        boolean hasDb = options.dbFile() != null && !options.dbFile().trim().isEmpty();
        boolean hasPcap = options.pcapFile() != null && !options.pcapFile().trim().isEmpty();
        if (hasDb == hasPcap) {
            throw new IllegalArgumentException("inspect requires exactly one data source: --db or --pcap");
        }
        validateTimeSelection(options);

        JSONObject root = new JSONObject();
        root.put("type", "inspect-result");
        root.put("inspectProtocol", 1);
        root.put("inspectSession", session);

        JSONObject source;
        JSONArray files;
        JSONObject summary;
        List<JSONObject> warnings = new ArrayList<>();

        if (hasDb) {
            InspectedDb db = inspectDb(options, progress, warnings);
            source = db.source();
            files = db.files();
            summary = db.summary();
        } else {
            InspectedPcap pcap = inspectPcap(options, progress, warnings);
            source = pcap.source();
            files = pcap.files();
            summary = pcap.summary();
        }

        root.put("source", source);
        root.put("files", files);
        root.put("summary", summary);
        root.put("selected", selected(options, summary, warnings));
        JSONArray warningArray = new JSONArray();
        warningArray.addAll(warnings);
        root.put("warnings", warningArray);
        return root;
    }

    // ==================== 参数校验 ====================

    private static void validateTimeSelection(Options o) {
        if (o.startMs() != null && o.endMs() != null && o.endMs() < o.startMs()) {
            throw new IllegalArgumentException(
                    "--end (" + o.endMs() + ") is before --start (" + o.startMs() + ")");
        }
    }

    // ==================== DB ====================

    private record InspectedDb(JSONObject source, JSONArray files, JSONObject summary) {
    }

    private static InspectedDb inspectDb(Options o, ProgressListener progress,
                                         List<JSONObject> warnings) {
        String dbFile = o.dbFile().trim();
        File base = new File(dbFile);
        List<String> discovered = SplitUtil.discoverAllSplitStyle(dbFile);
        List<String> paths = new ArrayList<>(discovered);
        boolean split = !paths.isEmpty();
        if (paths.isEmpty()) {
            if (!base.isFile()) {
                throw new IllegalArgumentException(
                        "Database file (or any time-split volume) does not exist: " + dbFile);
            }
            paths.add(base.getAbsolutePath());
        }

        // 稳定排序：最终/旧式按文件名时间，非分卷按文件名
        paths.sort(Comparator.comparing(SourceInspector::windowStartOrMax));

        JSONArray files = new JSONArray();
        long dataStart = Long.MAX_VALUE;
        long dataEnd = Long.MIN_VALUE;
        int replayableCount = 0;
        boolean live = false;
        // 帧级重放的前提是库里真的存了 frameData。旧库（payload 捕获）根本没有这一列，
        // 这里按卷探测：有帧的卷数 / 明确只有载荷的卷数。空卷（无数据）不参与判定。
        int frameVolumes = 0;
        int payloadOnlyVolumes = 0;

        for (int i = 0; i < paths.size(); i++) {
            String path = paths.get(i);
            File file = new File(path);
            boolean capturing = SplitUtil.isInProgressCaptureVolume(path);
            live |= capturing;

            Long windowStart = SplitUtil.volumeTimestamp(path);
            Long windowEnd = SplitUtil.volumeEndTimestamp(path);
            long bytes = file.isFile() ? file.length() : -1;
            long mtime = file.isFile() ? file.lastModified() : -1;
            String kind = capturing ? "capturing"
                    : (windowEnd != null ? "final"
                    : (windowStart != null ? "legacy" : "single"));

            JSONObject f = new JSONObject();
            f.put("path", file.getAbsolutePath());
            f.put("name", file.getName());
            f.put("kind", kind);
            f.put("windowStartMs", windowStart);
            f.put("windowEndMs", windowEnd);
            f.put("bytes", bytes);
            f.put("mtimeMs", mtime);

            if (progress != null) {
                progress.onProgress(new Progress("volumes", i + 1, paths.size(), bytes, 0,
                        "Reading volume " + (i + 1) + "/" + paths.size()));
            }

            if (capturing) {
                f.put("replayable", false);
                f.put("dataStartMs", null);
                f.put("dataEndMs", null);
                f.put("durationMs", null);
                f.put("status", "capturing");
                f.put("note", "still being written; not replayable");
                files.add(f);
                continue;
            }
            if (!file.isFile() || !file.canRead()) {
                f.put("replayable", false);
                f.put("dataStartMs", null);
                f.put("dataEndMs", null);
                f.put("durationMs", null);
                f.put("status", "unreadable");
                f.put("note", "file does not exist or is unreadable");
                addWarning(warnings, "VOLUME_UNREADABLE", file.getAbsolutePath());
                files.add(f);
                continue;
            }

            try {
                VolumeInfo info = queryVolume(file);
                long[] range = info.range();
                if (range == null) {
                    f.put("replayable", true);
                    f.put("dataStartMs", null);
                    f.put("dataEndMs", null);
                    f.put("durationMs", null);
                    f.put("status", "empty");
                    f.put("note", "no data");
                    // 空卷既不证明“有帧”，也不证明“只有载荷”：不参与帧能力判定。
                    f.put("hasFrames", null);
                } else {
                    long start = range[0];
                    long end = range[1];
                    f.put("replayable", true);
                    f.put("dataStartMs", start);
                    f.put("dataEndMs", end);
                    f.put("durationMs", Math.max(0, end - start));
                    f.put("status", "ok");
                    f.put("hasFrames", info.hasFrames());
                    if (info.hasFrames()) {
                        frameVolumes++;
                    } else {
                        payloadOnlyVolumes++;
                    }
                    dataStart = Math.min(dataStart, start);
                    dataEnd = Math.max(dataEnd, end);
                    replayableCount++;
                }
            } catch (Exception e) {
                f.put("replayable", false);
                f.put("dataStartMs", null);
                f.put("dataEndMs", null);
                f.put("durationMs", null);
                f.put("status", "error");
                f.put("note", rootMessage(e));
                addWarning(warnings, "VOLUME_READ_ERROR", file.getName() + ": " + rootMessage(e));
            }
            files.add(f);
        }

        if (replayableCount == 0) {
            dataStart = 0;
            dataEnd = 0;
        }
        boolean hasData = replayableCount > 0 && dataEnd >= dataStart;
        long duration = hasData ? Math.max(0, dataEnd - dataStart) : 0;

        // frameCapable：true = 至少一个可回放卷带 frameData；false = 全都没有（payload 捕获）；
        // null = 没有探测到任何可回放卷（仍在写入 / 空 / 不可读），此时不能下结论。
        int probedVolumes = frameVolumes + payloadOnlyVolumes;
        Boolean frameCapable = probedVolumes == 0 ? null : frameVolumes > 0;

        JSONObject source = new JSONObject();
        source.put("kind", "db");
        source.put("path", base.getAbsolutePath());
        source.put("split", split);
        source.put("live", live);
        source.put("frameCapable", frameCapable);
        source.put("frameVolumes", frameVolumes);
        source.put("payloadOnlyVolumes", payloadOnlyVolumes);
        // 默认重放模式就是 payload，因此默认（未显式指定）也算 effective payload，支持 follow。
        // 与重放侧共用同一份模式解析，避免 inspect 的 followSupported 与实际模式分叉。
        // 另外：payload-only 库不管参数怎么写都只能按载荷重放，所以也算 effective payload。
        boolean effectivePayload = Boolean.FALSE.equals(frameCapable)
                || ReplayModeResolver.effectivePayload(
                        o.replayMode(), o.replayModeExplicit(), o.hasInjectInterface());
        source.put("followSupported", split && effectivePayload);
        source.put("volumes", paths.size());
        source.put("replayableVolumes", replayableCount);

        JSONObject summary = new JSONObject();
        summary.put("dataStartMs", hasData ? dataStart : null);
        summary.put("dataEndMs", hasData ? dataEnd : null);
        summary.put("durationMs", hasData ? duration : null);
        summary.put("volumeCount", paths.size());
        summary.put("replayableCount", replayableCount);
        summary.put("live", live);
        summary.put("waiting", split && replayableCount == 0);

        if (live) {
            addWarning(warnings, "CAPTURING_VOLUME",
                    "Some volumes are still being written and were excluded from the replayable list.");
        }
        if (split && replayableCount == 0) {
            addWarning(warnings, "NO_REPLAYABLE_VOLUME",
                    "No closed, replayable volumes are currently available.");
        }
        if (Boolean.FALSE.equals(frameCapable)) {
            addWarning(warnings, "DB_PAYLOAD_ONLY",
                    "This database has no frameData (payload capture); frame replay is unavailable. Use --replayMode=payload.");
        } else if (payloadOnlyVolumes > 0) {
            addWarning(warnings, "DB_PARTIAL_FRAMES",
                    "There are " + payloadOnlyVolumes + " volumes without frameData (payload capture); they will be skipped in frame mode.");
        }
        return new InspectedDb(source, files, summary);
    }

    /** 单个卷的探测结果：时间范围（空表为 null）+ 是否含可注入的帧。 */
    private record VolumeInfo(long[] range, boolean hasFrames) {
    }

    /**
     * 用一个只读连接探测单个卷：时间范围与“是否含 frameData”。
     *
     * <p>帧能力是帧级重放的前提，而 payload 捕获的旧库压根没有 {@code frameData} 列。
     * 两件事共用一个连接，避免每个卷多开一次 DuckDB。</p>
     *
     * @return 探测结果；空表时 {@code range} 为 null
     */
    private static VolumeInfo queryVolume(File file) throws SQLException {
        Properties props = new Properties();
        props.setProperty("duckdb.read_only", "true");
        try (Connection connection = DriverManager.getConnection(
                "jdbc:duckdb:" + file.getAbsolutePath(), props)) {
            long[] range = queryRange(connection);
            // 空卷没有数据，也就谈不上“有帧”；不参与能力判定（见调用处）。
            boolean hasFrames = range != null && hasFrameData(connection);
            return new VolumeInfo(range, hasFrames);
        }
    }

    /**
     * 查询单个卷的 MIN/MAX(TimeStamp)。
     *
     * @return {@code [minMs,maxMs]}；空表返回 null
     */
    private static long[] queryRange(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT MIN(TimeStamp) AS firstTs, MAX(TimeStamp) AS lastTs FROM JSharkLog");
             ResultSet rs = statement.executeQuery()) {
            if (!rs.next()) {
                return null;
            }
            java.sql.Timestamp first = rs.getTimestamp("firstTs");
            java.sql.Timestamp last = rs.getTimestamp("lastTs");
            if (first == null || last == null) {
                return null;
            }
            return new long[]{first.getTime(), last.getTime()};
        }
    }

    /**
     * 该卷是否存有可注入的帧（{@code frameData} 非空）。
     *
     * <p>先看列是否存在：payload 捕获的旧库没有 {@code frameData} 列，这是“不能按帧重放”
     * 的确定判据；再看有没有非空值（防御性：列存在但全为空值，同样无法注入）。</p>
     *
     * @return true 表示该卷至少有一条记录带完整帧
     */
    private static boolean hasFrameData(Connection connection) throws SQLException {
        if (!hasColumn(connection, "frameData")) {
            return false;
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM JSharkLog WHERE frameData IS NOT NULL LIMIT 1");
             ResultSet rs = statement.executeQuery()) {
            return rs.next();
        }
    }

    /** 表里是否存在指定列（大小写不敏感）。 */
    private static boolean hasColumn(Connection connection, String column) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT * FROM JSharkLog LIMIT 0");
             ResultSet rs = statement.executeQuery()) {
            java.sql.ResultSetMetaData meta = rs.getMetaData();
            for (int i = 1; i <= meta.getColumnCount(); i++) {
                if (column.equalsIgnoreCase(meta.getColumnLabel(i))) {
                    return true;
                }
            }
            return false;
        }
    }

    // ==================== PCAP ====================

    private record InspectedPcap(JSONObject source, JSONArray files, JSONObject summary) {
    }

    private static InspectedPcap inspectPcap(Options o, ProgressListener progress,
                                             List<JSONObject> warnings) throws Exception {
        File file = new File(o.pcapFile().trim());
        if (!file.isFile()) {
            throw new IllegalArgumentException("PCAP file does not exist: " + o.pcapFile());
        }
        if (!file.canRead()) {
            throw new IllegalArgumentException("PCAP file is not readable: " + o.pcapFile());
        }

        long first = Long.MAX_VALUE;
        long last = Long.MIN_VALUE;
        long packets = 0;
        long bytes = file.length();
        long lastReport = 0;

        try (PcapHandle handle = Pcaps.openOffline(file.getAbsolutePath())) {
            while (true) {
                Packet packet;
                try {
                    packet = handle.getNextPacketEx();
                } catch (java.io.EOFException eof) {
                    break;
                }
                if (packet == null) {
                    break;
                }
                packets++;
                java.sql.Timestamp ts = handle.getTimestamp();
                if (ts != null) {
                    long ms = ts.getTime();
                    first = Math.min(first, ms);
                    last = Math.max(last, ms);
                }
                long now = System.nanoTime();
                if (progress != null && (now - lastReport > 200_000_000L)) {
                    lastReport = now;
                    progress.onProgress(new Progress("pcap", 0, 0, bytes, packets,
                            "Scanning PCAP, read " + packets + " packets"));
                }
            }
        }

        boolean hasData = packets > 0 && last >= first;
        JSONObject f = new JSONObject();
        f.put("path", file.getAbsolutePath());
        f.put("name", file.getName());
        f.put("kind", "pcap");
        f.put("replayable", true);
        f.put("windowStartMs", null);
        f.put("windowEndMs", null);
        f.put("dataStartMs", hasData ? first : null);
        f.put("dataEndMs", hasData ? last : null);
        f.put("durationMs", hasData ? Math.max(0, last - first) : null);
        f.put("bytes", bytes);
        f.put("mtimeMs", file.lastModified());
        f.put("packets", packets);
        f.put("status", hasData ? "ok" : "empty");
        f.put("hasFrames", true);   // pcap 的每条记录本身就是完整帧
        if (!hasData) {
            f.put("note", "no data");
        }

        JSONArray files = new JSONArray();
        files.add(f);

        JSONObject source = new JSONObject();
        source.put("kind", "pcap");
        source.put("path", file.getAbsolutePath());
        source.put("split", false);
        source.put("live", false);
        source.put("followSupported", false);
        // pcap 不涉及“库里有没有帧”的问题：每个包就是原始帧。
        source.put("frameCapable", true);
        source.put("frameVolumes", 1);
        source.put("payloadOnlyVolumes", 0);
        source.put("volumes", 1);
        source.put("replayableVolumes", 1);

        JSONObject summary = new JSONObject();
        summary.put("dataStartMs", hasData ? first : null);
        summary.put("dataEndMs", hasData ? last : null);
        summary.put("durationMs", hasData ? Math.max(0, last - first) : null);
        summary.put("volumeCount", 1);
        summary.put("replayableCount", hasData ? 1 : 0);
        summary.put("live", false);
        summary.put("waiting", false);

        if (!hasData) {
            addWarning(warnings, "EMPTY_PCAP", "PCAP contains no replayable packets.");
        }
        return new InspectedPcap(source, files, summary);
    }

    // ==================== selected ====================

    private static JSONObject selected(Options o, JSONObject summary,
                                       List<JSONObject> warnings) {
        Long dataStart = summary.getLong("dataStartMs");
        Long dataEnd = summary.getLong("dataEndMs");
        JSONObject selected = new JSONObject();
        if (dataStart == null || dataEnd == null) {
            selected.put("fromMs", null);
            selected.put("toMs", null);
            selected.put("durationMs", null);
            selected.put("source", "none");
            selected.put("clamped", false);
            return selected;
        }

        Long requestedFrom;
        Long requestedTo;
        String sourceKind;

        if (o.startMs() != null || o.endMs() != null) {
            requestedFrom = o.startMs() != null ? o.startMs() : dataStart;
            requestedTo = o.endMs() != null ? o.endMs() : dataEnd;
            sourceKind = "start/end";
        } else {
            requestedFrom = dataStart;
            requestedTo = dataEnd;
            sourceKind = "data-range";
        }

        long from = Math.max(requestedFrom, dataStart);
        long to = Math.min(requestedTo, dataEnd);
        boolean clamped = from != requestedFrom || to != requestedTo;
        if (clamped) {
            addWarning(warnings, "SELECTED_RANGE_CLAMPED",
                    "Playback range clipped to the available data range.");
        }
        // from == to 是合法的“单点窗口”（同一毫秒内可能有多包），只有 from > to
        // 才说明请求范围完全落在数据范围之外。
        if (from > to) {
            addWarning(warnings, "EMPTY_SELECTED_RANGE",
                    "Playback range does not intersect the data range.");
        }
        selected.put("fromMs", from);
        selected.put("toMs", to);
        selected.put("durationMs", Math.max(0, to - from));
        selected.put("requestedFromMs", requestedFrom);
        selected.put("requestedToMs", requestedTo);
        selected.put("source", sourceKind);
        selected.put("clamped", clamped);
        return selected;
    }

    // ==================== 工具 ====================

    private static long windowStartOrMax(String path) {
        Long ts = SplitUtil.volumeTimestamp(path);
        return ts != null ? ts : Long.MAX_VALUE;
    }

    private static void addWarning(List<JSONObject> warnings, String code, String message) {
        JSONObject w = new JSONObject();
        w.put("code", code);
        w.put("message", message);
        warnings.add(w);
    }

    private static String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        String msg = cur.getMessage();
        return msg == null || msg.isBlank() ? cur.getClass().getSimpleName() : msg;
    }
}
