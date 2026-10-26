package com.jshark.parser;

import java.io.File;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 时间分卷工具类。
 *
 * <p>负责：</p>
 * <ol>
 *   <li>解析 {@code --split} 参数为毫秒时长</li>
 *   <li>将 epoch 毫秒格式化为 YYYYMMDDHH24MISS 文件名后缀</li>
 *   <li>将 epoch 毫秒对齐到分卷时间网格的边界</li>
 * </ol>
 */
public final class SplitUtil {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss", Locale.ROOT);

    /** 匹配最终分卷文件名的时间戳段：{base}_{14位start}-{14位end}{ext}（采集完成后更名所得） */
    private static final Pattern VOLUME_FINAL_MIDDLE_PATTERN = Pattern.compile("^(\\d{14})-(\\d{14})$");
    /** 匹配"捕获中"分卷文件名的时间戳段：{base}_{14位start}-capturing{ext}（正在被写入，不可回放） */
    private static final Pattern VOLUME_INPROGRESS_MIDDLE_PATTERN = Pattern.compile("^(\\d{14})-capturing$");
    /** 匹配旧式分卷文件名的时间戳段：{base}_{14位时间戳}{ext}（无 end、无 -capturing 标记） */
    private static final Pattern VOLUME_MIDDLE_PATTERN = Pattern.compile("^(\\d{14})$");

    /** 匹配最终分卷文件名的完整后缀：{base}_{14位start}-{14位end} */
    private static final Pattern VOLUME_FINAL_BASENAME_PATTERN = Pattern.compile("^(.*)_(\\d{14})-(\\d{14})$");
    /** 匹配"捕获中"分卷文件名的完整后缀：{base}_{14位start}-capturing */
    private static final Pattern VOLUME_INPROGRESS_BASENAME_PATTERN = Pattern.compile("^(.*)_(\\d{14})-capturing$");
    /** 匹配旧式分卷文件名的完整后缀：{base}_{14位时间戳} */
    private static final Pattern VOLUME_BASENAME_PATTERN = Pattern.compile("^(.*)_(\\d{14})$");

    private SplitUtil() {
    }

    /**
     * 解析分卷时间参数。
     *
     * <p>支持单位：{@code m}（分）、{@code h}（时）、{@code d}（天），大小写均可。
     * <b>最小单位为分钟</b>——秒级分卷没有实际意义：每次轮转都要落盘、写 manifest、开新文件，
     * 秒级间隔下这些开销会喧宾夺主，分卷文件也会碎得无法管理。</p>
     *
     * <p>因此<b>不再支持秒</b>（{@code s}/{@code S}），也<b>不接受省略单位</b>的写法：
     * 旧版本里裸数字表示"秒"，若现在把它当成"分"，`300` 的含义会从 5 分钟悄悄变成 300 分钟
     * （相差 60 倍）。宁可让旧配置直接报错，也不要静默改变它的含义。</p>
     *
     * @param value 例如 {@code 5m}、{@code 1h}、{@code 1d}
     * @return 毫秒时长，必定大于 0
     * @throws IllegalArgumentException 参数非法
     */
    public static long parseSplit(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "--split requires a duration with an explicit unit, e.g. 5m, 1h, 1d");
        }

        String s = value.trim();
        char unit = Character.toLowerCase(s.charAt(s.length() - 1));
        long multiplier;
        String numberPart;

        switch (unit) {
            case 'm' -> {
                multiplier = 60L * 1000L;
                numberPart = s.substring(0, s.length() - 1);
            }
            case 'h' -> {
                multiplier = 60L * 60L * 1000L;
                numberPart = s.substring(0, s.length() - 1);
            }
            case 'd' -> {
                multiplier = 24L * 60L * 60L * 1000L;
                numberPart = s.substring(0, s.length() - 1);
            }
            case 's' -> throw new IllegalArgumentException(
                    "Invalid time split: " + value + ". Seconds are no longer supported; "
                            + "the smallest unit is minute (e.g. 1m, 5m).");
            default -> throw new IllegalArgumentException(
                    "Invalid time split: " + value + ". A unit is required: m (minutes), h (hours) "
                            + "or d (days), e.g. 5m.");
        }

        long number;
        try {
            number = Long.parseLong(numberPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid time split: " + value + ". Expected a number followed by a unit "
                            + "(m, h, d), e.g. 5m.", e);
        }

        if (number <= 0) {
            throw new IllegalArgumentException(
                    "Invalid time split: " + value + ". Duration must be greater than 0.");
        }

        try {
            return Math.multiplyExact(number, multiplier);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(
                    "Invalid time split: " + value + ". Duration is too large.", e);
        }
    }

    /**
     * 将 epoch 毫秒格式化为 YYYYMMDDHH24MISS（即 {@code yyyyMMddHHmmss}）。
     *
     * @param epochMillis epoch 毫秒
     * @return 14 位时间戳字符串
     */
    public static String formatTimestamp(long epochMillis) {
        return Instant.ofEpochMilli(epochMillis)
                .atZone(ZoneId.systemDefault())
                .format(TIMESTAMP_FORMAT);
    }

    /**
     * 判断给定的输出路径是否处于“时间分卷”模式。
     *
     * <p>判定规则：调用 {@link #discoverVolumes}，若发现的分卷列表不是“仅回退到 dbFile 本身”
     * （即存在 {@code base_YYYYMMDDHH24MISSext} 形式的分卷文件），则视为分卷模式。
     * 分卷模式下 capture 会持续产生新的时间分卷文件；非分卷模式下只有单个数据库文件。</p>
     *
     * @param filePath 基准输出路径（或某个分卷文件路径），例如 {@code /data/capture.db}
     * @return true 表示分卷模式
     */
    public static boolean isSplitMode(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return false;
        }
        // 分卷模式 = 目录里存在任何"分卷风格"的文件（最终卷、旧式卷，或正被采集的 -capturing 卷）。
        // 必须考虑 -capturing：实时跟进重放启动时，capture 可能尚未轮转出任何"最终"卷，
        // 若只看最终卷就会误判为单文件模式（见 discoverAllSplitStyle）。
        return !discoverAllSplitStyle(filePath).isEmpty();
    }

    /**
     * 发现给定 logdb 输出路径下的<b>可回放（已关闭）</b>分卷文件，并按时间戳顺序（文件名字典序）排序。
     *
     * <p>只会返回已轮转/已关卷的文件——即<b>最终卷</b>（"{@code <base>_<start>-<end><ext>}"）
     * 与<b>旧式卷</b>（"{@code <base>_<start><ext>}"，兼容历史归档）。正在被捕获写入的
     * "{@code ...-capturing.db}" 卷<b>不会</b>出现在结果里：它们尚未做 FORCE CHECKPOINT / 关闭，
     * 直接只读打开会与采集端发生锁冲突。</p>
     *
     * @param filePath 基准输出路径，例如 {@code /data/capture.db}、{@code capture_20260821101324-20260821111324.db}
     * @return 排序后的可分卷文件路径列表（绝对路径）
     */
    public static List<String> discoverVolumes(String filePath) {
        List<String> all = discoverAllSplitStyle(filePath);
        if (all.isEmpty()) {
            return List.of(new File(filePath).getAbsolutePath());
        }
        // 只保留"可回放"（已关闭）的卷：排除仍在采集中的 -capturing 文件。
        List<String> finalized = new ArrayList<>(all.size());
        for (String v : all) {
            if (!isInProgressCaptureVolume(v)) {
                finalized.add(v);
            }
        }
        if (finalized.isEmpty()) {
            // 目录里只有 -capturing（capture 刚启动、尚未轮转）：回退为基准单卷，
            // 但 isSplitMode 仍能通过 discoverAllSplitStyle 识别出分卷模式。
            return List.of(new File(filePath).getAbsolutePath());
        }
        return finalized;
    }

    /**
     * 发现给定输出路径下的<b>所有</b>分卷风格文件（最终卷、旧式卷、捕获中的 -capturing 卷），
     * 按文件名字典序（即时间戳序）排序。
     *
     * <p>与 {@link #discoverVolumes(String)} 的区别：本方法<b>包含</b>仍在采集中的
     * "{@code ...-capturing}" 文件，用于"是否处于分卷模式"的判定（live 跟进重放的起点检测）。
     * 含捕获中文件的列表<b>不可直接用于回放</b>（不得打开未关闭的卷）。</p>
     *
     * @param filePath 基准输出路径
     * @return 排序后的分卷风格文件路径列表（绝对路径）；目录无任何分卷风格文件时为空
     */
    public static List<String> discoverAllSplitStyle(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            throw new IllegalArgumentException("filePath must not be empty");
        }

        File target = new File(filePath).getAbsoluteFile();
        File parent = target.getParentFile();
        String fileName = target.getName();

        int dot = fileName.lastIndexOf('.');
        String base;
        String ext;
        if (dot > 0) {
            base = fileName.substring(0, dot);
            ext = fileName.substring(dot);
        } else {
            base = fileName;
            ext = "";
        }

        // 若 base 本身带时间戳/范围后缀，剥离为真正的基础名
        String trueBase = stripVolumeSuffix(base);

        File dir = parent != null ? parent : new File(".");
        String prefix = trueBase + "_";
        List<String> volumes = new ArrayList<>();

        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) {
                if (!f.isFile()) {
                    continue;
                }
                String fn = f.getName();
                if (fn.startsWith(prefix) && fn.endsWith(ext)) {
                    String middle = fn.substring(prefix.length(), fn.length() - ext.length());
                    if (VOLUME_FINAL_MIDDLE_PATTERN.matcher(middle).matches()
                            || VOLUME_MIDDLE_PATTERN.matcher(middle).matches()
                            || VOLUME_INPROGRESS_MIDDLE_PATTERN.matcher(middle).matches()) {
                        volumes.add(f.getAbsolutePath());
                    }
                }
            }
        }

        // 时间戳后缀为定长 14 位数字，字典序即时间序（"-capturing" 与 "-<end>" 均以 start 开头，次序稳定）
        Collections.sort(volumes);
        return volumes;
    }

    /**
     * 从文件名的基础名中剥离时间分卷后缀，得到真正的基础名。
     *
     * <p>支持：<ul>
     * <li>旧式：{@code ..._<start>}</li>
     * <li>最终：{@code ..._<start>-<end>}</li>
     * <li>捕获中：{@code ..._<start>-capturing}</li>
     * </ul>
     * 剥离失败时原样返回。</p>
     */
    private static String stripVolumeSuffix(String base) {
        Matcher m = VOLUME_FINAL_BASENAME_PATTERN.matcher(base);
        if (m.matches()) {
            return m.group(1);
        }
        m = VOLUME_INPROGRESS_BASENAME_PATTERN.matcher(base);
        if (m.matches()) {
            return m.group(1);
        }
        m = VOLUME_BASENAME_PATTERN.matcher(base);
        if (m.matches()) {
            return m.group(1);
        }
        return base;
    }

    /**
     * 从分卷文件路径中提取其窗口起点时间戳（文件名里的 {@code yyyyMMddHHmmss}），
     * 转换为 epoch 毫秒。
     *
     * <p>支持三种分卷文件名的窗口起点提取：</p>
     * <ul>
     *   <li>旧式：{@code {base}_{start}{ext}}</li>
     *   <li>最终：{@code {base}_{start}-{end}{ext}}</li>
     *   <li>捕获中：{@code {base}_{start}-capturing{ext}}</li>
     * </ul>
     * 该值与卷内包的绝对捕获时间（{@code TimeStamp}）同系，用于
     * {@code --start/--end} 这种"按卷名选卷"的天文时间筛选。</p>
     *
     * @param volumePath 分卷文件路径（如 {@code /data/capture_20260821101000.db}）
     * @return 窗口起点 epoch 毫秒；不是分卷文件名（不含 {@code yyyyMMddHHmmss}）时返回 {@code null}
     */
    public static Long volumeTimestamp(String volumePath) {
        SplitResult r = tryParseRange(volumePath);
        return r != null ? r.start : null;
    }

    /**
     * 从分卷文件路径中提取其窗口<b>结束边界</b>时间戳（文件名里的 {@code -<end>} 段）。
     *
     * <p>仅<b>最终卷</b>（"{@code {base}_{start}-{end}{ext}}"）携带结束边界；
     * 旧式卷与"捕获中"卷没有 end，返回 {@code null}。该值来自采集完成时更名所用的窗口网格边界，
     * 与卷内 manifest 的 {@code endMs} 一致，使回放端能凭文件名确定完整时间范围以快速跳过。</p>
     *
     * @param volumePath 分卷文件路径
     * @return 窗口结束边界 epoch 毫秒；无法从文件名取得（旧式/捕获中/非分卷命名）时返回 {@code null}
     */
    public static Long volumeEndTimestamp(String volumePath) {
        SplitResult r = tryParseRange(volumePath);
        return r != null ? r.end : null;
    }

    /**
     * 判断给定分卷文件是否仍处于"捕获中"（文件名带 {@code -capturing} 标记）。
     *
     * <p>捕获中的卷尚未关闭/CHECKPOINT，回放不应打开它（会与采集端锁冲突、
     * 或读到不完整数据）。回放路径应跳过此类文件。</p>
     *
     * @param volumePath 分卷文件路径
     * @return true 表示该卷仍在被采集写入
     */
    public static boolean isInProgressCaptureVolume(String volumePath) {
        if (volumePath == null || volumePath.trim().isEmpty()) {
            return false;
        }
        String base = baseOf(fileNameOf(volumePath));
        return VOLUME_INPROGRESS_BASENAME_PATTERN.matcher(base).matches();
    }

    /** 解析卷名携带的时间范围（{@code [start, end]}，end 可能为 null）。 */
    private record SplitResult(Long start, Long end) {}

    private static SplitResult tryParseRange(String volumePath) {
        if (volumePath == null || volumePath.trim().isEmpty()) {
            return null;
        }
        String fileName = fileNameOf(volumePath);
        String base = baseOf(fileName);
        // 最终卷：{base}_{start}-{end}
        Matcher finalM = VOLUME_FINAL_BASENAME_PATTERN.matcher(base);
        if (finalM.matches()) {
            try {
                return new SplitResult(parseTimestamp(finalM.group(2)), parseTimestamp(finalM.group(3)));
            } catch (Exception e) {
                return null;
            }
        }
        // 捕获中：{base}_{start}-capturing
        Matcher capM = VOLUME_INPROGRESS_BASENAME_PATTERN.matcher(base);
        if (capM.matches()) {
            try {
                return new SplitResult(parseTimestamp(capM.group(2)), null);
            } catch (Exception e) {
                return null;
            }
        }
        // 旧式：{base}_{start}
        Matcher legacyM = VOLUME_BASENAME_PATTERN.matcher(base);
        if (legacyM.matches()) {
            try {
                return new SplitResult(parseTimestamp(legacyM.group(2)), null);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private static String fileNameOf(String path) {
        return new File(path).getName();
    }

    private static String baseOf(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return (dot > 0) ? fileName.substring(0, dot) : fileName;
    }

    /**
     * 将 {@code yyyyMMddHHmmss} 本地时间字符串解析为 epoch 毫秒。
     *
     * @param ts 14 位时间戳字符串
     * @return epoch 毫秒
     */
    private static long parseTimestamp(String ts) {
        return java.time.LocalDateTime.parse(ts, TIMESTAMP_FORMAT)
                .atZone(ZoneId.systemDefault())
                .toInstant()
                .toEpochMilli();
    }

    /**
     * 从分卷列表中选出窗口起点时间戳落在 {@code [windowStart, windowEnd]}（天文绝对时间）内的卷。
     *
     * <p>这是 "--start/--end 先按卷名选卷"的纯逻辑：以分卷文件名里的
     * {@code yyyyMMddHHmmss} 窗口起点为准。未设置窗口时原样返回列表。
     * 非分卷命名（拿不到时间戳）的项按"不缩小范围"处理，保留之。</p>
     *
     * @param volumes     分卷路径列表（顺序无关）
     * @param windowStart 窗口起点（epoch 毫秒）；null 表示不限
     * @param windowEnd   窗口终点（epoch 毫秒）；null 表示不限
     * @return 落在窗口内的卷；窗口两端都未设置时返回列表的拷贝
     */
    public static List<String> selectVolumesInCaptureWindow(List<String> volumes,
                                                            Long windowStart, Long windowEnd) {
        if (windowStart == null && windowEnd == null) {
            return new ArrayList<>(volumes);
        }
        List<String> selected = new ArrayList<>();
        for (String v : volumes) {
            if (inCaptureWindowStatic(v, windowStart, windowEnd)) {
                selected.add(v);
            }
        }
        return selected;
    }

    /**
     * 判断单个分卷是否与 {@code [windowStart, windowEnd]}（天文绝对时间）相交。
     *
     * <p>这是 "--start/--end 先按卷名选卷、不必打开文件"的纯逻辑：</p>
     * <ul>
     *   <li><b>最终卷</b>（文件名携带 "{@code <start>-<end>}"）：按完整时间范围
     *       {@code [start, end)} 与窗口求交，可精确排除窗口外的卷；</li>
     *   <li><b>旧式/捕获中</b>（拿不到 end）：退化为以窗口起点 {@code start} 判定；</li>
     *   <li>非分卷命名（拿不到 start）：按"不缩小范围"处理，保留之。</li>
     * </ul>
     *
     * @param volume      分卷路径
     * @param windowStart 窗口起点（epoch 毫秒）；null 表示不限
     * @param windowEnd   窗口终点（epoch 毫秒）；null 表示不限
     * @return true 表示该卷可能包含窗口内的数据，应被回放
     */
    public static boolean inCaptureWindowStatic(String volume, Long windowStart, Long windowEnd) {
        if (windowStart == null && windowEnd == null) {
            return true;
        }
        SplitResult r = tryParseRange(volume);
        if (r == null || r.start == null) {
            // 非分卷命名：无法定位窗口，退化为不缩小范围
            return true;
        }
        long start = r.start;
        if (r.end != null) {
            // 最终卷：范围 [start, end) 与 [windowStart, windowEnd] 求交。
            // 排除"卷整体在窗口前"（end <= windowStart）或"卷整体在窗口后"（start >= windowEnd）。
            if (windowStart != null && r.end <= windowStart) {
                return false;
            }
            if (windowEnd != null && start >= windowEnd) {
                return false;
            }
            return true;
        }
        // 旧式/捕获中：只有起点，退化为按起点判定（保持历史语义）
        if (windowStart != null && start < windowStart) {
            return false;
        }
        if (windowEnd != null && start > windowEnd) {
            return false;
        }
        return true;
    }

    /**
     * 取分卷列表中最早（最小）的非空窗口起点时间戳。
     *
     * @param volumes 分卷路径列表
     * @return 最早的窗口起点 epoch 毫秒；列表为空或全部取不到时间戳时返回 {@code null}
     */
    public static Long earliestVolumeStart(List<String> volumes) {
        Long earliest = null;
        for (String v : volumes) {
            Long ts = volumeTimestamp(v);
            if (ts == null) {
                continue;
            }
            if (earliest == null || ts < earliest) {
                earliest = ts;
            }
        }
        return earliest;
    }

    /**
     * 将 epoch 毫秒向下对齐到分卷时间网格边界（本地自然日历边界）。
     *
     * <p>例如：</p>
     * <ul>
     *   <li>{@code 1h}  -> 边界落在本地整点（00:00、01:00 ...）</li>
     *   <li>{@code 5m}  -> 边界落在本地整 5 分钟（00/05/10 ... 55 分）</li>
     *   <li>{@code 1d}  -> 边界落在本地当日 00:00:00</li>
     *   <li>其他不整除的间隔 -> 自当日零点起按间隔偏移对齐</li>
     * </ul>
     *
     * @param epochMillis epoch 毫秒
     * @param intervalMs   分卷间隔（毫秒），必须大于 0
     * @return 对齐后的边界时间（epoch 毫秒）
     */
    public static long alignToGrid(long epochMillis, long intervalMs) {
        if (intervalMs <= 0) {
            throw new IllegalArgumentException("intervalMs must be greater than 0");
        }

        ZonedDateTime zdt = Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault());

        long dayMs = 24L * 60L * 60L * 1000L;
        if (intervalMs >= dayMs) {
            // 按天对齐：以 epochDay 为网格（大于等于 1 天的间隔）
            long days = intervalMs / dayMs;
            long epochDay = zdt.toLocalDate().toEpochDay();
            long alignedEpochDay = (epochDay / days) * days;
            return LocalDate.ofEpochDay(alignedEpochDay)
                    .atStartOfDay(zdt.getZone())
                    .toInstant()
                    .toEpochMilli();
        }

        // 按当日零点起算的毫秒偏移对齐，保证边界落在本地自然时间（整点/整分）
        ZonedDateTime startOfDay = zdt.toLocalDate().atStartOfDay(zdt.getZone());
        long startOfDayMillis = startOfDay.toInstant().toEpochMilli();
        long millisOfDay = epochMillis - startOfDayMillis;
        long alignedMillisOfDay = (millisOfDay / intervalMs) * intervalMs;
        return startOfDayMillis + alignedMillisOfDay;
    }
}