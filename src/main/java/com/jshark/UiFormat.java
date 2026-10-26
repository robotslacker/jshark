package com.jshark;

import java.io.File;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * 界面层的数字/时间格式化。
 *
 * <p>这些方法原来在采集、重放、转发三个 UI 里各有一份（{@code formatBytes} 甚至有三份），
 * 容易改一处漏两处。统一到这里之后，单位、精度、占位符（{@code —}）只有一种写法。</p>
 */
final class UiFormat {

    /** 只显示时分秒（截图/表格里够用）。 */
    private static final DateTimeFormatter HM = DateTimeFormatter.ofPattern("HH:mm");
    private static final DateTimeFormatter HMS = DateTimeFormatter.ofPattern("HH:mm:ss");

    /** 无数据时的统一占位符。 */
    static final String NONE = "—";

    private UiFormat() {
    }

    /**
     * 持续时间，格式 {@code HH:mm:ss}（超过 24 小时继续累加小时）。
     *
     * @param ms 毫秒；负数按 0 处理
     * @return 例如 {@code 00:12:34}
     */
    static String formatElapsed(long ms) {
        long total = Math.max(0, ms) / 1000;
        return String.format("%02d:%02d:%02d", total / 3600, (total % 3600) / 60, total % 60);
    }

    /**
     * 千分位整数。
     *
     * @param n 数值
     * @return 例如 {@code 1,234,567}
     */
    static String formatCount(long n) {
        return String.format("%,d", n);
    }

    /**
     * 人类可读的字节数（1024 进制，1 位小数；GB 保留 2 位）。
     *
     * @param bytes 字节数
     * @return 例如 {@code 0 B}、{@code 1.5 MB}
     */
    static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024) {
            return String.format("%.1f KB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024) {
            return String.format("%.1f MB", mb);
        }
        return String.format("%.2f GB", mb / 1024.0);
    }

    /**
     * {@link #formatBytes(long)} 的旧名字（重放 UI 使用）。
     *
     * @param bytes 字节数
     * @return 同 {@link #formatBytes(long)}
     */
        /**
     * 时间窗，格式 {@code HH:mm — HH:mm}；跨天时结束时间带 {@code MM-dd}。
     *
     * @param startMs 起点（epoch 毫秒）；&lt;= 0 表示无
     * @param endMs   终点（epoch 毫秒）；&lt;= 0 表示仍在进行
     * @return 可读区间
     */
    static String formatWindow(long startMs, long endMs) {
        if (startMs <= 0) {
            return NONE;
        }
        String start = HM.format(Instant.ofEpochMilli(startMs).atZone(ZoneId.systemDefault()));
        if (endMs <= 0) {
            return start + " " + NONE;
        }
        boolean sameDay = LocalDateTime.ofInstant(Instant.ofEpochMilli(startMs), ZoneId.systemDefault())
                .toLocalDate()
                .equals(LocalDateTime.ofInstant(Instant.ofEpochMilli(endMs), ZoneId.systemDefault())
                        .toLocalDate());
        String end = sameDay
                ? HM.format(Instant.ofEpochMilli(endMs).atZone(ZoneId.systemDefault()))
                : "MM-dd " + HM.format(Instant.ofEpochMilli(endMs).atZone(ZoneId.systemDefault()));
        return start + " " + NONE + " " + end;
    }

    /**
     * 路径里的文件名；空路径返回占位符。
     *
     * @param path 完整路径
     * @return 文件名
     */
    static String fileName(String path) {
        if (path == null || path.isBlank()) {
            return NONE;
        }
        try {
            return new File(path).getName();
        } catch (RuntimeException e) {
            return path;
        }
    }

    /** 时间点，格式 {@code HH:mm:ss}；&lt;= 0 返回占位符。 */
    static String formatSince(long sinceMs) {
        if (sinceMs <= 0) {
            return NONE;
        }
        return HMS.format(Instant.ofEpochMilli(sinceMs).atZone(ZoneId.systemDefault()));
    }

    /**
     * 速率，超过 1000 时用 {@code k pps}。
     *
     * @param pps 每秒包数
     * @return 可读速率
     */
    static String formatRate(double pps) {
        return pps >= 1000
                ? String.format("%.1fk pps", pps / 1000.0)
                : String.format("%.0f pps", pps);
    }

    /**
     * 丢包率；小于 0.01% 但非零时显示 {@code <0.01%}。
     *
     * @param dropped 丢弃数
     * @param ingress 入口总数
     * @return 百分比文本；无入口数据返回占位符
     */
    static String formatDropRate(long dropped, long ingress) {
        if (ingress <= 0) {
            return NONE;
        }
        double pct = 100.0 * dropped / ingress;
        if (pct > 0 && pct < 0.01) {
            return "<0.01%";
        }
        return String.format("%.2f%%", pct);
    }
}
