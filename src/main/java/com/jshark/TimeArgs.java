package com.jshark;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * 绝对时间参数解析与时间窗校验（CLI 的 {@code --start/--end} 与控制通道的 {@code seek} 共用）。
 *
 * <h3>为什么集中</h3>
 * <p>
 * 原来 {@code CliReplay.parseAbsoluteTime} 与 {@code ControlServer.parsePosition} 是两份独立实现：
 * 前者接受 {@code yyyy-MM-dd HH:mm}，后者不接受；后者接受 ISO 偏移，前者不接受。结果是
 * "同一种写法，在命令行能过、拖进度条却报错"。现在统一为同一个接受集：
 * </p>
 * <ul>
 *   <li>{@code yyyyMMddHHmmss}（分卷文件名里的紧凑格式）</li>
 *   <li>{@code yyyy-MM-dd HH:mm[:ss[.SSS]]}（日期与时间之间可用空格或 {@code T}）</li>
 *   <li>带 {@code Z} / {@code +08:00} 偏移的 ISO-8601 时间</li>
 * </ul>
 */
final class TimeArgs {

    private static final DateTimeFormatter COMPACT =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
    private static final DateTimeFormatter SECONDS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter MILLIS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final DateTimeFormatter MINUTES =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private TimeArgs() {
    }

    /**
     * 解析绝对时间。
     *
     * @param text 用户输入；null/空白返回 null（表示"不限"）
     * @return epoch 毫秒；空白返回 null
     * @throws IllegalArgumentException 格式非法（消息可直接展示）
     */
    static Long parse(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String s = text.trim();

        if (s.matches("\\d{14}")) {
            try {
                return LocalDateTime.parse(s, COMPACT)
                        .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
            } catch (DateTimeParseException e) {
                throw invalid(text);
            }
        }

        if (s.endsWith("Z") || s.matches(".*[+-]\\d{2}:?\\d{2}$")) {
            try {
                return Instant.parse(s).toEpochMilli();
            } catch (DateTimeParseException e) {
                throw invalid(text);
            }
        }

        String normalized = s.replace('t', ' ').replace('T', ' ');
        try {
            LocalDateTime parsed;
            if (normalized.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+")) {
                parsed = LocalDateTime.parse(normalized, MILLIS);
            } else if (normalized.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}")) {
                parsed = LocalDateTime.parse(normalized, SECONDS);
            } else if (normalized.matches("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}")) {
                parsed = LocalDateTime.parse(normalized, MINUTES);
            } else {
                throw invalid(text);
            }
            return parsed.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        } catch (DateTimeParseException e) {
            throw invalid(text);
        }
    }

    /**
     * 校验时间窗：{@code end} 不得早于 {@code start}。
     *
     * @param startMs 起点（epoch 毫秒；null 表示不限）
     * @param endMs   终点（epoch 毫秒；null 表示不限）
     * @throws IllegalArgumentException end 早于 start
     */
    static void validateWindow(Long startMs, Long endMs) {
        if (startMs != null && endMs != null && endMs < startMs) {
            throw new IllegalArgumentException(
                    "--end (" + new java.sql.Timestamp(endMs) + ") is before --start ("
                            + new java.sql.Timestamp(startMs) + ").");
        }
    }

    private static IllegalArgumentException invalid(String text) {
        return new IllegalArgumentException("Invalid absolute time: " + text
                + ". --start/--end take an absolute capture time such as "
                + "'2026-08-21 08:10:00'; relative offsets like '00:05:00' are no longer supported.");
    }
}
