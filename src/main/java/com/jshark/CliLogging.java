package com.jshark;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.FileAppender;
import org.slf4j.LoggerFactory;

/**
 * CliShark / CliReplay 共用的日志初始化：把日志输出到控制台和/或 {@code --logfile} 指定的文件。
 *
 * <h3>目标规格</h3>
 * <p>
 * {@code --logfile} 的取值是<b>逗号分隔</b>的目标列表，每一项要么是 {@code CONSOLE}（控制台），
 * 要么是一个文件路径。默认（未指定 {@code --logfile}）只有 {@code CONSOLE}，
 * 与历史行为逐字符一致；写成 {@code CONSOLE,logs/jshark.log} 就是"同时输出"。
 * 这与 slackerdb dbserver 的 {@code --log} 语义相同，用户在两套工具之间不用换脑子。
 * </p>
 *
 * <p>落盘失败（目录不可写、路径是目录等）时退回控制台并给出告警：宁可"没落到文件"，
 * 也不能"日志全丢"——后台运行时日志就是唯一现场。</p>
 */
public final class CliLogging {

    /** 表示"输出到控制台"的保留字。 */
    public static final String CONSOLE_TARGET = "CONSOLE";

    /** 控制台格式：保持历史格式不变（现网脚本/人眼都按这个解析）。 */
    private static final String CONSOLE_PATTERN =
            "%d{HH:mm:ss.SSS} %-5level [%16.16thread] %-30.30logger{0} -- %msg%n";

    /** 文件格式：落盘日志需要看日期，否则跨天的文件里只有时分秒。 */
    private static final String FILE_PATTERN =
            "%d{yyyy-MM-dd HH:mm:ss.SSS} %-5level [%16.16thread] %-30.30logger{0} -- %msg%n";

    private CliLogging() {
    }

    /**
     * 初始化日志系统（控制台输出到 stdout）。
     *
     * @param logTarget 目标规格（逗号分隔，{@code CONSOLE} 或文件路径）；null/空白表示仅控制台
     */
    public static void configure(String logTarget) {
        configure(logTarget, false);
    }

    /**
     * 初始化日志系统。
     *
     * <p>{@code consoleToStderr} 用于 {@code --inspect} / {@code --control stdio} 这类
     * “stdout 是协议、日志必须走 stderr”的模式。CLI 默认仍输出到 stdout。</p>
     *
     * @param logTarget       目标规格（逗号分隔，{@code CONSOLE} 或文件路径）
     * @param consoleToStderr true 表示 {@code CONSOLE} 写到 stderr
     */
    public static void configure(String logTarget, boolean consoleToStderr) {
        String spec = (logTarget == null || logTarget.isBlank()) ? CONSOLE_TARGET : logTarget;

        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        context.reset();

        // pcap4j 的内部日志与业务无关，且量很大，直接关掉（历史行为）
        context.getLogger("org.pcap4j.core").setLevel(Level.OFF);
        context.getLogger("org.pcap4j.util.PropertiesLoader").setLevel(Level.OFF);
        context.getLogger("org.pcap4j.packet.factory.PacketFactories").setLevel(Level.OFF);

        Logger root = context.getLogger(Logger.ROOT_LOGGER_NAME);
        boolean consoleAdded = false;
        boolean anyAdded = false;

        for (String raw : spec.split(",")) {
            String target = raw.trim();
            if (target.isEmpty()) {
                continue;
            }
            if (target.equalsIgnoreCase(CONSOLE_TARGET)) {
                root.addAppender(buildConsoleAppender(context, consoleToStderr));
                consoleAdded = true;
                anyAdded = true;
                continue;
            }
            Appender<ILoggingEvent> fileAppender = buildFileAppender(context, target);
            if (fileAppender != null) {
                root.addAppender(fileAppender);
                anyAdded = true;
            } else {
                if (!consoleAdded) {
                    root.addAppender(buildConsoleAppender(context, consoleToStderr));
                    consoleAdded = true;
                    anyAdded = true;
                }
                root.warn("[JShark] Cannot write log file [{}]; falling back to console output.", target);
            }
        }

        if (!anyAdded) {
            // 例如 --logfile=, 这种全是空项的写法：不能让日志彻底消失
            root.addAppender(buildConsoleAppender(context, consoleToStderr));
        }

        root.setLevel(Level.INFO);
    }

    /**
     * @param target 单个目标取值
     * @return 是否是"输出到控制台"的保留字
     */
    public static boolean isConsoleTarget(String target) {
        return target != null && target.trim().equalsIgnoreCase(CONSOLE_TARGET);
    }

    private static ConsoleAppender<ILoggingEvent> buildConsoleAppender(LoggerContext context,
                                                                       boolean toStderr) {
        ConsoleAppender<ILoggingEvent> appender = new ConsoleAppender<>();
        appender.setContext(context);
        appender.setName(toStderr ? "STDERR" : "STDOUT");
        appender.setTarget(toStderr ? "System.err" : "System.out");
        appender.setEncoder(buildEncoder(context, CONSOLE_PATTERN));
        appender.start();
        return appender;
    }

    /**
     * @return 已启动的文件 appender；启动失败（不可写/路径非法）返回 null，由调用方退回控制台
     */
    private static Appender<ILoggingEvent> buildFileAppender(LoggerContext context, String path) {
        FileAppender<ILoggingEvent> appender = new FileAppender<>();
        appender.setContext(context);
        appender.setName("FILE-" + Integer.toHexString(path.hashCode()));
        appender.setFile(path);
        appender.setAppend(true);
        appender.setImmediateFlush(true);
        appender.setEncoder(buildEncoder(context, FILE_PATTERN));
        appender.start();
        return appender.isStarted() ? appender : null;
    }

    private static PatternLayoutEncoder buildEncoder(LoggerContext context, String pattern) {
        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setPattern(pattern);
        encoder.start();
        return encoder;
    }
}
