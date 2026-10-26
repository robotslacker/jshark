package com.jshark;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code --daemon} / {@code --logfile} 的验收。
 *
 * <h3>为什么这样测</h3>
 * <p>
 * 这两个选项都属于"出错也不报错、只是行为不对"的类型：{@code --daemon} 拼错命令行会变成
 * 前台运行或无限 fork，{@code --logfile} 写错会静默丢日志。而 {@code CliShark.main} /
 * {@code CliReplay.main} 需要真实网卡/管理员权限才能进得去，所以这里拆成三层分别验证：</p>
 * <ul>
 *   <li><b>取值映射</b>：{@code --daemon true/false/裸写} 与 {@code --logfile} 是否落到字段（反射读取）；</li>
 *   <li><b>纯逻辑</b>：日志目标预读、daemon 取值解析、子进程命令行拼装（含"子进程必须 --daemon false"）；</li>
 *   <li><b>落盘</b>：{@link CliLogging} 真的把日志写进文件、不可写时退回控制台。</li>
 * </ul>
 *
 * <p>不抓包、不开网卡、不真的拉起后台进程。</p>
 */
class CliDaemonTest {

    // ------------------------------------------------------------------ 取值映射

    @Test
    @DisplayName("capture：--daemon 支持 true / false / 裸写，--logfile 落到字段")
    void captureMapsDaemonAndLogfile() throws Exception {
        CliShark cli = new CliShark();
        cli.parse(new String[]{"--daemon", "true", "--logfile", "logs/capture.log"});
        assertEquals(Boolean.TRUE, read(cli, "daemon"));
        assertEquals("logs/capture.log", read(cli, "logFile"));

        CliShark bare = new CliShark();
        bare.parse(new String[]{"--daemon"});
        assertEquals(Boolean.TRUE, read(bare, "daemon"), "裸写 --daemon 等价于 --daemon true");

        CliShark off = new CliShark();
        off.parse(new String[]{"--daemon=false"});
        assertEquals(Boolean.FALSE, read(off, "daemon"));

        CliShark eq = new CliShark();
        eq.parse(new String[]{"--daemon=true", "--logfile=logs/x.log"});
        assertEquals(Boolean.TRUE, read(eq, "daemon"));
        assertEquals("logs/x.log", read(eq, "logFile"), "--logfile=v 语法必须可用");
    }

    @Test
    @DisplayName("capture：非法 --daemon 取值 / 缺取值的 --logfile 一律报错（退出码 1）")
    void captureRejectsBadValues() {
        assertEquals(1, assertThrows(CliExitException.class,
                () -> new CliShark().parse(new String[]{"--daemon", "maybe"})).exitCode(),
                "--daemon 只接受 true/false");
        assertEquals(1, assertThrows(CliExitException.class,
                () -> new CliShark().parse(new String[]{"--logfile"})).exitCode(),
                "--logfile 必须带取值");
        assertEquals(1, assertThrows(CliExitException.class,
                () -> new CliShark().parse(new String[]{"--logfile="})).exitCode(),
                "--logfile= 空取值必须报错，而不是静默退回控制台");
    }

    @Test
    @DisplayName("replay：--daemon / --logfile 同样映射到字段")
    void replayMapsDaemonAndLogfile() throws Exception {
        // CliReplay.parse() 解析完会直接进入重放流程（会真的发包），所以这里直接调字段映射那一层
        CliReplay cli = new CliReplay();
        Method setFieldValue = CliReplay.class.getDeclaredMethod("setFieldValue", String.class, String.class);
        setFieldValue.setAccessible(true);

        setFieldValue.invoke(cli, "daemon", "true");
        setFieldValue.invoke(cli, "logFile", "logs/replay.log");
        assertEquals(Boolean.TRUE, read(cli, "daemon"));
        assertEquals("logs/replay.log", read(cli, "logFile"));

        CliReplay off = new CliReplay();
        setFieldValue.invoke(off, "daemon", "false");
        assertEquals(Boolean.FALSE, read(off, "daemon"));

        InvocationTargetException badDaemon = assertThrows(InvocationTargetException.class,
                () -> setFieldValue.invoke(new CliReplay(), "daemon", "maybe"));
        assertTrue(badDaemon.getCause() instanceof IllegalArgumentException,
                "非法取值必须报错，实际: " + badDaemon.getCause());

        InvocationTargetException blankLog = assertThrows(InvocationTargetException.class,
                () -> setFieldValue.invoke(new CliReplay(), "logFile", ""));
        assertTrue(blankLog.getCause() instanceof IllegalArgumentException,
                "--logfile= 空取值必须报错，实际: " + blankLog.getCause());
    }

    // ------------------------------------------------------------------ 纯逻辑

    @Test
    @DisplayName("--logfile 预读：两种写法、逗号目标、重复取最后一个，且不会被 --daemon 的取值带偏")
    void prelaunchScanOfLogTarget() {
        assertNull(CliRuntime.scanLogTarget(new String[0]));
        assertNull(CliRuntime.scanLogTarget(null));
        assertNull(CliRuntime.scanLogTarget(new String[]{"--ip_address", "10.0.0.1"}));
        assertNull(CliRuntime.scanLogTarget(new String[]{"--logfile"}), "缺取值时预读不到东西，报错交给解析层");

        assertEquals("logs/a.log", CliRuntime.scanLogTarget(new String[]{"--logfile", "logs/a.log"}));
        assertEquals("logs/a.log", CliRuntime.scanLogTarget(new String[]{"--logfile=logs/a.log"}));
        assertEquals("CONSOLE,logs/a.log",
                CliRuntime.scanLogTarget(new String[]{"--logfile=CONSOLE,logs/a.log"}));
        assertEquals("b.log", CliRuntime.scanLogTarget(new String[]{"--logfile=a.log", "--logfile", "b.log"}));
        assertEquals("b.log", CliRuntime.scanLogTarget(new String[]{"--daemon", "false", "--logfile", "b.log"}),
                "--daemon 的取值不能被当成 --logfile 的取值");
        assertEquals("b.log", CliRuntime.scanLogTarget(new String[]{"--daemon", "--logfile", "b.log"}),
                "裸写 --daemon 不能吞掉后面的 --logfile");
    }

    @Test
    @DisplayName("--daemon 取值解析")
    void daemonFlagParsing() {
        assertTrue(CliRuntime.parseDaemonFlag(null), "裸写按 true 处理");
        assertTrue(CliRuntime.parseDaemonFlag("  "));
        assertTrue(CliRuntime.parseDaemonFlag("true"));
        assertTrue(CliRuntime.parseDaemonFlag("TRUE"));
        assertFalse(CliRuntime.parseDaemonFlag("false"));
        assertFalse(CliRuntime.parseDaemonFlag("False"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CliRuntime.parseDaemonFlag("1"));
        assertTrue(e.getMessage().contains("true or false"), e.getMessage());
    }

    @Test
    @DisplayName("子进程命令行：剥掉 --daemon 的三种写法，并追加 --daemon false")
    void daemonFlagIsStrippedForChild() {
        assertEquals(List.of("--a", "1", "--b"),
                CliRuntime.stripDaemonOption(new String[]{"--daemon", "true", "--a", "1", "--b"}));
        assertEquals(List.of("--a", "--b"),
                CliRuntime.stripDaemonOption(new String[]{"--daemon", "--a", "--b"}),
                "裸写 --daemon 不能吞掉后面的选项");
        assertEquals(List.of("--a"),
                CliRuntime.stripDaemonOption(new String[]{"--daemon=false", "--a"}));
        assertEquals(List.of(), CliRuntime.stripDaemonOption(new String[]{"--daemon"}));
    }

    @Test
    @DisplayName("后台命令行：带空格的取值必须整体传递，且显式给出 start 的标题参数")
    void daemonCommandShape() throws Exception {
        String jar = new File("target/cli-daemon-test/jshark-1.0.0-capture.jar").getAbsolutePath();
        List<String> cmd = CliRuntime.buildDaemonCommand(jar, new String[]{
                "--ip_address", "10.0.0.1",
                "--filter", "udp port 3000",
                "--daemon", "true",
                "--logfile=logs/x.log"});

        assertNotNull(cmd);

        if (CliRuntime.isWindows()) {
            // Windows 下每个参数是一个列表元素，可以按元素断言。
            assertTrue(cmd.contains(jar), "必须重新执行同一个 jar: " + cmd);
            assertTrue(cmd.contains("--filter") && cmd.contains("udp port 3000"),
                    "带空格的取值必须是一个整体参数: " + cmd);
            assertTrue(cmd.contains("--logfile=logs/x.log"), "--logfile 必须原样传给子进程: " + cmd);
            assertFalse(cmd.contains("true"), "父进程命令行里的 --daemon true 必须被剥掉: " + cmd);

            int daemonIndex = cmd.indexOf("--daemon");
            assertTrue(daemonIndex >= 0, "子进程必须显式带 --daemon false: " + cmd);
            assertEquals("false", cmd.get(daemonIndex + 1), "否则子进程会继续 fork，无限递归: " + cmd);

            assertEquals("cmd", cmd.get(0));
            assertEquals("/c", cmd.get(1));
            assertEquals("start", cmd.get(2));
            assertEquals("\"\"", cmd.get(3),
                    "必须显式给出空标题：start 会把第一个带引号的参数（路径带空格的 java.exe）当成窗口标题");
            assertEquals("/B", cmd.get(4));
        } else {
            // POSIX 下整条命令行是一个 shell 脚本字符串（shellQuote 把每个参数整体包成单引号），
            // 不能再按“一个参数一个元素”断言——那样永远找不到 jar，等于这条用例没在 POSIX 上跑过。
            assertEquals(3, cmd.size(), "POSIX 命令行应为 [shell, -c, script]: " + cmd);
            assertEquals("-c", cmd.get(1));

            String script = cmd.get(2);
            assertTrue(script.startsWith("nohup "), "POSIX 后台启动必须脱离终端: " + script);
            assertTrue(script.contains(CliRuntime.shellQuote(jar)),
                    "必须重新执行同一个 jar: " + script);
            assertTrue(script.contains("'--filter' 'udp port 3000'"),
                    "带空格的取值必须整体加引号，否则 shell 会把它拆成两个参数: " + script);
            assertTrue(script.contains("'--logfile=logs/x.log'"),
                    "--logfile 必须原样传给子进程: " + script);
            assertFalse(script.contains("'true'"),
                    "父进程命令行里的 --daemon true 必须被剥掉: " + script);
            assertTrue(script.endsWith("'--daemon' 'false' >/dev/null 2>&1 &"),
                    "子进程必须显式带 --daemon false，否则子进程会继续 fork，无限递归: " + script);
        }
    }

    @Test
    @DisplayName("开发模式（从 classes 启动）：无法脱离当前进程，命令行拼装返回 null")
    void devModeCannotDetach() throws Exception {
        assertNull(CliRuntime.resolveJarPath(CliShark.class),
                "surefire 下是从 target/classes 启动的，应当识别为开发模式");
        assertNull(CliRuntime.buildDaemonCommand(CliShark.class, new String[]{"--daemon", "true"}),
                "开发模式必须退化为前台运行，而不是拼出一个跑不起来的命令行");
    }

    @Test
    @DisplayName("POSIX 参数转义")
    void shellQuoting() {
        assertEquals("'a b'", CliRuntime.shellQuote("a b"));
        assertEquals("'it'\\''s'", CliRuntime.shellQuote("it's"));
        assertEquals("'--filter=udp port 3000'", CliRuntime.shellQuote("--filter=udp port 3000"));
    }

    // ------------------------------------------------------------------ 日志落盘

    @Test
    @DisplayName("--logfile：日志真的写进文件（追加），CONSOLE 可以与文件并存")
    void logfileWritesToFile() throws Exception {
        Path dir = Path.of("target", "cli-daemon-test");
        Files.createDirectories(dir);
        Path log = dir.resolve("capture.log");
        Files.deleteIfExists(log);

        try {
            CliLogging.configure(log.toString());
            LoggerFactory.getLogger(CliDaemonTest.class).info("logfile-target-check");
            String written = Files.readString(log, StandardCharsets.UTF_8);
            assertTrue(written.contains("logfile-target-check"), "日志文件内容: " + written);
            assertTrue(written.contains("main]"),
                    "文件格式应带线程名（与历史格式对齐），便于排查是哪个线程写的: " + written);

            // 追加而不是覆盖：父进程/后台副本可能先后写同一个文件
            CliLogging.configure(log.toString());
            LoggerFactory.getLogger(CliDaemonTest.class).info("logfile-second-check");
            String appended = Files.readString(log, StandardCharsets.UTF_8);
            assertTrue(appended.contains("logfile-target-check") && appended.contains("logfile-second-check"),
                    "重新配置后应追加而不是截断: " + appended);

            assertTrue(CliLogging.isConsoleTarget("console"));
            assertFalse(CliLogging.isConsoleTarget(log.toString()));
        } finally {
            CliLogging.configure(null);   // 恢复控制台，避免影响同一 JVM 内的其它用例
        }
    }

    @Test
    @DisplayName("日志目标不可写时退回控制台，而不是把日志全丢掉")
    void unwritableLogTargetFallsBackToConsole() throws Exception {
        Path dir = Path.of("target", "cli-daemon-test", "not-a-file");
        Files.createDirectories(dir);
        try {
            assertDoesNotThrow(() -> CliLogging.configure(dir.toString()),
                    "把目录当成日志文件时必须退回控制台");
            assertDoesNotThrow(() -> LoggerFactory.getLogger(CliDaemonTest.class).info("fallback-check"));
        } finally {
            CliLogging.configure(null);
        }
    }

    // ------------------------------------------------------------------ 工具

    /**
     * 读取私有字段：解析结果只放在字段里，而这一层的价值正是"选项名有没有落到字段上"，
     * 所以用反射读取，而不是为了测试去开放一堆 getter。
     */
    private static Object read(Object target, String fieldName) throws Exception {
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field f = type.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException e) {
                type = type.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }
}
