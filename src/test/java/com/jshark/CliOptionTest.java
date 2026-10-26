package com.jshark;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * CLI 参数解析验收：README 里写出来的选项，命令行上必须真的能生效。
 *
 * <h3>为什么单独测这一层</h3>
 * <p>
 * 文档写了一个选项，而它实际不生效（拼错字段名、忘了加 case），是最容易发生也最误导人的缺陷：
 * 用户照着文档敲，程序不报错也不按预期工作。{@link CliShark#main} 需要管理员权限才能进入，
 * 因此这里直接调用公开的 {@link CliShark#parse} 来验证"选项名 → 内部字段"的映射。
 * </p>
 *
 * <p>纯解析测试：不抓包、不开网卡、不需要管理员权限。</p>
 */
public class CliOptionTest {

    private static final Logger logger = LoggerFactory.getLogger(CliOptionTest.class);

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void cliOptionRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  CLI 选项解析验收");
        logger.info("=================================================");

        checkCaptureOptionMapping();
        checkEnableAdditionInfoDefaults();
        checkExfilterImpliesAdditionInfo();
        checkBooleanFlags();
        checkRemovedCaptureOptionsAbsent();
        checkRemovedReplayOptionsAbsent();
        checkDocumentedOptionsAreRegistered();
        checkInspectHiddenFromHelp();
        checkHelpMentionsEnableAdditionInfo();
        checkCaptureUiOptions();
        checkAbsoluteCaptureTimeParsing();
        checkVolumeTimestampParsing();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    private static void checkCaptureOptionMapping() throws Exception {
        logger.info("---- [2] 采集端选项映射 ----");

        CliShark cli = new CliShark();
        cli.parse(new String[]{
                "--pcapinput=in.pcap",
                "--logdb=out.db",
                "--split=5m",
                "--exfilter=dis.pdu.type=28"
        });

        check("in.pcap".equals(read(cli, "pcapInputFile")),
                "--pcapinput 映射到 pcapInputFile（实际 " + read(cli, "pcapInputFile") + "）");
        check("dis.pdu.type=28".equals(read(cli, "exfilter")),
                "--exfilter 正常解析（实际 " + read(cli, "exfilter") + "）");
        check(Boolean.TRUE.equals(read(cli, "enableAdditionInfo")),
                "--exfilter 自动开启 enableAdditionInfo");
    }

    /**
     * 纯开关：裸写 = true，显式 {@code =false} 必须真的关掉，非法取值报错。
     */
    private static void checkBooleanFlags() throws Exception {
        logger.info("---- [2d] 纯开关的 =true/=false ----");

        CliShark defaults = new CliShark();
        defaults.parse(new String[]{"--logdb=out.db"});
        check(Boolean.FALSE.equals(read(defaults, "promiscuous")), "--promiscuous 默认 false");
        check(Boolean.FALSE.equals(read(defaults, "immediate")), "--immediate 默认 false");

        CliShark bare = new CliShark();
        bare.parse(new String[]{"--promiscuous", "--immediate"});
        check(Boolean.TRUE.equals(read(bare, "promiscuous")), "裸写 --promiscuous 等价 true");
        check(Boolean.TRUE.equals(read(bare, "immediate")), "裸写 --immediate 等价 true");

        CliShark explicitFalse = new CliShark();
        explicitFalse.parse(new String[]{"--promiscuous=false", "--immediate=false"});
        check(Boolean.FALSE.equals(read(explicitFalse, "promiscuous")),
                "--promiscuous=false 必须关闭（曾经被静默当成 true）");
        check(Boolean.FALSE.equals(read(explicitFalse, "immediate")),
                "--immediate=false 必须关闭");

        CliShark invalid = new CliShark();
        int code = -1;
        try {
            invalid.parse(new String[]{"--promiscuous=maybe"});
        } catch (CliExitException e) {
            code = e.exitCode();
        }
        check(code == 1, "--promiscuous=maybe 应报错并以 1 退出（实际 " + code + "）");
    }

    /**
     * --enable_additioninfo 默认 false；裸写等价 true；显式 false 与非法取值。
     */
    private static void checkEnableAdditionInfoDefaults() throws Exception {
        logger.info("---- [2a] --enable_additioninfo 默认值与取值 ----");

        CliShark defaultCli = new CliShark();
        defaultCli.parse(new String[]{"--logdb=out.db"});
        check(Boolean.FALSE.equals(read(defaultCli, "enableAdditionInfo")),
                "--enable_additioninfo 默认 false（实际 " + read(defaultCli, "enableAdditionInfo") + "）");

        CliShark bare = new CliShark();
        bare.parse(new String[]{"--enable_additioninfo"});
        check(Boolean.TRUE.equals(read(bare, "enableAdditionInfo")),
                "裸写 --enable_additioninfo 等价于 true");

        CliShark explicitFalse = new CliShark();
        explicitFalse.parse(new String[]{"--enable_additioninfo=false"});
        check(Boolean.FALSE.equals(read(explicitFalse, "enableAdditionInfo")),
                "--enable_additioninfo=false 保持关闭");

        org.junit.jupiter.api.Assertions.assertThrows(CliExitException.class,
                () -> new CliShark().parse(new String[]{"--enable_additioninfo=maybe"}),
                "非法取值必须报错，而不是静默按 true/false 处理");
    }

    /**
     * --exfilter 隐含 --enable_additioninfo=true：表达式写在前面、显式 =false 都不能改变。
     */
    private static void checkExfilterImpliesAdditionInfo() throws Exception {
        logger.info("---- [2a-2] --exfilter 自动开启 --enable_additioninfo ----");

        CliShark onlyExfilter = new CliShark();
        onlyExfilter.parse(new String[]{"--exfilter=dis.pdu.type=28"});
        check(Boolean.TRUE.equals(read(onlyExfilter, "enableAdditionInfo")),
                "只写 --exfilter 时自动开启（实际 " + read(onlyExfilter, "enableAdditionInfo") + "）");

        CliShark explicitFalse = new CliShark();
        explicitFalse.parse(new String[]{"--exfilter=dis.pdu.type=28", "--enable_additioninfo=false"});
        check(Boolean.TRUE.equals(read(explicitFalse, "enableAdditionInfo")),
                "--exfilter + --enable_additioninfo=false 仍自动开启（实际 "
                        + read(explicitFalse, "enableAdditionInfo") + "）");

        CliShark noExfilter = new CliShark();
        noExfilter.parse(new String[]{"--logdb=out.db"});
        check(Boolean.FALSE.equals(read(noExfilter, "enableAdditionInfo")),
                "没有 --exfilter 时保持 --enable_additioninfo 默认 false");
    }

    /**
     * --graceMs / --flushTimeout / --verbose 已移除：grace 硬编码 30s、flushTimeout 硬编码 0、
     * verbose 不支持。这里用反射断言这些选项键不再出现在 OPTIONS 里
     * （不能调用 parse() 去验证：它现在对未知选项抛 {@code CliExitException(1)}，
     * 曾经是直接 System.exit，会把 forked 测试 JVM 一起带走）。
     */
    private static void checkRemovedCaptureOptionsAbsent() throws Exception {
        logger.info("---- [2b] 已移除选项不在注册表 ----");

        Field field = CliShark.class.getDeclaredField("OPTIONS");
        field.setAccessible(true);
        java.util.Map<?, ?> options0 = (java.util.Map<?, ?>) field.get(null);

        check(!options0.containsKey("--flushTimeout"), "--flushTimeout 已从 CliShark 选项移除");
        check(!options0.containsKey("--graceMs"), "--graceMs 已从 CliShark 选项移除");
        check(!options0.containsKey("--verbose"), "--verbose 已从 CliShark 选项移除");
        check(!options0.containsKey("--exfilter-unmatched"),
                "--exfilter-unmatched 已从 CliShark 选项移除（不匹配的包一律丢弃）");
    }

    /**
     * --speed-exact 已移除：自适应降速始终开启，CLI 不再提供固定倍率入口。
     * 与采集端的已移除选项一样，用反射断言它不在注册表里。
     */
    private static void checkRemovedReplayOptionsAbsent() throws Exception {
        logger.info("---- [2c] 已移除的重放选项不在注册表 ----");

        Field field = CliReplay.class.getDeclaredField("OPTIONS");
        field.setAccessible(true);
        java.util.Map<?, ?> options0 = (java.util.Map<?, ?>) field.get(null);

        check(!options0.containsKey("--speed-exact"),
                "--speed-exact 已从 CliReplay 选项移除（自适应始终开启）");
        check(!options0.containsKey("--startc"),
                "--startc 已移除（绝对时间窗口统一为 --start）");
        check(!options0.containsKey("--endc"),
                "--endc 已移除（绝对时间窗口统一为 --end）");
    }

    /**
     * README 里写出来的选项，必须都是真实注册过的选项。
     *
     * <h3>为什么不去测 CliReplay 的字段映射</h3>
     * <p>
     * {@code CliReplay.parse()} 不是"只解析"——它解析完会直接进入重放流程
     * （日志里能看到 "Starting PCAP replay mode..."），并且会校验 pcap 是否存在。
     * 因此无法在单元测试里安全调用（会真的往网络上发包）。这里退一步，
     * 只校验<b>选项名是否已注册</b>：这能挡住"文档写了、程序不认"这一类最误导人的错误。
     * </p>
     */
    private static void checkDocumentedOptionsAreRegistered() throws Exception {
        logger.info("---- [3] README 中列出的选项均已注册 ----");

        String[] captureOptions = {
                "--ip_address", "--filter", "--count", "--timeout", "--pcapoutput", "--pcapinput",
                "--split", "--logdb", "--exfilter", "--enable_additioninfo",
                "--multicast",
                "--promiscuous", "--daemon", "--logfile", "--ui"
        };
        assertRegistered(CliShark.class, captureOptions, "CliShark");

        String[] replayOptions = {
                "--db", "--pcap", "--speed", "--start", "--end",
                "--sourceIp", "--destinationIp",
                "--sourcePort", "--destinationPort", "--ipProtocol", "--applicationProtocol",
                "--exfilter", "--replayMode", "--injectInterface", "--dstMac", "--replayTargetMapping",
                "--daemon", "--logfile"
        };
        assertRegistered(CliReplay.class, replayOptions, "CliReplay");
    }

    private static void checkInspectHiddenFromHelp() throws Exception {
        logger.info("---- [3b] --inspect/--control 是内部参数，不出现在 --help ----");

        String text = helpText(CliReplay.class);
        check(!text.contains("--inspect"), "--inspect 不出现在 help 输出");
        check(!text.contains("--control"), "--control 不出现在 help 输出");
        check(text.contains("--start") && text.contains("--end"), "help 仍展示 --start/--end");
        check(text.contains("--ui"), "help 仍展示 --ui");
    }

    /**
     * 帮助文本必须交代 --enable_additioninfo 与其影响。
     *
     * <p>采集端会列出该选项本身；重放端没有这个选项，但 {@code --exfilter} 依赖库里已有的
     * {@code additionalInfo} 列——采集时没开这个开关，重放的表达式过滤会静默地匹配不到任何包。
     * 这条断言就是钉住"重放帮助里必须提示这个前置条件"。</p>
     */
    private static void checkHelpMentionsEnableAdditionInfo() throws Exception {
        logger.info("---- [3c] --help 中交代 --enable_additioninfo ----");

        String captureHelp = helpText(CliShark.class);
        check(captureHelp.contains("--enable_additioninfo"),
                "采集端 --help 列出 --enable_additioninfo");
        check(captureHelp.contains("additionalInfo"),
                "采集端 --help 说明 additionalInfo 列");

        String replayHelp = helpText(CliReplay.class);
        check(replayHelp.contains("--enable_additioninfo"),
                "重放端 --help 在 --exfilter 说明里提示需要采集时开启 --enable_additioninfo");
        check(replayHelp.contains("additionalInfo"),
                "重放端 --help 说明 --exfilter 匹配的是 additionalInfo 列");
    }

    /**
     * 采集 UI 的两个参数：{@code --ui} 出现在帮助里，{@code --control} 是内部协议必须隐藏。
     */
    private static void checkCaptureUiOptions() throws Exception {
        logger.info("---- [3d] 采集 UI 参数 ----");

        String help = helpText(CliShark.class);
        check(help.contains("--ui"), "采集端 --help 展示 --ui");
        check(!help.contains("--control"), "--control 不出现在采集端 --help");

        CliShark cli = new CliShark();
        cli.parse(new String[]{"--control", "stdio"});
        check("stdio".equals(read(cli, "controlMode")),
                "--control stdio 映射到 controlMode（实际 " + read(cli, "controlMode") + "）");

        org.junit.jupiter.api.Assertions.assertThrows(CliExitException.class,
                () -> new CliShark().parse(new String[]{"--control"}),
                "--control 缺少取值必须报错");
    }

    /** 反射调用某个 CLI 的私有 printHelp() 并捕获 stdout（不需要管理员权限）。 */
    private static String helpText(Class<?> cliClass) throws Exception {
        PrintStream original = System.out;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        try {
            Method help = cliClass.getDeclaredMethod("printHelp");
            help.setAccessible(true);
            help.invoke(null);
        } finally {
            System.setOut(original);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private static void assertRegistered(Class<?> cliClass, String[] options, String label)
            throws Exception {
        // OPTIONS 是 private static final Map<String, OptionInfo>
        Field field = cliClass.getDeclaredField("OPTIONS");
        field.setAccessible(true);
        java.util.Map<?, ?> options0 = (java.util.Map<?, ?>) field.get(null);

        java.util.List<String> missing = new java.util.ArrayList<>();
        for (String option : options) {
            if (!options0.containsKey(option)) {
                missing.add(option);
            }
        }
        check(missing.isEmpty(), label + "：README 列出的 " + options.length
                + " 个选项全部已注册（缺失 " + missing + "）");
    }

    /**
     * 读取私有字段。
     * <p>
     * CLI 解析结果只放在私有字段里，而这一层的价值恰恰是"选项名有没有正确落到字段上"，
     * 所以这里用反射读取，而不是为了测试去开放一堆 getter。
     * </p>
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

    /**
     * 验证 --start/--end 的绝对时间解析（parseAbsoluteTime）覆盖各种格式，
     * 并确认旧的相对偏移（hh:mm:ss）已被拒绝。
     */
    private static void checkAbsoluteCaptureTimeParsing() throws Exception {
        logger.info("---- [4] --start/--end 绝对时间解析 ----");

        CliReplay cli = new CliReplay();
        java.lang.reflect.Method parse = CliReplay.class.getDeclaredMethod("parseAbsoluteTime", String.class);
        parse.setAccessible(true);

        // 期望值：按系统时区把 2026-08-21 08:10:00 转成 epoch 毫秒
        long expected = java.time.LocalDateTime.of(2026, 8, 21, 8, 10, 0)
                .atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();

        check(expected == (Long) parse.invoke(cli, "2026-08-21 08:10:00"),
                "yyyy-MM-dd HH:mm:ss 解析（实际 " + parse.invoke(cli, "2026-08-21 08:10:00") + "）");
        check(expected == (Long) parse.invoke(cli, "2026-08-21 08:10"),
                "yyyy-MM-dd HH:mm 解析");
        check(expected == (Long) parse.invoke(cli, "20260821081000"),
                "yyyyMMddHHmmss 紧凑格式解析");
        check(expected == (Long) parse.invoke(cli, "2026-08-21T08:10:00"),
                "'T' 分隔符解析");

        // 含毫秒
        long expectedMs = java.time.LocalDateTime.of(2026, 8, 21, 8, 10, 0, 123_000_000)
                .atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        check(expectedMs == (Long) parse.invoke(cli, "2026-08-21 08:10:00.123"),
                "yyyy-MM-dd HH:mm:ss.SSS 含毫秒解析");

        // 非法格式应抛 IllegalArgumentException
        boolean threw = false;
        try {
            parse.invoke(cli, "08:10:00");
        } catch (java.lang.reflect.InvocationTargetException e) {
            threw = e.getCause() instanceof IllegalArgumentException;
        }
        check(threw, "缺少日期的时间格式（08:10:00）应报错");

        // 旧的相对偏移格式必须被明确拒绝（而不是被当成别的语义）
        boolean relativeRejected = false;
        String relativeMessage = null;
        try {
            parse.invoke(cli, "00:05:00");
        } catch (java.lang.reflect.InvocationTargetException e) {
            relativeRejected = e.getCause() instanceof IllegalArgumentException;
            relativeMessage = e.getCause().getMessage();
        }
        check(relativeRejected, "旧的相对偏移（00:05:00）应报错");
        check(relativeMessage != null && relativeMessage.contains("no longer supported"),
                "相对偏移报错应说明该用法已不再支持（实际 " + relativeMessage + "）");
    }

    /**
     * 验证从分卷文件名提取窗口起点时间戳（SplitUtil.volumeTimestamp）。
     */
    private static void checkVolumeTimestampParsing() {
        logger.info("---- [5] 分卷文件名时间戳提取 ----");
        long expected = java.time.LocalDateTime.of(2026, 8, 21, 8, 10, 0)
                .atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        long expectedEnd = java.time.LocalDateTime.of(2026, 8, 21, 8, 20, 0)
                .atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();

        // 旧式：capture_<start>.db
        Long ts = com.jshark.parser.SplitUtil.volumeTimestamp(
                new java.io.File("capture_20260821081000.db").getAbsolutePath());
        check(expected == ts, "capture_20260821081000.db -> " + ts);
        // 最终：capture_<start>-<end>.db
        String finalPath = new java.io.File("capture_20260821081000-20260821082000.db").getAbsolutePath();
        check(expected == com.jshark.parser.SplitUtil.volumeTimestamp(finalPath),
                "capture_<start>-<end>.db 起点解析正常");
        check(expectedEnd == com.jshark.parser.SplitUtil.volumeEndTimestamp(finalPath),
                "capture_<start>-<end>.db 结束边界解析正常");
        // 捕获中：capture_<start>-capturing.db
        String capPath = new java.io.File("capture_20260821081000-capturing.db").getAbsolutePath();
        check(expected == com.jshark.parser.SplitUtil.volumeTimestamp(capPath),
                "capture_<start>-capturing.db 起点解析正常");
        check(com.jshark.parser.SplitUtil.volumeEndTimestamp(capPath) == null,
                "捕获中卷无 end（返回 null）");
        check(com.jshark.parser.SplitUtil.isInProgressCaptureVolume(capPath),
                "捕获中卷被识别为 -capturing");
        check(!com.jshark.parser.SplitUtil.isInProgressCaptureVolume(finalPath),
                "最终卷不是 -capturing");

        check(com.jshark.parser.SplitUtil.volumeTimestamp("plain.db") == null,
                "非分卷文件名返回 null（实际 "
                        + com.jshark.parser.SplitUtil.volumeTimestamp("plain.db") + "）");
        check(com.jshark.parser.SplitUtil.volumeTimestamp(null) == null,
                "null 返回 null");
    }

    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
