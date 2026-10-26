package com.jshark;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 锁定 CLI 的"退出策略"：<b>解析层永不退进程，只抛 {@link CliExitException}，
 * 退出码由 {@code main} 这个进程边界决定。</b>
 *
 * <p>为什么值得专门测：改造前 {@code CliShark.parse()} 在参数非法时直接 {@code System.exit(1)}。
 * 这类用例一旦被测试调用，选项解析回归的症状就变成<b>杀掉 forked 测试 JVM</b>（surefire 崩溃、
 * 看不到失败原因），而不是一条干净的断言失败。这条测试的存在本身就是那个约束的守卫：
 * 如果谁把 {@code System.exit} 加回来，本用例会连同整个 fork 一起消失/崩溃，而不是悄悄通过。</p>
 */
class CliSharkExitPolicyTest {

    @Test
    @DisplayName("非法选项：抛 CliExitException(1)，不退进程")
    void invalidOptionThrowsInsteadOfExiting() {
        CliShark cli = new CliShark();
        CliExitException e = assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--definitely-not-an-option"}));
        assertEquals(1, e.exitCode(), "非法选项的退出码应为 1");
        assertNotNull(e.getMessage(), "应带上可读的错误原因");
        assertTrue(e.getMessage().contains("--definitely-not-an-option"),
                "错误信息应指出是哪个选项，实际: " + e.getMessage());
    }

    @Test
    @DisplayName("非法取值：抛 CliExitException(1)")
    void invalidValueThrows() {
        CliShark cli = new CliShark();
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--count", "not-a-number"})).exitCode());
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--pcap-buffer", "-1"})).exitCode());
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--parse-threads", "0"})).exitCode());
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--count", "-1"})).exitCode());
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--timeout", "-5"})).exitCode());
    }

    @Test
    @DisplayName("缺少取值 / 多余的裸参数：抛 CliExitException(1)")
    void missingValueAndStrayArgumentThrow() {
        CliShark cli = new CliShark();
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--filter"})).exitCode());
        assertEquals(1, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"stray"})).exitCode());
    }

    @Test
    @DisplayName("--help / -h：抛 CliExitException(0)（正常退出语义）")
    void helpSignalsZeroExitCode() {
        CliShark cli = new CliShark();
        assertEquals(0, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"--help"})).exitCode(), "--help 属于正常退出，退出码应为 0");
        assertEquals(0, assertThrows(CliExitException.class,
                () -> cli.parse(new String[] {"-h"})).exitCode(), "-h 与 --help 等价");
    }

    @Test
    @DisplayName("--help 是纯查询：不要求 Npcap/管理员权限")
    void helpDoesNotRequireCaptureEnvironment() {
        assertEquals(0, assertThrows(CliExitException.class,
                () -> CliShark.run(new String[] {"--help"})).exitCode(),
                "--help 必须在环境预检之前返回 0（否则无 Npcap/非管理员机器上看不到帮助）");
    }

    @Test
    @DisplayName("合法参数：不抛任何异常（解析层没有副作用）")
    void validArgumentsParseCleanly() {
        CliShark cli = new CliShark();
        cli.parse(new String[] {
                "--ip_address", "10.1.1.10",
                "--filter", "udp port 3000",
                "--logdb", "target/cli-exit-policy-test/out.db",
                "--count", "10",
                "--pcap-buffer", "32",
                "--parse-threads", "2",
                "--immediate",
                "--promiscuous",
                "--multicast", "224.3.0.0"
        });
    }
}
