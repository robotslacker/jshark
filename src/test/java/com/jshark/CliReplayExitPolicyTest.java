package com.jshark;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 重放入口的退出策略：与 {@code CliShark} 一致——解析层只抛 {@link CliExitException}，
 * 退出码由 {@code main} 决定，测试直接调用 {@code parse()} 不会被杀掉 JVM。
 */
class CliReplayExitPolicyTest {

    @Test
    void invalidOptionThrowsUsageExitInsteadOfExiting() {
        CliExitException e = assertThrows(CliExitException.class,
                () -> new CliReplay().parse(new String[] {"--definitely-not-an-option"}));
        assertEquals(CliExitException.EXIT_USAGE, e.exitCode());
        assertTrue(e.getMessage().contains("--definitely-not-an-option"), e.getMessage());
    }

    @Test
    void removedOptionPointsAtReplacement() {
        CliExitException e = assertThrows(CliExitException.class,
                () -> new CliReplay().parse(new String[] {"--startc", "2026-08-21 08:10:00"}));
        assertTrue(e.getMessage().contains("renamed to --start"), e.getMessage());
    }

    @Test
    void portFilterMustBeInRange() {
        CliExitException e = assertThrows(CliExitException.class,
                () -> new CliReplay().parse(new String[] {"--db", "x.db", "--sourcePort", "70000"}));
        assertTrue(e.getMessage().contains("1-65535"), e.getMessage());
    }

    @Test
    void helpSignalsZeroExitCode() {
        CliExitException e = assertThrows(CliExitException.class,
                () -> new CliReplay().parse(new String[] {"--help"}));
        assertEquals(CliExitException.EXIT_OK, e.exitCode());
    }
}
