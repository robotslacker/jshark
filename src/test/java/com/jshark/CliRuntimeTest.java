package com.jshark;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CliRuntime#isEnabled} 契约：模式开关必须尊重显式 {@code =false}。
 */
class CliRuntimeTest {

    @Test
    void bareFlagIsEnabled() {
        assertTrue(CliRuntime.isEnabled(new String[] {"--ui"}, "--ui"));
        assertFalse(CliRuntime.isEnabled(new String[] {}, "--ui"));
    }

    @Test
    void explicitFalseDisablesMode() {
        assertFalse(CliRuntime.isEnabled(new String[] {"--ui=false"}, "--ui"));
        assertTrue(CliRuntime.isEnabled(new String[] {"--ui=true"}, "--ui"));
        assertFalse(CliRuntime.isEnabled(new String[] {"--daemon", "false"}, "--daemon"));
        assertTrue(CliRuntime.isEnabled(new String[] {"--daemon", "true"}, "--daemon"));
    }

    @Test
    void otherOptionsDoNotEnableIt() {
        assertFalse(CliRuntime.isEnabled(
                new String[] {"--logfile", "ui.log", "--filter", "udp port 53"}, "--ui"));
    }
}
