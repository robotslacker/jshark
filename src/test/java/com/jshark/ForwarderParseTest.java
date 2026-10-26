package com.jshark;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 转发器 CLI 参数解析：重复 {@code --peer} 在 Map 里转成 peer1..peerN。
 */
public class ForwarderParseTest {

    @Test
    void unknownOptionIsRejectedInsteadOfSilentlyIgnored() {
        IllegalArgumentException e = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> CliForwarder.parseOptions(new String[]{"--udpifx", "10.0.0.0/8"}));
        assertEquals("Unknown option: --udpifx", e.getMessage());
    }

    @Test
    void generatedPeerKeysAreAccepted() {
        Map<String, String> opts = CliForwarder.parseOptions(new String[]{
                "--udpaddr=224.3.0.0:3000",
                "--peer1=10.10.1.100:3001"});
        assertEquals("10.10.1.100:3001", opts.get("peer1"));
    }

    @Test
    void repeatedPeerKeepsAllEntries() {
        Map<String, String> opts = CliForwarder.parseOptions(new String[]{
                "--udpaddr", "224.3.0.0:3000",
                "--udpif", "192.168.1.0/24",
                "--port", "3001",
                "--peer", "10.10.1.100:3001",
                "--peer", "10.10.2.100:3001"});
        assertEquals("224.3.0.0:3000", opts.get("udpaddr"));
        assertEquals("10.10.1.100:3001", opts.get("peer"));
        assertEquals("10.10.2.100:3001", opts.get("peer1"));
    }

    @Test
    void equalsFormIsAccepted() {
        Map<String, String> opts = CliForwarder.parseOptions(new String[]{
                "--udpaddr=224.3.0.0:3000",
                "--udpif=192.168.1.0/24",
                "--port=3001",
                "--peer=10.10.1.100:3001",
                "--peer=10.10.2.100:3001"});
        assertEquals("224.3.0.0:3000", opts.get("udpaddr"));
        assertEquals("192.168.1.0/24", opts.get("udpif"));
        assertEquals("10.10.1.100:3001", opts.get("peer"));
        assertEquals("10.10.2.100:3001", opts.get("peer1"));
    }
}
