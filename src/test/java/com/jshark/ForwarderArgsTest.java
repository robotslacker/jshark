package com.jshark;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 转发器 UI 表单 → 命令行参数（不依赖 Swing）。
 */
public class ForwarderArgsTest {

    private static List<ForwarderArgs.Endpoint> onePeer() {
        return List.of(new ForwarderArgs.Endpoint("10.10.1.100", 3001));
    }

    @Test
    void bridgeArgsDefaultsBidirectional() {
        List<String> args = ForwarderArgs.buildBridge(new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "3001",
                true, true,
                List.of(new ForwarderArgs.Endpoint("10.10.1.100", 3001),
                        new ForwarderArgs.Endpoint("10.10.2.100", 3001))));
        assertEquals(List.of(
                "--udpaddr", "224.3.0.0:3000",
                "--udpif", "192.168.1.0/24",
                "--port", "3001",
                "--utot", "true",
                "--ttou", "true",
                "--peer1", "10.10.1.100:3001",
                "--peer2", "10.10.2.100:3001"), args);
    }

    @Test
    void ttouFalseOmitsPortAndFlag() {
        // --ttou=false 时 --port 不生成，字段可留空。
        List<String> args = ForwarderArgs.buildBridge(new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "",
                true, false, onePeer()));
        assertEquals(List.of(
                "--udpaddr", "224.3.0.0:3000",
                "--udpif", "192.168.1.0/24",
                "--utot", "true",
                "--ttou", "false",
                "--peer1", "10.10.1.100:3001"), args);
    }

    @Test
    void utotFalseEmitsTtouOnly() {
        List<String> args = ForwarderArgs.buildBridge(new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "3001",
                false, true, onePeer()));
        assertTrue(args.contains("--ttou"));
        assertTrue(args.contains("false"));
        assertTrue(args.contains("--port"));
    }

    @Test
    void bothDirectionsDisabledRejected() {
        ForwarderArgs.BridgeForm bothOff = new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "3001",
                false, false, onePeer());
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderArgs.buildBridge(bothOff)).getMessage().contains("At least one"));
    }

    @Test
    void bothDirectionsDisabledIsReportedBeforePeerValidation() {
        // 两个方向都关 + 没加 peer：提示方向错误，而不是先抱怨缺 peer。
        ForwarderArgs.BridgeForm bothOffNoPeers = new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "",
                false, false, List.of());
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderArgs.buildBridge(bothOffNoPeers)).getMessage().contains("At least one"));
    }

    @Test
    void bridgeRequiresLocalIfPeerAndListenPort() {
        ForwarderArgs.BridgeForm noIf = new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "", "3001",
                true, true, onePeer());
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderArgs.buildBridge(noIf)).getMessage().contains("Local interface"));

        ForwarderArgs.BridgeForm noPeer = new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "3001",
                true, true, List.of());
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderArgs.buildBridge(noPeer)).getMessage().contains("peer"));

        // --ttou=true（默认）时监听端口必填。
        ForwarderArgs.BridgeForm noListen = new ForwarderArgs.BridgeForm(
                "224.3.0.0", "3000", "192.168.1.0/24", "",
                true, true, onePeer());
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderArgs.buildBridge(noListen)).getMessage().contains("Listen port"));
    }

    @Test
    void endpointValidation() {
        assertEquals("10.0.0.1:3000", ForwarderArgs.endpoint(" 10.0.0.1:3000 ", "Peer").text());
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0.1", "Peer"));
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0.1:0", "Peer"));
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0.1:99999", "Peer"));

        // peer 必须是 IPv4:port —— 主机名、越界段、缺段、多个冒号都不行。
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderArgs.endpoint("example.com:3000", "Peer"))
                .getMessage().contains("IPv4:port"));
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0.256:3000", "Peer"));
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0:3000", "Peer"));
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0.1:3000:4000", "Peer"));
        assertThrows(IllegalArgumentException.class, () -> ForwarderArgs.endpoint("10.0.0.1:twenty", "Peer"));
    }

    @Test
    void udpGroupMustBeOneIpv4Address() {
        List<ForwarderArgs.Endpoint> peer = onePeer();
        for (String group : new String[]{"example.com", "224.3.0.0,224.3.0.1", "224.3.0.256", "224.3.0"}) {
            ForwarderArgs.BridgeForm form = new ForwarderArgs.BridgeForm(
                    group, "3000", "192.168.1.0/24", "3001", true, true, peer);
            assertTrue(assertThrows(IllegalArgumentException.class,
                            () -> ForwarderArgs.buildBridge(form)).getMessage().contains("IPv4"),
                    "UDP group 应拒绝：" + group);
        }
        assertTrue(ForwarderArgs.isIpv4("224.3.0.0"));
        assertFalse(ForwarderArgs.isIpv4("224.3.0.256"));
        assertFalse(ForwarderArgs.isIpv4(" 224.3.0.0"));
    }
}
