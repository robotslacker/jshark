package com.jshark;

import com.jshark.forwarder.ForwarderFactory;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 转发器参数校验（与 UI 共用 {@link ForwarderFactory}）。
 */
public class ForwarderFactoryTest {

    private static Map<String, String> opts(String... pairs) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put(pairs[i].toLowerCase(java.util.Locale.ROOT), pairs[i + 1]);
        }
        return map;
    }

    @Test
    void bridgeNeedsUdpIfAndPeers() {
        Map<String, String> noIf = opts("udpaddr", "224.3.0.0:3000",
                "port", "3001", "peer1", "10.0.0.1:3001");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderFactory.create(noIf, LoggerFactory.getLogger("test")))
                .getMessage().contains("--udpif"));

        Map<String, String> noPeer = opts("udpaddr", "224.3.0.0:3000",
                "udpif", "192.168.1.0/24", "port", "3001");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderFactory.create(noPeer, LoggerFactory.getLogger("test")))
                .getMessage().contains("--peer"));
    }

    @Test
    void portIsRequired() {
        Map<String, String> noListen = opts("udpaddr", "224.3.0.0:3000",
                "udpif", "192.168.1.0/24", "peer1", "10.0.0.1:3001");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderFactory.create(noListen, LoggerFactory.getLogger("test")))
                .getMessage().contains("--port"));
    }

    @Test
    void validBridgeBuildsSource() {
        ForwarderFactory.Built bridge = ForwarderFactory.create(
                opts("udpaddr", "224.3.0.0:3000",
                        "udpif", "192.168.1.0/24", "port", "3001",
                        "peer1", "10.0.0.1:3001", "peer2", "10.0.0.2:3001"),
                LoggerFactory.getLogger("test"));
        assertEquals("bridge", bridge.mode());
        bridge.source().stop();
    }

    @Test
    void utotAndTtouBothDisabledRejected() {
        Map<String, String> bothFalse = opts("udpaddr", "224.3.0.0:3000",
                "udpif", "192.168.1.0/24", "port", "3001", "peer1", "10.0.0.1:3001",
                "utot", "false", "ttou", "false");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderFactory.create(bothFalse, LoggerFactory.getLogger("test")))
                .getMessage().contains("--utot"));
    }

    @Test
    void ttouFalseAllowsOmittedPort() {
        // ttou=false（TCP→UDP 关闭）时 --port 不被使用，可不填。
        ForwarderFactory.Built bridge = ForwarderFactory.create(
                opts("udpaddr", "224.3.0.0:3000",
                        "udpif", "192.168.1.0/24", "ttou", "false",
                        "peer1", "10.0.0.1:3001"), LoggerFactory.getLogger("test"));
        assertEquals("bridge", bridge.mode());
        bridge.source().stop();
    }

    @Test
    void invalidUtotValueRejected() {
        Map<String, String> bad = opts("udpaddr", "224.3.0.0:3000",
                "udpif", "192.168.1.0/24", "port", "3001", "peer1", "10.0.0.1:3001",
                "utot", "maybe");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ForwarderFactory.create(bad, LoggerFactory.getLogger("test")))
                .getMessage().contains("--utot"));
    }
}
