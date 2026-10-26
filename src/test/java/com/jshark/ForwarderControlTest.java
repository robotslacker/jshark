package com.jshark;

import com.alibaba.fastjson2.JSONObject;
import com.jshark.forwarder.ForwarderStatus;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 转发器 status 协议与 UI 解析端的字段契约。
 */
public class ForwarderControlTest {

    @Test
    void statusRoundTripsThroughUiParser() {
        ForwarderStatus.Snapshot snap = new ForwarderStatus.Snapshot(
                new ForwarderStatus.Direction(12_442, 8_620_000),
                new ForwarderStatus.Direction(9_810, 5_200_000),
                12,
                "0.0.0.0:3001",
                "224.3.0.0:3000",
                List.of(new ForwarderStatus.Peer("10.10.1.100:3001", "ready", 1_700_000_000_000L),
                        new ForwarderStatus.Peer("10.10.2.100:3001", "reconnecting", 0L)),
                12_000);

        JSONObject json = ForwarderControl.statusJson(7, "RUNNING", "bridge", "", 12_345, snap);
        assertEquals("status", json.getString("type"));
        assertEquals("bridge", json.getString("mode"));
        assertEquals(12_000, json.getLongValue("udpIn"));
        assertEquals(0.001, json.getDoubleValue("dropRate"), 1e-9);

        ForwarderUi.UiStatus s = ForwarderUi.UiStatus.from(json);
        assertEquals(7, s.seq);
        assertEquals("RUNNING", s.state);
        assertEquals("bridge", s.mode);
        assertEquals(12_345, s.elapsedMs);
        assertEquals(12_442, s.udpToTcpPackets);
        assertEquals(8_620_000, s.udpToTcpBytes);
        assertEquals(9_810, s.tcpToUdpPackets);
        assertEquals(5_200_000, s.tcpToUdpBytes);
        assertEquals(12, s.dropped);
        assertEquals(12_000, s.udpIn);
        assertEquals(0.001, s.dropRate, 1e-9);
        assertEquals("0.0.0.0:3001", s.listen);
        assertEquals("224.3.0.0:3000", s.udpLocal);
        assertEquals(2, s.peers.size());
        assertEquals("ready", s.peers.get(0).state());
        assertEquals(1_700_000_000_000L, s.peers.get(0).sinceMs());
        assertEquals("reconnecting", s.peers.get(1).state());
    }

    @Test
    void nullSnapshotYieldsZeros() {
        JSONObject json = ForwarderControl.statusJson(1, "READY", "bridge", "", 0, null);
        ForwarderUi.UiStatus s = ForwarderUi.UiStatus.from(json);
        assertEquals("READY", s.state);
        assertEquals(0, s.udpToTcpPackets);
        assertEquals(0, s.tcpToUdpPackets);
        assertEquals(0, s.udpIn);
        assertEquals(0.0, s.dropRate, 1e-9);
        assertTrue(s.peers.isEmpty());
        assertEquals("", s.listen);
    }

    @Test
    void failedStatusCarriesMessage() {
        JSONObject json = ForwarderControl.statusJson(2, "FAILED", "bridge",
                "--udpif is required", 0, null);
        assertEquals("--udpif is required", json.getString("message"));
        assertEquals("--udpif is required",
                ForwarderUi.UiStatus.from(json).message);
    }
}
