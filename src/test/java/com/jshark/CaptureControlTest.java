package com.jshark;

import com.alibaba.fastjson2.JSONObject;
import com.jshark.PacketCapture.Snapshot;
import com.jshark.PacketCapture.VolumeRow;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code --control stdio} 的 status 协议与 UI 解析端的契约测试。
 *
 * <p>不启动子进程：直接把同一份 Snapshot 序列化成 JSON，再让 UI 的 {@code UiStatus.from}
 * 解析回来，确保字段名/类型不会各写各的。</p>
 */
public class CaptureControlTest {

    @Test
    void statusRoundTripsThroughUiParser() {
        Snapshot snap = new Snapshot("RUNNING", 12_345L, 128_442L, 127_901L, 541L, 0L,
                8_620_000L, "C:\\captures\\cap_20261023-capturing.db",
                List.of(new VolumeRow(1, "C:\\captures\\cap_20261023-capturing.db",
                        1_700_000_000_000L, 0L, 42_118L, 31_700_000L, "capturing")));
        JSONObject json = CaptureControl.statusJson(7, "RUNNING", "", snap);

        assertEquals("status", json.getString("type"));
        assertEquals(7, json.getLongValue("seq"));
        assertEquals("RUNNING", json.getString("state"));

        CaptureUi.UiStatus status = CaptureUi.UiStatus.from(json);
        assertEquals(7, status.seq);
        assertEquals("RUNNING", status.state);
        assertEquals(12_345L, status.elapsedMs);
        assertEquals(128_442L, status.captured);
        assertEquals(127_901L, status.stored);
        assertEquals(541L, status.filtered);
        assertEquals(0L, status.dropped);
        assertEquals(8_620_000L, status.bytes);
        assertEquals("C:\\captures\\cap_20261023-capturing.db", status.currentVolume);
        assertEquals(1, status.volumes.size());
        CaptureUi.Volume v = status.volumes.get(0);
        assertEquals(1, v.seq());
        assertEquals(42_118L, v.packets());
        assertEquals(31_700_000L, v.bytes());
        assertEquals("capturing", v.status());
        assertEquals(1_700_000_000_000L, v.startMs());
    }

    @Test
    void nullSnapshotBecomesEmptyStatus() {
        JSONObject json = CaptureControl.statusJson(1, "READY", "", null);
        assertEquals("READY", json.getString("state"));
        assertEquals(0L, json.getLongValue("captured"));
        assertTrue(json.getJSONArray("volumes").isEmpty());
        assertNull(json.getString("currentVolume"));

        CaptureUi.UiStatus status = CaptureUi.UiStatus.from(json);
        assertEquals("READY", status.state);
        assertEquals(0, status.captured);
        assertTrue(status.volumes.isEmpty());
    }

    @Test
    void failedStatusCarriesMessage() {
        JSONObject json = CaptureControl.statusJson(3, "FAILED", "Npcap not installed", null);
        assertEquals("FAILED", json.getString("state"));
        assertEquals("Npcap not installed", json.getString("message"));
        assertEquals("Npcap not installed", CaptureUi.UiStatus.from(json).message);
    }
}
