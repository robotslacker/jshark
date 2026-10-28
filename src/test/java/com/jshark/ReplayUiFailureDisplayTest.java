package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 回放失败/停止的展示规则。
 *
 * <p>以前 UI 只显示 “Failed (exit 1)”：既没有原因，也会把用户按 Stop 后被子进程看门狗
 * 强制结束的情况误报成失败。这里锁住两条文案规则，并验证 status 里的 error/warnings
 * 会被解析出来（供 Log 页展示）。</p>
 */
public class ReplayUiFailureDisplayTest {

    @Test
    void userStopIsNotAFailure() {
        assertEquals("Stopped", ReplayUi.ReplayMainFrame.exitStateText(true, 1));
        assertEquals("Stopped", ReplayUi.ReplayMainFrame.exitStateText(true, 0));
        assertEquals("Exited", ReplayUi.ReplayMainFrame.exitStateText(false, 0));
        assertEquals("Failed (exit 1)", ReplayUi.ReplayMainFrame.exitStateText(false, 1));
        assertEquals("Failed (exit 2)", ReplayUi.ReplayMainFrame.exitStateText(false, 2));
    }

    @Test
    void failureReasonIsCollapsedToOneLine() {
        assertEquals("boom", ReplayUi.ReplayMainFrame.oneLine("boom"));
        assertEquals("first line", ReplayUi.ReplayMainFrame.oneLine("first line\nsecond line\nthird"));
        assertEquals("", ReplayUi.ReplayMainFrame.oneLine(null));
        assertEquals("", ReplayUi.ReplayMainFrame.oneLine("   "));
        String longReason = "x".repeat(400);
        String shown = ReplayUi.ReplayMainFrame.oneLine(longReason);
        assertEquals(100, shown.length(), "状态栏只放一行，过长要截断");
    }

    @Test
    void uiStatusCarriesWarningsAndLastError() {
        JSONObject json = JSON.parseObject("""
                {
                  "seq": 7,
                  "state": "RUNNING",
                  "playheadMs": 1000,
                  "warnings": [
                    {"code": "OPTION_IGNORED", "message": "inject ignored"},
                    {"code": "INJECTION_FAILED", "message": "self-check failed"}
                  ],
                  "lastError": {"code": "REPLAY_FAILED", "message": "No network interface has IP 10.0.0.1"}
                }
                """);
        ReplayUi.UiStatus status = ReplayUi.UiStatus.from(json);
        assertEquals(2, status.warnings.size());
        assertEquals("self-check failed", status.warnings.get(1));
        assertEquals("No network interface has IP 10.0.0.1", status.lastError);

        ReplayUi.UiStatus clean = ReplayUi.UiStatus.from(JSON.parseObject(
                "{\"seq\":8,\"state\":\"RUNNING\"}"));
        assertEquals(0, clean.warnings.size());
        assertNull(clean.lastError);
    }
}
