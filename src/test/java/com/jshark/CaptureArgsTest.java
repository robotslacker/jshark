package com.jshark;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 采集 UI 的纯逻辑验收：表单 → 命令行参数、分卷/组播校验、显示格式化。
 *
 * <p>不创建窗口，因此无头环境也能跑。</p>
 */
public class CaptureArgsTest {

    /** 只开 Log DB 的最小表单。 */
    private static CaptureUi.CaptureForm minimal() {
        return new CaptureUi.CaptureForm("192.168.1.100", "", "", false,
                false, false, "", true, "C:\\captures\\dis.db",
                false, "", "", 1, "", "");
    }

    @Test
    void minimalFormMapsToIpAndLogDb() {
        List<String> args = CaptureUi.buildArgs(minimal());
        assertEquals(List.of("--ip_address", "192.168.1.100", "--logdb", "C:\\captures\\dis.db"), args,
                "最小表单只应产出 IP 与 Log DB");
    }

    @Test
    void fullFormMapsEveryOption() {
        CaptureUi.CaptureForm f = new CaptureUi.CaptureForm(
                "10.0.0.5", "udp port 3000", "dis.pdu.type=28", true,
                true, true, "224.3.0.0, 224.3.0.1", true, "C:\\cap\\a.db",
                true, "C:\\cap\\a.pcap", "5m", 4, "128", "C:\\cap\\a.log");
        List<String> args = CaptureUi.buildArgs(f);
        assertEquals(List.of(
                "--ip_address", "10.0.0.5",
                "--filter", "udp port 3000",
                "--exfilter", "dis.pdu.type=28",
                "--enable_additioninfo=true",
                "--promiscuous",
                "--immediate",
                "--multicast", "224.3.0.0",
                "--multicast", "224.3.0.1",
                "--logdb", "C:\\cap\\a.db",
                "--pcapoutput", "C:\\cap\\a.pcap",
                "--split", "5m",
                "--parse-threads", "4",
                "--pcap-buffer", "128",
                "--logfile", "C:\\cap\\a.log"), args);
    }

    @Test
    void outputIsRequired() {
        CaptureUi.CaptureForm f = new CaptureUi.CaptureForm("10.0.0.5", "", "", false,
                false, false, "", false, "", false, "", "", 1, "", "");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> CaptureUi.buildArgs(f));
        assertTrue(e.getMessage().contains("at least one output"), e.getMessage());
    }

    @Test
    void enabledOutputRequiresPath() {
        CaptureUi.CaptureForm blankLogDb = new CaptureUi.CaptureForm("10.0.0.5", "", "", false,
                false, false, "", true, "  ", false, "", "", 1, "", "");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> CaptureUi.buildArgs(blankLogDb)).getMessage().contains("Log DB"));

        CaptureUi.CaptureForm blankPcap = new CaptureUi.CaptureForm("10.0.0.5", "", "", false,
                false, false, "", false, "", true, "", "", 1, "", "");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> CaptureUi.buildArgs(blankPcap)).getMessage().contains("PCAP"));
    }

    @Test
    void ipIsRequired() {
        CaptureUi.CaptureForm f = new CaptureUi.CaptureForm(" ", "", "", false,
                false, false, "", true, "a.db", false, "", "", 1, "", "");
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> CaptureUi.buildArgs(f)).getMessage().contains("interface IP"));
    }

    @Test
    void splitIsOptional() {
        List<String> args = CaptureUi.buildArgs(minimal());
        assertFalse(args.contains("--split"), "空 Split 表示单文件，不应下发参数");
    }

    @Test
    void splitAcceptsMinutesHoursDays() {
        assertEquals(List.of(), acceptSplit("1m"));
        assertEquals(List.of(), acceptSplit("5m"));
        assertEquals(List.of(), acceptSplit("1h"));
        assertEquals(List.of(), acceptSplit("2d"));
    }

    @Test
    void splitRejectsBadValues() {
        for (String bad : new String[]{"5", "0m", "0h", "m", "5 s", "-1m", "abc", "1w"}) {
            assertThrows(IllegalArgumentException.class, () -> CaptureUi.validateSplit(bad),
                    "应拒绝 " + bad);
        }
    }

    /** 只做校验、返回空列表，方便表驱动断言。 */
    private static List<String> acceptSplit(String split) {
        CaptureUi.validateSplit(split);
        return List.of();
    }

    @Test
    void multicastSplitsAndValidates() {
        assertEquals(List.of("224.3.0.0", "224.3.0.1"),
                CaptureUi.multicastGroups("224.3.0.0, 224.3.0.1"));
        assertEquals(List.of(), CaptureUi.multicastGroups("  "));
        assertThrows(IllegalArgumentException.class, () -> CaptureUi.multicastGroups("999.1.1.1"));
        assertThrows(IllegalArgumentException.class, () -> CaptureUi.multicastGroups("224.3.0"));
    }

    @Test
    void parseDetailsIsExplicitTrue() {
        CaptureUi.CaptureForm f = new CaptureUi.CaptureForm("10.0.0.5", "", "", true,
                false, false, "", true, "a.db", false, "", "", 1, "", "");
        assertTrue(CaptureUi.buildArgs(f).contains("--enable_additioninfo=true"),
                "Parse details 必须显式下发 =true");
    }

    @Test
    void expressionImpliesParseDetails() {
        CaptureUi.CaptureForm f = new CaptureUi.CaptureForm("10.0.0.5", "", "dis.pdu.type=28", false,
                false, false, "", true, "a.db", false, "", "", 1, "", "");
        List<String> args = CaptureUi.buildArgs(f);
        assertTrue(args.contains("--exfilter"), "Expression 必须下发 --exfilter");
        assertTrue(args.contains("--enable_additioninfo=true"),
                "--exfilter 隐含开启 --enable_additioninfo");
        assertFalse(args.contains("--exfilter-unmatched"), "不再下发 --exfilter-unmatched");
    }

    @Test
    void parseThreadsOneIsOmitted() {
        assertFalse(CaptureUi.buildArgs(minimal()).contains("--parse-threads"),
                "默认 1 线程不必下发");
    }

    @Test
    void formattingHelpers() {
        assertEquals("00:00:00", UiFormat.formatElapsed(0));
        assertEquals("00:12:34", UiFormat.formatElapsed((12 * 60 + 34) * 1000L));
        assertEquals("1,234,567", UiFormat.formatCount(1_234_567));
        assertEquals("0 B", UiFormat.formatBytes(0));
        assertEquals("1.0 KB", UiFormat.formatBytes(1024));
        assertEquals("1.5 MB", UiFormat.formatBytes(1024 * 1536));
        assertEquals("—", UiFormat.formatWindow(0, 0));
    }
}
