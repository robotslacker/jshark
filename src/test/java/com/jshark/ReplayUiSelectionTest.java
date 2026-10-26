package com.jshark;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Start 前本地预览的纯逻辑测试：把 {@code --start/--end}（绝对捕获时间）
 * 裁剪到数据范围。
 *
 * <p>这段逻辑只服务 UI 标签与 Start 门禁；权威值仍由子进程 {@code --inspect} 给出。
 * 单独测它，是因为它直接决定“Start 是否可点”，且不该依赖 Swing。</p>
 */
public class ReplayUiSelectionTest {

    @Test
    void fullRangeWhenNoTimeArguments() {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 9, 0, 0);
        ReplayUi.Selection selection = ReplayUi.previewSelection(start, end, "", "");
        assertNotNull(selection);
        assertEquals(start, selection.fromMs());
        assertEquals(end, selection.toMs());
        assertFalse(selection.clamped());
        assertFalse(selection.empty());
    }

    @Test
    void absoluteWindowIsClampedToDataRange() {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 9, 0, 0);
        long from = at(2026, 8, 21, 8, 10, 0);
        long to = at(2026, 8, 21, 8, 35, 0);

        ReplayUi.Selection inside = ReplayUi.previewSelection(start, end,
                "2026-08-21 08:10:00", "2026-08-21 08:35:00");
        assertEquals(from, inside.fromMs());
        assertEquals(to, inside.toMs());
        assertFalse(inside.clamped());

        ReplayUi.Selection outside = ReplayUi.previewSelection(start, end,
                "2026-08-21 07:00:00", "2026-08-21 10:00:00");
        assertEquals(start, outside.fromMs());
        assertEquals(end, outside.toMs());
        assertTrue(outside.clamped(), "超出数据范围的窗口应被裁剪");
    }

    @Test
    void openEndedWindowKeepsDataBounds() {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 9, 0, 0);
        long from = at(2026, 8, 21, 8, 20, 0);

        ReplayUi.Selection onlyStart = ReplayUi.previewSelection(start, end,
                "2026-08-21 08:20:00", "");
        assertEquals(from, onlyStart.fromMs());
        assertEquals(end, onlyStart.toMs());

        ReplayUi.Selection onlyEnd = ReplayUi.previewSelection(start, end,
                "", "2026-08-21 08:20:00");
        assertEquals(start, onlyEnd.fromMs());
        assertEquals(from, onlyEnd.toMs());
    }

    @Test
    void windowOutsideDataIsEmpty() {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 9, 0, 0);
        ReplayUi.Selection selection = ReplayUi.previewSelection(start, end,
                "2026-08-22 00:00:00", "2026-08-22 01:00:00");
        assertTrue(selection.empty(), "完全落在数据范围之外的窗口应为 empty");
    }

    @Test
    void invalidOrIncompleteTextYieldsNullPreview() {
        long start = at(2026, 8, 21, 8, 0, 0);
        long end = at(2026, 8, 21, 9, 0, 0);
        assertNull(ReplayUi.previewSelection(start, end, "not-a-time", ""));
        assertNull(ReplayUi.previewSelection(start, end, "", "1:2"));
        // 旧的相对偏移格式不再被接受
        assertNull(ReplayUi.previewSelection(start, end, "00:05:00", ""),
                "相对偏移应视为无效参数，而不是又被解释成绝对时间");
        assertNull(ReplayUi.previewSelection(null, end, "", ""), "数据范围未知时不预览");
    }

    @Test
    void absoluteTimeFormats() {
        long expected = at(2026, 8, 21, 8, 10, 0);
        assertEquals(expected, ReplayUi.parseAbsoluteTime("2026-08-21 08:10:00"));
        assertEquals(expected, ReplayUi.parseAbsoluteTime("2026-08-21T08:10:00"));
        assertEquals(expected, ReplayUi.parseAbsoluteTime("20260821081000"));
        assertEquals(expected, ReplayUi.parseAbsoluteTime("2026-08-21 08:10"));
        assertThrows(RuntimeException.class, () -> ReplayUi.parseAbsoluteTime("2026/08/21 08:10"));
    }

    @Test
    void fileRangeTrimsWindowArguments() {
        long from = at(2026, 8, 21, 8, 20, 0);
        long to = at(2026, 8, 21, 8, 35, 0);

        java.util.List<String> noChange = new java.util.ArrayList<>(
                java.util.List.of("--db", "cap.db", "--speed", "1.0"));
        assertEquals(noChange, ReplayUi.overrideTimeWindowArgs(noChange, false, false, null, null, false, false),
                "全部文件且未显式设置时间时不追加参数");

        java.util.List<String> trimmed = ReplayUi.overrideTimeWindowArgs(
                new java.util.ArrayList<>(java.util.List.of("--db", "cap.db")),
                false, false, from, to, true, true);
        assertEquals("--db", trimmed.get(0));
        assertEquals("--start", trimmed.get(2));
        assertEquals("2026-08-21 08:20:00.000", trimmed.get(3));
        assertEquals("--end", trimmed.get(4));
        assertEquals("2026-08-21 08:35:00.000", trimmed.get(5));

        // 用户显式填写的原始值先被移除，只保留按文件范围裁剪后的等效窗口
        java.util.List<String> replaced = ReplayUi.overrideTimeWindowArgs(
                new java.util.ArrayList<>(java.util.List.of(
                        "--db", "cap.db", "--start", "2026-08-21 08:00:00", "--end", "2026-08-21 09:00:00")),
                true, true, from, to, false, false);
        assertEquals("--db", replaced.get(0));
        assertEquals("--start", replaced.get(2));
        assertEquals("2026-08-21 08:20:00.000", replaced.get(3));
        assertEquals("--end", replaced.get(4));
        assertEquals("2026-08-21 08:35:00.000", replaced.get(5));

        // 自动填充的默认值不算显式参数；清空 End（unselect）时也不传 --end
        java.util.List<String> startOnly = ReplayUi.overrideTimeWindowArgs(
                new java.util.ArrayList<>(java.util.List.of("--db", "cap.db")),
                true, false, from, to, false, false);
        assertEquals("--start", startOnly.get(2));
        assertEquals("2026-08-21 08:20:00.000", startOnly.get(3));
        org.junit.jupiter.api.Assertions.assertFalse(startOnly.contains("--end"),
                "End 为空时不应向上游传递 --end（follow 模式需要继续跟随新卷）");
    }

    @Test
    void followModeDefaultsEndToEmpty() {
        long end = at(2026, 8, 21, 8, 35, 0);
        assertEquals("", ReplayUi.defaultEndText(true, end),
                "follow 模式下 End 默认必须为空，否则会停止跟随新分卷");
        assertEquals("2026-08-21 08:35:00.000", ReplayUi.defaultEndText(false, end),
                "非 follow 模式 End 默认是所选文件范围的结束时间");
    }

    @Test
    void filterSectionCollapsesAndExpands() {
        javax.swing.JPanel content = new javax.swing.JPanel();
        ReplayUi.ReplayMainFrame.CollapsibleSection section =
                new ReplayUi.ReplayMainFrame.CollapsibleSection("Filters", content);
        javax.swing.JButton toggle = section.toggleButton();
        assertFalse(content.isVisible(), "默认折叠");
        toggle.doClick();
        assertTrue(content.isVisible(), "点击标题后展开");
        toggle.doClick();
        assertFalse(content.isVisible(), "再次点击后折叠");
    }

    @Test
    void targetMappingColumnsComposeAndSplit() {
        assertEquals("", ReplayUi.composeTargetMapping("", "", "", ""),
                "四段都为空时不生成映射参数");
        assertEquals("11.0.0.1:5520-192.178.0.1:5530",
                ReplayUi.composeTargetMapping("11.0.0.1", "5520", "192.178.0.1", "5530"));
        assertEquals("11.0.0.1:*-*:*",
                ReplayUi.composeTargetMapping("11.0.0.1", "", "", ""));
        assertEquals("*:*-*:*",
                ReplayUi.composeTargetMapping("*", "*", "*", "*"),
                "四段默认 * 合并为不修改");
        assertEquals("a:1-b:2, c:3-d:4",
                ReplayUi.composeTargetMapping("a, c", "1, 3", "b, d", "2, 4"));

        String mapping = "11.0.0.1:5520-192.178.0.1:5530, *:*-192.168.0.5:*";
        String[] columns = ReplayUi.targetMappingFields(mapping);
        assertEquals("11.0.0.1, *", columns[0]);
        assertEquals("5520, *", columns[1]);
        assertEquals("192.178.0.1, 192.168.0.5", columns[2]);
        assertEquals("5530, *", columns[3]);
        assertEquals(mapping, ReplayUi.composeTargetMapping(
                columns[0], columns[1], columns[2], columns[3]),
                "拆分后合并应与原映射一致");

        String[] invalid = ReplayUi.targetMappingFields("broken");
        assertEquals("", invalid[0]);
        assertEquals("", invalid[1]);
        assertEquals("", invalid[2]);
        assertEquals("", invalid[3]);
    }

    @Test
    void injectInterfaceCandidateExtractsIp() {
        assertEquals("192.168.1.20",
                ReplayUi.ReplayMainFrame.ipFromInjectText("192.168.1.20  (Ethernet 2)"));
        assertEquals("10.0.0.5",
                ReplayUi.ReplayMainFrame.ipFromInjectText("10.0.0.5"));
        assertEquals("", ReplayUi.ReplayMainFrame.ipFromInjectText(" "));
    }

    @Test
    void windowIconResourcesExist() {
        for (int size : new int[]{16, 32, 64}) {
            assertNotNull(ReplayUi.class.getResource("/com/jshark/replay-icon-" + size + ".png"),
                    "缺少 replay-icon-" + size + ".png");
        }
    }

    private static long at(int y, int mo, int d, int h, int mi, int s) {
        return LocalDateTime.of(y, mo, d, h, mi, s)
                .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }
}
