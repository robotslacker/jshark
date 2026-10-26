package com.jshark;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.swing.JComboBox;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * UI 的模式可用性：payload 捕获的数据库（没有 {@code frameData}）不能选 frame。
 *
 * <h3>为什么需要它</h3>
 * <p>以前无论数据源是什么，下拉框都提供 frame。用户选中后重放会先打开网卡、跑注入自检，
 * 然后才在第一个分卷上因为“没有 frameData 列”失败——白等一场，还容易误判成库损坏。
 * 现在由 {@code --inspect} 判定帧能力，UI 把不可用的选项去掉，并<b>显式</b>下发
 * {@code --replayMode payload}（默认模式本身就是 payload，显式下发保证与 UI 展示一致）。</p>
 *
 * <p>需要桌面环境的用例在 headless 下自动跳过；纯逻辑用例在任何环境都跑。</p>
 */
public class ReplayUiSourceModeTest {

    // ==================== 纯逻辑：模式参数的显式下发 ====================

    @Test
    void replayModeArgsAreExplicitOnlyWhenNeeded() {
        assertEquals(List.of(), ReplayUi.ReplayMainFrame.replayModeArgs(false, false, "frame"),
                "用户没选模式、数据源也没限制时不传 --replayMode（保持 CLI 默认语义：payload）");
        assertEquals(List.of("--replayMode", "frame"),
                ReplayUi.ReplayMainFrame.replayModeArgs(true, false, "frame"));
        assertEquals(List.of("--replayMode", "payload"),
                ReplayUi.ReplayMainFrame.replayModeArgs(true, false, "payload"));

        // payload-only 数据源：即便用户从未选过模式，也必须显式下发 payload。
        // UI 默认会填 --injectInterface，少传 mode 时 CLI 会解析成 frame（不可用）。
        assertEquals(List.of("--replayMode", "payload"),
                ReplayUi.ReplayMainFrame.replayModeArgs(false, true, "payload"));
        assertEquals(List.of("--replayMode", "payload"),
                ReplayUi.ReplayMainFrame.replayModeArgs(true, true, "payload"));
    }

    @Test
    void inspectionParsesFrameCapabilityAndFileFlags() {
        JSONObject json = JSON.parseObject("""
                {
                  "summary": {"replayableCount": 2, "dataStartMs": 1, "dataEndMs": 2,
                              "durationMs": 1, "live": false, "waiting": false},
                  "source": {"kind": "db", "followSupported": true, "frameCapable": false,
                             "frameVolumes": 0, "payloadOnlyVolumes": 2},
                  "files": [{"name": "a.db", "hasFrames": false},
                            {"name": "b.db", "hasFrames": null}]
                }
                """);

        ReplayUi.Inspection inspection = ReplayUi.Inspection.from(json);
        assertEquals(Boolean.FALSE, inspection.frameCapable);
        assertEquals(0, inspection.frameVolumes);
        assertEquals(2, inspection.payloadOnlyVolumes);
        assertEquals(Boolean.FALSE, inspection.files.get(0).hasFrames);
        assertNull(inspection.files.get(1).hasFrames, "null 表示空卷/未知，不能被当成 false");
    }

    // ==================== 真窗口：下拉项随数据源能力变化 ====================

    @Test
    void payloadOnlySourceRemovesFrameOption() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 组件状态");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            JComboBox<?> mode = onEdt(() -> findModeCombo(frame));
            assertEquals(List.of("frame", "payload"), items(mode), "默认两种模式都可选");

            onEdt(() -> {
                frame.applyModeAvailability(false);
                return null;
            });
            assertEquals(List.of("payload"), items(mode),
                    "payload 捕获的数据源上 frame 必须从下拉项中消失");
            assertEquals("payload", mode.getSelectedItem());

            onEdt(() -> {
                frame.applyModeAvailability(true);
                return null;
            });
            assertEquals(List.of("frame", "payload"), items(mode), "换回带帧的数据源后 frame 恢复");
            assertEquals("payload", mode.getSelectedItem(),
                    "之前的 payload 是替用户选的（不是用户意图），恢复后回到默认 payload");
        } finally {
            closeFrame(frame);
        }
    }

    @Test
    void unknownCapabilityKeepsBothOptions() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 组件状态");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            JComboBox<?> mode = onEdt(() -> findModeCombo(frame));

            onEdt(() -> {
                frame.applyModeAvailability(false);
                return null;
            });
            // 换源/清空检查结果：能力未知时不能继续限制用户。
            onEdt(() -> {
                frame.applyModeAvailability(null);
                return null;
            });
            assertEquals(List.of("frame", "payload"), items(mode));
            assertEquals("payload", mode.getSelectedItem());
        } finally {
            closeFrame(frame);
        }
    }

    // ==================== 建窗/关窗 ====================

    private static ReplayUi.ReplayMainFrame showFrame() throws Exception {
        AtomicReference<ReplayUi.ReplayMainFrame> holder = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ReplayUi.installTheme(true);
            ReplayUi.ReplayMainFrame frame = new ReplayUi.ReplayMainFrame(new String[]{"--ui"});
            holder.set(frame);
            frame.setVisible(true);
            // prefill 会顺手起一次 400ms 的检查防抖：源为空时它会把顶部提示改成
            // “Pick a source first”，让依赖标签文本的断言变得不确定。这里直接停掉，
            // 这些用例本来就不需要真的去检查数据源。
            stopTimers(frame);
        });
        SwingUtilities.invokeAndWait(() -> {
        });
        return holder.get();
    }

    private static void closeFrame(ReplayUi.ReplayMainFrame frame) throws Exception {
        onEdt(() -> {
            stopTimers(frame);
            frame.dispose();
            return null;
        });
    }

    /** Timer 会一直往 EDT 上投任务；不停掉的话测试 JVM 可能迟迟不退出。 */
    private static void stopTimers(ReplayUi.ReplayMainFrame frame) {
        for (String name : new String[]{"logTimer", "inspectDebounce", "inspectTimeout",
                "replayStartWatchdog"}) {
            try {
                java.lang.reflect.Field field = frame.getClass().getDeclaredField(name);
                field.setAccessible(true);
                Object value = field.get(frame);
                if (value instanceof Timer timer) {
                    timer.stop();
                }
            } catch (ReflectiveOperationException ignored) {
                // 字段改名/不存在时不影响结论。
            }
        }
    }

    private static <T> T onEdt(Callable<T> callable) throws Exception {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                result.set(callable.call());
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        Throwable error = failure.get();
        if (error instanceof Error e) {
            throw e;
        }
        if (error instanceof Exception e) {
            throw e;
        }
        if (error != null) {
            throw new AssertionError(error);
        }
        return result.get();
    }

    private static JComboBox<?> findModeCombo(Component c) {
        JComboBox<?> found = findModeComboOrNull(c);
        if (found == null) {
            throw new AssertionError("找不到模式下拉框");
        }
        return found;
    }

    private static JComboBox<?> findModeComboOrNull(Component c) {
        if (c instanceof JComboBox<?> combo && combo.getItemCount() > 0
                && ("frame".equals(combo.getItemAt(0)) || "payload".equals(combo.getItemAt(0)))) {
            return combo;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                JComboBox<?> found = findModeComboOrNull(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static List<String> items(JComboBox<?> combo) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < combo.getItemCount(); i++) {
            out.add(String.valueOf(combo.getItemAt(i)));
        }
        return out;
    }

    // ==================== 真窗口：加载指示 ====================

    @Test
    void loadingIndicatorIsVisibleWhileInspecting() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 组件状态");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            JProgressBar bar = onEdt(() -> findProgressBar(frame));
            assertFalse(bar.isVisible(), "静止状态下不显示加载条");

            onEdt(() -> {
                frame.showLoading("Loading cap.db…");
                return null;
            });
            assertTrue(bar.isVisible(), "检查数据源时必须显示加载指示，否则用户会以为卡死");
            assertTrue(bar.isIndeterminate(), "尚未拿到分卷数时用滚动动画证明“在干活”");
            assertEquals("Loading cap.db…", onEdt(() -> findLabelText(frame, "Loading cap.db…")));

            onEdt(() -> {
                frame.updateLoading(2, 5, 0);
                return null;
            });
            assertFalse(bar.isIndeterminate(), "有分卷计数后应显示确定进度");
            assertEquals(2, bar.getValue());
            assertEquals(5, bar.getMaximum());
            assertNotNull(onEdt(() -> findLabelText(frame, "Loading cap.db… · 2/5 volumes")));

            // PCAP 没有“总数”，但已读包数在动：同样是“没卡死”的证据。
            onEdt(() -> {
                frame.showLoading("Loading capture.pcap…");
                frame.updateLoading(0, 0, 12345);
                return null;
            });
            assertTrue(bar.isIndeterminate());
            assertNotNull(onEdt(() -> findLabelText(frame, "Loading capture.pcap… · 12,345 packets scanned")));

            onEdt(() -> {
                frame.hideLoading();
                return null;
            });
            assertFalse(bar.isVisible(), "检查结束/失败后必须收起加载条");
            assertNull(onEdt(() -> findLabelText(frame, "Loading cap.db…")));
        } finally {
            closeFrame(frame);
        }
    }

    @Test
    void seekLoadingStaysUntilTheNewSegmentStarts() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 组件状态");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            JProgressBar bar = onEdt(() -> findProgressBar(frame));
            long target = System.currentTimeMillis();
            String beforeSeek = onEdt(() -> inspectLabelText(frame));

            onEdt(() -> {
                frame.beginSeekLoading(target, 7L);
                return null;
            });
            assertTrue(bar.isVisible(), "拖动进度条后必须显示加载态");
            assertTrue(onEdt(() -> inspectLabelText(frame)).startsWith("Seeking to "),
                    "加载态应说明正在定位到哪里");

            // ack 之前的旧状态（seeking=false）不能让它提前收起。
            onEdt(() -> {
                frame.onSeekStatus(false, 10, 5, false);
                return null;
            });
            assertTrue(bar.isVisible(), "命令还没被接受时，旧状态的 seeking=false 不算数");

            // 其它命令的 ack 与这次 seek 无关。
            onEdt(() -> {
                frame.onSeekAck(8L, true);
                return null;
            });
            assertTrue(bar.isVisible(), "别的命令的 ack 不能收起 seek 的加载态");

            // 本条 seek 被接受：仍要等新段真的开始读数据。
            onEdt(() -> {
                frame.onSeekAck(7L, true);
                return null;
            });
            assertTrue(bar.isVisible(), "ack 只代表命令被接受，进度还没切换完");
            onEdt(() -> {
                frame.onSeekStatus(true, 10, 5, false);
                return null;
            });
            assertTrue(bar.isVisible(), "seeking=true 期间必须继续显示");

            // 子进程先报 seeking=false（此时才开始打开新段，大 PCAP 还在跳过前导数据），
            // 这条只作为基线。
            onEdt(() -> {
                frame.onSeekStatus(false, 10, 5, false);
                return null;
            });
            assertTrue(bar.isVisible(), "新段刚开始重开（计数未增长）时不能收起");
            onEdt(() -> {
                frame.onSeekStatus(false, 10, 5, false);
                return null;
            });
            assertTrue(bar.isVisible(), "计数没动说明数据还没流起来");

            // 计数增长 = 新段真的开始读了：这才是“进度完全切换完成”。
            onEdt(() -> {
                frame.onSeekStatus(false, 11, 5, false);
                return null;
            });
            assertFalse(bar.isVisible(), "新段开始读数据后才收起");
            assertEquals(beforeSeek, onEdt(() -> inspectLabelText(frame)),
                    "收起后要恢复被“Seeking…”覆盖的检查摘要");
        } finally {
            closeFrame(frame);
        }
    }

    @Test
    void rejectedOrSupersededSeekStillClearsLoading() throws Exception {
        Assumptions.assumeFalse(GraphicsEnvironment.isHeadless(),
                "需要桌面环境才能验证 Swing 组件状态");
        ReplayUi.ReplayMainFrame frame = showFrame();
        try {
            JProgressBar bar = onEdt(() -> findProgressBar(frame));
            long target = System.currentTimeMillis();

            // 子进程拒绝 seek（例如已经播完）：加载态必须立刻收起，不能永远挂着。
            onEdt(() -> {
                frame.beginSeekLoading(target, 9L);
                return null;
            });
            assertTrue(bar.isVisible());
            onEdt(() -> {
                frame.onSeekAck(9L, false);
                return null;
            });
            assertFalse(bar.isVisible(), "被拒绝的 seek 不能留下加载态");

            // 连续拖动：只认最后一条 seek 的 ack，且仍要等它切换完成。
            onEdt(() -> {
                frame.beginSeekLoading(target, 10L);
                frame.beginSeekLoading(target, 11L);
                return null;
            });
            assertTrue(bar.isVisible());
            onEdt(() -> {
                frame.onSeekAck(10L, true);
                return null;
            });
            assertTrue(bar.isVisible(), "旧 seek 的 ack 不应收起新的加载态");
            onEdt(() -> {
                frame.onSeekAck(11L, true);
                frame.onSeekStatus(false, 30, 7, false);
                return null;
            });
            assertTrue(bar.isVisible(), "第 11 条 seek 的基线状态，还不能收起");
            onEdt(() -> {
                frame.onSeekStatus(false, 31, 7, false);
                return null;
            });
            assertFalse(bar.isVisible(), "最后一条 seek 切换完成后收起");

            // LIVE：新段打开后在等新分卷数据，同样算切换完成（否则会永远转圈）。
            onEdt(() -> {
                frame.beginSeekLoading(target, 12L);
                frame.onSeekAck(12L, true);
                frame.onSeekStatus(false, 40, 8, true);
                return null;
            });
            assertFalse(bar.isVisible(), "LIVE 等待新数据时也要收起");
        } finally {
            closeFrame(frame);
        }
    }

    /** 读取顶部“检查摘要”标签的实际文本（私有字段，只用于断言加载态覆盖/恢复）。 */
    private static String inspectLabelText(ReplayUi.ReplayMainFrame frame) {
        try {
            java.lang.reflect.Field field = frame.getClass().getDeclaredField("inspectLabel");
            field.setAccessible(true);
            return ((javax.swing.JLabel) field.get(frame)).getText();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static JProgressBar findProgressBar(Component c) {
        if (c instanceof JProgressBar bar) {
            return bar;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                JProgressBar found = findProgressBar(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static String findLabelText(Component c, String text) {
        if (c instanceof javax.swing.JLabel label && text.equals(label.getText())) {
            return text;
        }
        if (c instanceof Container container) {
            for (Component child : container.getComponents()) {
                String found = findLabelText(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    @Test
    void statusTextMarksPayloadOnlyVolumesAsInformational() {
        ReplayUi.FileRow payloadOnly = new ReplayUi.FileRow();
        payloadOnly.status = "ok";
        payloadOnly.hasFrames = false;
        ReplayUi.FileRow frameRow = new ReplayUi.FileRow();
        frameRow.status = "ok";
        frameRow.hasFrames = true;

        String text = ReplayUi.ReplayMainFrame.statusText(payloadOnly);
        assertEquals("Payload only (no frame data)", text);
        assertTrue(ReplayUi.ReplayMainFrame.informationalStatus(text),
                "这条说明不能被渲染成失败色");
        assertEquals("", ReplayUi.ReplayMainFrame.statusText(frameRow),
                "带帧的正常卷不该多出一条说明");
        assertFalse(ReplayUi.ReplayMainFrame.informationalStatus("Read error: boom"));
    }
}
