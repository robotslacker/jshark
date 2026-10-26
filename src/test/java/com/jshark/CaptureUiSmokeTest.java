package com.jshark;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.GraphicsEnvironment;
import java.util.concurrent.CountDownLatch;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 采集 UI 的构造冒烟测试：按生产主题（Metal + 深色）建窗，确认布局/组件初始化不抛异常，
 * 然后 dispose。窗口不 setVisible，无头环境自动跳过。
 */
public class CaptureUiSmokeTest {

    @Test
    void frameBuildsWithProductionTheme() throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            return;   // 无头环境：JFrame 无法构造，跳过
        }
        CountDownLatch latch = new CountDownLatch(1);
        final Throwable[] failure = new Throwable[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                CaptureUi.installTheme(true);
                CaptureUi.CaptureFrame frame = new CaptureUi.CaptureFrame(latch);
                frame.setSize(1180, 800);
                frame.addNotify();
                frame.validate();
                assertTrue(frame.getContentPane().getComponentCount() >= 3,
                        "根面板应包含 header / tabs / player 三块");
                assertTrue(frame.getContentPane().getPreferredSize().height < 1_400,
                        "布局不应无限拉伸");
                assertTrue(frame.getTitle().contains("Capture"));
                frame.dispose();
            } catch (Throwable t) {
                failure[0] = t;
            }
        });
        if (failure[0] != null) {
            throw new AssertionError("capture UI construction failed", failure[0]);
        }
        // 注：窗口从未 setVisible，dispose 不保证派发 windowClosed；这里只验证构造/释放不抛异常。
    }
}
