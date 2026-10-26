package com.jshark;

import javax.imageio.ImageIO;
import javax.swing.JDialog;
import javax.swing.JFrame;
import java.awt.Image;
import java.awt.Window;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * 三个 UI（采集 / 重放 / 转发）共用的 JShark 窗口图标。
 *
 * <p>图标资源沿用 {@code /com/jshark/replay-icon-{16,32,64}.png}：多尺寸一起交给
 * {@link Window#setIconImages}，由系统按标题栏/任务栏/Alt-Tab 自行选最合适的一张。</p>
 */
final class UiIcons {

    private UiIcons() {
    }

    static void apply(Window window) {
        if (window == null) {
            return;
        }
        List<Image> icons = new ArrayList<>();
        for (int size : new int[]{16, 32, 64}) {
            String resource = "/com/jshark/replay-icon-" + size + ".png";
            try (InputStream in = UiIcons.class.getResourceAsStream(resource)) {
                if (in != null) {
                    Image image = ImageIO.read(in);
                    if (image != null) {
                        icons.add(image);
                    }
                }
            } catch (Exception ignored) {
                // 缺图标不能影响 UI 启动。
            }
        }
        if (icons.isEmpty()) {
            return;
        }
        if (window instanceof JFrame frame) {
            frame.setIconImages(icons);
        } else if (window instanceof JDialog dialog) {
            dialog.setIconImages(icons);
        }
    }
}
