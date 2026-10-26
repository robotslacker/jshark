package com.jshark;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.GraphicsEnvironment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 转发器 UI 构造冒烟：按生产主题建窗，确认面板能装配，然后 dispose。
 */
public class ForwarderUiSmokeTest {

    @Test
    void childCommandUsesExplicitForwarderMainClass() {
        List<String> cmd = ForwarderUi.ForwarderProcess.buildCommand(
                List.of("--udpaddr", "224.3.0.0:3000", "--udpif", "192.168.1.0/24",
                        "--port", "3001", "--peer", "10.10.1.100:3001"));
        assertTrue(cmd.contains("com.jshark.CliForwarder"), cmd.toString());
        assertFalse(cmd.contains("-jar"), "不能依赖 jar 的 Main-Class（主 jar 是 CliShark）");
        assertTrue(cmd.contains("-cp"), cmd.toString());
        assertTrue(cmd.contains("--control") && cmd.contains("stdio"), cmd.toString());
    }

    @Test
    void bootJarChildGoesThroughPropertiesLauncher() {
        // Spring Boot 可执行 jar 的类在 BOOT-INF/classes 下，`-cp jar 主类` 会
        // ClassNotFoundException；必须让 PropertiesLauncher 按 loader.main 启动。
        List<String> cmd = ForwarderUi.ForwarderProcess.buildCommand(
                List.of("--udpaddr", "224.3.0.0:3000"),
                "C:\\apps\\jshark-1.0.0-udpforwarder.jar",
                "org.springframework.boot.loader.launch.PropertiesLauncher");

        assertTrue(cmd.contains("-Dloader.main=com.jshark.CliForwarder"), cmd.toString());
        assertTrue(cmd.contains("org.springframework.boot.loader.launch.PropertiesLauncher"), cmd.toString());
        assertTrue(cmd.contains("C:\\apps\\jshark-1.0.0-udpforwarder.jar"), cmd.toString());
        assertFalse(cmd.contains("-jar"), cmd.toString());
        assertEquals("--control", cmd.get(cmd.size() - 2), cmd.toString());
        assertEquals("stdio", cmd.get(cmd.size() - 1), cmd.toString());
    }

    @Test
    void detectsSpringBootJarLayout() throws Exception {
        Path bootJar = Files.createTempFile("jshark-boot", ".jar");
        try {
            try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(bootJar))) {
                out.putNextEntry(new JarEntry("BOOT-INF/classes/com/jshark/CliForwarder.class"));
                out.closeEntry();
                out.putNextEntry(new JarEntry(
                        "org/springframework/boot/loader/launch/PropertiesLauncher.class"));
                out.closeEntry();
            }
            assertEquals("org.springframework.boot.loader.launch.PropertiesLauncher",
                    ForwarderUi.ForwarderProcess.springBootLauncher(bootJar.toString()));

            Path plainJar = Files.createTempFile("jshark-plain", ".jar");
            try {
                try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(plainJar))) {
                    out.putNextEntry(new JarEntry("com/jshark/CliForwarder.class"));
                    out.closeEntry();
                }
                assertNull(ForwarderUi.ForwarderProcess.springBootLauncher(plainJar.toString()),
                        "普通 jar 不应走 PropertiesLauncher");
            } finally {
                Files.deleteIfExists(plainJar);
            }
        } finally {
            Files.deleteIfExists(bootJar);
        }
    }

    @Test
    void dropRateFormatting() {
        assertEquals("—", UiFormat.formatDropRate(0, 0));
        assertEquals("0.00%", UiFormat.formatDropRate(0, 100));
        assertEquals("<0.01%", UiFormat.formatDropRate(1, 100_000));
        assertEquals("1.00%", UiFormat.formatDropRate(1, 100));
    }

    @Test
    void frameBuilds() throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            return;
        }
        CountDownLatch latch = new CountDownLatch(1);
        Throwable[] failure = new Throwable[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                ForwarderUi.installTheme(true);
                ForwarderUi.ForwarderFrame frame = new ForwarderUi.ForwarderFrame(latch);
                assertTrue(frame.getContentPane().getComponentCount() >= 3,
                        "根面板应包含 header / tabs / player");
                assertTrue(frame.getTitle().contains("Forwarder"));
                assertFalse(frame.getIconImages().isEmpty(), "窗口应带 JShark 图标（同采集/重放）");
                frame.dispose();
            } catch (Throwable t) {
                failure[0] = t;
            }
        });
        if (failure[0] != null) {
            throw new AssertionError("forwarder UI construction failed", failure[0]);
        }
    }
}
