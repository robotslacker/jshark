package com.jshark;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 界面子进程启动命令：必须显式指定主类（不能用 {@code -jar}），Spring Boot jar 走
 * {@code PropertiesLauncher}，普通 jar/开发模式走 {@code -cp}。
 */
class UiLauncherTest {

    private static Path bootJar(String mainClass) throws Exception {
        Path jar = Files.createTempFile("jshark-boot", ".jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
            out.putNextEntry(new JarEntry("BOOT-INF/classes/"
                    + mainClass.replace('.', '/') + ".class"));
            out.closeEntry();
            out.putNextEntry(new JarEntry(
                    "org/springframework/boot/loader/launch/PropertiesLauncher.class"));
            out.closeEntry();
        }
        return jar;
    }

    @Test
    void bootJarGoesThroughPropertiesLauncherWithExplicitMain() throws Exception {
        Path jar = bootJar("com.jshark.CliReplay");
        try {
            List<String> cmd = UiLauncher.command("com.jshark.CliReplay",
                    List.of("--db", "x.db"), jar.toString());
            assertTrue(cmd.contains("-Dloader.main=com.jshark.CliReplay"), cmd.toString());
            assertTrue(cmd.contains("org.springframework.boot.loader.launch.PropertiesLauncher"));
            assertFalse(cmd.contains("-jar"), "不能依赖 jar 的 Main-Class");
            assertTrue(cmd.indexOf("--db") < cmd.indexOf("x.db"), "业务参数应原样追加");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    @Test
    void plainJarUsesClasspathAndExplicitMain() throws Exception {
        Path jar = Files.createTempFile("jshark-plain", ".jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
            out.putNextEntry(new JarEntry("com/jshark/CliShark.class"));
            out.closeEntry();
        }
        try {
            List<String> cmd = UiLauncher.command("com.jshark.CliShark", List.of(), jar.toString());
            assertTrue(cmd.contains("-cp"), cmd.toString());
            assertTrue(cmd.contains(jar.toString()));
            assertEquals("com.jshark.CliShark", cmd.get(cmd.size() - 1), cmd.toString());
            assertFalse(cmd.contains("-jar"), cmd.toString());
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    @Test
    void devModeUsesJavaClasspath() {
        List<String> cmd = UiLauncher.command("com.jshark.CliForwarder", List.of(), null);
        assertTrue(cmd.contains("-cp"), cmd.toString());
        assertTrue(cmd.contains(System.getProperty("java.class.path")), cmd.toString());
        assertEquals("com.jshark.CliForwarder", cmd.get(cmd.size() - 1), cmd.toString());
    }
}
