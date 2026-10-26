package com.jshark;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;

/**
 * 三个 Swing 界面拉起"headless 子进程"时的命令拼装。
 *
 * <h3>为什么不用 {@code -jar}</h3>
 * <p>
 * 三个可执行 jar 的 Main-Class 分别是 {@code CliShark}/{@code CliReplay}/{@code CliForwarder}，
 * 但类都在同一个 uber jar 里。如果从 capture jar 里跑 {@code CliReplay --ui}，{@code -jar}
 * 会启动错误的主类（CliShark）。因此这里统一用"显式主类"启动：
 * </p>
 * <ul>
 *   <li>Spring Boot 可执行 jar：{@code -cp <jar> PropertiesLauncher -Dloader.main=<main>}；</li>
 *   <li>普通 jar：{@code -cp <jar> <main>}；</li>
 *   <li>开发模式（classes 目录）：{@code -cp <java.class.path> <main>}。</li>
 * </ul>
 *
 * <p>Windows 上优先用 {@code javaw.exe}，避免每个 UI 子进程都弹一个控制台窗口。</p>
 */
final class UiLauncher {

    private UiLauncher() {
    }

    /**
     * 为界面子进程拼装命令（不含业务参数）。
     *
     * @param anchor    用于推断当前 jar 的类（{@code CliShark.class} 等）
     * @param mainClass 子进程主类全名
     * @param args      业务参数（原样追加在末尾）
     * @return 完整命令
     */
    static List<String> command(Class<?> anchor, String mainClass, List<String> args) {
        return command(mainClass, args, CliRuntime.resolveJarPath(anchor));
    }

    /**
     * 显式指定 jar 的命令拼装（便于单测喂假路径）。
     *
     * @param mainClass 主类全名
     * @param args      业务参数
     * @param jar       jar 路径；null 表示开发模式
     * @return 完整命令
     */
    static List<String> command(String mainClass, List<String> args, String jar) {
        String launcher = jar == null ? null : springBootLauncher(jar, mainClass);
        return command(mainClass, args, jar, launcher);
    }

    /**
     * 命令拼装本体。
     *
     * @param mainClass 主类全名
     * @param args      业务参数
     * @param jar       jar 路径；null 表示开发模式
     * @param launcher  Spring Boot {@code PropertiesLauncher} 类名；null 表示普通 jar/开发模式
     * @return 完整命令
     */
    static List<String> command(String mainClass, List<String> args, String jar, String launcher) {
        List<String> cmd = new ArrayList<>();
        cmd.add(javaExecutable());
        cmd.add("-Djava.awt.headless=true");
        cmd.add("-Dfile.encoding=UTF-8");
        if (launcher != null) {
            cmd.add("-Dloader.main=" + mainClass);
            cmd.add("-cp");
            cmd.add(jar);
            cmd.add(launcher);
        } else if (jar != null) {
            cmd.add("-cp");
            cmd.add(jar);
            cmd.add(mainClass);
        } else {
            String classpath = System.getProperty("java.class.path");
            if (classpath == null || classpath.isBlank()) {
                throw new IllegalStateException(
                        "Cannot start UI child process: java.class.path is unavailable in dev mode");
            }
            cmd.add("-cp");
            cmd.add(classpath);
            cmd.add(mainClass);
        }
        cmd.addAll(args);
        return cmd;
    }

    /**
     * 判断 {@code jarPath} 是不是包含指定主类的 Spring Boot 可执行 jar；是则返回与之匹配的
     * {@code PropertiesLauncher} 类名（兼容 Boot 3.2 前后两种包名），否则返回 null。
     *
     * @param jarPath   jar 路径
     * @param mainClass 主类全名
     * @return launcher 类名；不是 Boot jar/读不了 jar 返回 null
     */
    static String springBootLauncher(String jarPath, String mainClass) {
        Path path = Path.of(jarPath);
        if (!Files.isRegularFile(path)) {
            return null;
        }
        try (JarFile jar = new JarFile(path.toFile())) {
            if (jar.getEntry("BOOT-INF/classes/" + mainClass.replace('.', '/') + ".class") == null) {
                return null;
            }
            if (jar.getEntry("org/springframework/boot/loader/launch/PropertiesLauncher.class") != null) {
                return "org.springframework.boot.loader.launch.PropertiesLauncher";
            }
            if (jar.getEntry("org/springframework/boot/loader/PropertiesLauncher.class") != null) {
                return "org.springframework.boot.loader.PropertiesLauncher";
            }
        } catch (IOException ignored) {
            // 读不了 jar 就退回普通类路径启动
        }
        return null;
    }

    private static String javaExecutable() {
        Path bin = Path.of(System.getProperty("java.home"), "bin");
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (windows) {
            Path javaw = bin.resolve("javaw.exe");
            if (Files.isRegularFile(javaw)) {
                return javaw.toString();
            }
            return bin.resolve("java.exe").toString();
        }
        return bin.resolve("java").toString();
    }
}
