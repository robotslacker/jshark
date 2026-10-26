package com.jshark.forwarder;

import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

/**
 * 把 CLI/UI 的字符串参数翻译成转发器，并做统一的必填/格式校验。
 *
 * <p>与重放/采集一样，参数错误以 {@link IllegalArgumentException} 抛出（消息可直接展示），
 * 由调用方决定打印帮助还是走控制通道的 FAILED。</p>
 */
public final class ForwarderFactory {

    private ForwarderFactory() {
    }

    /**
     * 构建结果。
     *
     * @param source 可运行、可停止、可快照的转发器
     */
    public record Built(String mode, ForwarderStatus.Source source) {
    }

    public static Built create(Map<String, String> opts, Logger logger) {
        // 转发器仅支持 bridge 模式，不再读取 --mode。
        return new Built("bridge", bridge(opts, logger));
    }

    // ==================== bridge ====================

    private static ForwarderStatus.Source bridge(Map<String, String> opts, Logger logger) {
        HostPort localUdp = hostPort(require(opts, "udpaddr"), "--udpaddr");
        String localIf = opts.get("udpif");
        if (localIf == null || localIf.isBlank()) {
            // 实现里 UdpBridgeNode 强制要求 udpif（不支持自动探测）
            throw new IllegalArgumentException(
                    "--udpif is required (CIDR of the multicast NIC, e.g. 192.168.1.0/24).");
        }

        // --utot（UDP→TCP）与 --ttou（TCP→UDP），均默认启用；两个都关闭则无转发意义，拒绝启动。
        boolean utotEnabled = boolOpt(opts, "utot", true);
        boolean ttouEnabled = boolOpt(opts, "ttou", true);
        if (!utotEnabled && !ttouEnabled) {
            throw new IllegalArgumentException(
                    "Both --utot and --ttou are disabled, nothing to forward; enable at least one.");
        }

        // --port 是本地 TCP 监听端口（接收对端 TCP → 发到本地 UDP，属 ttou 方向）。
        // ttou 关闭时该端口不被使用，可不填；其他情况必填。
        int listenPort;
        if (ttouEnabled) {
            listenPort = port(require(opts, "port"), -1, "--port");
        } else {
            listenPort = port(opts.get("port"), 0, "--port");
        }

        TreeMap<String, PeerConfig> peers = new TreeMap<>();
        for (Map.Entry<String, String> e : opts.entrySet()) {
            String key = e.getKey();
            if (!key.equals("peer") && !key.matches("peer\\d+")) {
                continue;
            }
            if (e.getValue() == null || e.getValue().isBlank()) {
                throw new IllegalArgumentException("--" + key + " requires host:port.");
            }
            HostPort hp = hostPort(e.getValue(), "--" + key);
            peers.put(key, new PeerConfig(hp.host(), hp.port()));
        }
        if (peers.isEmpty()) {
            throw new IllegalArgumentException("bridge mode needs at least one --peer host:port.");
        }
        return new UdpBridgeNode(localUdp.host(), localUdp.port(), localIf.trim(),
                listenPort, new ArrayList<>(peers.values()), utotEnabled, ttouEnabled, logger);
    }

    // ==================== helpers ====================

    private record HostPort(String host, int port) {
    }

    private static HostPort hostPort(String value, String option) {
        String v = value == null ? "" : value.trim();
        int idx = v.lastIndexOf(':');
        if (idx <= 0 || idx == v.length() - 1) {
            throw new IllegalArgumentException(option + " must be host:port (got: " + value + ").");
        }
        String host = v.substring(0, idx).trim();
        String portText = v.substring(idx + 1).trim();
        int port;
        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " has an invalid port: " + portText);
        }
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException(option + " port must be 1-65535 (got: " + port + ").");
        }
        return new HostPort(host, port);
    }

    private static int port(String value, int defaultValue, String option) {
        if (value == null || value.isBlank()) {
            if (defaultValue < 0) {
                throw new IllegalArgumentException(option + " is required.");
            }
            return defaultValue;
        }
        int p;
        try {
            p = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(option + " must be a number (got: " + value + ").");
        }
        if (p < 0 || p > 65535) {
            throw new IllegalArgumentException(option + " must be 0-65535 (got: " + p + ").");
        }
        if (defaultValue < 0 && p == 0) {
            throw new IllegalArgumentException(option + " must be 1-65535 (got: 0).");
        }
        return p;
    }

    private static String require(Map<String, String> opts, String key) {
        String v = opts.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("--" + key + " is required.");
        }
        return v.trim();
    }

    /** 解析布尔选项，接受 true/false/1/0（大小写不敏感），缺省返回 {@code defaultValue}。 */
    private static boolean boolOpt(Map<String, String> opts, String key, boolean defaultValue) {
        String v = opts.get(key);
        if (v == null || v.isBlank()) {
            return defaultValue;
        }
        String s = v.trim().toLowerCase(java.util.Locale.ROOT);
        switch (s) {
            case "true", "1", "yes", "on" -> {
                return true;
            }
            case "false", "0", "no", "off" -> {
                return false;
            }
            default -> throw new IllegalArgumentException("--" + key
                    + " must be true or false (got: " + v + ").");
        }
    }
}
