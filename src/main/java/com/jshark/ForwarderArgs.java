package com.jshark;

import java.util.ArrayList;
import java.util.List;

/**
 * 转发器 UI 的表单 → 命令行参数（可单测，不依赖 Swing）。
 *
 * <p>表单校验必填项；地址统一用 {@code host:port}，CIDR 用
 * {@code a.b.c.d/prefix}。参数错误抛 {@link IllegalArgumentException}，消息可直接展示。</p>
 */
public final class ForwarderArgs {

    private ForwarderArgs() {
    }

    /** 一个 host:port 端点。 */
    public record Endpoint(String host, int port) {
        public String text() {
            return host + ":" + port;
        }
    }

    public record BridgeForm(String udpGroup, String udpPort, String localIf,
                             String listenPort, boolean utot, boolean ttou, List<Endpoint> peers) {
    }

    /** bridge：UDP 组播 ⇄ 多个 peer。 */
    public static List<String> buildBridge(BridgeForm f) {
        String group = require(f.udpGroup(), "UDP group");
        if (!isIpv4(group)) {
            throw new IllegalArgumentException(
                    "UDP group must be a single IPv4 address (e.g. 224.3.0.0).");
        }
        int port = port(f.udpPort(), "UDP port", false);
        String cidr = cidr(f.localIf(), true, "Local interface");
        // 方向先校验：两个都关时，“At least one…” 比缺 peer/端口更接近真实原因。
        if (!f.utot() && !f.ttou()) {
            throw new IllegalArgumentException("At least one of UDP→TCP / TCP→UDP must be enabled.");
        }
        if (f.peers() == null || f.peers().isEmpty()) {
            throw new IllegalArgumentException("Add at least one peer (host:port).");
        }
        // --port 是本地 TCP 监听端口（接收对端 TCP → 发到本地 UDP，属 ttou 方向）。
        // --ttou 关闭时该端口不被使用，可不填；其他情况必填。
        int listen = f.ttou()
                ? port(f.listenPort(), "Listen port", false)
                : port(f.listenPort(), "Listen port", true);

        List<String> args = new ArrayList<>();
        args.add("--udpaddr");
        args.add(group + ":" + port);
        args.add("--udpif");
        args.add(cidr);
        if (f.ttou()) {
            args.add("--port");
            args.add(Integer.toString(listen));
        }
        args.add("--utot");
        args.add(Boolean.toString(f.utot()));
        args.add("--ttou");
        args.add(Boolean.toString(f.ttou()));
        for (int i = 0; i < f.peers().size(); i++) {
            Endpoint p = f.peers().get(i);
            args.add("--peer" + (i + 1));
            args.add(p.text());
        }
        return args;
    }

    /** 解析 {@code IPv4:port}（UI 的 Add 行；不接受主机名/IPv6）。 */
    public static Endpoint endpoint(String value, String what) {
        String v = value == null ? "" : value.trim();
        int idx = v.lastIndexOf(':');
        if (idx <= 0 || idx == v.length() - 1) {
            throw new IllegalArgumentException(what + " must be IPv4:port, e.g. 1.1.1.1:2000.");
        }
        String host = v.substring(0, idx).trim();
        if (!isIpv4(host)) {
            throw new IllegalArgumentException(what + " must be IPv4:port, e.g. 1.1.1.1:2000.");
        }
        int port;
        try {
            port = Integer.parseInt(v.substring(idx + 1).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(what + " has an invalid port.");
        }
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException(what + " port must be 1-65535.");
        }
        return new Endpoint(host, port);
    }

    /**
     * 严格匹配单个 IPv4 字面量：4 段、每段 0-255、不接受主机名/IPv6/前导零。
     */
    static boolean isIpv4(String value) {
        if (value == null || value.isEmpty() || value.length() > 15) {
            return false;
        }
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                return false;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char ch = part.charAt(i);
                if (ch < '0' || ch > '9') {
                    return false;
                }
                octet = octet * 10 + (ch - '0');
            }
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    private static int port(String value, String what, boolean optional) {
        if (blank(value)) {
            if (optional) {
                return 0;
            }
            throw new IllegalArgumentException(what + " is required.");
        }
        int p;
        try {
            p = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(what + " must be a number.");
        }
        if (p < 0 || p > 65535) {
            throw new IllegalArgumentException(what + " must be 0-65535.");
        }
        if (!optional && p == 0) {
            throw new IllegalArgumentException(what + " must be 1-65535.");
        }
        return p;
    }

    private static String cidr(String value, boolean required, String what) {
        if (blank(value)) {
            if (required) {
                throw new IllegalArgumentException(what + " is required (CIDR, e.g. 192.168.1.0/24).");
            }
            return null;
        }
        String v = value.trim();
        if (!v.matches("\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}")) {
            throw new IllegalArgumentException(what + " must look like 192.168.1.0/24.");
        }
        return v;
    }

    private static String require(String value, String what) {
        if (blank(value)) {
            throw new IllegalArgumentException(what + " is required.");
        }
        return value.trim();
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }
}
