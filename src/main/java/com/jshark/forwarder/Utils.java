package com.jshark.forwarder;

import org.apache.commons.net.util.SubnetUtils;

import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * 转发器的网络/格式化小工具。
 *
 * <p>历史包袱：这里曾是从 slackerdb 拷来的一整套通用工具（字节序转换、locale 解析、
 * 后台进程拉起……），绝大部分没有任何调用方。拉起后台进程的逻辑已经统一到
 * {@link com.jshark.CliRuntime}，其余不再使用的成员已删除，只保留实际用到的两个方法。</p>
 */
public final class Utils {

    private Utils() {
    }

    /**
     * 按 CIDR 找到所属网卡（只支持 IPv4）。
     *
     * @param cidr 例如 {@code 10.10.10.0/24}；null/空返回 null
     * @return 匹配的网卡；没有匹配返回 null
     * @throws SocketException 枚举网卡失败
     */
    public static NetworkInterface getInterfaceByCidr(String cidr) throws SocketException {
        if (cidr == null || cidr.isEmpty()) {
            return null;
        }
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();
            for (InterfaceAddress interfaceAddress : ni.getInterfaceAddresses()) {
                // 跳过 IPv6 地址，SubnetUtils 只支持 IPv4
                String hostAddress = interfaceAddress.getAddress().getHostAddress();
                if (hostAddress.contains(":")) {
                    continue;
                }
                // 移除 IPv4 地址中的 % 后缀
                int percentIdx = hostAddress.indexOf('%');
                if (percentIdx > 0) {
                    hostAddress = hostAddress.substring(0, percentIdx);
                }
                SubnetUtils utils = new SubnetUtils(cidr);
                if (utils.getInfo().isInRange(hostAddress)) {
                    return ni;
                }
            }
        }
        return null;
    }

    /**
     * 人类可读的字节数（{@code 1536 -> 1.5KB}）。
     *
     * @param bytes 字节数
     * @return 带单位的字符串
     */
    public static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + "B";
        }
        int unit = 1024;
        String[] units = {"KB", "MB", "GB", "TB", "PB", "EB"};
        int exp = (int) (Math.log(bytes) / Math.log(unit));
        return String.format("%.1f%s", bytes / Math.pow(unit, exp), units[exp - 1]);
    }
}
