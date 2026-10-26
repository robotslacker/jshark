package com.jshark.parser;

import java.util.ArrayList;
import java.util.List;

/**
 * 目标映射配置 - 支持 IP:端口 映射，支持通配符和逗号分隔多个映射
 * <p>
 * 格式：SrcIP:SrcPort-DestIP:DestPort
 * 通配符 * 表示任意匹配；映射后的 * 表示与源一致（即不修改）
 * 多个映射用逗号分隔
 * </p>
 * <p>
 * 示例：
 * <ul>
 *   <li>11.0.0.1:5520-192.178.0.1:5530</li>
 *   <li>*:*-192.168.0.5:*</li>
 *   <li>11.0.0.1:5520-192.178.0.1:5530, *:*-192.168.0.5:*</li>
 * </ul>
 * </p>
 */
public class TargetMapping {

    private final List<MappingEntry> entries = new ArrayList<>();

    /**
     * 映射条目
     *
     * @param srcIpPattern   源IP匹配模式（支持通配符）
     * @param srcPortPattern 源端口匹配模式（支持通配符）
     * @param targetIp       映射后的目标IP（* 表示与原始目标IP一致）
     * @param targetPort     映射后的目标端口（* 表示与原始目标端口一致）
     */
        private record MappingEntry(String srcIpPattern, String srcPortPattern, String targetIp, String targetPort) {

        /**
             * 检查此条目是否匹配给定的源IP和源端口
             */
            boolean matches(String srcIp, int srcPort) {
                return matchesPattern(srcIpPattern, srcIp) &&
                        matchesPattern(srcPortPattern, String.valueOf(srcPort));
            }

            /**
             * 获取映射后的目标IP
             */
            String getMappedIp(String originalDstIp) {
                return "*".equals(targetIp) ? originalDstIp : targetIp;
            }

            /**
             * 获取映射后的目标端口
             * @param dstPort 原始目标端口（当 targetPort 为 * 时保持原目标端口不变）
             */
            int getMappedPort(int dstPort) {
                return "*".equals(targetPort) ? dstPort : Integer.parseInt(targetPort);
            }
        }

    /**
     * 解析映射配置字符串
     *
     * @param mappingStr 映射配置字符串，格式如 "11.0.0.1:5520-192.178.0.1:5530, *:*-192.168.0.5:*"
     * @return TargetMapping 实例
     * @throws IllegalArgumentException 如果格式无效
     */
    public static TargetMapping parse(String mappingStr) {
        TargetMapping mapping = new TargetMapping();
        if (mappingStr == null || mappingStr.trim().isEmpty()) {
            // 默认映射：*:*:*:* 表示不修改
            mapping.entries.add(new MappingEntry("*", "*", "*", "*"));
            return mapping;
        }

        // 按逗号分隔多个映射
        String[] parts = mappingStr.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            mapping.entries.add(parseSingleMapping(trimmed));
        }

        if (mapping.entries.isEmpty()) {
            // 默认映射
            mapping.entries.add(new MappingEntry("*", "*", "*", "*"));
        }

        return mapping;
    }

    /**
     * 解析单个映射条目
     * 格式：SrcIP:SrcPort-DestIP:DestPort
     */
    private static MappingEntry parseSingleMapping(String mappingStr) {
        int dashIndex = mappingStr.indexOf('-');
        if (dashIndex <= 0) {
            throw new IllegalArgumentException("Invalid mapping format: " + mappingStr +
                "; expected SrcIP:SrcPort-DestIP:DestPort (e.g. 11.0.0.1:5520-192.178.0.1:5530)");
        }

        String srcPart = mappingStr.substring(0, dashIndex).trim();
        String dstPart = mappingStr.substring(dashIndex + 1).trim();

        String[] srcFields = splitByColon(srcPart);
        String[] dstFields = splitByColon(dstPart);

        if (srcFields.length != 2 || dstFields.length != 2) {
            throw new IllegalArgumentException("Invalid mapping format: " + mappingStr +
                "; expected SrcIP:SrcPort-DestIP:DestPort (e.g. 11.0.0.1:5520-192.178.0.1:5530)");
        }

        return new MappingEntry(
            srcFields[0], srcFields[1],
            dstFields[0], dstFields[1]
        );
    }

    /**
     * 按冒号分割（简单实现，因为IP是IPv4格式，不包含冒号）
     */
    private static String[] splitByColon(String str) {
        return str.split(":", -1);
    }

    /**
     * 将通配符模式转换为正则表达式
     */
    private static String wildcardToRegex(String pattern) {
        if ("*".equals(pattern)) {
            return ".*";
        }
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '*') {
                regex.append(".*");
            } else if (c == '.') {
                regex.append("\\.");
            } else {
                regex.append(c);
            }
        }
        return regex.toString();
    }

    /**
     * 检查值是否匹配模式（支持通配符 *）
     */
    private static boolean matchesPattern(String pattern, String value) {
        if ("*".equals(pattern)) {
            return true;
        }
        String regex = wildcardToRegex(pattern);
        return value.matches(regex);
    }

    /**
     * 根据源IP和源端口查找匹配的映射条目
     */
    private MappingEntry findMatch(String srcIp, int srcPort) {
        for (MappingEntry entry : entries) {
            if (entry.matches(srcIp, srcPort)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * 应用映射，返回映射后的目标IP和端口
     *
     * @param srcIp  源IP
     * @param srcPort 源端口
     * @param dstIp  原始目标IP
     * @param dstPort 原始目标端口
     * @return 映射结果，包含映射后的IP和端口
     */
    public MappingResult apply(String srcIp, int srcPort, String dstIp, int dstPort) {
        MappingEntry entry = findMatch(srcIp, srcPort);
        if (entry == null) {
            // 没有匹配的映射，使用原始目标
            return new MappingResult(dstIp, dstPort);
        }
        String mappedIp = entry.getMappedIp(dstIp);
        int mappedPort = entry.getMappedPort(dstPort);
        return new MappingResult(mappedIp, mappedPort);
    }

    /**
         * 映射结果
         */
    public record MappingResult(String ip, int port) {
        @Override
        public String toString() {
            return ip + ":" + port;
        }
    }

    /**
     * 获取所有映射条目的描述
     */
    public List<String> getDescriptions() {
        List<String> descs = new ArrayList<>();
        for (MappingEntry entry : entries) {
            descs.add(String.format("src=%s:%s -> dst=%s:%s",
                entry.srcIpPattern, entry.srcPortPattern,
                entry.targetIp, entry.targetPort));
        }
        return descs;
    }
}
