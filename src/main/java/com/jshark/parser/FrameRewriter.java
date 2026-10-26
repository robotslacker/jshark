package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 帧改写器：把抓到的原始帧改写成"发往新目标"的帧，**且只改动寻址与校验和**。
 *
 * <h3>不变量（帧级原样重放的核心约束）</h3>
 * <pre>
 * 允许改写：IPv4/IPv6 目的地址、TCP/UDP 目的端口、受影响的校验和、以太网目的 MAC
 * 禁止改写：payload 任何字节、源地址/源端口、seq/ack/flags/window、
 *           IP ID、分片 offset/MF、TTL/HopLimit、DSCP、IP 选项、UDP 长度、IP 总长度
 * no-op 情形（目的地址与端口都未变）：逐字节原样返回，连校验和都不重算
 * </pre>
 *
 * <h3>已知限制（明确跳过而非猜测）</h3>
 * <ul>
 *   <li><b>分片数据报不改端口</b>：端口只在首片里。若只改首片的端口而不改后续片，
 *       对端重组后会出现"目的端口与校验和不一致"，比不改更糟。因此对分片数据报
 *       只做地址改写，端口改写计入 {@link Status#SKIPPED_FRAGMENTED_PORT}。</li>
 *   <li><b>校验和不合法的帧拒绝改写</b>：常见于采集端开启 checksum offload 的机器
 *       （网卡卸载导致线上帧的传输层校验和是占位值）。此时任何重算都无法与对端既有
 *       校验和口径对齐，故拒绝改写并计数，提示在采集端关闭 offload。</li>
 *   <li><b>非 IPv4/IPv6 帧（ARP 等）不改写</b>，计入 {@link Status#SKIPPED_UNSUPPORTED}。</li>
 *   <li><b>IPv6 扩展头暂不支持</b>，遇到时计入 {@link Status#SKIPPED_UNSUPPORTED}。</li>
 * </ul>
 */
public class FrameRewriter {

    private static final Logger logger = LoggerFactory.getLogger(FrameRewriter.class);

    /** 以太网头长度 */
    private static final int ETH_HEADER_LEN = 14;
    /** IPv4 最小头长度 */
    private static final int IPV4_MIN_HEADER = 20;
    /** IPv6 固定头长度 */
    private static final int IPV6_HEADER = 40;
    /** UDP 头长度 */
    private static final int UDP_HEADER = 8;
    /** TCP 最小头长度 */
    private static final int TCP_MIN_HEADER = 20;

    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_IPV6 = 0x86DD;
    private static final int ETHERTYPE_VLAN = 0x8100;
    private static final int ETHERTYPE_QINQ = 0x88A8;

    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;

    /** 改写结果状态 */
    public enum Status {
        /** 目的地址与端口都未变化：原字节直发 */
        UNCHANGED,
        /** 已改写（地址和/或端口） */
        REWRITTEN,
        /** 非 IPv4/IPv6（如 ARP），不改写 */
        SKIPPED_UNSUPPORTED,
        /** 帧被 snaplen 截断，无法安全改写 */
        SKIPPED_TRUNCATED,
        /** 原传输层校验和不合法（疑似 checksum offload），拒绝改写 */
        SKIPPED_BAD_CHECKSUM,
        /** 该帧是分片数据报但需要改端口，拒绝改端口（仅可改地址） */
        SKIPPED_FRAGMENTED_PORT
    }

    /**
     * 改写结果。
     *
     * @param status      结果状态
     * @param bytes       输出帧字节（无改动时即为原始数组本身）
     * @param dstIp       该帧的目的 IP
     * @param dstPort     实际写入的目的端口（-1 表示未改端口或无法确定）
     */
    public record RewriteResult(Status status, byte[] bytes, String dstIp, int dstPort) {

        /**
         * 该帧是否可以直接注入。
         * <p>
         * {@link Status#SKIPPED_FRAGMENTED_PORT} 表示"拒绝改端口"，但该帧**仍可在原端口上原样注入**，
         * 因此也算可注入；只有截断、非 IP、校验和不合法这三类才真正不可注入。
         * </p>
         *
         * @return true 表示可以注入
         */
        public boolean injectable() {
            return status == Status.UNCHANGED
                    || status == Status.REWRITTEN
                    || status == Status.SKIPPED_FRAGMENTED_PORT;
        }

        /** @return 该帧是否被实际修改过 */
        public boolean modified() {
            return status == Status.REWRITTEN;
        }
    }

    /**
     * 目的 MAC 策略。
     *
     * <ul>
     *   <li>{@link Mode#PRESERVE} —— 保留原帧的目的 MAC（默认；被动采集器多为混杂模式，无需解析）</li>
     *   <li>{@link Mode#REPLACE} —— 用显式指定值覆盖</li>
     *   <li>{@link Mode#AUTO} —— 按规则自动解析（组播/广播用公式合成；单播查邻居表/主动探测）</li>
     *   <li>{@link Mode#PER_IP} —— 按目的 IP 逐条覆盖（{@code IP=MAC,IP=MAC} 形式）</li>
     * </ul>
     */
    public static final class MacPolicy {

        /** 策略模式 */
        public enum Mode { PRESERVE, REPLACE, AUTO, PER_IP }

        private final Mode mode;
        private final byte[] explicitMac;
        private final Map<String, byte[]> perIp;

        private MacPolicy(Mode mode, byte[] explicitMac, Map<String, byte[]> perIp) {
            this.mode = mode;
            this.explicitMac = explicitMac;
            this.perIp = perIp;
        }

        /** @return 保留原 MAC 的策略（默认） */
        public static MacPolicy preserve() {
            return new MacPolicy(Mode.PRESERVE, null, Map.of());
        }

        /**
         * 用固定 MAC 覆盖。
         *
         * @param mac 6 字节 MAC
         * @return 策略
         */
        public static MacPolicy replace(byte[] mac) {
            return new MacPolicy(Mode.REPLACE, mac, Map.of());
        }

        /** @return 自动解析策略 */
        public static MacPolicy auto() {
            return new MacPolicy(Mode.AUTO, null, Map.of());
        }

        /** @return 按目的 IP 映射的策略 */
        public static MacPolicy perIp(Map<String, byte[]> mapping) {
            return new MacPolicy(Mode.PER_IP, null, mapping);
        }

        /** @return 模式 */
        public Mode mode() {
            return mode;
        }

        /** @return 显式 MAC（仅 REPLACE 模式有效） */
        public byte[] explicitMac() {
            return explicitMac;
        }

        /** @return 按 IP 的映射（仅 PER_IP 模式有效） */
        public Map<String, byte[]> mapping() {
            return perIp;
        }

        /** @return 是否为"不需要任何解析"的策略（PRESERVE/REPLACE/PER_IP 命中） */
        public boolean needsResolution(String dstIp) {
            return mode == Mode.AUTO
                    || (mode == Mode.PER_IP && !perIp.containsKey(dstIp));
        }

        /**
         * 解析 {@code --dstMac} 取值。
         *
         * @param spec 取值：{@code preserve}（默认）、{@code auto}、单个 MAC、
         *             或 {@code IP=MAC,IP=MAC}
         * @return 策略
         * @throws IllegalArgumentException 格式非法
         */
        public static MacPolicy parse(String spec) {
            if (spec == null || spec.trim().isEmpty() || "preserve".equalsIgnoreCase(spec.trim())) {
                return preserve();
            }
            String s = spec.trim();
            if ("auto".equalsIgnoreCase(s)) {
                return auto();
            }
            if (s.indexOf('=') < 0) {
                return replace(parseMac(s));
            }
            Map<String, byte[]> map = new HashMap<>();
            for (String part : s.split(",")) {
                String p = part.trim();
                if (p.isEmpty()) {
                    continue;
                }
                int eq = p.indexOf('=');
                if (eq <= 0 || eq == p.length() - 1) {
                    throw new IllegalArgumentException("Invalid --dstMac entry (expected IP=MAC): " + p);
                }
                map.put(p.substring(0, eq).trim(), parseMac(p.substring(eq + 1).trim()));
            }
            if (map.isEmpty()) {
                throw new IllegalArgumentException("Invalid --dstMac value: " + spec);
            }
            return perIp(map);
        }

        /**
         * 解析 MAC 字符串为 6 字节数组。
         *
         * @param mac {@code aa:bb:cc:dd:ee:ff} 或 {@code aa-bb-cc-dd-ee-ff}
         * @return 6 字节数组
         * @throws IllegalArgumentException 格式非法
         */
        public static byte[] parseMac(String mac) {
            String hex = mac.replace(":", "").replace("-", "").replace(".", "");
            if (hex.length() != 12) {
                throw new IllegalArgumentException("Invalid MAC address: " + mac);
            }
            byte[] out = new byte[6];
            for (int i = 0; i < 6; i++) {
                out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }

        /**
         * 取该目的 IP 应使用的目的 MAC；返回 null 表示"保留原 MAC"。
         *
         * @param dstIp 目的 IP
         * @return 6 字节 MAC 或 null
         */
        public byte[] resolve(String dstIp) {
            switch (mode) {
                case REPLACE:
                    return explicitMac;
                case PER_IP:
                    return perIp.get(dstIp);
                default:
                    return null;
            }
        }
    }

    private final MacPolicy macPolicy;

    /** 解析器回调：把单播目的 IP 解析为 MAC；无解析能力时返回 null */
    private java.util.function.Function<String, byte[]> unicastResolver;

    /** 统计各状态出现次数（便于运行报告） */
    private final Map<Status, Long> counters = new HashMap<>();

    /**
     * 构造帧改写器。
     *
     * @param macPolicy       目的 MAC 策略，null 视为 {@code preserve}
     * @param unicastResolver 单播 MAC 解析器（仅当策略需要解析时调用）；可为 null
     */
    public FrameRewriter(MacPolicy macPolicy, java.util.function.Function<String, byte[]> unicastResolver) {
        this.macPolicy = macPolicy != null ? macPolicy : MacPolicy.preserve();
        this.unicastResolver = unicastResolver;
    }

    /**
     * 改写帧：把目的地址改为 {@code dstIp}、目的端口改为 {@code dstPort}。
     *
     * @param frame        原始完整帧
     * @param dstIp        目标目的 IP
     * @param dstPort      目标目的端口（&lt;=0 或 &gt;65535 表示不改端口，仅改地址）
     * @return 改写结果
     */
    public RewriteResult rewrite(byte[] frame, String dstIp, int dstPort) {
        RewriteResult result = doRewrite(frame, dstIp, dstPort);
        counters.merge(result.status(), 1L, Long::sum);
        return result;
    }

    /** @return 各状态的累计次数快照 */
    public Map<Status, Long> counters() {
        return new HashMap<>(counters);
    }

    /** @return 目的 MAC 策略 */
        // ==================== 实现 ====================

    private RewriteResult doRewrite(byte[] frame, String dstIp, int dstPort) {
        if (frame == null || frame.length < ETH_HEADER_LEN + IPV4_MIN_HEADER) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }

        // ---- L2：解析以太网类型（跳过可能的 VLAN 标签） ----
        int typeOffset = 12;
        int etherType = ((frame[typeOffset] & 0xFF) << 8) | (frame[typeOffset + 1] & 0xFF);
        int ipOffset = ETH_HEADER_LEN;
        while (etherType == ETHERTYPE_VLAN || etherType == ETHERTYPE_QINQ) {
            if (frame.length < ipOffset + 4) {
                return new RewriteResult(Status.SKIPPED_TRUNCATED, frame, null, -1);
            }
            etherType = ((frame[ipOffset + 2] & 0xFF) << 8) | (frame[ipOffset + 3] & 0xFF);
            ipOffset += 4;
        }

        if (etherType == ETHERTYPE_IPV4) {
            return rewriteIpv4(frame, ipOffset, dstIp, dstPort);
        }
        if (etherType == ETHERTYPE_IPV6) {
            return rewriteIpv6(frame, ipOffset, dstIp, dstPort);
        }
        return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
    }

    private RewriteResult rewriteIpv4(byte[] frame, int ipOffset, String dstIp, int dstPort) {
        if (frame.length < ipOffset + IPV4_MIN_HEADER) {
            return new RewriteResult(Status.SKIPPED_TRUNCATED, frame, null, -1);
        }
        int version = (frame[ipOffset] & 0xF0) >> 4;
        if (version != 4) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }
        int ihl = (frame[ipOffset] & 0x0F) * 4;
        if (ihl < IPV4_MIN_HEADER || frame.length < ipOffset + ihl) {
            return new RewriteResult(Status.SKIPPED_TRUNCATED, frame, null, -1);
        }
        int totalLength = u16(frame, ipOffset + 2);
        // 线上总长度（不含以太网填充）
        int ipPacketLen = Math.min(totalLength, frame.length - ipOffset);
        // 截断检测：pcap 首部长度 > 实际帧长
        boolean truncated = totalLength > frame.length - ipOffset;
        if (truncated) {
            return new RewriteResult(Status.SKIPPED_TRUNCATED, frame, null, -1);
        }

        int protocol = frame[ipOffset + 9] & 0xFF;
        int fragField = u16(frame, ipOffset + 6);
        boolean moreFragments = (fragField & 0x2000) != 0;
        int fragmentOffset = (fragField & 0x1FFF) * 8;
        boolean fragmented = moreFragments || fragmentOffset > 0;

        // ---- 目的 IP ----
        byte[] target;
        try {
            target = InetAddress.getByName(dstIp).getAddress();
        } catch (Exception e) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }
        if (target.length != 4) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }
        int dstAddrOffset = ipOffset + 16;
        boolean addrChanged = !Arrays.equals(
                Arrays.copyOfRange(frame, dstAddrOffset, dstAddrOffset + 4), target);

        // ---- 传输层端口位置 ----
        // 注意：即使帧是分片（首片），也**必须**尝试读取端口，因为需要与目标端口比较后才能判断
        // "是否真的要改端口"。端口只在首片里；续片（offset>0）没有传输层头。
        boolean hasTransportHeader = fragmentOffset == 0;
        int transportOffset = ipOffset + ihl;
        int transportChecksumOffset = -1;
        int oldPort = -1;
        if (hasTransportHeader) {
            if (protocol == PROTO_UDP) {
                if (frame.length >= transportOffset + UDP_HEADER) {
                    oldPort = u16(frame, transportOffset + 2);
                    transportChecksumOffset = transportOffset + 6;
                }
            } else if (protocol == PROTO_TCP) {
                if (frame.length >= transportOffset + TCP_MIN_HEADER) {
                    oldPort = u16(frame, transportOffset + 2);
                    transportChecksumOffset = transportOffset + 16;
                }
            }
        }

        // 传输层段长度：取"IP 总长度推导值"与"实际捕获长度推导值"的较小者。
        // 分片帧里 IP 总长度只描述本片，两者恰好相等；非分片帧里捕获可能少于总长度（截断）。
        int transportLenByIp = ipPacketLen - ihl;
        int transportLenByCap = frame.length - transportOffset;
        int transportLen = Math.min(transportLenByIp, transportLenByCap);
        boolean transportLenUsable = transportChecksumOffset > 0 && transportLen > 0;

        boolean portWanted = dstPort > 0 && dstPort <= 65535;
        boolean portChanged = portWanted && oldPort >= 0 && oldPort != dstPort;

        // ---- no-op 快路径：逐字节原样 ----
        if (!addrChanged && !portChanged) {
            String current = ipv4ToString(frame, dstAddrOffset);
            int currentPort = oldPort >= 0 ? oldPort : -1;
            boolean needMac = needMacRewrite(current);
            if (!needMac) {
                return new RewriteResult(Status.UNCHANGED, frame, current, currentPort);
            }
            // 仅需改 MAC
            byte[] out = frame.clone();
            byte[] mac = resolveMac(current, frame);
            if (mac == null) {
                return new RewriteResult(Status.UNCHANGED, frame, current, currentPort);
            }
            System.arraycopy(mac, 0, out, 0, 6);
            return new RewriteResult(Status.REWRITTEN, out, current, currentPort);
        }

        // ---- 分片数据报：端口只在首片里，无法安全改端口 ----
        // 只有在"确实需要改端口"时才受限；端口本来就等于目标值时不受影响。
        if (fragmented && portChanged) {
            if (!addrChanged) {
                // 地址不用改、端口必须改但改不了 → 无法达成目标
                return new RewriteResult(Status.SKIPPED_FRAGMENTED_PORT, frame, dstIp, -1);
            }
            // 地址与端口都要改 → 只改地址，端口保持原值（仍可注入）
            byte[] out = frame.clone();
            System.arraycopy(target, 0, out, dstAddrOffset, 4);
            recomputeIpv4HeaderChecksum(out, ipOffset, ihl);
            applyMac(out, dstIp, frame);
            return new RewriteResult(Status.SKIPPED_FRAGMENTED_PORT, out, dstIp, -1);
        }

        // ---- 校验和合法性预检：原传输层校验和不合法（疑似 offload）→ 拒绝改写 ----
        // UDP 校验和为 0 表示发送方未计算，属合法情况，跳过校验。
        if ((portChanged || addrChanged) && transportLenUsable) {
            int oldChecksum = u16(frame, transportChecksumOffset);
            if (oldChecksum != 0 && !verifyTransportIpv4(frame, ipOffset, ihl, protocol,
                    transportOffset, transportLen)) {
                return new RewriteResult(Status.SKIPPED_BAD_CHECKSUM, frame, null, -1);
            }
        }

        // ---- 执行改写 ----
        byte[] out = frame.clone();
        if (addrChanged) {
            System.arraycopy(target, 0, out, dstAddrOffset, 4);
        }
        if (portChanged) {
            out[transportOffset + 2] = (byte) ((dstPort >> 8) & 0xFF);
            out[transportOffset + 3] = (byte) (dstPort & 0xFF);
        }

        // 先重算 IP 头校验和（只依赖 IP 头）。
        // 注意：传输层校验和只覆盖"伪首部 + 传输层内容"，其中含源/目的地址，
        // 因此改地址也**必须**重算传输层校验和，否则对端按新地址验证会失败。
        // 分片帧不走这里（见上）。
        recomputeIpv4HeaderChecksum(out, ipOffset, ihl);
        if (transportLenUsable) {
            // 原 UDP 校验和为 0（未计算）时保持 0，不写入新值
            int oldChecksum = u16(out, transportChecksumOffset);
            if (oldChecksum != 0) {
                recomputeTransportIpv4(out, ipOffset, ihl, protocol, transportOffset, transportLen);
            }
        }
        applyMac(out, dstIp, frame);
        return new RewriteResult(Status.REWRITTEN, out, dstIp, portChanged ? dstPort : oldPort);
    }

    private RewriteResult rewriteIpv6(byte[] frame, int ipOffset, String dstIp, int dstPort) {
        if (frame.length < ipOffset + IPV6_HEADER) {
            return new RewriteResult(Status.SKIPPED_TRUNCATED, frame, null, -1);
        }
        if (((frame[ipOffset] & 0xF0) >> 4) != 6) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }
        int payloadLength = u16(frame, ipOffset + 4);
        int nextHeader = frame[ipOffset + 6] & 0xFF;
        if (nextHeader != PROTO_UDP && nextHeader != PROTO_TCP) {
            // 扩展头暂不支持
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }
        if (frame.length < ipOffset + IPV6_HEADER + payloadLength) {
            return new RewriteResult(Status.SKIPPED_TRUNCATED, frame, null, -1);
        }

        byte[] target;
        try {
            target = InetAddress.getByName(dstIp).getAddress();
        } catch (Exception e) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }
        if (target.length != 16) {
            return new RewriteResult(Status.SKIPPED_UNSUPPORTED, frame, null, -1);
        }

        int dstAddrOffset = ipOffset + 24;
        boolean addrChanged = !Arrays.equals(
                Arrays.copyOfRange(frame, dstAddrOffset, dstAddrOffset + 16), target);

        int transportOffset = ipOffset + IPV6_HEADER;
        int transportChecksumOffset = nextHeader == PROTO_UDP ? transportOffset + 6 : transportOffset + 16;
        int oldPort = u16(frame, transportOffset + 2);
        boolean portWanted = dstPort > 0 && dstPort <= 65535;
        boolean portChanged = portWanted && oldPort != dstPort;

        if (!addrChanged && !portChanged) {
            String current = ipv6ToString(frame, dstAddrOffset);
            if (!needMacRewrite(current)) {
                return new RewriteResult(Status.UNCHANGED, frame, current, oldPort);
            }
            byte[] out = frame.clone();
            byte[] mac = resolveMac(current, frame);
            if (mac == null) {
                return new RewriteResult(Status.UNCHANGED, frame, current, oldPort);
            }
            System.arraycopy(mac, 0, out, 0, 6);
            return new RewriteResult(Status.REWRITTEN, out, current, oldPort);
        }

        if (portChanged) {
            int oldChecksum = u16(frame, transportChecksumOffset);
            if (oldChecksum != 0 && !verifyTransportIpv6(frame, ipOffset, nextHeader,
                    transportOffset, payloadLength)) {
                return new RewriteResult(Status.SKIPPED_BAD_CHECKSUM, frame, null, -1);
            }
        }

        byte[] out = frame.clone();
        if (addrChanged) {
            System.arraycopy(target, 0, out, dstAddrOffset, 16);
        }
        if (portChanged) {
            out[transportOffset + 2] = (byte) ((dstPort >> 8) & 0xFF);
            out[transportOffset + 3] = (byte) (dstPort & 0xFF);
        }
        if (portChanged || addrChanged) {
            recomputeTransportIpv6(out, ipOffset, nextHeader, transportOffset, payloadLength);
        }
        applyMac(out, dstIp, frame);
        return new RewriteResult(Status.REWRITTEN, out, dstIp, portChanged ? dstPort : oldPort);
    }

    // ==================== MAC ====================

    /** @return 该策略下是否需要为重点目的 IP 改写 MAC */
    private boolean needMacRewrite(String dstIp) {
        return macPolicy.resolve(dstIp) != null || macPolicy.mode() == MacPolicy.Mode.AUTO;
    }

    private void applyMac(byte[] out, String dstIp, byte[] originalFrame) {
        byte[] mac = resolveMac(dstIp, originalFrame);
        if (mac != null) {
            System.arraycopy(mac, 0, out, 0, 6);
        }
    }

    /** 解析目的 MAC；null 表示保留原值 */
    private byte[] resolveMac(String dstIp, byte[] frame) {
        byte[] direct = macPolicy.resolve(dstIp);
        if (direct != null) {
            return direct;
        }
        if (macPolicy.mode() == MacPolicy.Mode.PRESERVE) {
            return null;
        }
        // AUTO 或 PER_IP 未命中：组播/广播用公式合成，其余交给单播解析器
        InetAddress addr;
        try {
            addr = InetAddress.getByName(dstIp);
        } catch (Exception e) {
            return null;
        }
        if (addr.isMulticastAddress()) {
            return multicastMac(addr);
        }
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            // IPv4 广播：255.255.255.255 或子网广播无法从单地址判断，统一按有限广播处理
            if ((b[0] & 0xFF) == 255 && (b[1] & 0xFF) == 255
                    && (b[2] & 0xFF) == 255 && (b[3] & 0xFF) == 255) {
                return new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
            }
        }
        if (unicastResolver == null) {
            logger.warn("[JShark] Cannot resolve destination MAC for unicast {} "
                    + "(no resolver available and --dstMac does not specify one)", dstIp);
            return null;
        }
        byte[] resolved = unicastResolver.apply(dstIp);
        if (resolved == null) {
            logger.warn("[JShark] Failed to resolve destination MAC for unicast {}; "
                    + "if the collector runs in promiscuous mode use --dstMac=preserve", dstIp);
        }
        return resolved;
    }

    /**
     * 按标准公式合成组播 MAC。
     * <p>
     * IPv4：{@code 01:00:5E} + IP 低 23 位；IPv6：{@code 33:33} + IP 低 32 位。
     * </p>
     *
     * @param addr 组播地址
     * @return 6 字节组播 MAC
     */
    static byte[] multicastMac(InetAddress addr) {
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            return new byte[]{0x01, 0x00, 0x5E,
                    (byte) (b[1] & 0x7F), (byte) (b[2] & 0xFF), (byte) (b[3] & 0xFF)};
        }
        return new byte[]{0x33, 0x33, b[12], b[13], b[14], b[15]};
    }

    // ==================== 校验和 ====================

    private void recomputeIpv4HeaderChecksum(byte[] frame, int ipOffset, int ihl) {
        frame[ipOffset + 10] = 0;
        frame[ipOffset + 11] = 0;
        int sum = IpChecksum.compute(frame, ipOffset, ihl);
        frame[ipOffset + 10] = (byte) ((sum >> 8) & 0xFF);
        frame[ipOffset + 11] = (byte) (sum & 0xFF);
    }

    /** 重算 IPv4 传输层校验和（伪首部 + 传输层段） */
    private void recomputeTransportIpv4(byte[] frame, int ipOffset, int ihl, int protocol,
                                        int transportOffset, int transportLen) {
        byte[] pseudo = ipv4PseudoHeader(frame, ipOffset, protocol, transportLen);
        int checksumOffset = protocol == PROTO_UDP ? transportOffset + 6 : transportOffset + 16;
        frame[checksumOffset] = 0;
        frame[checksumOffset + 1] = 0;
        int sum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, transportOffset, transportLen);
        // UDP 计算结果为 0 时按 RFC 768 写 0xFFFF；TCP 恒为强制校验
        if (protocol == PROTO_UDP && sum == 0) {
            sum = 0xFFFF;
        }
        frame[checksumOffset] = (byte) ((sum >> 8) & 0xFF);
        frame[checksumOffset + 1] = (byte) (sum & 0xFF);
    }

    private boolean verifyTransportIpv4(byte[] frame, int ipOffset, int ihl, int protocol,
                                        int transportOffset, int transportLen) {
        if (transportLen <= 0) {
            return false;
        }
        byte[] pseudo = ipv4PseudoHeader(frame, ipOffset, protocol, transportLen);
        // 判据：伪首部 + 含校验和字段的传输层段，求和后校验和为 0
        int sum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, transportOffset, transportLen);
        return sum == 0;
    }

    private byte[] ipv4PseudoHeader(byte[] frame, int ipOffset, int protocol, int transportLen) {
        byte[] pseudo = new byte[12];
        System.arraycopy(frame, ipOffset + 12, pseudo, 0, 8); // 源 + 目的地址
        pseudo[8] = 0;
        pseudo[9] = (byte) protocol;
        pseudo[10] = (byte) ((transportLen >> 8) & 0xFF);
        pseudo[11] = (byte) (transportLen & 0xFF);
        return pseudo;
    }

    private void recomputeTransportIpv6(byte[] frame, int ipOffset, int nextHeader,
                                        int transportOffset, int transportLen) {
        byte[] pseudo = ipv6PseudoHeader(frame, ipOffset, nextHeader, transportLen);
        int checksumOffset = nextHeader == PROTO_UDP ? transportOffset + 6 : transportOffset + 16;
        frame[checksumOffset] = 0;
        frame[checksumOffset + 1] = 0;
        int sum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, transportOffset, transportLen);
        if (nextHeader == PROTO_UDP && sum == 0) {
            sum = 0xFFFF;
        }
        frame[checksumOffset] = (byte) ((sum >> 8) & 0xFF);
        frame[checksumOffset + 1] = (byte) (sum & 0xFF);
    }

    private boolean verifyTransportIpv6(byte[] frame, int ipOffset, int nextHeader,
                                        int transportOffset, int transportLen) {
        if (transportLen <= 0) {
            return false;
        }
        byte[] pseudo = ipv6PseudoHeader(frame, ipOffset, nextHeader, transportLen);
        int sum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, transportOffset, transportLen);
        return sum == 0;
    }

    private byte[] ipv6PseudoHeader(byte[] frame, int ipOffset, int nextHeader, int transportLen) {
        byte[] pseudo = new byte[40];
        System.arraycopy(frame, ipOffset + 8, pseudo, 0, 32);  // 源 + 目的地址（16+16）
        pseudo[32] = (byte) ((transportLen >> 24) & 0xFF);
        pseudo[33] = (byte) ((transportLen >> 16) & 0xFF);
        pseudo[34] = (byte) ((transportLen >> 8) & 0xFF);
        pseudo[35] = (byte) (transportLen & 0xFF);
        pseudo[39] = (byte) nextHeader;
        return pseudo;
    }

    // ==================== 工具 ====================

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static String ipv4ToString(byte[] b, int off) {
        return String.format(Locale.ROOT, "%d.%d.%d.%d",
                b[off] & 0xFF, b[off + 1] & 0xFF, b[off + 2] & 0xFF, b[off + 3] & 0xFF);
    }

    private static String ipv6ToString(byte[] b, int off) {
        try {
            return InetAddress.getByAddress(Arrays.copyOfRange(b, off, off + 16)).getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }
}
