package com.jshark.parser;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IP 分片重组器
 * <p>
 * 用于缓存和重组 IPv4 分片数据包。当 UDP/TCP 报文超过 MTU 时，IP 层会将报文分成多个分片。
 * 只有第一个分片（offset=0）包含传输层头（端口信息），后续分片没有端口信息。
 * </p>
 *
 * <h3>工作原理：</h3>
 * <ol>
 *   <li>按 (srcIp, dstIp, identification, protocol) 分组缓存分片</li>
 *   <li>保存第一个分片（offset=0）的原始 Packet 引用，用于后续解析端口等元数据</li>
 *   <li>收到 MF=0 的分片后，验证所有分片连续覆盖 0..totalLength</li>
 *   <li>拼接完成后返回完整 payload，同时返回第一个分片的 Packet</li>
 *   <li>30 秒超时自动清理未完成的分组</li>
 * </ol>
 *
 * <h3>返回值含义：</h3>
 * <ul>
 *   <li>{@code null} — 分片已缓存，等待更多分片到达（调用者应跳过此包）</li>
 *   <li>{@code isReassembled=false} — 该包不是 IP 分片，正常处理</li>
 *   <li>{@code isReassembled=true} — 分片重组完成，使用返回的完整 payload 和 firstFragmentPacket 解析</li>
 * </ul>
 */
public class IpDefrag {
    private static final Logger logger = LoggerFactory.getLogger(IpDefrag.class);

    /** 分片组超时时间（毫秒） */
    private static final long GROUP_TIMEOUT_MS = 30_000L;
    /** 最大缓存分片组数量 */
    private static final int MAX_GROUPS = 500;

    /**
     * 分片组标识
     */
    private record FKey(String srcIp, String dstIp, int identification, IpNumber protocol) {}

    /**
     * 单个分片组
     */
    private static class FGroup {
        final NavigableMap<Integer, byte[]> fragments = new TreeMap<>();
        Packet firstFragmentPacket; // offset=0 的原始 Packet
        long firstSeenAt = System.currentTimeMillis();
        boolean lastReceived;
        int totalLength;

        /**
         * 检查是否已收齐：已收到最后一个分片 且 所有分片从 offset=0 开始连续覆盖
         */
        boolean isComplete() {
            if (!lastReceived) return false;
            int expected = 0;
            for (Map.Entry<Integer, byte[]> e : fragments.entrySet()) {
                if (e.getKey() != expected) return false;
                expected = e.getKey() + e.getValue().length;
            }
            return expected >= totalLength;
        }
    }

    private final Map<FKey, FGroup> groups = new ConcurrentHashMap<>();

    /**
     * 处理一个数据包，尝试 IP 分片重组。
     *
     * @param packet pcap4j Packet
     * @return 重组结果：null=已缓存正在等待; isReassembled=false=非分片; isReassembled=true=重组完成
     */
    public ReassembledResult addFragment(Packet packet) {
        if (!packet.contains(IpV4Packet.class)) {
            return new ReassembledResult(false, null, null);
        }

        IpV4Packet ip4 = packet.get(IpV4Packet.class);
        IpV4Packet.IpV4Header h = ip4.getHeader();

        String srcIp = h.getSrcAddr().getHostAddress();
        String dstIp = h.getDstAddr().getHostAddress();
        IpNumber proto = h.getProtocol();
        int id = h.getIdentification();
        // 注意：pcap4j 的 getFragmentOffset() 返回的是**纯偏移值（以 8 字节为单位）**，
        // 不含标志位；MF 必须通过 getMoreFragmentFlag() 获取。
        // 早期实现把它当作"原始 16 位字段"并做 (raw & 0x2000) 位运算，
        // 导致 MF 恒被判为 false，分片组永远无法完成重组。
        int offset = h.getFragmentOffset() * 8;
        boolean mf = h.getMoreFragmentFlag();

        // 非分片
        if (offset == 0 && !mf) {
            return new ReassembledResult(false, null, null);
        }

        // 只处理 UDP/TCP 分片（其他协议不需要端口信息）
        if (!(proto.equals(IpNumber.UDP) || proto.equals(IpNumber.TCP))) {
            // 非传输层分片，直接返回，让调用者按原样处理
            return new ReassembledResult(false, null, null);
        }

        FKey key = new FKey(srcIp, dstIp, id, proto);

        // 定期清理超时组
        cleanup();

        FGroup g = groups.computeIfAbsent(key, k -> {
            if (groups.size() >= MAX_GROUPS) {
                evictOldest();
            }
            return new FGroup();
        });

        // 提取 IP payload（IP 头之后的所有字节）
        byte[] payload;
        try {
            org.pcap4j.packet.Packet pl = ip4.getPayload();
            payload = pl != null ? pl.getRawData() : new byte[0];
        } catch (Exception e) {
            payload = new byte[0];
        }

        g.fragments.put(offset, payload);
        if (offset == 0) {
            g.firstFragmentPacket = packet;
        }

        if (!mf) {
            g.lastReceived = true;
            g.totalLength = offset + payload.length;
        }

        if (g.isComplete()) {
            groups.remove(key);

            byte[] full = concat(g);
            if (full == null || full.length == 0) {
                logger.warn("Empty reassembled payload for {} -> {} id={}", srcIp, dstIp, id);
                return null;
            }

            logger.debug("IP defrag done: {} -> {} id={}, {} frags, {} bytes",
                    srcIp, dstIp, id, g.fragments.size(), full.length);

            return new ReassembledResult(true, g.firstFragmentPacket, full);
        }

        // 分片已缓存，等待其余分片
        return null;
    }

    private byte[] concat(FGroup g) {
        int total = 0;
        for (byte[] b : g.fragments.values()) total += b.length;
        ByteBuffer buf = ByteBuffer.allocate(total);
        for (Map.Entry<Integer, byte[]> e : g.fragments.entrySet()) {
            buf.put(e.getValue());
        }
        return buf.array();
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        groups.entrySet().removeIf(e -> {
            if (now - e.getValue().firstSeenAt > GROUP_TIMEOUT_MS) {
                logger.debug("Expired frag group: {} -> {} id={}", 
                        e.getKey().srcIp(), e.getKey().dstIp(), e.getKey().identification());
                return true;
            }
            return false;
        });
    }

    private void evictOldest() {
        FKey oldest = null;
        long minTime = Long.MAX_VALUE;
        for (Map.Entry<FKey, FGroup> e : groups.entrySet()) {
            if (e.getValue().firstSeenAt < minTime) {
                minTime = e.getValue().firstSeenAt;
                oldest = e.getKey();
            }
        }
        if (oldest != null) groups.remove(oldest);
    }

    /**
     * 重组结果
     *
     * @param isReassembled         true=重组完成有完整数据; false=非分片包
     * @param firstFragmentPacket   第一个分片（offset=0）的原始 Packet（仅 isReassembled=true 时有效）
     * @param reassembledPayload    重组后的完整传输层 payload（仅 isReassembled=true 时有效）
     */
    public record ReassembledResult(
            boolean isReassembled,
            Packet firstFragmentPacket,
            byte[] reassembledPayload
    ) {}
}
