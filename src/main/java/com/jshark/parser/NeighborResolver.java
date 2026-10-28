package com.jshark.parser;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 目的 MAC 解析器。
 *
 * <h3>解析顺序（逐级回退，全部失败则返回 null 由调用方决定）</h3>
 * <ol>
 *   <li><b>组播 / 广播</b>：按标准公式直接合成，无需查询、无需探测
 *       （IPv4 组播 {@code 01:00:5E}+低 23 位；IPv6 组播 {@code 33:33}+低 32 位；广播全 FF）</li>
 *   <li><b>OS 邻居表</b>：读取系统 ARP/ND 表（Windows {@code GetIpNetTable}，Linux {@code /proc/net/arp}）</li>
 *   <li><b>主动 ARP 探测</b>：在注入网卡上直接发出 ARP 请求并等待应答（自包含，不依赖系统状态）</li>
 * </ol>
 *
 * <h3>为什么默认不需要它</h3>
 * <p>
 * 被动采集器通常运行在**混杂模式**，此时保留原帧的目的 MAC 即可，完全不需要解析
 * （即 {@code --dstMac=preserve}）。只有在采集器按自身 MAC 过滤（非混杂）时，
 * 才必须把目的 MAC 改成采集器的 MAC。
 * </p>
 *
 * <p>解析结果带缓存；解析失败的条目会记录失败时间，避免对同一目标反复探测拖慢重放。</p>
 */
public class NeighborResolver {

    private static final Logger logger = LoggerFactory.getLogger(NeighborResolver.class);

    /** 主动 ARP 探测的单次等待（毫秒） */
    private static final long ARP_PROBE_TIMEOUT_MS = 800L;
    /** 失败缓存的有效期（毫秒）：期间不再重试同一目标 */
    private static final long FAILURE_TTL_MS = 30_000L;
    /** 系统邻居表缓存的有效期（毫秒）：避免为每个新目标都启动一次 {@code arp -a} */
    private static final long NEIGHBOR_TABLE_TTL_MS = 5_000L;
    /** {@code arp -a} / {@code ip neigh} 的超时（秒）：系统命令卡住时不能拖死重放线程 */
    private static final long NEIGHBOR_COMMAND_TIMEOUT_SECONDS = 2L;

    /** 已解析成功的 IP -> MAC */
    private final Map<String, byte[]> cache = new ConcurrentHashMap<>();
    /** 解析失败的 IP -> 失败时间 */
    private final Map<String, Long> failures = new ConcurrentHashMap<>();
    /** 系统邻居表快照与刷新时间（只由解析线程写；volatile 允许其它线程安全读取） */
    private volatile Map<String, byte[]> neighborTable = Map.of();
    private volatile long neighborTableAtMs;

    /** 注入网卡（用于主动 ARP 探测）；为 null 时跳过主动探测 */
    private final PcapNetworkInterface nif;
    /** 本机发送用的源 MAC（探测请求的发送方） */
    private final byte[] localMac;
    /** 本机源 IP（探测请求的发送方，需与注入网卡同网段） */
    private final String localIp;
    /** 是否允许主动 ARP 探测 */
    private final boolean activeProbeEnabled;

    /**
     * 构造解析器。
     *
     * @param nif     注入网卡；null 表示不做主动探测
     * @param localMac 本机 MAC；null 时尝试从网卡地址推断
     * @param localIp  本机 IP（注入网卡上的地址）；null 时尝试推断
     * @param activeProbeEnabled 是否允许主动 ARP 探测
     */
    public NeighborResolver(PcapNetworkInterface nif, byte[] localMac, String localIp,
                            boolean activeProbeEnabled) {
        this.nif = nif;
        this.localMac = localMac;
        this.localIp = localIp;
        this.activeProbeEnabled = activeProbeEnabled && nif != null;
    }

    /**
     * 解析目的 IP 的 MAC。
     *
     * @param ip 目的 IP
     * @return 6 字节 MAC；无法解析返回 null
     */
    public byte[] resolve(String ip) {
        if (ip == null) {
            return null;
        }
        byte[] cached = cache.get(ip);
        if (cached != null) {
            return cached;
        }
        Long failedAt = failures.get(ip);
        if (failedAt != null && System.currentTimeMillis() - failedAt < FAILURE_TTL_MS) {
            return null;
        }

        InetAddress addr;
        try {
            addr = InetAddress.getByName(ip);
        } catch (Exception e) {
            return null;
        }

        // 1) 组播 / 广播：公式合成
        byte[] synthesized = synthesize(addr);
        if (synthesized != null) {
            cache.put(ip, synthesized);
            return synthesized;
        }

        // 2) OS 邻居表
        byte[] fromTable = lookupNeighborTable(ip);
        if (fromTable != null) {
            logger.info("[JShark] Resolved MAC for {} from OS neighbor table: {}", ip, format(fromTable));
            cache.put(ip, fromTable);
            return fromTable;
        }

        // 3) 主动 ARP 探测
        if (activeProbeEnabled) {
            byte[] probed = activeArpProbe(ip);
            if (probed != null) {
                logger.info("[JShark] Resolved MAC for {} via active ARP probe: {}", ip, format(probed));
                cache.put(ip, probed);
                return probed;
            }
        }

        logger.warn("[JShark] Cannot resolve MAC for {}. If the collector runs in promiscuous mode, "
                + "use --dstMac=preserve; otherwise specify --dstMac=<MAC> explicitly.", ip);
        failures.put(ip, System.currentTimeMillis());
        return null;
    }

    /** @return 已缓存的成功解析结果数 */
        // ==================== 1) 组播/广播合成 ====================

    /**
     * 按标准公式合成组播/广播 MAC。
     *
     * @param addr 目的地址
     * @return 6 字节 MAC；非组播/广播返回 null
     */
    static byte[] synthesize(InetAddress addr) {
        if (addr.isMulticastAddress()) {
            return multicastMac(addr);
        }
        byte[] b = addr.getAddress();
        if (b.length == 4
                && (b[0] & 0xFF) == 255 && (b[1] & 0xFF) == 255
                && (b[2] & 0xFF) == 255 && (b[3] & 0xFF) == 255) {
            return new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        }
        return null;
    }

    /**
     * 组播地址到 MAC 的标准映射。
     *
     * @param addr 组播地址（v4 或 v6）
     * @return 6 字节组播 MAC
     */
    static byte[] multicastMac(InetAddress addr) {
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            // 01:00:5E + IPv4 低 23 位
            return new byte[]{0x01, 0x00, 0x5E,
                    (byte) (b[1] & 0x7F), (byte) (b[2] & 0xFF), (byte) (b[3] & 0xFF)};
        }
        // 33:33 + IPv6 低 32 位
        return new byte[]{0x33, 0x33, b[12], b[13], b[14], b[15]};
    }

    // ==================== 2) OS 邻居表 ====================

    /** Windows {@code arp -a} / Linux {@code /proc/net/arp} 行：IP 后跟 MAC（十六进制，分隔符任意） */
    private static final Pattern NEIGHBOR_LINE = Pattern.compile(
            "(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})");

    /**
     * 读取操作系统邻居表。
     *
     * <p>邻居表有 {@value #NEIGHBOR_TABLE_TTL_MS} 毫秒的缓存：重放线程对每个新目标 IP
     * 都会查一次，若每次都启动 {@code arp -a}，大量不同目标会把开播拖成“点了 Start 没反应”。
     * 表本身变化很快，缓存 5 秒足够，且失败结果另有 30 秒负缓存。</p>
     *
     * @param ip 目标 IP
     * @return MAC；未命中返回 null
     */
    private byte[] lookupNeighborTable(String ip) {
        // Linux：直接读 /proc（不启动进程，代价很低）
        java.io.File proc = new java.io.File("/proc/net/arp");
        if (proc.isFile()) {
            try (BufferedReader r = new BufferedReader(new java.io.FileReader(proc))) {
                String line;
                while ((line = r.readLine()) != null) {
                    Matcher m = NEIGHBOR_LINE.matcher(line);
                    if (m.find() && m.group(1).equals(ip)) {
                        return parseMac(m.group(2));
                    }
                }
            } catch (Exception e) {
                logger.debug("Failed to read /proc/net/arp: {}", e.getMessage());
            }
        }

        // Windows / 其他：调用 arp -a（带缓存）
        return neighborTableSnapshot().get(ip);
    }

    /** @return 系统邻居表快照；超过 TTL 时重新读取 */
    private Map<String, byte[]> neighborTableSnapshot() {
        long now = System.currentTimeMillis();
        Map<String, byte[]> table = neighborTable;
        if (!table.isEmpty() && now - neighborTableAtMs <= NEIGHBOR_TABLE_TTL_MS) {
            return table;
        }
        synchronized (this) {
            now = System.currentTimeMillis();
            if (neighborTable.isEmpty() || now - neighborTableAtMs > NEIGHBOR_TABLE_TTL_MS) {
                Map<String, byte[]> refreshed = readArpCommand();
                // 读失败时不要用空表覆盖旧表：旧数据可能仍然有效。
                if (!refreshed.isEmpty() || neighborTable.isEmpty()) {
                    neighborTable = refreshed;
                }
                neighborTableAtMs = now;
            }
            return neighborTable;
        }
    }

    /** @return {@code arp -a} 解析出的 IP -> MAC 映射（失败返回空表） */
    private Map<String, byte[]> readArpCommand() {
        Map<String, byte[]> table = new LinkedHashMap<>();
        Process p = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(isWindows() ? new String[]{"arp", "-a"}
                    : new String[]{"ip", "neigh"});
            pb.redirectErrorStream(true);
            p = pb.start();

            // 先把输出读完（命令输出很小），但读取线程与进程都可能卡住：两者都用超时兜住。
            StringBuilder output = new StringBuilder();
            Process process = p;
            Thread reader = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        synchronized (output) {
                            output.append(line).append('\n');
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Failed to read OS neighbor table: {}", e.getMessage());
                }
            }, "jshark-arp-reader");
            reader.setDaemon(true);
            reader.start();

            if (!p.waitFor(NEIGHBOR_COMMAND_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS)) {
                logger.debug("OS neighbor table command timed out after {}s; killing it",
                        NEIGHBOR_COMMAND_TIMEOUT_SECONDS);
                p.destroyForcibly();
            }
            reader.join(500);
            if (reader.isAlive()) {
                reader.interrupt();
            }

            String text;
            synchronized (output) {
                text = output.toString();
            }
            Matcher m = NEIGHBOR_LINE.matcher(text);
            while (m.find()) {
                byte[] mac = parseMac(m.group(2));
                if (mac != null) {
                    table.put(m.group(1), mac);
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to read OS neighbor table: {}", e.getMessage());
        } finally {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
        }
        return table;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static byte[] parseMac(String s) {
        try {
            return FrameRewriter.MacPolicy.parseMac(s.replace('-', ':'));
        } catch (Exception e) {
            return null;
        }
    }

    private static String format(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02x", mac[i]));
            if (i < mac.length - 1) {
                sb.append(':');
            }
        }
        return sb.toString();
    }

    // ==================== 3) 主动 ARP 探测 ====================

    /**
     * 在注入网卡上发出 ARP 请求并等待应答。
     * <p>
     * 自包含：不依赖操作系统是否已经与该 IP 通信过。使用与注入相同的 pcap 句柄，
     * 因此不会污染业务流量，也不会改变系统邻居表。
     * </p>
     *
     * @param ip 目标 IPv4 地址
     * @return MAC；超时或非 IPv4 返回 null
     */
    private byte[] activeArpProbe(String ip) {
        if (localMac == null || localIp == null) {
            logger.debug("Active ARP probe skipped: local MAC/IP unknown");
            return null;
        }
        try {
            InetAddress target = InetAddress.getByName(ip);
            byte[] tb = target.getAddress();
            if (tb.length != 4) {
                return null;
            }
            byte[] sb = InetAddress.getByName(localIp).getAddress();
            if (sb.length != 4) {
                return null;
            }

            ArpPacket.Builder arp = new ArpPacket.Builder()
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) 6)
                    .protocolAddrLength((byte) 4)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(MacAddress.getByName(format(localMac)))
                    .srcProtocolAddr(InetAddress.getByAddress(sb))
                    .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .dstProtocolAddr(InetAddress.getByAddress(tb));

            byte[] frame = new EthernetPacket.Builder()
                    .srcAddr(MacAddress.getByName(format(localMac)))
                    .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                    .type(EtherType.ARP)
                    .payloadBuilder(arp)
                    .paddingAtBuild(true)
                    .build()
                    .getRawData();

            try (PcapHandle probe = nif.openLive(65536,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
                byte[] local = sb;
                byte[] targetBytes = tb;
                probe.setFilter("arp", org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE);
                probe.sendPacket(frame);
                logger.debug("Sent ARP request for {} on {}", ip, nif.getName());

                long deadline = System.currentTimeMillis() + ARP_PROBE_TIMEOUT_MS;
                while (System.currentTimeMillis() < deadline) {
                    Packet pkt;
                    try {
                        pkt = probe.getNextPacketEx();
                    } catch (java.util.concurrent.TimeoutException te) {
                        continue;
                    }
                    if (pkt == null || !pkt.contains(ArpPacket.class)) {
                        continue;
                    }
                    ArpPacket reply = pkt.get(ArpPacket.class);
                    if (reply.getHeader().getOperation() != ArpOperation.REPLY) {
                        continue;
                    }
                    byte[] spa = reply.getHeader().getSrcProtocolAddr().getAddress();
                    if (!java.util.Arrays.equals(spa, targetBytes)) {
                        continue;
                    }
                    byte[] sha = reply.getHeader().getSrcHardwareAddr().getAddress();
                    if (sha == null || sha.length != 6) {
                        continue;
                    }
                    // 忽略把自己的地址当成目标的异常应答
                    if (java.util.Arrays.equals(spa, local)) {
                        continue;
                    }
                    return sha;
                }
            }
        } catch (Exception e) {
            logger.debug("Active ARP probe for {} failed: {}", ip, e.getMessage());
        }
        return null;
    }
}
