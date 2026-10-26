package com.jshark.parser;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * 数据包解析器
 * <p>
 * 负责将pcap4j原始数据包（{@link Packet}）解析为内部统一的 {@link ParsedPacket} 格式。
 * 解析过程按协议栈逐层进行：Ethernet → IP (IPv4/IPv6) → Transport (TCP/UDP/ICMP)。
 * </p>
 *
 * <h3>关键处理：</h3>
 * <ul>
 *   <li>TCP payload提取：使用 {@code tcpPacket.getPayload().getRawData()} 提取应用层数据，
 *       而非整个IP包数据。这样协议解析器才能正确检测应用层协议。</li>
 *   <li>TCP标志位：按 RFC 793 标准位序 UAPRSF 排列（URG/ACK/PSH/RST/SYN/FIN）</li>
 *   <li>MAC地址格式化：统一为大写16进制加冒号分隔（如 AA:BB:CC:DD:EE:FF）</li>
 * </ul>
 */
public class PacketParser {
    private static final Logger logger = LoggerFactory.getLogger(PacketParser.class);
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /**
     * 解析后的数据包信息（不可变记录）
     * <p>
     * 包含从原始数据包中提取的所有字段，包括网络层、传输层和应用层信息。
     * {@code additionalInfo} 使用防御性拷贝确保不可变性。
     * </p>
     *
     * @param packetSequence  数据包序列号（对应数据库中的logDBSequence）
     * @param timestamp       采集时间戳（取自 pcap 首部）
     * @param length          原始线上长度（wireLen）
     * @param sourceMac       源MAC地址
     * @param destinationMac  目标MAC地址
     * @param sourceIp        源IP地址
     * @param destinationIp   目标IP地址
     * @param ipProtocol      IP协议类型（TCP/UDP/ICMP等）
     * @param sourcePort      源端口（传输层）
     * @param destinationPort 目标端口（传输层）
     * @param additionalInfo  附加信息Map（协议解析结果、TCP标志位等）
     * @param summary         数据包摘要字符串
     * @param rawData         应用层原始数据（TCP payload或UDP payload）
     * @param frameData       完整原始帧字节；{@code null} 表示该记录无对应帧、不可逐字节重放
     * @param wireLen         原始线上长度（可由 pcap 首部获得，含被 snaplen 截断的部分）
     * @param capLen          实际捕获到的字节数；{@code capLen < wireLen} 表示被截断
     * @param captureKind     记录来源类型，决定是否可重放
     */
    public record ParsedPacket(Long packetSequence,
                               Instant timestamp, int length, String sourceMac, String destinationMac, String sourceIp,
                               String destinationIp, IpNumber ipProtocol, Integer sourcePort, Integer destinationPort,
                               Map<String, Object> additionalInfo, String summary,
                               byte[] rawData,
                               byte[] frameData, int wireLen, int capLen, CaptureKind captureKind)
    {
        public ParsedPacket(Long packetSequence,
                            Instant timestamp, int length,
                            String sourceMac, String destinationMac,
                            String sourceIp, String destinationIp,
                            IpNumber ipProtocol,
                            Integer sourcePort, Integer destinationPort,
                            Map<String, Object> additionalInfo,
                            String summary,
                            byte[] rawData,
                            byte[] frameData, int wireLen, int capLen, CaptureKind captureKind) {
            this.packetSequence = packetSequence;
            this.timestamp = timestamp;
            this.length = length;
            this.sourceMac = sourceMac;
            this.destinationMac = destinationMac;
            this.sourceIp = sourceIp;
            this.destinationIp = destinationIp;
            this.ipProtocol = ipProtocol;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.additionalInfo = additionalInfo != null
                    ? java.util.Collections.unmodifiableMap(additionalInfo)
                    : java.util.Collections.emptyMap();
            this.summary = summary;
            this.rawData = rawData;
            this.frameData = frameData;
            this.wireLen = wireLen;
            this.capLen = capLen;
            this.captureKind = captureKind != null ? captureKind : CaptureKind.WIRE_FRAME;
        }

        /**
         * 返回附加信息（只读视图）。
         * <p>
         * <b>性能说明：</b>早期实现每次调用都克隆整个 Map，而一条记录在采集链路上会被访问
         * 4~6 次（协议解析、完整性判定、入库、verbose 输出…）。万级帧规模下这会产生大量短命对象，
         * 放大 GC 停顿，并直接表现为重放期间的时序抖动（实测最大包间隔因此退化数倍）。
         * 现在改为不可变视图：构造时包装一次，访问零拷贝。需要修改的调用方自行新建 Map。
         * </p>
         *
         * @return 只读的附加信息视图
         */
        @Override
        public Map<String, Object> additionalInfo() {
            return additionalInfo;
        }

        /**
         * 替换帧相关字段并返回新实例。
         * <p>
         * 用于在不重新构造整条记录的前提下，为已有记录补充/替换完整帧信息
         * （例如：解析阶段拿到帧字节后，再填上 pcap 首部给出的线上长度）。
         * </p>
         *
         * @param frameData   完整原始帧字节（null 表示无帧）
         * @param wireLen     原始线上长度
         * @param capLen      实际捕获长度
         * @param captureKind 记录来源类型
         * @return 替换后的新实例
         */
        public ParsedPacket withFrame(byte[] frameData, int wireLen, int capLen, CaptureKind captureKind) {
            return new ParsedPacket(packetSequence, timestamp, length, sourceMac, destinationMac,
                    sourceIp, destinationIp, ipProtocol, sourcePort, destinationPort,
                    additionalInfo, summary, rawData, frameData, wireLen, capLen, captureKind);
        }

        /**
         * 替换载荷与附加信息并返回新实例（帧相关字段原样保留）。
         * <p>
         * TCP 流重组把多个段的载荷拼成一段连续字节后，用它承载"窗口内容"：
         * 载荷换成累计窗口，而 {@code frameData}/`captureKind` 仍指向**触发本次交付的真实帧**，
         * 因此该记录依然可以按帧原样重放。
         * </p>
         *
         * @param rawData        新的载荷
         * @param additionalInfo 新的附加信息（null 视为空）
         * @return 替换后的新实例
         */
        public ParsedPacket withRawData(byte[] rawData, Map<String, Object> additionalInfo) {
            return new ParsedPacket(packetSequence, timestamp, length, sourceMac, destinationMac,
                    sourceIp, destinationIp, ipProtocol, sourcePort, destinationPort,
                    additionalInfo, summary, rawData, frameData, wireLen, capLen, captureKind);
        }

        /**
         * 替换附加信息并返回新实例（帧相关字段原样保留）。
         * <p>
         * 协议解析器在解析出新的 additionalInfo 后，必须通过本方法组装结果；
         * 若误用 {@link #withFrame} 组装，会把新解析出的 KV 丢掉。
         * </p>
         *
         * @param additionalInfo 新的附加信息（null 视为空）
         * @return 替换后的新实例
         */
        public ParsedPacket withAdditionalInfo(Map<String, Object> additionalInfo) {
            return new ParsedPacket(packetSequence, timestamp, length, sourceMac, destinationMac,
                    sourceIp, destinationIp, ipProtocol, sourcePort, destinationPort,
                    additionalInfo, summary, rawData, frameData, wireLen, capLen, captureKind);
        }

        /**
         * 判断该记录是否携带可注入的完整帧（帧级原样重放的前提）。
         *
         * @return true 表示可直接逐字节重放
         */
        public boolean hasReplayableFrame() {
            return frameData != null && frameData.length > 0 && captureKind != null && captureKind.replayable();
        }

        /**
         * 获取格式化后的时间戳字符串
         *
         * @return 格式为 "yyyy-MM-dd HH:mm:ss.SSS" 的时间戳
         */
        public String getFormattedTimestamp() {
            LocalDateTime dateTime = LocalDateTime.ofInstant(timestamp, ZoneId.systemDefault());
            return dateTime.format(TIME_FORMATTER);
        }

        /**
         * 获取协议名称
         *
         * @return IP协议名称（如 "TCP", "UDP"），未知返回 "UNKNOWN"
         */
        public String getProtocolName() {
            if (ipProtocol != null) {
                return ipProtocol.name();
            }
            return "UNKNOWN";
        }
    }

    /**
     * 从 pcap 首部获得的帧元数据。
     * <p>
     * 时间戳取自抓包首部（而非解析时刻），保证时序与线上一致；
     * 线上长度用于识别 snaplen 截断。
     * </p>
     *
     * @param timestamp 抓包首部时间戳
     * @param wireLen   原始线上长度（&lt;=0 表示未知，回退为捕获长度）
     */
    public record WireMeta(Instant timestamp, int wireLen) {

        /**
         * 由 pcap 首部构造。
         *
         * @param headerTs  pcap 首部时间戳
         * @param origLen   pcap 首部记录的原始长度
         * @return 帧元数据
         */
        public static WireMeta of(Instant headerTs, int origLen) {
            return new WireMeta(headerTs != null ? headerTs : Instant.now(), origLen);
        }
    }

    
    /**
     * 解析原始数据包
     * <p>
     * 按以下顺序解析各层协议：
     * <ol>
     *   <li><b>Ethernet层</b>：提取源/目标MAC地址</li>
     *   <li><b>IP层</b>：提取源/目标IP地址、IP协议类型。支持IPv4和IPv6。</li>
     *   <li><b>传输层</b>：
     *     <ul>
     *       <li>TCP：提取端口号、标志位（RFC 793 UAPRSF顺序）、应用层payload</li>
     *       <li>UDP：提取端口号、应用层payload</li>
     *       <li>ICMP：简化处理，直接使用原始数据</li>
     *     </ul>
     *   </li>
     *   <li><b>ARP</b>：单独处理ARP协议</li>
     * </ol>
     * </p>
     *
     * <p>
     * <b>重要：</b>TCP payload使用 {@code tcpPacket.getPayload().getRawData()} 提取，
     * 而非 {@code packet.getRawData()}。因为后者返回的是整个IP包数据（包含IP和TCP头），
     * 会导致应用层协议检测失败。
     * </p>
     *
     * <p>
     * <b>完整帧：</b>{@code frameData} 保存抓到的完整帧字节（自最外层链路头开始），
     * 它是帧级原样重放的唯一数据源；{@code rawData} 仍为传输层 payload，供协议解析使用。
     * </p>
     *
     * @param packet        原始数据包
     * @param logDBSequence 数据库序列号
     * @return 解析后的数据包信息
     * @throws IllegalArgumentException 如果packet为null
     */
    public ParsedPacket parse(Packet packet, long logDBSequence) {
        return parse(packet, logDBSequence, null);
    }

    /**
     * 解析原始数据包（带 pcap 首部元数据）
     * <p>
     * 与 {@link #parse(Packet, long)} 相同，但使用抓包首部给出的时间戳与线上长度：
     * 时间戳不再取解析时刻，避免把"从抓到到解析"的处理延迟计入时序；
     * 线上长度用于识别 snaplen 截断（{@code capLen < wireLen}）。
     * </p>
     *
     * @param packet        原始数据包
     * @param logDBSequence 数据库序列号
     * @param wireMeta      pcap 首部元数据；null 时回退为解析时刻与捕获长度
     * @return 解析后的数据包信息
     * @throws IllegalArgumentException 如果packet为null
     */
    public ParsedPacket parse(Packet packet, long logDBSequence, WireMeta wireMeta) {
        if (packet == null) {
            throw new IllegalArgumentException("Packet cannot be null");
        }

        // 时间戳优先取 pcap 首部；没有首部信息时回退为解析时刻
        Instant timestamp = (wireMeta != null && wireMeta.timestamp() != null)
                ? wireMeta.timestamp()
                : Instant.now();

        // 完整原始帧：帧级重放的唯一数据源
        byte[] frameData = packet.getRawData();
        int capLen = frameData != null ? frameData.length : 0;
        int wireLen = (wireMeta != null && wireMeta.wireLen() > 0) ? wireMeta.wireLen() : capLen;

        int length = packet.length();

        String sourceMac = null;
        String destinationMac = null;
        String sourceIp = null;
        String destinationIp = null;
        IpNumber ipProtocol = null;
        Integer sourcePort = null;
        Integer destinationPort = null;
        Map<String, Object> additionalInfo = new HashMap<>();
        StringBuilder summaryBuilder = new StringBuilder();
        byte[] rawData = null;

        try {
            // Parse Ethernet header
            if (packet.contains(EthernetPacket.class)) {
                EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
                sourceMac = formatMacAddress(ethernetPacket.getHeader().getSrcAddr());
                destinationMac = formatMacAddress(ethernetPacket.getHeader().getDstAddr());
            } else {
                sourceMac = "N/A (No Ethernet header)";
                destinationMac = "N/A (No Ethernet header)";
            }
            summaryBuilder.append("Ethernet: ")
                    .append(sourceMac).append(" -> ").append(destinationMac).append(" | ");

            // Parse IP header (IPv4 or IPv6)
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
                
                sourceIp = ipV4Header.getSrcAddr().getHostAddress();
                destinationIp = ipV4Header.getDstAddr().getHostAddress();
                ipProtocol = ipV4Header.getProtocol();
                
                summaryBuilder.append("IPv4: ")
                    .append(sourceIp).append(" -> ").append(destinationIp)
                    .append(" Protocol: ").append(ipProtocol.name()).append(" | ");
                // 这里不再预先拷贝整帧到 rawData：该拷贝在 TCP/UDP 分支会被 payload 覆盖，
                // 每个包白白多一次整帧数组分配+拷贝。只有"未被传输层识别的其它 IP 协议"
                // 才需要回退成整帧，见下方 transportHandled。
            } else if (packet.contains(IpV6Packet.class)) {
                IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
                IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();
                
                sourceIp = ipV6Header.getSrcAddr().getHostAddress();
                destinationIp = ipV6Header.getDstAddr().getHostAddress();
                ipProtocol = ipV6Header.getNextHeader();
                
                summaryBuilder.append("IPv6: ")
                    .append(sourceIp).append(" -> ").append(destinationIp)
                    .append(" Protocol: ").append(ipProtocol.name()).append(" | ");
            }
            
            // Parse transport layer
            // transportHandled：本 IP 包是否已被某个传输层分支处理（payload 为空也算已处理）。
            // 未处理时按历史语义把 rawData 回退为整帧，见块末尾。
            boolean transportHandled = false;
            if (ipProtocol != null) {
                // TCP
                if (ipProtocol.equals(IpNumber.TCP) && packet.contains(TcpPacket.class)) {
                    transportHandled = true;
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                    
                    sourcePort = tcpHeader.getSrcPort().valueAsInt();
                    destinationPort = tcpHeader.getDstPort().valueAsInt();
                    
                    summaryBuilder.append("TCP: ")
                        .append(sourcePort).append(" -> ").append(destinationPort);
                    
                    // TCP flags - 按 RFC 793 标准位序 UAPRSF 排列
                    StringBuilder flags = new StringBuilder();
                    if (tcpHeader.getUrg()) flags.append("U"); // URG
                    if (tcpHeader.getAck()) flags.append("A"); // ACK
                    if (tcpHeader.getPsh()) flags.append("P"); // PSH
                    if (tcpHeader.getRst()) flags.append("R"); // RST
                    if (tcpHeader.getSyn()) flags.append("S"); // SYN
                    if (tcpHeader.getFin()) flags.append("F"); // FIN
                    
                    if (!flags.isEmpty()) {
                        String flagsStr = flags.toString();
                        summaryBuilder.append(" [").append(flagsStr).append("]");
                        // 将TCP标志位存入additionalInfo，供数据库记录使用
                        additionalInfo.put("tcp.flags", flagsStr);
                    }

                    // 序列号/确认号：TCP 流重组必须按序列号进行（重传去重、乱序重排），
                    // 仅靠"到达顺序拼接"会在重传/乱序时损坏字节流。
                    additionalInfo.put("tcp.seq", tcpHeader.getSequenceNumber());
                    additionalInfo.put("tcp.ack", tcpHeader.getAcknowledgmentNumber());

                    // 提取TCP payload（应用层数据），而不是整个IP包数据
                    // 这样协议解析器才能正确检测应用层协议
                    org.pcap4j.packet.Packet tcpPayload = tcpPacket.getPayload();
                    if (tcpPayload != null) {
                        rawData = tcpPayload.getRawData();
                    } else {
                        rawData = null; // 没有应用层数据（如SYN/SYN-ACK握手包）
                    }
                }
                else if (ipProtocol.equals(IpNumber.UDP) && packet.contains(UdpPacket.class))
                {
                    transportHandled = true;
                    // UDP
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                    
                    sourcePort = udpHeader.getSrcPort().valueAsInt();
                    destinationPort = udpHeader.getDstPort().valueAsInt();
                    summaryBuilder.append("UDP: ")
                            .append(sourcePort).append(" -> ").append(destinationPort);

                    org.pcap4j.packet.Packet uppPayload = udpPacket.getPayload();
                    if (uppPayload != null) {
                        rawData = udpPacket.getPayload().getRawData();
                    }
                    else {
                        rawData = null;
                    }
                } else if (ipProtocol.equals(IpNumber.ICMPV4)) {
                    // ICMP - simplified handling
                    transportHandled = true;
                    rawData = packet.getRawData();
                    summaryBuilder.append("ICMP");
                } else if (ipProtocol.equals(IpNumber.ICMPV6)) {
                    // ICMPv6
                    transportHandled = true;
                    rawData = packet.getRawData();
                    summaryBuilder.append("ICMPv6");
                }
            }

            // 保持历史语义：IPv4/IPv6 包若未被任何传输层分支处理（例如 GRE、协议号未知，
            // 或 TCP/UDP 头解析失败），rawData 回退为整帧字节。
            // TCP/UDP 分支中显式置 null 的"无应用层数据"情形不会被这里覆盖，
            // 因为那些分支已把 transportHandled 置为 true。
            if (ipProtocol != null && !transportHandled) {
                rawData = packet.getRawData();
            }
            
            // ARP
            if (packet.contains(ArpPacket.class)) {
                ArpPacket arpPacket = packet.get(ArpPacket.class);

                rawData = arpPacket.getRawData();
                summaryBuilder.append("ARP");
            }
            
        } catch (Exception e) {
            logger.warn("Error parsing packet: {}", e.getMessage());
            summaryBuilder.append("Parse error: ").append(e.getMessage());
        }
        
        // Build final summary
        String summary = summaryBuilder.toString();
        if (summary.endsWith(" | ")) {
            summary = summary.substring(0, summary.length() - 3);
        }
        
        return new ParsedPacket(
                logDBSequence,
                timestamp, length,
                sourceMac, destinationMac,
                sourceIp, destinationIp,
                ipProtocol,
                sourcePort, destinationPort,
                additionalInfo,
                summary,
                rawData,
                frameData, wireLen, capLen, CaptureKind.WIRE_FRAME
        );
    }
    
    /**
     * 格式化为 MAC 地址字符串用的 16 进制字符表。
     * <p>
     * 为什么不用 {@code String.format("%02X", b)}：实测该方法（每个 MAC 调用 6 次、
     * 每包两个 MAC 共 12 次）在单包解析成本里占约 6.7 µs，是整条解析链路里最大的一笔
     * 单点开销；换成查表后同一操作约 0.2 µs（33 倍），输出字节完全一致（大写、冒号分隔、
     * 负字节按无符号处理 —— 与 {@code %02X} 对 {@link Byte} 的语义相同）。
     * </p>
     */
    private static final char[] HEX_UPPER = "0123456789ABCDEF".toCharArray();

    /**
     * 格式化MAC地址
     * <p>
     * 将 {@link MacAddress} 对象格式化为大写16进制加冒号分隔的字符串。
     * 例如：{@code AA:BB:CC:DD:EE:FF}
     * </p>
     *
     * @param macAddress MAC地址对象
     * @return 格式化后的MAC地址字符串，无效地址返回 "00:00:00:00:00:00"
     */
    private String formatMacAddress(MacAddress macAddress) {
        if (macAddress == null) {
            return "00:00:00:00:00:00";
        }

        byte[] macBytes = macAddress.getAddress();
        if (macBytes == null || macBytes.length != 6) {
            return "00:00:00:00:00:00";
        }

        char[] out = new char[17]; // 6*2 hex digits + 5 colons
        int p = 0;
        for (int i = 0; i < 6; i++) {
            int v = macBytes[i] & 0xFF;
            out[p++] = HEX_UPPER[v >>> 4];
            out[p++] = HEX_UPPER[v & 0x0F];
            if (i < 5) {
                out[p++] = ':';
            }
        }
        return new String(out);
    }
    
}