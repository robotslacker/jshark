package com.jshark.parser;

import com.jshark.parser.dis.DISProtocolParser;
import com.jshark.parser.http.HTTPProtocolParser;
import com.jshark.parser.pg.PGProtocolParser;
import org.pcap4j.packet.namednumber.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * 协议解析器
 * <p>
 * 负责对解析后的数据包进行进一步的协议分析，提取详细的协议信息并填充到 additionalInfo 中。
 * 支持以下协议：
 * <ul>
 *   <li>IP层：IPv4/IPv6 版本检测</li>
 *   <li>传输层：TCP（标志位分析、窗口分析）、UDP、ICMP</li>
 *   <li>应用层：PG（PostgreSQL）、HTTP、DIS</li>
 * </ul>
 * </p>
 *
 * <p>
 * <b>性能开关：</b>构造时传入 {@code enableAdditionalInfo=false} 可关闭上述"事实分析 + 详细字段展开"，
 * 只保留 {@code application.protocol}（appProtocol 列/重放过滤需要）和 PG 切分所需的
 * {@code pg.consumed_bytes}。采集端对应 CLI 参数 {@code --enable_additioninfo}（默认 false）。
 * </p>
 *
 * <h3>PG协议检测流程：</h3>
 * <ol>
 *   <li>{@link #detectByContent(PacketParser.ParsedPacket)} 先检查数据开头是否匹配已知协议</li>
 *   <li>如果数据不以PG标签开头，检查是否有 tcp.has_buffer 或 tcp.reassembled 标记</li>
 *   <li>如果有缓冲区/重组标记，调用 {@link #isReassembledPGData} 扫描数据中是否包含PG标签</li>
 *   <li>如果检测到PG协议，调用 {@link #parsePGProtocol} 进行详细解析</li>
 * </ol>
 *
 * <h3>TCP流重组支持：</h3>
 * <p>
 * 对于TCP流重组场景（数据可能不以PG标签开头），
 * 通过 tcp.has_buffer 和 tcp.reassembled 标记来识别。
 * 扫描数据前200字节查找PG标签，找到后验证长度字段有效性，
 * 避免二进制数据中的假阳性匹配。
 * </p>
 */
public class ProtocolParser {
    private static final Logger logger = LoggerFactory.getLogger(ProtocolParser.class);

    /**
     * 是否把 DIS / HTTP / PG 的详细字段展开进 {@code additionalInfo}。
     * <p>
     * 这是性能开关：关闭后不再做 IP/传输层的事实分析，也不再展开 DIS/HTTP 的详细字段，
     * 只保留采集与重放必须的最小信息（{@code application.protocol}，以及 PG 消息切分需要的
     * {@code pg.consumed_bytes}）。数据库的 {@code additionalInfo} 列此时恒为 NULL。
     * </p>
     */
    private volatile boolean enableAdditionalInfo = true;

    /**
     * 默认构造：保持历史行为（展开 additionalInfo）。
     * <p>采集端由 CLI 参数 {@code --enable_additioninfo} 显式控制（默认 false）。</p>
     */
    public ProtocolParser() {
        this(true);
    }

    /**
     * @param enableAdditionalInfo true = 展开 DIS/HTTP/PG 详细字段；
     *                             false = 只保留采集/重放所必需的最小信息
     */
    public ProtocolParser(boolean enableAdditionalInfo) {
        this.enableAdditionalInfo = enableAdditionalInfo;
    }

    /**
     * 运行时切换详细字段展开（供采集端在参数解析完成后再应用）。
     *
     * @param enableAdditionalInfo true = 展开详细字段
     */
    public void setEnableAdditionalInfo(boolean enableAdditionalInfo) {
        this.enableAdditionalInfo = enableAdditionalInfo;
    }

    /**
     * Parse protocol details from a parsed packet and populate additionalInfo
     * @param parsedPacket the parsed packet from PacketParser
     * @return updated parsed packet with additionalInfo populated
     */
    public PacketParser.ParsedPacket parseProtocolDetails(PacketParser.ParsedPacket parsedPacket) {
        if (parsedPacket == null) {
            throw new IllegalArgumentException("Parsed packet cannot be null");
        }
        
        Map<String, Object> additionalInfo = new HashMap<>(parsedPacket.additionalInfo());
        
        try {
            if (enableAdditionalInfo) {
                // Parse IP layer details
                parseIpLayerDetails(parsedPacket, additionalInfo);

                // Parse transport layer details
                parseTransportLayerDetails(parsedPacket, additionalInfo);
            }

            // 应用协议识别始终执行：appProtocol 是独立的数据库列，重放端会用
            // --applicationProtocol 过滤它；把它和 additionalInfo 的详细展开绑在一起，
            // 会让"关闭 additionalInfo"变成"重放时按应用协议筛选失效"。
            parseApplicationLayerDetails(parsedPacket, additionalInfo);
            
        } catch (Exception e) {
            logger.warn("Error parsing protocol details: {}", e.getMessage());
        }
        
        // 返回填充了 additionalInfo 的新实例。
        // 注意：必须用 withAdditionalInfo（帧字段在记录内部原样保留）。
        // 早期实现误用 withFrame 组装，导致这里新解析出的 KV 被静默丢弃，
        // 表现为 appProtocol/additionalInfo 全空、--applicationProtocol 过滤后无数据可重放。
        return parsedPacket.withAdditionalInfo(additionalInfo);
    }
    
    /**
     * Parse IP layer details
     */
    private void parseIpLayerDetails(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        if (parsedPacket.ipProtocol() == null) {
            return;
        }
        
        // IP version detection
        if (parsedPacket.sourceIp() != null) {
            if (parsedPacket.sourceIp().contains(":")) {
                additionalInfo.put("ip.version", "IPv6");
            } else {
                additionalInfo.put("ip.version", "IPv4");
            }
        }
        
        // Protocol-specific details
        if (parsedPacket.ipProtocol().equals(IpNumber.TCP)) {
            additionalInfo.put("ip.protocol.name", "TCP");
        } else if (parsedPacket.ipProtocol().equals(IpNumber.UDP)) {
            additionalInfo.put("ip.protocol.name", "UDP");
        } else if (parsedPacket.ipProtocol().equals(IpNumber.ICMPV4)) {
            additionalInfo.put("ip.protocol.name", "ICMP");
        } else if (parsedPacket.ipProtocol().equals(IpNumber.ICMPV6)) {
            additionalInfo.put("ip.protocol.name", "ICMPv6");
        } else {
            additionalInfo.put("ip.protocol.name", parsedPacket.ipProtocol().name());
        }
    }
    
    /**
     * Parse transport layer details
     */
    private void parseTransportLayerDetails(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        if (parsedPacket.ipProtocol() == null) {
            return;
        }
        
        // Check for TCP
        if (parsedPacket.ipProtocol().equals(org.pcap4j.packet.namednumber.IpNumber.TCP)) {
            String flags = (String) additionalInfo.get("tcp.flags");
            if (flags != null) {
                additionalInfo.put("tcp.flags.analysis", analyzeTcpFlags(flags));

                // Connection state analysis
                if (flags.contains("S") && !flags.contains("A")) {
                    additionalInfo.put("tcp.connection.state", "SYN (Connection Request)");
                } else if (flags.contains("S") && flags.contains("A")) {
                    additionalInfo.put("tcp.connection.state", "SYN-ACK (Connection Response)");
                } else if (flags.contains("F")) {
                    additionalInfo.put("tcp.connection.state", "FIN (Connection Termination)");
                } else if (flags.contains("R")) {
                    additionalInfo.put("tcp.connection.state", "RST (Connection Reset)");
                }
            }

            // Window size analysis
            Object windowObj = additionalInfo.get("tcp.window");
            if (windowObj instanceof Integer) {
                int window = (Integer) windowObj;
                additionalInfo.put("tcp.window.size", window + " bytes");
                if (window < 1024) {
                    additionalInfo.put("tcp.window.analysis", "Small window (potential congestion)");
                } else if (window > 65535) {
                    additionalInfo.put("tcp.window.analysis", "Large window (high throughput)");
                }
            }
        }
        // Check for UDP
        else if (parsedPacket.ipProtocol().equals(org.pcap4j.packet.namednumber.IpNumber.UDP)) {
            Object lengthObj = additionalInfo.get("udp.length");
            if (lengthObj instanceof Short) {
                int length = ((Short) lengthObj) & 0xFFFF;
                additionalInfo.put("udp.packet.length", length + " bytes");

                // Calculate payload length (subtract 8 bytes for UDP header)
                int payloadLength = length - 8;
                if (payloadLength > 0) {
                    additionalInfo.put("udp.payload.length", payloadLength + " bytes");
                }
            }
        }
        // Check for ICMPv4
        else if (parsedPacket.ipProtocol().equals(org.pcap4j.packet.namednumber.IpNumber.ICMPV4)) {
            additionalInfo.put("icmp.protocol", "ICMPv4");
        }
        // Check for ICMPv6
        else if (parsedPacket.ipProtocol().equals(org.pcap4j.packet.namednumber.IpNumber.ICMPV6)) {
            additionalInfo.put("icmp.protocol", "ICMPv6");
        }
    }
    
    /**
     * Parse application layer details
     */
    private void parseApplicationLayerDetails(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        // Detect application protocol
        ApplicationProtocol appProtocol = detectApplicationProtocol(parsedPacket);
        
        // Store protocol information
        additionalInfo.put("application.protocol", appProtocol.name());

        if (!enableAdditionalInfo) {
            // 关闭详细展开时只保留"采集/重放必需"的最小信息：
            //   - application.protocol：appProtocol 列与重放过滤
            //   - pg.consumed_bytes：PG 的 TCP 消息切分依赖它（见 PacketCapture#completeMessageBytes），
            //     缺了它重组窗口永远不会被消费，会直接把采集逻辑改坏。
            // DIS/HTTP 的切分由 MessageFramer 只按字节长度完成，不需要详细解析。
            if (appProtocol == ApplicationProtocol.PG) {
                retainPGConsumedBytes(parsedPacket, additionalInfo);
            }
            return;
        }

        // Call specific protocol parser based on detected protocol
        switch (appProtocol) {
            case DIS:
                parseDISProtocol(parsedPacket, additionalInfo);
                break;
            case HTTP:
                parseHTTPProtocol(parsedPacket, additionalInfo);
                break;
            case PG:
                parsePGProtocol(parsedPacket, additionalInfo);
                break;
            // Add more protocol parsers as needed
            default:
                // For unknown or unsupported protocols, just log basic info
                logger.debug("Application protocol {} detected but no specific parser available", appProtocol);
                break;
        }
    }

    /**
     * 只保留 PG 消息切分所需的 {@code pg.consumed_bytes}，不展开其他 pg.* 字段。
     * <p>
     * 为什么不能像 DIS/HTTP 一样完全不解析：{@link MessageFramer} 对 PG 不做长度扫描
     * （PG 的启动消息没有标签，普通消息的消耗字节数还取决于消息类型），
     * 上层完全依赖解析器给出的 {@code consumed_bytes} 决定"能从重组窗口消费多少字节"。
     * 把它也跳过会让 PG 流的窗口无限增长、并让每条记录携带越来越大的 rawData。
     * </p>
     */
    private void retainPGConsumedBytes(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        try {
            byte[] rawData = parsedPacket.rawData();
            if (rawData == null || rawData.length == 0) {
                return;
            }
            Map<String, Object> pgDetails = new PGProtocolParser().parse(rawData);
            Object consumed = pgDetails.get("consumed_bytes");
            if (consumed instanceof Integer) {
                additionalInfo.put("pg.consumed_bytes", consumed);
            }
        } catch (Exception e) {
            // 纯优化路径：解析失败时不写入任何详情，行为与"没有可消费字节"一致
            logger.debug("PG framing parse failed while additionalInfo is disabled: {}", e.getMessage());
        }
    }
    
    /**
     * Analyze TCP flags
     */
    private String analyzeTcpFlags(String flags) {
        StringBuilder analysis = new StringBuilder();
        
        if (flags.contains("S")) analysis.append("SYN ");
        if (flags.contains("A")) analysis.append("ACK ");
        if (flags.contains("F")) analysis.append("FIN ");
        if (flags.contains("R")) analysis.append("RST ");
        if (flags.contains("P")) analysis.append("PSH ");
        if (flags.contains("U")) analysis.append("URG ");
        
        return analysis.toString().trim();
    }
    
    /**
     * 检测应用层协议
     * 根据端口号和原始数据内容识别应用协议
     *
     * @param parsedPacket 解析后的数据包
     * @return 检测到的应用协议枚举
     */
    private ApplicationProtocol detectApplicationProtocol(PacketParser.ParsedPacket parsedPacket) {
        if (parsedPacket.rawData() == null || parsedPacket.rawData().length == 0) {
            return ApplicationProtocol.UNKNOWN;
        }
        
        // 基于数据内容推断应用协议
        return detectByContent(parsedPacket);
    }

    /**
     * 基于数据内容检测应用协议
     * 检测逻辑：
     * 1. 先检查数据开头是否匹配已知协议（DIS/HTTP/PG）
     * 2. 对于TCP流重组场景（tcp.has_buffer=true），如果数据不以PG标签开头，
     *    扫描数据中是否包含PG标签（可能是PG消息的中间部分）
     * 3. 对于已标记为重组完成的数据（tcp.reassembled=true），同样扫描PG标签
     */
    private ApplicationProtocol detectByContent(PacketParser.ParsedPacket parsedPacket)
    {
        byte[] rawData = parsedPacket.rawData();
        if (rawData == null || rawData.length == 0) {
            return ApplicationProtocol.UNKNOWN;
        }
        
        // 检查DIS协议（PDU格式）
        if (isDISProtocol(rawData)) {
            return ApplicationProtocol.DIS;
        }
        
        // 检查HTTP协议
        if (isHTTPProtocol(rawData)) {
            return ApplicationProtocol.HTTP;
        }
        
        // 检查PG协议
        if (isPGProtocol(rawData)) {
            return ApplicationProtocol.PG;
        }
        
        // 检查是否有TCP缓冲区（正在收集中）或已标记为重组完成
        // 如果有缓冲区，说明当前流正在收集分片数据，数据可能不以PG标签开头
        // 但仍然可能是PG消息的中间部分，需要扫描PG标签
        Object hasBuffer = parsedPacket.additionalInfo().get("tcp.has_buffer");
        Object reassembled = parsedPacket.additionalInfo().get("tcp.reassembled");
        boolean isBufferOrReassembled = "true".equals(hasBuffer) || "true".equals(reassembled);
        
        if (isBufferOrReassembled && isReassembledPGData(parsedPacket, rawData)) {
            return ApplicationProtocol.PG;
        }
        
        return ApplicationProtocol.UNKNOWN;
    }

    /**
     * 检查TCP重组或缓冲区中的数据是否包含PG消息
     * 适用场景：
     * 1. tcp.reassembled=true：重组完成的数据，头部可能不是PG标签开头（PG消息的中间部分）
     * 2. tcp.has_buffer=true：当前流有缓冲区（正在收集中），数据可能不以PG标签开头
     * 在这两种情况下，扫描数据中是否包含PG标签来判断是否为PG协议
     */
    private boolean isReassembledPGData(PacketParser.ParsedPacket parsedPacket, byte[] data) {
        // 检查是否有缓冲区或已重组完成
        Object hasBuffer = parsedPacket.additionalInfo().get("tcp.has_buffer");
        Object reassembled = parsedPacket.additionalInfo().get("tcp.reassembled");
        boolean isBufferOrReassembled = "true".equals(hasBuffer) || "true".equals(reassembled);
        if (!isBufferOrReassembled) {
            return false;
        }
        
        if (data == null || data.length < 5) {
            return false;
        }
        
        // 扫描数据前200字节，查找是否包含PG标签
        // 找到标签后还需验证长度字段有效，避免二进制数据中的假阳性
        int scanLimit = Math.min(data.length, 200);
        for (int i = 0; i <= scanLimit - 5; i++) {
            char c = (char) (data[i] & 0xFF);
            boolean isKnownFrontend = com.jshark.parser.pg.PGEnums.FrontendMessageType.fromTag(c)
                    != com.jshark.parser.pg.PGEnums.FrontendMessageType.UNKNOWN;
            boolean isKnownBackend = com.jshark.parser.pg.PGEnums.BackendMessageType.fromTag(c)
                    != com.jshark.parser.pg.PGEnums.BackendMessageType.UNKNOWN;
            
            if (isKnownFrontend || isKnownBackend) {
                // 找到PG标签，验证长度字段是否有效
                // 长度字段在标签后的4字节，必须 >= 4 且不超出数据范围
                try {
                    java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(data, i + 1, data.length - i - 1);
                    bb.order(java.nio.ByteOrder.BIG_ENDIAN);
                    int messageLength = bb.getInt();
                    if (messageLength >= 4 && (i + 1 + messageLength) <= data.length) {
                        return true;
                    }
                } catch (Exception e) {
                    // 长度字段解析失败，继续扫描
                }
            }
        }
        
        return false;
    }
    
    /**
     * 检查是否为DIS协议数据
     */
    private boolean isDISProtocol(byte[] data) {
        if (data == null || data.length < 12) {
            return false;
        }
        
        try {
            // DIS Header 至少 12 字节
            // 字节0: 协议版本 (Protocol Version)
            int version = data[0] & 0xFF;
            
            // 使用ByteBuffer读取PDU长度，确保字节序一致性
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN); // DIS协议使用大端字节序
            
            // 跳过前8个字节（协议版本1 + 演习ID1 + PDU类型1 + 协议族1 + 时间戳4 = 8字节）
            // PDU长度在字节8-9
            buffer.position(8);
            int pduLength = buffer.getShort() & 0xFFFF;

            // 逻辑判定：版本在合理范围 且 报文声明长度与抓到的数据长度匹配
            return version >= 5 && version <= 7 && pduLength == data.length;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 检查是否为HTTP协议数据
     */
    private boolean isHTTPProtocol(byte[] data) {
        if (data == null || data.length < 4) {
            return false;
        }
        
        try {
            // 使用HTTP协议解析器检查
            HTTPProtocolParser httpParser = new HTTPProtocolParser();
            return httpParser.isValidHTTPData(data);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 检查是否为PG协议数据
     */
    private boolean isPGProtocol(byte[] data) {
        if (data == null || data.length < 1) {
            return false;
        }

        try {
            PGProtocolParser pgParser = new PGProtocolParser();
            return pgParser.isValidPGData(data);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 解析DIS协议
     */
    private void parseDISProtocol(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        try {
            // 创建DIS协议解析器实例
            DISProtocolParser disParser = new DISProtocolParser();
            byte[] rawData = parsedPacket.rawData();
            
            if (rawData == null || rawData.length == 0) {
                additionalInfo.put("dis.error", "No raw data available for DIS parsing");
                return;
            }
            
            // 检查是否为有效的DIS PDU
            boolean isValid = disParser.isValidDISPDU(rawData);
            additionalInfo.put("dis.pdu.valid", isValid);
            
            if (isValid) {
                // 进行详细解析
                Map<String, Object> disDetails = disParser.parse(rawData);

                // 将DIS解析结果添加到additionalInfo中，添加前缀避免冲突
                for (Map.Entry<String, Object> entry : disDetails.entrySet()) {
                    additionalInfo.put("dis." + entry.getKey(), entry.getValue());
                }
            } else {
                additionalInfo.put("dis.warning", "Data may not be a valid DIS PDU");
            }
            
        } catch (Exception e) {
            additionalInfo.put("dis.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析HTTP协议
     */
    private void parseHTTPProtocol(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        try {
            // 创建HTTP协议解析器实例
            HTTPProtocolParser httpParser = new HTTPProtocolParser();
            byte[] rawData = parsedPacket.rawData();
            
            if (rawData == null || rawData.length == 0) {
                additionalInfo.put("http.error", "No raw data available for HTTP parsing");
                return;
            }
            
            // 检查是否为有效的HTTP数据
            boolean isValid = httpParser.isValidHTTPData(rawData);
            additionalInfo.put("http.valid", isValid);
            
            if (isValid) {
                // 进行详细解析
                Map<String, Object> httpDetails = httpParser.parse(rawData);

                // 将HTTP解析结果添加到additionalInfo中，添加前缀避免冲突
                for (Map.Entry<String, Object> entry : httpDetails.entrySet()) {
                    additionalInfo.put("http." + entry.getKey(), entry.getValue());
                }
            } else {
                additionalInfo.put("http.warning", "Data may not be valid HTTP");
            }
            
        } catch (Exception e) {
            additionalInfo.put("http.parse.error", e.getMessage());
        }
    }

    /**
     * 解析PG协议
     */
    private void parsePGProtocol(PacketParser.ParsedPacket parsedPacket, Map<String, Object> additionalInfo) {
        try {
            // 创建PG协议解析器实例
            PGProtocolParser pgParser = new PGProtocolParser();
            byte[] rawData = parsedPacket.rawData();

            if (rawData == null || rawData.length == 0) {
                additionalInfo.put("pg.error", "No raw data available for PG parsing");
                return;
            }

            // 检查是否为有效的PG数据
            boolean isValid = pgParser.isValidPGData(rawData);
            additionalInfo.put("pg.valid", isValid);

            // 检查是否有缓冲区或已重组完成（TCP流重组场景）
            Object hasBuffer = additionalInfo.get("tcp.has_buffer");
            Object reassembled = additionalInfo.get("tcp.reassembled");
            boolean isBufferOrReassembled = "true".equals(hasBuffer) || "true".equals(reassembled);

            if (isValid || isBufferOrReassembled) {
                // 对于有效的PG数据，或者有缓冲区/重组标记的数据，都尝试解析
                // 有缓冲区/重组标记时，数据可能不以PG标签开头（PG消息的中间部分），
                // 但 pgParser.parse() 内部会扫描PG标签并从第一个标签开始解析
                Map<String, Object> pgDetails = pgParser.parse(rawData);

                // 将PG解析结果添加到additionalInfo中，添加前缀避免冲突
                for (Map.Entry<String, Object> entry : pgDetails.entrySet()) {
                    additionalInfo.put("pg." + entry.getKey(), entry.getValue());
                }
            } else {
                additionalInfo.put("pg.warning", "Data may not be valid PG protocol");
            }

        } catch (Exception e) {
            additionalInfo.put("pg.parse.error", e.getMessage());
        }
    }
}