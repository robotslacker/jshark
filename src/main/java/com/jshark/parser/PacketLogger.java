package com.jshark.parser;

import com.jshark.PacketCaptureException;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.sql.Connection;
import java.util.Map;

/**
 * 数据包日志记录器
 * <p>
 * 负责将解析后的数据包输出到控制台（verbose模式）和PCAP文件。
 * 内部使用 {@link ProtocolParser} 对数据包进行应用层协议解析，
 * 并将结果记录到数据库（通过 {@link PacketDBEventHandler} 异步写入）。
 * </p>
 *
 * <h3>功能：</h3>
 * <ul>
 *   <li>控制台输出：verbose模式下显示详细的数据包信息</li>
 *   <li>PCAP文件：将原始数据包写入PCAP文件，支持时间分卷轮转</li>
 *   <li>数据库记录：通过PacketDBEventHandler异步写入数据库</li>
 * </ul>
 */
public class PacketLogger implements Closeable {
    private static final Logger logger = LoggerFactory.getLogger(PacketLogger.class);
    
    // PCAP输出文件基础名（去除 .pcap 扩展名）
    private String pcapBase = null;
    // 当前实际打开的 PCAP 文件路径（openPcap 显式指定时使用）
    private String currentPcapPath = null;
    private Connection  logDb = null;
    private boolean verbose = false;
    // additionalInfo 过滤表达式（分卷切换时需要保留）
    private String exfilter = null;

    /** 是否展开 DIS/HTTP/PG 详细字段（对应 CLI --enable_additioninfo） */
    private volatile boolean enableAdditionalInfo = false;

    /** 是否把 additionalInfo 写进数据库列（false = 恒为 NULL） */
    private volatile boolean storeAdditionalInfo = false;
    
    // PCAP文件写入器
    private PcapDumper dumper = null;
    private PcapHandle dumperHandle = null;
    
    // 协议解析器，用于解析应用层协议详情
    private final ProtocolParser protocolParser = new ProtocolParser(false);
    
    // 数据库日志记录器
    private PacketDBEventHandler packetHandler = new PacketDBEventHandler();

    // 统计信息
    //
    // 用 LongAdder 而不是普通 int：解析并行化后 logPacket 会被多个 worker 线程调用，
    // 普通 int 自增属于数据竞争（计数丢失）。LongAdder 在高并发自增下比 AtomicLong 更快。
    private final java.util.concurrent.atomic.LongAdder packetCount =
            new java.util.concurrent.atomic.LongAdder();
    private volatile boolean closed = false;

    /** close()/flushAndCloseLogDb() 之后仍然可查询的最终计数（见对应方法内的说明） */
    private volatile long finalCommittedPackets = 0;
    private volatile long finalDroppedQueueFull = 0;
    private volatile long finalAbandonedAtShutdown = 0;

    // ========== 运行级累计（跨卷不清零） ==========
    //
    // 为什么必须有这一组：分卷模式下每卷都会新建一个 PacketDBEventHandler，其计数器从 0 开始；
    // 只读"最后一卷"的闩存值会让停机报告看起来像是丢了很多数据（committed 偏小），
    // 或反过来把前面各卷的丢弃完全漏掉（queueFull 只存在于轮转那一刻的日志里）。
    // 停机对账必须用带 Total 后缀的访问器。
    private final java.util.concurrent.atomic.AtomicLong totalCommittedPackets =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong totalDroppedQueueFull =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong totalAbandonedAtShutdown =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong totalFailedToEnqueue =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong totalFailedToCommit =
            new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong totalFilteredOut =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * "卷已关闭、但仍有解析 worker 在交付包"而被丢弃的数量。
     * <p>
     * 触发条件是轮转/停机屏障超时（worker 慢或卡住）后仍有包到达：此时 {@code logDb} 已被置空，
     * 早期实现是<b>静默跳过</b>——既不入库、也不进任何 dropped 计数。现在如实计数并进运行报告，
     * 让"queued &gt; committed + dropped*"的差额不再是谜。</p>
     */
    private final java.util.concurrent.atomic.AtomicLong droppedAfterVolumeClose =
            new java.util.concurrent.atomic.AtomicLong();

    /**
     * {@code close()} 之后才到达、因而永远不会入库的包数。
     * <p>
     * 为什么需要单独一个计数器：{@code close()} 会把 {@link #closed} 置真，而上面那条
     * {@code droppedAfterVolumeClose} 分支要求 {@code !closed}，于是<b>未启用分卷</b>
     * （走 {@code close()} 而不是 {@code flushAndCloseLogDb()}）时，卡死的解析 worker
     * 之后才交付的包既不入库、也不进任何丢弃计数——只有 worker join 超时那一刻的一行
     * ERROR 提到过它，包数完全不可查。
     * </p>
     * <p>
     * 只在"本次运行确实启用过 logdb"时计数：只写 pcap 时不入库是预期行为，不是丢包
     * （那些包的帧早已由抓包线程写进 pcap 文件了）。
     * </p>
     */
    private final java.util.concurrent.atomic.AtomicLong droppedAfterClose =
            new java.util.concurrent.atomic.AtomicLong();

    /** 上一次"收尾后仍到达"告警的时间戳（毫秒）；用于按秒限流，见 {@code logPacket} */
    private final java.util.concurrent.atomic.AtomicLong lastAfterCloseLogMs =
            new java.util.concurrent.atomic.AtomicLong();

    /** 是否已经关闭过至少一个卷（用于区分"没配 logdb"与"卷已关、包来晚了"） */
    private volatile boolean volumeClosedOnce = false;

    /** 本次运行是否真的启用过 logdb（未启用时 logPacket 不入库是预期行为，不是丢包） */
    private volatile boolean logDbEnabled = false;

    /**
     * 打开指定路径的 PCAP 输出文件（由采集端按时间窗决定文件名）。
     * <p>
     * 本方法不做任何命名与分卷决策，文件名完全由调用方给出。
     * 时间窗的分卷由 {@code VolumeWindows} 统管，PCAP 与 logdb 共用同一个时钟。
     * </p>
     *
     * @param path PCAP 文件完整路径
     */
    public void openPcap(String path) {
        this.pcapBase = resolvePcapBase(path);
        initializeDumper();
    }

    /**
     * 关闭当前 PCAP 文件（切换到下一个时间窗时调用）。
     */
    public void closePcap() {
        closeDumper();
    }

    /**
     * @return 当前 PCAP 文件路径；未打开时返回 null
     */
    public String currentPcapPath() {
        return dumper == null ? null : currentPcapPath;
    }

    /**
     * @return 已通过 {@link #logPacket} 记录（或计入 PDB 队列）的包数
     */
    public long totalLogged() {
        return packetCount.sum();
    }

    /**
     * @return 本次运行累计因 DB 队列满而被丢弃的包数（跨卷累计）
     */
    public long droppedQueueFull() {
        return totalDroppedQueueFull.get() + (packetHandler != null ? packetHandler.droppedQueueFull() : 0);
    }

    /**
     * @return 本次运行累计"停机冲刷预算用尽、未入库"的包数
     */
    public long abandonedAtShutdown() {
        return totalAbandonedAtShutdown.get() + (packetHandler != null ? packetHandler.abandonedAtShutdown() : 0);
    }

    /** @return 本次运行累计"入队前处理失败"的包数 */
    public long failedToEnqueue() {
        return totalFailedToEnqueue.get() + (packetHandler != null ? packetHandler.failedToEnqueue() : 0);
    }

    /** @return 本次运行累计"批次提交失败而丢失"的包数 */
    public long failedToCommit() {
        return totalFailedToCommit.get() + (packetHandler != null ? packetHandler.failedToCommit() : 0);
    }

    /** @return 本次运行累计被 --exfilter 过滤掉的包数（跨卷累计；这些包不会入库） */
    public long filteredOut() {
        return totalFilteredOut.get() + (packetHandler != null ? packetHandler.filteredOut() : 0);
    }

    /**
     * @return 卷已关闭后仍到达、因而被丢弃的包数（屏障超时的掉队包）
     */
    public long droppedAfterVolumeClose() {
        return droppedAfterVolumeClose.get();
    }

    /**
     * @return {@code close()} 之后才到达、因而永远不会入库的包数
     *         （未启用分卷时的掉队包；见字段注释）
     */
    public long droppedAfterClose() {
        return droppedAfterClose.get();
    }

    /**
     * 把某个即将关闭的 handler 的计数留存下来，并累计进运行级总计。
     * <p>必须在 {@code closing.shutdown()} <b>之前</b>读取（shutdown 之后计数虽仍可读，
     * 但先读能避免与收尾过程产生任何交叉）。</p>
     */
    private void latchVolumeCounters(PacketDBEventHandler closing) {
        finalCommittedPackets = closing.committedPackets();
        finalDroppedQueueFull = closing.droppedQueueFull();
        finalAbandonedAtShutdown = closing.abandonedAtShutdown();
        totalCommittedPackets.addAndGet(finalCommittedPackets);
        totalDroppedQueueFull.addAndGet(finalDroppedQueueFull);
        totalAbandonedAtShutdown.addAndGet(finalAbandonedAtShutdown);
        totalFailedToEnqueue.addAndGet(closing.failedToEnqueue());
        totalFailedToCommit.addAndGet(closing.failedToCommit());
        totalFilteredOut.addAndGet(closing.filteredOut());
    }

    /**
     * 停机快照：把截止调用时刻已入队的记录全部落库，快照之外丢弃。
     *
     * @param deadlineMs 兜底截止时间（epoch 毫秒）
     * @return 被丢弃（快照之外）的记录数
     */
    public long drainSnapshot(long deadlineMs) {
        return packetHandler != null ? packetHandler.drainSnapshot(deadlineMs) : 0;
    }

    /**
     * @return 本卷（或最近关闭的一卷）已提交入库的包数。
     *         <p>分卷模式下这是<b>单卷</b>数字，不要拿它做整轮对账，用
     *         {@link #committedPacketsTotal()}。</p>
     */
    public long committedPackets() {
        return packetHandler != null ? packetHandler.committedPackets() : finalCommittedPackets;
    }

    /**
     * @return 本次运行累计已提交入库的包数（跨卷累计；停机对账用这个）
     */
    public long committedPacketsTotal() {
        return totalCommittedPackets.get() + (packetHandler != null ? packetHandler.committedPackets() : 0);
    }

    /**
     * 重置"已提交入库"计数（每个时间窗开始时调用，使 manifest 记录的是<b>本卷</b>的包数）。
     */
    public void resetCommittedCount() {
        if (packetHandler != null) {
            packetHandler.resetCommittedCount();
        }
    }

    /** @return 是否启用了 PCAP 输出 */
    public boolean isPcapEnabled() {
        return pcapBase != null;
    }
    
    /**
     * 记录数据包到控制台和数据库
     * <p>
     * 注意：此方法内部会再次调用 {@link ProtocolParser#parseProtocolDetails} 进行协议解析。
     * 这意味着如果调用者已经解析过协议，这里会重复解析一次。
     * 当前设计如此是因为中的解析仅用于判断数据完整性，
     * 而此处的解析结果用于最终的日志输出。
     * </p>
     *
     * @param parsedPacket 解析后的数据包
     * @return 经过协议解析后的增强数据包（包含application.protocol等信息）
     */
    public PacketParser.ParsedPacket logPacket(PacketParser.ParsedPacket parsedPacket) {
        return logPacket(parsedPacket, false);
    }

    /**
     * 记录数据包到控制台和数据库
     * <p>
     * 如果 {@code alreadyParsed} 为 true，则跳过协议解析步骤，直接使用传入的数据包。
     * 这避免了在调用方已经解析过协议时的重复解析。
     * </p>
     *
     * @param parsedPacket 解析后的数据包
     * @param alreadyParsed 是否已经由调用方解析过协议（true=跳过重复解析）
     * @return 经过协议解析后的增强数据包（包含application.protocol等信息）
     */
    public PacketParser.ParsedPacket logPacket(PacketParser.ParsedPacket parsedPacket, boolean alreadyParsed) {
        packetCount.increment();
        
        // 解析推断报文（如果尚未解析）
        PacketParser.ParsedPacket enhancedPacket;
        if (alreadyParsed) {
            enhancedPacket = parsedPacket;
        } else {
            // 协议解析不改变帧相关字段，withFrame 在此处做一次显式透传
            PacketParser.ParsedPacket detailed = protocolParser.parseProtocolDetails(parsedPacket);
            enhancedPacket = detailed.withFrame(
                    parsedPacket.frameData(),
                    parsedPacket.wireLen(),
                    parsedPacket.capLen(),
                    parsedPacket.captureKind());
        }
        
        // 根据verbose设置决定是否输出信息
        if (verbose) {
            logger.info("Packet {}: {}", enhancedPacket.packetSequence(), enhancedPacket.summary());
            logger.info(formatPacketOutput(enhancedPacket));
        }
        if (logDb != null && packetHandler != null) {
            // 使用队列异步插入数据库
            try {
                packetHandler.addPacket(enhancedPacket, enhancedPacket.additionalInfo());
            } catch (Exception e) {
                logger.error("Failed to add packet to queue", e);
            }
        } else if (logDbEnabled && closed) {
            // 已经 close()（未启用分卷时的收尾路径）：不会再有任何输出被打开，这个包
            // 永远不会入库。早期实现这里静默丢弃——它既躲过了下面的 volumeClosedOnce 分支，
            // 也没有任何别的计数点，只剩 worker join 超时那行 ERROR，包数无从查起。
            //
            // 必须在这里打日志：停机对账是"某一刻的快照"，而掉队包往往在汇总打印**之后**
            // 才到达，那时任何计数器都不会再被汇报一次。本模式下又没有 manifest 可写
            // （manifest 只在"配了 logdb 且启用分卷"时存在，见 PacketCapture.finalizeVolume），
            // 所以这行 WARN 是唯一的实时痕迹。
            long late = droppedAfterClose.incrementAndGet();
            long now = System.currentTimeMillis();
            // 限流刻意按**时间**而不是按条数：按条数（如"前 3 条 + 每 1000 条"）会把尾部
            // 完全吃掉——若总共只掉 500 个，日志里永远只看到 "total 3"，而不是真实规模。
            // 按秒限流时，最后一条日志的累计值最多滞后 1 秒的到达量。
            if (late <= 3 || now - lastAfterCloseLogMs.get() >= 1000L) {
                lastAfterCloseLogMs.set(now);
                logger.warn("Packet arrived after the logger was closed and will NOT be stored "
                                + "(total {} so far). A parse worker is still delivering late; look for the "
                                + "'did not terminate' ERROR logged at shutdown", late);
            }
        } else if (volumeClosedOnce && !closed) {
            // 卷已关闭但本包仍然到达：说明轮转/停机屏障超时后有 worker 掉队。
            // 早期实现这里是静默跳过（既不入库也不计数），现在如实计数，进运行报告。
            droppedAfterVolumeClose.incrementAndGet();
        }
        
        return enhancedPacket;
    }
    
    /**
     * 将原始数据包保存到PCAP文件
     * <p>
     * 如果启用了时间分卷且当前时间跨过卷边界，会自动轮转文件。
     * </p>
     *
     * @param packet 原始数据包
     */
    public void saveToPcap(Packet packet) {
        if (dumper != null && packet != null) {
            try {
                dumper.dump(packet);

            } catch (Exception e) {
                logger.error("Failed to save packet to PCAP file", e);
            }
        }
    }
    
    /**
     * 设置PCAP输出文件
     *
     * @param outputFile PCAP文件路径
     */
    public void setOutputFile(String outputFile) {
        this.pcapBase = resolvePcapBase(outputFile);
        initializeDumper();
    }
    
    /**
     * 格式化数据包信息用于控制台输出（verbose模式）
     * <p>
     * 输出格式包含：
     * <ul>
     *   <li>[时间戳] 源IP:端口 -> 目标IP:端口 协议 长度</li>
     *   <li>TCP标志位（如 [AP]）</li>
     *   <li>TCP重组信息（如 [重组: 2个分片, 458字节]）</li>
     *   <li>协议详情（application.protocol等）</li>
     *   <li>Hex dump（16进制+ASCII对照）</li>
     * </ul>
     * </p>
     *
     * @param parsedPacket 解析后的数据包
     * @return 格式化后的字符串
     */
    private String formatPacketOutput(PacketParser.ParsedPacket parsedPacket) {
        StringBuilder sb = new StringBuilder();
        
        // Basic format: [timestamp] src:port -> dst:port protocol length summary
        sb.append("[").append(parsedPacket.getFormattedTimestamp()).append("] ");
        
        // Source and destination
        if (parsedPacket.sourceIp() != null && parsedPacket.destinationIp() != null) {
            sb.append(parsedPacket.sourceIp());
            
            if (parsedPacket.sourcePort() != null) {
                sb.append(":").append(parsedPacket.sourcePort());
            }
            
            sb.append(" -> ").append(parsedPacket.destinationIp());
            
            if (parsedPacket.destinationPort() != null) {
                sb.append(":").append(parsedPacket.destinationPort());
            }
            
            sb.append(" ");
        } else if (parsedPacket.sourceMac() != null && parsedPacket.destinationMac() != null) {
            // MAC addresses only
            sb.append(parsedPacket.sourceMac())
              .append(" -> ")
              .append(parsedPacket.destinationMac())
              .append(" ");
        }
        
        // Protocol
        sb.append(parsedPacket.getProtocolName()).append(" ");
        
        // Length
        sb.append(parsedPacket.length()).append(" bytes");

        // 帧信息：线上长度/捕获长度/记录来源（帧级重放的可重放性判据）
        int wireLen = parsedPacket.wireLen();
        int capLen = parsedPacket.capLen();
        if (capLen > 0 && capLen < wireLen) {
            sb.append(" [truncated: ").append(capLen).append("/").append(wireLen).append("]");
        }
        if (parsedPacket.captureKind() != null) {
            sb.append(" [").append(parsedPacket.captureKind().name()).append("]");
        }
        sb.append(parsedPacket.hasReplayableFrame() ? " [replayable]" : " [no-frame]");
        
        // Additional info for TCP
        if (parsedPacket.ipProtocol() != null && parsedPacket.ipProtocol().equals(org.pcap4j.packet.namednumber.IpNumber.TCP)) {
            Object flags = parsedPacket.additionalInfo().get("tcp.flags");
            if (flags != null) {
                sb.append(" [").append(flags).append("]");
            }
        }
        
        // TCP重组信息显示
        Map<String, Object> additionalInfo = parsedPacket.additionalInfo();
        Object reassembled = additionalInfo.get("tcp.reassembled");
        if ("true".equals(reassembled)) {
            Object fragments = additionalInfo.get("tcp.fragments");
            Object expectedLen = additionalInfo.get("tcp.expected_length");
            sb.append(" [reassembled: ").append(fragments).append(" fragments");
            if (expectedLen != null) {
                sb.append(", ").append(expectedLen).append("bytes");
            }
            sb.append("]");
        }
        
        // Verbose mode adds more details
        sb.append("\n  Summary: ").append(parsedPacket.summary());

        // Add MAC addresses if not already shown
        if (parsedPacket.sourceIp() != null && parsedPacket.sourceMac() != null) {
            sb.append("\n  MAC: ").append(parsedPacket.sourceMac())
              .append(" -> ").append(parsedPacket.destinationMac());
        }

        // Additional info
        if (!additionalInfo.isEmpty()) {
            sb.append("\n  Details: ");
            additionalInfo.forEach((key, value) -> {
                // 跳过已经在摘要中显示的TCP重组信息
                if ("tcp.reassembled".equals(key) || "tcp.fragments".equals(key)
                        || "tcp.expected_length".equals(key) || "tcp.first_seq".equals(key)
                        || "tcp.last_seq".equals(key)) {
                    return;
                }
                sb.append(key).append("=").append(value).append(" ");
            });
        }

        // Add hex dump of packet data
        byte[] rawData = parsedPacket.rawData();
        if (rawData != null && rawData.length > 0) {
            sb.append("\n  Hex dump (").append(rawData.length).append(" bytes):\n");
            sb.append(formatHex(rawData));
        }

        return sb.toString();
    }
    
    /**
     * 将字节数组格式化为16进制+ASCII对照字符串
     * <p>
     * 每行显示16字节，左侧为16进制，右侧为ASCII可打印字符。
     * 不可打印字符显示为 '.'。
     * </p>
     *
     * @param data 字节数组
     * @return 格式化后的16进制字符串
     */
    private String formatHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "[No data]";
        }
        
        StringBuilder hex = new StringBuilder();
        StringBuilder ascii = new StringBuilder();
        int bytesPerLine = 16;
        
        for (int i = 0; i < data.length; i++) {
            // Hex representation
            hex.append(String.format("%02x ", data[i]));
            
            // ASCII representation (for printable characters)
            char c = (char) (data[i] & 0xFF);
            ascii.append((c >= 32 && c <= 126) ? c : '.');
            
            // New line every bytesPerLine bytes
            if ((i + 1) % bytesPerLine == 0 || i == data.length - 1) {
                // Pad hex if needed
                while ((i + 1) % bytesPerLine != 0) {
                    hex.append("   ");
                    ascii.append(" ");
                    i++;
                }
                hex.append("  ").append(ascii);
                if (i < data.length - 1) {
                    hex.append("\n");
                }
                ascii.setLength(0);
            }
        }
        
        return hex.toString();
    }
    
    /**
     * 解析PCAP输出文件基础名，去除 .pcap 扩展名（若存在）。
     *
     * @param outputFile 原始PCAP文件路径
     * @return 去除 .pcap 扩展名后的基础名
     */
    private String resolvePcapBase(String outputFile) {
        if (outputFile == null) {
            return null;
        }
        if (outputFile.endsWith(".pcap")) {
            return outputFile.substring(0, outputFile.length() - 5);
        }
        return outputFile;
    }
    
    /**
     * 设置数据库日志记录配置
     *
     * @param logDb 数据库连接
     */
    public void setLogDb(Connection logDb) {
        if (packetHandler == null) {
            packetHandler = new PacketDBEventHandler();
            // 分卷切换会新建 handler，必须把采集参数重新应用一遍；
            // 否则"卷 2 之后 additionalInfo 又开始写库"这种差异只会在换卷后才出现。
            packetHandler.setStoreAdditionalInfo(storeAdditionalInfo);
            if (exfilter != null && !exfilter.isEmpty()) {
                packetHandler.setExfilter(exfilter);
            }
        }
        packetHandler.setLogDb(logDb);
        this.logDb = logDb;
        this.logDbEnabled = true;
    }

    /**
     * @return 本次运行是否启用过 logdb。未启用时 {@code logPacket} 不入库属于预期行为，
     *         不应被当成"未记账的丢失"。
     */
    public boolean isLogDbEnabled() {
        return logDbEnabled;
    }

    /**
     * 刷新并关闭当前数据库日志记录器
     * <p>
     * 在数据库文件轮转时调用：将队列中剩余数据写入当前连接后，
     * 关闭并丢弃旧的 PacketDBEventHandler，方便后续重新 setLogDb 创建新的记录器。
     * </p>
     */
    public void flushAndCloseLogDb() {
        PacketDBEventHandler closing = detachLogDb();
        if (closing != null) {
            // 先把最终计数留存并累计：close 之后再查询拿不到这些数字，
            // 会导致停机汇总"看起来没有丢包"（曾经真的踩到过）。
            latchVolumeCounters(closing);
            closing.shutdown();
        }
    }

    /**
     * 摘除当前 logdb handler 返回给调用方，但<b>不</b>在其线程上 latch / shutdown。
     * <p>
     * 供<b>切卷异步收尾</b>使用：抓包线程只摘引用并立即开新卷，把旧 handler 交给后台
     * "每文件一个写库线程"去 {@code drainFully} → latch → shutdown，实现"切换不卡、旧卷慢慢写完"。
     * </p>
     * <ul>
     *   <li>必须先摘引用再收尾：并发的 {@code logPacket} 会立刻看到"本卷已关"，
     *       从而计入 {@code droppedAfterVolumeClose}，而不是把包塞进一个正在关闭的队列里静默丢失；</li>
     *   <li>调用方负责在后台线程中对返回值执行 {@code drainFully()} + {@link #latchVolumeCountersExternal(PacketDBEventHandler)}
     *       + {@code shutdown()}。</li>
     * </ul>
     *
     * @return 被摘除的旧 handler；本次运行不曾建立过 handler 时返回 null
     */
    public PacketDBEventHandler detachLogDb() {
        PacketDBEventHandler closing = this.packetHandler;
        this.packetHandler = null;
        this.logDb = null;
        volumeClosedOnce = true;
        return closing;
    }

    /**
     * 对外暴露的计数闩存：把某个（即将由后台线程关闭的）handler 的最终计数留存并累计进运行级总计。
     * <p>必须在 {@code closing.shutdown()} <b>之前</b>调用（见 {@link #latchVolumeCounters}）。</p>
     */
    public void latchVolumeCountersExternal(PacketDBEventHandler closing) {
        latchVolumeCounters(closing);
    }

    /**
     * 设置当前 logdb 分卷序号（分卷轮转时由采集端更新）。
     *
     * @param volumeSeq 分卷序号，从 1 开始；0 表示未启用分卷
     */
    public void setVolumeSeq(int volumeSeq) {
        if (packetHandler != null) {
            packetHandler.setVolumeSeq(volumeSeq);
        }
    }

    /**
     * 设置verbose输出模式
     *
     * @param verbose 是否启用verbose模式
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * 设置是否展开 DIS/HTTP/PG 详细字段。
     * <p>
     * 只影响本类自己的 {@link ProtocolParser}（用于 verbose 输出以及非 TCP 路径的解析）；
     * 数据库列是否落盘由 {@link #setStoreAdditionalInfo(boolean)} 单独控制。
     * </p>
     *
     * @param enableAdditionalInfo true = 展开详细字段
     */
    public void setEnableAdditionalInfo(boolean enableAdditionalInfo) {
        this.enableAdditionalInfo = enableAdditionalInfo;
        protocolParser.setEnableAdditionalInfo(enableAdditionalInfo);
    }

    /**
     * 设置是否把 {@code additionalInfo} 写进数据库列。
     * <p>关闭时该列恒为 NULL（appProtocol/tcpFlags 等独立列不受影响）。</p>
     *
     * @param storeAdditionalInfo false = 不落 additionalInfo 列
     */
    public void setStoreAdditionalInfo(boolean storeAdditionalInfo) {
        this.storeAdditionalInfo = storeAdditionalInfo;
        if (packetHandler != null) {
            packetHandler.setStoreAdditionalInfo(storeAdditionalInfo);
        }
    }

    /**
     * 设置附加信息过滤表达式。不匹配的包不会入库。
     *
     * @param exfilter 过滤表达式
     */
    public void setExfilter(String exfilter) {
        this.exfilter = exfilter;
        if (exfilter != null && !exfilter.isEmpty()) {
            logger.info("[JShark] Additional info filter enabled: {}", exfilter);
            // 将exfilter传递给packetHandler
            packetHandler.setExfilter(exfilter);
        }
    }

    /**
     * 生成PCAP文件名
     * <p>
     * 文件名由调用方通过 {@link #openPcap(String)} 决定（启用分卷时带窗口时间戳），
     * 本方法只负责在未显式指定时回退为 {@code {base}.pcap}。
     * </p>
     *
     * @return PCAP文件名
     */
    private String generateFileName() {
        if (pcapBase == null) {
            return null;
        }
        return pcapBase + ".pcap";
    }
    
    /**
     * 初始化PCAP dumper
     * <p>
     * 如果已存在dumper，先关闭再创建新的。
     * 使用EN10MB（以太网）数据链路类型。
     * </p>
     */
    private void initializeDumper() {
        if (pcapBase == null) {
            return;
        }
        
        // Generate target filename
        String targetFile = generateFileName();
        if (targetFile == null) {
            return;
        }
        
        try {
            // Close existing dumper if any
            closeDumper();
            
            // Create a dummy handle for dumping - use Ethernet DLT
            dumperHandle = Pcaps.openDead(org.pcap4j.packet.namednumber.DataLinkType.EN10MB, 65536);
            dumper = dumperHandle.dumpOpen(targetFile);
            currentPcapPath = targetFile;
            logger.info("[JShark] PCAP output file: {}", targetFile);
        } catch (Exception e) {
            throw new PacketCaptureException("Failed to open PCAP file for writing: " + targetFile, e);
        }
    }

    /**
     * 关闭PCAP dumper
     * <p>
     * 同时关闭dumper和dumperHandle，释放资源。
     * </p>
     */
    private void closeDumper() {
        if (dumper != null) {
            try {
                dumper.close();
                logger.debug("PCAP dumper closed");
            } catch (Exception e) {
                logger.error("Error closing PCAP dumper", e);
            }
            dumper = null;
        }
        
        if (dumperHandle != null) {
            try {
                dumperHandle.close();
            } catch (Exception e) {
                logger.error("Error closing PCAP handle", e);
            }
            dumperHandle = null;
        }
    }
    
    /**
     * 关闭所有资源
     * <p>
     * 关闭PCAP dumper和数据库日志记录器。
     * 打印总处理数据包数量。
     * </p>
     */
    @Override
    public void close() {
        close(System.currentTimeMillis() + 5_000L);
    }

    /**
     * 预算化关闭：在 {@code deadlineMs} 之前关掉 PCAP 与库连接。
     * <p>
     * 停机路径必须用这个重载：预算里要给"FORCE CHECKPOINT + close"留出尾段时间，
     * 不能把时间全花在冲刷队列上。
     * </p>
     *
     * @param deadlineMs 绝对截止时间（epoch 毫秒）；{@link Long#MAX_VALUE} 表示不限
     */
    public void close(long deadlineMs) {
        if (closed) {
            return;
        }
        closed = true;
        
        closeDumper();
        
        // 关闭PacketDBEventHandler
        if (packetHandler != null) {
            // 同上：留存最终计数并累计进运行级总计，保证 close() 之后查询仍然准确
            PacketDBEventHandler closing = packetHandler;
            packetHandler = null;
            latchVolumeCounters(closing);
            closing.shutdown(deadlineMs);
        }
        // 必须同时清掉 logDb：否则 logPacket 里的 `logDb != null` 判断仍然成立，
        // 接着解引用已经置空的 packetHandler 会抛 NPE，被解析 worker 的 catch(Throwable)
        // 吞掉，表现成"丢包 + 一行 worker task failed"，既不崩也不计数。
        this.logDb = null;
        
        logger.info("Packet logger closed. Total packets: {}", packetCount.sum());
    }
}
