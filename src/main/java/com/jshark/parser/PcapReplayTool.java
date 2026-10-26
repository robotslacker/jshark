package com.jshark.parser;

import com.jshark.PacketCaptureException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;

/**
 * 从离线 pcap 文件重放数据包（两种模式）。
 *
 * <h3>模式</h3>
 * <table border="1">
 *   <caption>重放模式对比</caption>
 *   <tr><th>模式</th><th>机制</th><th>保真度</th></tr>
 *   <tr>
 *     <td>{@link Mode#FRAME}（默认）</td>
 *     <td>取出<b>完整原始帧</b>，仅改写目的地址/端口并重算校验和，用 pcap 直接注入网卡</td>
 *     <td>源 IP/源端口/seq/ack/TTL/分片结构全保真，且<b>双方向全部原样重放</b></td>
 *   </tr>
 *   <tr>
 *     <td>{@link Mode#PAYLOAD}</td>
 *     <td>取传输层 payload，经内核协议栈（Netty）发送到目标地址</td>
 *     <td>只保载荷；源地址/端口/序列号由内核决定</td>
 *   </tr>
 * </table>
 *
 * <h3>两种模式共用的部分</h3>
 * <ul>
 *   <li>时序：{@link ReplayClock} 的严格仿射倍率（总时长 = 首末包间隔 / speed，绝不提前发送）</li>
 *   <li>过滤：源/目的 IP、源/目的端口、IP 协议</li>
 *   <li>映射：{@link TargetMapping}（按 {@code SrcIP:SrcPort} 匹配，改写目的 IP/端口）</li>
 *   <li>报告：理想/实际时长、实测倍率、迟到分布、帧改写状态分布</li>
 * </ul>
 *
 * <h3>为什么 FRAME 模式是审计场景的正确选择</h3>
 * <p>
 * 被动采集器靠 seq/ack 双向配对重建 TCP 会话。{@code FRAME} 模式把两个方向的原帧
 * 原样发出，采集器看到的内容与直接读原始 pcap 完全一致；{@code PAYLOAD} 模式则会让
 * 采集器看到一堆"新会话"，从而审计到被重放过程扭曲过的内容。
 * </p>
 */
public class PcapReplayTool {

    private static final Logger logger = LoggerFactory.getLogger(PcapReplayTool.class);

    /** 重放模式 */
    public enum Mode {
        /** 帧级原样注入（默认） */
        FRAME,
        /** 传输层载荷经内核协议栈发送（对照/调试用） */
        PAYLOAD
    }

    private final String pcapFile;
    private final double speedMultiplier;
    private final Mode mode;
    private final String sourceIpFilter;
    private final String destinationIpFilter;
    private final Integer sourcePortFilter;
    private final Integer destinationPortFilter;
    private final String ipProtocolFilter;
    private final TargetMapping targetMapping;

    /** 注入网卡（FRAME 模式必需） */
    private final PcapNetworkInterface injectionInterface;

    private NettyPacketSender packetSender;
    private final FrameRewriter frameRewriter;
    private ReplayClock replayClock;
    /** 帧级重放的统计结果（供测试与调用方读取） */
    private FrameReplayEngine.Result engineResult;

    /** 首个被实际重放的包的时间（用于理想总时长与实测倍率） */
    private ReplayClock.PacketTime firstReplayedPacketTime = null;
    /** 最后一个被实际重放的包的时间 */
    private ReplayClock.PacketTime lastReplayedPacketTime = null;
    /** 重放墙钟起点（纳秒） */
    private long replayStartNano = 0;
    /** 重放墙钟终点（纳秒） */
    private long replayEndNano = 0;

    /** 停止请求（CTRL+C） */
    private volatile boolean stopRequested = false;

    /** 控制/进度通道（CLI 控制模式/UI）；普通 CLI 也可只读统计。 */
    private ReplayControl control;

    /** payload 模式的重放起点（epoch ms）；null 表示从头开始。 */
    private volatile Long startAtMs;

    /** payload 模式的重放终点（epoch ms，含）；null 表示到文件末尾。 */
    private volatile Long endAtMs;

    /**
     * 会话级的注入自检结果：由 CLI 在会话首段算好并注入，seek 重开段直接复用
     * （自检会真实发一帧探测包，每段重跑既浪费也会在 seek 时多打一帧）。
     */
    private StartupSelfCheck.Result startupCheck;

    /** 是否启用自适应降速；false 仅用于测试固定倍率（命令行已不再提供关闭入口） */
    private boolean adaptiveSpeedEnabled = true;

    /** 自适应倍率控制器（与 replayClock 同生命周期） */
    private AdaptiveSpeedController speedController = null;

    private final AtomicLong examined = new AtomicLong();
    private final AtomicLong sentPackets = new AtomicLong();
    private final AtomicLong sentBytes = new AtomicLong();
    /** 每 20 秒打印一次"过去这一段"的平均回放流量（MB/s） */
    private final ThroughputMeter rateMeter = new ThroughputMeter("Replay(pcap)", 20_000L);
    private final AtomicLong filteredOut = new AtomicLong();
    private final AtomicLong skippedNoPort = new AtomicLong();

    /**
     * 构造 pcap 重放工具（全参数）。
     *
     * @param pcapFile              pcap 文件路径
     * @param speedMultiplier       重放倍率，必须 &gt; 0
     * @param mode                  重放模式；null 视为 {@link Mode#FRAME}
     * @param sourceIpFilter        源 IP 过滤（null/空表示不过滤）
     * @param destinationIpFilter   目的 IP 过滤（null/空表示不过滤）
     * @param sourcePortFilter      源端口过滤（null 表示不过滤）
     * @param destinationPortFilter 目的端口过滤（null 表示不过滤）
     * @param ipProtocolFilter      IP 协议过滤，如 {@code UDP}/{@code TCP}
     * @param targetMappingStr      目标映射，格式 {@code SrcIP:SrcPort-DestIP:DestPort}
     * @param injectionInterface    注入网卡；FRAME 模式下不可为 null
     * @param macPolicy             目的 MAC 策略；null 视为 {@code preserve}
     * @param unicastResolver       单播 MAC 解析器；可为 null
     */
    public PcapReplayTool(String pcapFile, double speedMultiplier, Mode mode,
                          String sourceIpFilter, String destinationIpFilter,
                          Integer sourcePortFilter, Integer destinationPortFilter,
                          String ipProtocolFilter, String targetMappingStr,
                          PcapNetworkInterface injectionInterface,
                          FrameRewriter.MacPolicy macPolicy,
                          java.util.function.Function<String, byte[]> unicastResolver) {
        this.pcapFile = pcapFile;
        this.speedMultiplier = speedMultiplier;
        this.mode = mode != null ? mode : Mode.FRAME;
        this.sourceIpFilter = sourceIpFilter;
        this.destinationIpFilter = destinationIpFilter;
        this.sourcePortFilter = sourcePortFilter;
        this.destinationPortFilter = destinationPortFilter;
        this.ipProtocolFilter = ipProtocolFilter;
        this.targetMapping = TargetMapping.parse(targetMappingStr);
        this.injectionInterface = injectionInterface;
        this.frameRewriter = new FrameRewriter(macPolicy, unicastResolver);
        this.control = new ReplayControl(speedMultiplier);
    }

    /**
     * 构造 payload 模式的重放工具（对照/调试用，不需要注入网卡）。
     *
     * @param pcapFile              pcap 文件路径
     * @param speedMultiplier       重放倍率
     * @param sourceIpFilter        源 IP 过滤
     * @param destinationIpFilter   目的 IP 过滤
     * @param sourcePortFilter      源端口过滤
     * @param destinationPortFilter 目的端口过滤
     * @param ipProtocolFilter      IP 协议过滤
     * @param targetMappingStr      目标映射
     */
    public PcapReplayTool(String pcapFile, double speedMultiplier,
                          String sourceIpFilter, String destinationIpFilter,
                          Integer sourcePortFilter, Integer destinationPortFilter,
                          String ipProtocolFilter, String targetMappingStr) {
        this(pcapFile, speedMultiplier, Mode.PAYLOAD,
                sourceIpFilter, destinationIpFilter, sourcePortFilter, destinationPortFilter,
                ipProtocolFilter, targetMappingStr, null, FrameRewriter.MacPolicy.preserve(), null);
    }

    /** 请求停止重放（由 CTRL+C 处理调用） */
    public void stopReplay() {
        logger.info("[JShark] Stopping pcap replay...");
        stopRequested = true;
        control.requestStop();
    }

    /**
     * 注入控制/进度通道（CLI 控制模式/UI）。
     *
     * @param control 控制通道；null 表示忽略
     */
    public void setControl(ReplayControl control) {
        if (control != null) {
            this.control = control;
        }
    }

    /**
     * 注入会话级的注入自检结果（由 CLI 在会话首段算好后复用）。
     *
     * @param check 自检结果；null 表示没有（frame 模式下会重新自检）
     */
    public void setStartupCheck(StartupSelfCheck.Result check) {
        this.startupCheck = check;
    }

    /**
     * 设置 payload 模式的起点（seek 重开段用）。
     *
     * @param startAtMs epoch 毫秒；null/负值表示从头开始
     */
    public void setStartAtMs(Long startAtMs) {
        this.startAtMs = startAtMs != null && startAtMs >= 0 ? startAtMs : null;
    }

    /**
     * 设置 payload 模式的终点（epoch ms，含）。
     *
     * @param endAtMs 终点；null/负值表示到文件末尾
     */
    public void setEndAtMs(Long endAtMs) {
        this.endAtMs = endAtMs != null && endAtMs >= 0 ? endAtMs : null;
    }

    /**
     * 执行重放。
     *
     * @throws PacketCaptureException 文件不存在、无法打开，或帧模式下缺少可用注入网卡
     */
    public void startReplay() {
        java.io.File file = new java.io.File(pcapFile);
        if (!file.isFile()) {
            throw new PacketCaptureException("PCAP file does not exist: " + pcapFile);
        }

        logger.info("[JShark] Replaying from PCAP file: {} (mode={})", file.getAbsolutePath(), mode);
        logger.info("[JShark] Speed multiplier: {}x", speedMultiplier);
        for (String desc : targetMapping.getDescriptions()) {
            logger.info("[JShark] Target mapping: {}", desc);
        }

        if (mode == Mode.FRAME) {
            if (injectionInterface == null) {
                throw new PacketCaptureException(
                        "Frame-level replay requires an injection interface. Specify --injectInterface=<IP>.");
            }
            // 帧级重放统一走 FrameReplayEngine（与数据库帧来源共用同一套引擎）
            try (RawFrameSender sender = new RawFrameSender(injectionInterface)) {
                // 会话级缓存（CLI 注入）：seek 重开段不再重跑自检；
                // 直接构造工具的调用方没注入时仍自行自检一次。
                StartupSelfCheck.Result check = startupCheck;
                if (check == null) {
                    check = StartupSelfCheck.run(injectionInterface, -1, 0);
                }
                if (check != null) {
                    sender.setToleratesReportedError(
                            check.verdict() == StartupSelfCheck.InjectVerdict.OBSERVED_DESPITE_ERROR,
                            check.detail());
                    if (check.verdict() == StartupSelfCheck.InjectVerdict.FAILED) {
                        logger.error("[JShark] Injection self-check FAILED on this NIC; frames will not reach the "
                                + "network. Pick another NIC with --injectInterface, then retry.");
                    }
                }

                ReplayClock clock = new ReplayClock(speedMultiplier, null, null);
                AdaptiveSpeedController frameSpeedController =
                        new AdaptiveSpeedController(speedMultiplier, adaptiveSpeedEnabled);
                PcapFrameSource frameSource = new PcapFrameSource(pcapFile);
                frameSource.setStartAtMs(startAtMs);
                frameSource.setEndAtMs(endAtMs);
                // 跳过前导帧时要能被 stop/seek 打断（seek 大文件时可能跳很久）。
                frameSource.setAbortCondition(
                        () -> stopRequested || control.shouldStop() || control.hasPendingSeek());
                FrameReplayEngine engine = new FrameReplayEngine(
                        frameSource,
                        sourceIpFilter, destinationIpFilter,
                        sourcePortFilter, destinationPortFilter, ipProtocolFilter);
                engine.setSpeedController(frameSpeedController);
                engine.setControl(control);
                control.setAdaptive(adaptiveSpeedEnabled);
                control.speedObserved(speedMultiplier, speedMultiplier);
                control.minSpeedObserved(speedMultiplier);
                control.setLive(false, false);

                FrameReplayEngine.Result result;
                try {
                    result = engine.run(clock, frameRewriter, sender, targetMapping);
                } catch (PacketCaptureException e) {
                    throw e;
                } catch (Exception e) {
                    throw new PacketCaptureException("Failed to replay PCAP file: " + pcapFile, e);
                }
                engine.report(clock, result);
                this.engineResult = result;
            }
            return;
        }

        // ---- payload 模式（对照/调试用）----
        packetSender = new NettyPacketSender();
        replayClock = new ReplayClock(speedMultiplier, null, null);
        speedController = new AdaptiveSpeedController(speedMultiplier, adaptiveSpeedEnabled);
        control.setAdaptive(adaptiveSpeedEnabled);
        control.speedObserved(speedMultiplier, speedMultiplier);
        control.minSpeedObserved(speedMultiplier);
        control.setLive(false, false);
        control.setWaitingForData(false);
        try (PcapHandle handle = Pcaps.openOffline(file.getAbsolutePath())) {
            payloadReplayLoop(handle);
        } catch (Exception e) {
            throw new PacketCaptureException("Failed to replay PCAP file: " + pcapFile, e);
        } finally {
            packetSender.shutdown();
        }
        reportTiming();
    }

    /** payload 模式的主循环（不经帧注入，仅用于对照/调试） */
    private void payloadReplayLoop(PcapHandle handle) {
        long skippedForStart = 0;
        while (!stopRequested && !control.shouldStop() && !control.hasPendingSeek()) {
            Packet packet;
            try {
                packet = handle.getNextPacketEx();
            } catch (java.io.EOFException e) {
                logger.info("[JShark] Reached end of PCAP file");
                if (!control.hasPendingSeek()) {
                    control.markEndReached();
                }
                break;
            } catch (Exception e) {
                if (stopRequested || control.shouldStop()) {
                    break;
                }
                logger.warn("[JShark] Stop reading PCAP due to error: {}", e.getMessage());
                control.reportError(e);
                break;
            }
            if (packet == null) {
                if (!control.hasPendingSeek()) {
                    control.markEndReached();
                }
                break;
            }

            ReplayClock.PacketTime packetTime = packetTime(handle);
            if (packetTime == null) {
                packetTime = ReplayClock.PacketTime.of(java.time.Instant.now());
            }
            // seek 重开段：只读不发送地跳过目标之前的包（不占用时间轴/统计）。
            // 每 256 个包检查一次 stop/seek：否则大文件 seek 后的“停止”会静默卡住。
            if (startAtMs != null && packetTime.timestampMillis() < startAtMs) {
                if ((++skippedForStart & 0xFF) == 0
                        && (stopRequested || control.shouldStop() || control.hasPendingSeek())) {
                    return;
                }
                continue;
            }
            if (endAtMs != null && packetTime.timestampMillis() > endAtMs) {
                if (!control.hasPendingSeek()) {
                    control.markEndReached();
                }
                break;
            }
            examined.incrementAndGet();
            control.examined();
            control.position(packetTime.timestampMillis());

            byte[] payload = extractTransportPayload(packet);
            // 元数据从帧字节解析，与帧级重放（PcapFrameSource/DbFrameSource）走同一条路径
            FrameSource.FrameMeta meta = PcapFrameSource.extractMeta(packet.getRawData());
            String ipProtocol = meta.ipProtocol();
            String srcIp = meta.srcIp();
            String dstIp = meta.dstIp();
            Integer srcPort = meta.srcPort();
            Integer dstPort = meta.dstPort();

            if (!passesFilter(srcIp, dstIp, srcPort, dstPort, ipProtocol)) {
                filteredOut.incrementAndGet();
                control.filtered();
                continue;
            }

            // 目标映射（与 DbReplayTool 同规则：按 SrcIP:SrcPort 匹配）
            TargetMapping.MappingResult mapped = targetMapping.apply(
                    srcIp, srcPort != null ? srcPort : 0,
                    dstIp, dstPort != null ? dstPort : 0);

            if (payload == null || payload.length == 0) {
                filteredOut.incrementAndGet();
                control.filtered();
                continue;
            }
            int sendPort = mapped.port();
            if (sendPort <= 0 || sendPort > 65535) {
                skippedNoPort.incrementAndGet();
                control.skipped();
                continue;
            }

            if (stopRequested || control.checkpoint(replayClock, speedController, true)) {
                break;
            }
            if (!scheduleAndWait(packetTime)) {
                break;
            }

            packetSender.sendPacket(mapped.ip(), mapped.port(), payload, ipProtocol);
            sentPackets.incrementAndGet();
            sentBytes.addAndGet(payload.length);
            control.sent(payload.length);
            rateMeter.addPacket(payload.length);
            replayEndNano = System.nanoTime();
            // 每 20 秒打印"过去这一段"的平均回放流量（MB/s + pps）
            rateMeter.tick();
        }

        rateMeter.flush();
        logger.info("[JShark] PCAP replay finished: examined={}, sent={} ({} bytes), filtered={}, skippedNoPort={}",
                examined.get(), sentPackets.get(), sentBytes.get(), filteredOut.get(), skippedNoPort.get());
    }

    /**
     * 按精确倍率时间轴等待到该包的应发时刻。
     *
     * @param packetTime 包时间
     * @return false 表示收到停止请求，调用方应退出循环
     */
    private boolean scheduleAndWait(ReplayClock.PacketTime packetTime) {
        if (!replayClock.isAnchored()) {
            replayClock.anchor(packetTime);
            firstReplayedPacketTime = packetTime;
            replayStartNano = System.nanoTime();
        } else {
            ReplayClock.Schedule schedule = replayClock.scheduleNext(packetTime);
            while (schedule.waitNanos() > 0) {
                replayClock.await(schedule);
                if (stopRequested || control.checkpoint(replayClock, speedController, true)) {
                    break;
                }
                schedule = replayClock.scheduleNext(packetTime);
            }
            if (stopRequested || control.shouldStop() || control.hasPendingSeek()) {
                return false;
            }
            // 自适应降速：本包已调度、尚未发送，调速从本包起算
            if (speedController != null) {
                AdaptiveSpeedController.Decision decision =
                        speedController.observe(System.nanoTime(), schedule.latenessNanos());
                if (decision.changed()) {
                    replayClock.setSpeed(decision.speed());
                    control.speedObserved(speedMultiplier, replayClock.speed());
                    control.minSpeedObserved(speedController.minSpeed());
                    control.adaptiveObserved(speedController.downCount(), speedController.upCount());
                }
            }
        }
        if (stopRequested) {
            return false;
        }
        lastReplayedPacketTime = packetTime;
        return true;
    }

    /**
     * 读取 pcap 首部时间戳。
     *
     * @param handle 已打开的离线句柄
     * @return 包时间；读取失败返回 null
     */
    private ReplayClock.PacketTime packetTime(PcapHandle handle) {
        try {
            java.sql.Timestamp ts = handle.getTimestamp();
            if (ts != null) {
                return ReplayClock.PacketTime.of(ts);
            }
        } catch (Exception e) {
            logger.debug("Failed to read pcap timestamp: {}", e.getMessage());
        }
        return null;
    }

    /** 提取传输层应用载荷（UDP/TCP payload）；无载荷返回 null */
    private byte[] extractTransportPayload(Packet packet) {
        try {
            if (packet.contains(UdpPacket.class)) {
                org.pcap4j.packet.Packet p = packet.get(UdpPacket.class).getPayload();
                return p != null ? p.getRawData() : null;
            }
            if (packet.contains(TcpPacket.class)) {
                org.pcap4j.packet.Packet p = packet.get(TcpPacket.class).getPayload();
                return p != null ? p.getRawData() : null;
            }
        } catch (Exception e) {
            logger.debug("Failed to extract payload: {}", e.getMessage());
        }
        return null;
    }

    /** 过滤：源/目的 IP、源/目的端口、IP 协议（与 DbReplayTool 规则一致） */
    private boolean passesFilter(String srcIp, String dstIp, Integer srcPort, Integer dstPort, String protocol) {
        if (sourceIpFilter != null && !sourceIpFilter.isEmpty() && !sourceIpFilter.equals(srcIp)) {
            return false;
        }
        if (destinationIpFilter != null && !destinationIpFilter.isEmpty() && !destinationIpFilter.equals(dstIp)) {
            return false;
        }
        if (sourcePortFilter != null && !sourcePortFilter.equals(srcPort)) {
            return false;
        }
        if (destinationPortFilter != null && !destinationPortFilter.equals(dstPort)) {
            return false;
        }
        return ipProtocolFilter == null || ipProtocolFilter.isEmpty()
                || ipProtocolFilter.equalsIgnoreCase(protocol);
    }

    /** 打印时序报告：理想时长 / 实际时长 / 实测倍率 / 迟到统计 */
    private void reportTiming() {
        if (replayClock == null || firstReplayedPacketTime == null || lastReplayedPacketTime == null) {
            return;
        }
        ReplayTiming.log(logger, replayClock, speedController, speedMultiplier,
                firstReplayedPacketTime.toEpochNanos(), lastReplayedPacketTime.toEpochNanos(),
                replayEndNano - replayStartNano);
    }

    /** @return 已发送帧数（含"驱动报错但已发出"的帧） */
    public long sentPackets() {
        if (engineResult != null) {
            return engineResult.sent();
        }
        return sentPackets.get();
    }

    /** @return 驱动报错但帧已发出的帧数 */
    public long sentDespiteReportedError() {
        return engineResult != null ? engineResult.sentDespiteReportedError() : 0;
    }

    /** @return 确实未能发出的帧数 */
    public long injectionFailures() {
        return engineResult != null ? engineResult.injectionFailures() : 0;
    }

    /** @return 参与重放的帧数 */
    public long examinedCount() {
        return examined.get();
    }
}
