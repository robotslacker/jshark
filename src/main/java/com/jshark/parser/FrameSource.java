package com.jshark.parser;

import java.io.Closeable;

/**
 * 重放数据源：按时间顺序提供"可注入的完整帧"。
 *
 * <h3>抽象出的原因</h3>
 * <p>
 * 帧级重放的骨架（时序调度、过滤、目标映射、改写、注入、统计）与"帧从哪来"无关。
 * 把数据源抽出来之后，pcap 文件与数据库（{@code JSharkLog.frameData}）可以共用同一个引擎，
 * 避免出现两份会各自漂移的重放实现——这正是早期代码里 {@code PcapEndToEndTest}
 * 内嵌一份重放副本所暴露的问题。
 * </p>
 *
 * <h3>实现约定</h3>
 * <ul>
 *   <li>{@link #next()} 必须按时间顺序返回，且顺序必须与 {@link #isOrderedByTimestamp()} 的声明一致：
 *       {@code true} 表示"读到的顺序就是时间顺序"，引擎会直接用 pcap 首部时间戳做精确时序；
 *       {@code false} 表示顺序可能因存储精度而退化，引擎会按实际的非递减时间轴推进。</li>
 *   <li>{@code frameData} 必须是完整帧字节；无帧的记录（TCP 重组体等）{@link #next()} 不应返回，
 *       而应计入 {@link #skippedWithoutFrame()}。</li>
 * </ul>
 */
public interface FrameSource extends Closeable {

    /**
     * 一帧及其解析出的地址元数据。
     *
     * @param frameData 完整帧字节
     * @param timestampNanos 采集时刻（自 epoch 纳秒）
     * @param srcIp     源 IP（非 IP 帧为 null）
     * @param dstIp     目的 IP（非 IP 帧为 null）
     * @param srcPort   源端口（非 TCP/UDP 或非首片为 null）
     * @param dstPort   目的端口（非 TCP/UDP 或非首片为 null）
     * @param ipProtocol IP 协议名（如 UDP/TCP；未知为空串）
     */
    record Frame(byte[] frameData, long timestampNanos, String srcIp, String dstIp,
                 Integer srcPort, Integer dstPort, String ipProtocol) {
    }

    /**
     * 从完整帧字节解析出的地址元数据（过滤与目标映射只需要这些字段）。
     *
     * @param srcIp      源 IP；非 IP 帧为 null
     * @param dstIp      目的 IP；非 IP 帧为 null
     * @param ipProtocol IP 协议名（TCP/UDP/ICMPV4/...）；未知为空串
     * @param srcPort    源端口；非 TCP/UDP、非首片或解析不出时为 null
     * @param dstPort    目的端口；同上
     */
    record FrameMeta(String srcIp, String dstIp, String ipProtocol, Integer srcPort, Integer dstPort) {
    }

    /**
     * 打开数据源并准备游标。
     *
     * @throws Exception 打开失败（文件不存在、数据库结构不符等）
     */
    void open() throws Exception;

    /**
     * 取下一帧。
     *
     * @return 下一帧；已到末尾返回 null
     * @throws Exception 读取失败
     */
    Frame next() throws Exception;

    /**
     * 该数据源的读取顺序是否保证为时间顺序。
     *
     * @return true 表示顺序即时间顺序
     */
    boolean isOrderedByTimestamp();

    /**
     * 描述数据源（用于启动日志与报告）。
     *
     * @return 可读描述
     */
    String describe();

    /** @return 因"无完整帧"（TCP 重组体、缓冲区冲刷体等）而被跳过的记录数 */
    long skippedWithoutFrame();

    @Override
    void close();
}
