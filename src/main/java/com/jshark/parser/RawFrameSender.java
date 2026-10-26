package com.jshark.parser;

import com.jshark.PacketCaptureException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 帧注入发送器：把完整帧按原样写到网卡上（帧级重放的发送端）。
 *
 * <h3>与 {@link NettyPacketSender} 的根本差别</h3>
 * <p>
 * Netty 发送器走内核协议栈：源地址、源端口、序列号、分片结构全部由内核决定，
 * 只能做到"把载荷送到某个目的地址"。本发送器直接用 {@code pcap_sendpacket} 把帧写到网卡，
 * <b>绕过内核协议栈</b>，因此帧里的源地址、源端口、seq/ack、TTL、分片结构、校验和
 * 全部原样保留——这正是"原样重放"的含义。
 * </p>
 *
 * <h3>为什么不需要 pthread_np 之类的额外处理</h3>
 * <p>
 * 实测（阶段 B0）表明 pcap4j 在 Windows 上已把 {@code pcap_sendpacket} 的返回值规范化为
 * "成功 0 / 失败 −1"，因此 {@link #send(byte[])} 抛异常即代表**真实发送失败**。
 * 但"能不能注入"与网卡/驱动强相关，且失败是静默的，所以本类会统计失败并在
 * 失败率异常时给出明确告警（自检见 {@link StartupSelfCheck}）。
 * </p>
 *
 * <h3>线程模型</h3>
 * <p>
 * 注入句柄只被重放线程使用；统计计数用原子量，供运行报告读取。
 * </p>
 */
public class RawFrameSender implements Closeable, FrameSender {

    private static final Logger logger = LoggerFactory.getLogger(RawFrameSender.class);

    /** 打开注入句柄时的快照长度：注入不需要截断，但要足够大以容纳巨帧 */
    private static final int SNAPLEN = 65536;

    private final PcapNetworkInterface networkInterface;
    private final String interfaceName;

    private final AtomicLong framesFailed = new AtomicLong();
    /** "调用报错但帧确实被观察到"的次数（由调用方在自检确认后置位） */
    private final AtomicLong framesSentDespiteError = new AtomicLong();
    /**
     * 该网卡是否存在"pcap_sendpacket 报错但帧实际已发出"的特性。
     * <p>
     * 由启动自检判定（{@link StartupSelfCheck.InjectVerdict#OBSERVED_DESPITE_ERROR}）后置位。
     * 置位后，注入异常不再计为失败，而是计入 {@link #framesSentDespiteError()}——
     * 这样才能如实反映"帧到底有没有出去"，而不是被驱动的错误码误导。
     * </p>
     */
    private volatile boolean toleratesReportedError;

    private PcapHandle handle;
    private volatile boolean closed = false;
    /** 首次失败的原因（用于报告） */
    private volatile String firstFailure;

    /**
     * 构造并打开注入句柄。
     *
     * @param networkInterface 注入网卡
     * @throws PacketCaptureException 句柄打开失败（权限不足、驱动不支持等）
     */
    public RawFrameSender(PcapNetworkInterface networkInterface) {
        if (networkInterface == null) {
            throw new PacketCaptureException("Injection interface must not be null");
        }
        this.networkInterface = networkInterface;
        this.interfaceName = networkInterface.getName();
        try {
            // 只写不读：使用较长的读超时以降低句柄开销；本类不会读取该句柄
            this.handle = networkInterface.openLive(SNAPLEN,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
            logger.info("[JShark] Frame injection ready on {} ({})",
                    interfaceName, networkInterface.getDescription());
        } catch (Exception e) {
            throw new PacketCaptureException("Failed to open injection interface " + interfaceName
                    + ". Frame injection needs Administrator/root privileges and a NIC/driver that supports it.", e);
        }
    }

    /**
     * 声明该网卡是否存在"报错但帧已发出"的特性（由启动自检得出）。
     *
     * @param tolerates true 表示把注入异常计为"已发送（驱动误报）"
     * @param evidence  判定依据，仅用于日志
     */
    public void setToleratesReportedError(boolean tolerates, String evidence) {
        this.toleratesReportedError = tolerates;
        if (tolerates) {
            logger.warn("[JShark] This NIC reports injection errors even though frames do reach the network "
                    + "({}). Injection failures will be counted separately as 'sent despite reported error'.",
                    evidence == null ? "confirmed by self-check" : evidence);
        }
    }

    /**
     * 注入一帧（原样）。
     *
     * @param frame 完整帧字节
     * @return true 表示帧已发出（含"驱动报错但已发出"的情形）
     */
    public boolean send(byte[] frame) {
        if (closed) {
            return false;
        }
        if (frame == null || frame.length == 0) {
            return false;
        }
        try {
            handle.sendPacket(frame);
            return true;
        } catch (Exception e) {
            if (toleratesReportedError) {
                // 自检已确认该网卡的错误码不可靠：帧确实出去了，只是报告为失败
                framesSentDespiteError.incrementAndGet();
                    return true;
            }
            framesFailed.incrementAndGet();
            if (firstFailure == null) {
                firstFailure = e.getMessage();
                logger.error("[JShark] Frame injection failed (first occurrence). "
                        + "Replay will not reach the network. Cause: {}", e.getMessage());
            } else if (framesFailed.get() % 10_000L == 0) {
                logger.error("[JShark] Frame injection is still failing ({} failures so far): {}",
                        framesFailed.get(), e.getMessage());
            }
            return false;
        }
    }

    /** @return 注入成功的帧数 */
        /** @return 注入成功的字节数 */
        /** @return 注入失败的帧数 */
    public long framesFailed() {
        return framesFailed.get();
    }

    /** @return "驱动报错但帧已发出"的帧数（该网卡错误码不可靠时） */
    public long framesSentDespiteError() {
        return framesSentDespiteError.get();
    }

    /** @return 实际发出的帧总数（成功 + 驱动误报） */
        /** @return 被跳过（空帧/已关闭）的帧数 */
        /** @return 首次失败的原因；从未失败返回 null */
        /** @return 注入网卡名 */
        /**
     * 打印发送统计，并在失败率异常时给出告警。
     *
     */
        @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (handle != null && handle.isOpen()) {
            try {
                handle.close();
            } catch (Exception e) {
                logger.debug("[JShark] Error closing injection handle: {}", e.getMessage());
            }
        }
        handle = null;
        logger.info("[JShark] Frame injection closed on {}", interfaceName);
    }
}
