package com.jshark.parser;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * 启动自检：在真正开始重放之前，确认"这台机器、这张网卡能不能把帧发出去"。
 *
 * <h3>为什么必须有它</h3>
 * <p>
 * 帧注入的失败现象是**静默的**：工具看起来正常跑完，而被动采集器一个包都没收到。
 * 实测已确认该行为与网卡/驱动强相关（同一台机器上，虚拟网卡可注入、Wi-Fi 网卡注入失败），
 * 因此必须在上线前把结论摆出来，而不是等重放结束后靠"对端什么都没收到"去猜。
 * </p>
 *
 * <h3>设计原则</h3>
 * <ul>
 *   <li><b>永不阻断</b>：本自检只打印结论，不决定进程是否退出。真正无法发送时，
 *       注入本身会失败并计数，由使用者决定如何处理。</li>
 *   <li><b>不污染业务流量</b>：探测帧使用保留的以太网实验类型 {@code 0x88B5}，
 *       目的 MAC 为广播，任何正常协议栈都会直接丢弃；不会进入任何人的业务处理路径。</li>
 * </ul>
 */
public class StartupSelfCheck {

    private static final Logger logger = LoggerFactory.getLogger(StartupSelfCheck.class);

    /** IEEE 本地实验用 EtherType（0x88B5），保证探测帧不会被任何正常协议栈消费 */
    private static final short PROBE_ETHERTYPE = (short) 0x88B5;

    /** 注入能力自检结论 */
    public enum InjectVerdict {
        /** 成功注入并在同网卡抓包中观察到该帧 */
        OBSERVED,
        /** 注入调用返回错误，但帧仍被观察到（驱动/Npcap 报错不可靠，实际已发出） */
        OBSERVED_DESPITE_ERROR,
        /** 注入调用成功，但未能在本机观察到（通常只表示该网卡/驱动不把注入帧回环给抓包） */
        SENT_NOT_OBSERVED,
        /** 注入调用失败，且未观察到该帧 */
        FAILED,
        /** 无法完成自检（句柄打不开等） */
        UNKNOWN;

        /**
         * 该结论是否表示"这张网卡能把帧发出去"。
         * <p>
         * 判据以**是否观察到帧**为准：实测存在"驱动报错但帧确实发出并被抓到"的情况，
         * 也存在"调用成功但驱动不回环、无法在本机观察"的情况（后者按可注入处理，
         * 因为无法观察不等于没有发出）。
         * </p>
         *
         * @return true 表示可用于帧注入
         */
        public boolean injectable() {
            return this == OBSERVED || this == OBSERVED_DESPITE_ERROR || this == SENT_NOT_OBSERVED;
        }
    }

    /**
     * 自检结果。
     *
     * @param interfaceName 网卡名
     * @param description   网卡描述
     * @param dlt           数据链路类型
     * @param ethernet      DLT 是否为以太网（帧结构与捕获内容匹配的前提）
     * @param verdict      注入能力结论
     * @param detail       结论细节（错误信息或提示）
     * @param warnings     其他需要提醒的事项
     */
    public record Result(String interfaceName, String description, String dlt, boolean ethernet,
                         InjectVerdict verdict, String detail, List<String> warnings) {

        /** @return 针对注入结论的处置建议 */
        public String advice() {
            switch (verdict) {
                case OBSERVED:
                    return null;
                case OBSERVED_DESPITE_ERROR:
                    return "Injection reported an error but the frame WAS observed on the NIC, so frames do reach "
                            + "the network. This Npcap/driver combination reports a false negative; the tool "
                            + "tolerates it (failures are counted, and this NIC is still usable).";
                case SENT_NOT_OBSERVED:
                    return "Injection calls succeeded but the frame was not observed on the same NIC. "
                            + "This is usually normal (many drivers do not loop injected frames back to capture). "
                            + "Verify on the collector side that frames actually arrive.";
                case FAILED:
                    return "Frame injection FAILED on this NIC and the frame was not observed. "
                            + "Typical causes: (1) the driver/adapter does not support injection "
                            + "(common for Wi-Fi on Windows) — use a wired Ethernet adapter; "
                            + "(2) the adapter link is down; "
                            + "(3) Npcap was not installed with WinPcap API compatibility; "
                            + "(4) insufficient privileges — run as Administrator/root. "
                            + "Choose the NIC explicitly with --injectInterface=<IP>.";
                default:
                    return "Injection capability could not be determined; verify manually before relying on replay.";
            }
        }
    }

    private StartupSelfCheck() {
    }

    /**
     * 按本机 IP 选择注入网卡。
     *
     * @param ip 目标网卡上的 IP 地址
     * @return 网卡；未找到返回 null
     */
    public static PcapNetworkInterface findInterfaceByIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }
        try {
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                for (org.pcap4j.core.PcapAddress a : nif.getAddresses()) {
                    if (a.getAddress() != null && ip.equals(a.getAddress().getHostAddress())) {
                        return nif;
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("[JShark] Failed to enumerate network interfaces: {}", e.getMessage());
        } catch (LinkageError e) {
            // Npcap/libpcap 未安装或 wpcap.dll 加载失败：这是环境问题，必须给出可操作的提示，
            // 而不是让 UnsatisfiedLinkError 冒到控制通道并表现为一次无原因的 exit 1。
            logger.error("[JShark] Npcap/libpcap is unavailable ({}). Install Npcap with WinPcap API "
                    + "compatibility (or libpcap) and run as Administrator for frame injection.",
                    e.toString());
        }
        return null;
    }

    /** @return 本机所有 IPv4（含网卡名），用于“找不到注入网卡”时给出可操作提示 */
    public static java.util.List<String> listIpv4Addresses() {
        java.util.List<String> result = new java.util.ArrayList<>();
        try {
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                for (org.pcap4j.core.PcapAddress a : nif.getAddresses()) {
                    if (a.getAddress() instanceof java.net.Inet4Address) {
                        result.add(a.getAddress().getHostAddress()
                                + " (" + (nif.getDescription() == null ? nif.getName() : nif.getDescription()) + ")");
                    }
                }
            }
        } catch (Exception | LinkageError ignored) {
            // 枚举失败时返回空表，调用方只把提示降级为“无法枚举网卡”
        }
        return result;
    }

    /**
     * 执行自检并打印结果。
     *
     * @param nif         注入网卡
     * @param frameCount  预计重放的帧数（仅用于展示）
     * @param volumeCount 预计重放的分卷数（仅用于展示）
     * @return 自检结果；网卡为空时返回 null
     */
    public static Result run(PcapNetworkInterface nif, long frameCount, int volumeCount) {
        if (nif == null) {
            return null;
        }
        List<String> warnings = new ArrayList<>();
        String dlt = "-";
        boolean ethernet = false;

        try (PcapHandle handle = nif.openLive(65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
            dlt = String.valueOf(handle.getDlt());
            ethernet = DataLinkType.EN10MB.equals(handle.getDlt());
        } catch (Exception e) {
            logger.warn("[SelfCheck] Cannot open {} for a capability check: {}", nif.getName(), e.getMessage());
            warnings.add("Failed to open the injection interface: " + e.getMessage());
        } catch (LinkageError e) {
            logger.error("[SelfCheck] Npcap/libpcap is unavailable: {}", e.toString());
            warnings.add("Npcap/libpcap is unavailable: " + e);
        }

        if (!ethernet && !"-".equals(dlt)) {
            warnings.add("Injection interface link type is " + dlt + ", not Ethernet. "
                    + "Captured frames are Ethernet frames, so injection would produce malformed output.");
        }
        if (isWireless(nif)) {
            // 自检只能证明“本机能构造并发出帧”，证明不了 AP 会接受它：
            // Wi-Fi 客户端通常不能伪造源 MAC，AP 会把带原始源 MAC 的注入帧丢掉。
            warnings.add("This looks like a Wi-Fi adapter. Frame injection over Wi-Fi is unreliable: "
                    + "the access point usually drops frames whose source MAC is not this client's, even though "
                    + "the local self-check may pass. Use a wired Ethernet adapter for frame-level replay.");
        }

        InjectVerdict verdict = InjectVerdict.UNKNOWN;
        String detail = "";
        if (ethernet) {
            InjectProbe probe = probeInjection(nif);
            verdict = probe.verdict();
            detail = probe.detail();
        } else {
            detail = "skipped: non-Ethernet link type";
        }

        Result result = new Result(nif.getName(), nif.getDescription(), dlt, ethernet, verdict, detail, warnings);
        log(result, frameCount, volumeCount);
        return result;
    }

    /**
     * 打印自检结果。
     *
     * @param result      自检结果
     * @param frameCount  待重放帧数
     * @param volumeCount 分卷数
     */
    public static void log(Result result, long frameCount, int volumeCount) {
        if (result == null) {
            return;
        }
        logger.info("[SelfCheck] Injection interface: {} ({})", result.interfaceName(), result.description());
        logger.info("[SelfCheck] Link type: {} (Ethernet: {})", result.dlt(), result.ethernet());
        if (frameCount > 0) {
            logger.info("[SelfCheck] Frames to replay: {}, volumes: {}", frameCount, volumeCount);
        }

        String mark = switch (result.verdict()) {
            case OBSERVED -> "[OK]";
            case OBSERVED_DESPITE_ERROR -> "[OK*]";
            case SENT_NOT_OBSERVED -> "[WARN]";
            default -> "[FAIL]";
        };
        logger.info("[SelfCheck] {} Frame injection: {}{}", mark, result.verdict(),
                result.detail() == null || result.detail().isEmpty() ? "" : " (" + result.detail() + ")");

        String advice = result.advice();
        if (advice != null) {
            logger.warn("[SelfCheck] {}", advice);
        }
        for (String w : result.warnings()) {
            logger.warn("[SelfCheck] {}", w);
        }
    }

    /** 注入探测结果 */
    private record InjectProbe(InjectVerdict verdict, String detail) {
    }

    /** @return 网卡描述/设备名是否看起来像 Wi-Fi（用于提示常见的“注入成功但 AP 丢弃”场景） */
    static boolean isWireless(PcapNetworkInterface nif) {
        if (nif == null) {
            return false;
        }
        String text = ((nif.getDescription() == null ? "" : nif.getDescription())
                + " " + (nif.getName() == null ? "" : nif.getName())).toLowerCase(java.util.Locale.ROOT);
        return text.contains("wi-fi") || text.contains("wifi") || text.contains("wireless")
                || text.contains("wlan") || text.contains("802.11");
    }

    /**
     * 注入能力自检：在目标网卡上发出探测帧，并尝试在同一网卡上观察到它。
     * <p>
     * 观察成功可以证明"帧确实被构造并交给了驱动"；观察不到时无法区分
     * "驱动不回环注入帧"（常见且无害）与"真的没发出去"，因此结论区分为
     * {@link InjectVerdict#OBSERVED} 与 {@link InjectVerdict#SENT_NOT_OBSERVED} 两档，
     * 而注入调用失败则直接判 {@link InjectVerdict#FAILED}。
     * </p>
     *
     * @param nif 注入网卡
     * @return 探测结果
     */
    private static InjectProbe probeInjection(PcapNetworkInterface nif) {
        byte[] probeFrame = buildProbeFrame();
        try (PcapHandle handle = nif.openLive(65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
            try {
                handle.setFilter("ether proto 0x88b5", org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE);
            } catch (Exception e) {
                // 过滤器并非必需，失败则退化为全量收包
            }

            int sent = 0;
            String lastError = null;
            for (int i = 0; i < 3; i++) {
                try {
                    handle.sendPacket(probeFrame);
                    sent++;
                } catch (Exception e) {
                    lastError = e.getMessage();
                    break;
                }
            }

            // 在同网卡上等待探测帧。以"是否观察到"为首要判据：
            // 实测存在"驱动报错但帧确实发出"与"调用成功但驱动不回环"两种相反情况。
            long deadline = System.currentTimeMillis() + 600;
            while (System.currentTimeMillis() < deadline) {
                Packet pkt;
                try {
                    pkt = handle.getNextPacketEx();
                } catch (java.util.concurrent.TimeoutException te) {
                    continue;
                } catch (java.io.EOFException eof) {
                    break;
                }
                if (pkt == null) {
                    continue;
                }
                if (isProbeFrame(pkt.getRawData())) {
                    if (sent > 0) {
                        return new InjectProbe(InjectVerdict.OBSERVED, "observed on the same NIC");
                    }
                    return new InjectProbe(InjectVerdict.OBSERVED_DESPITE_ERROR,
                            "observed on the same NIC although sendPacket reported an error");
                }
            }

            if (sent == 0) {
                return new InjectProbe(InjectVerdict.FAILED, lastError);
            }
            return new InjectProbe(InjectVerdict.SENT_NOT_OBSERVED, sent + " frame(s) injected");
        } catch (PcapNativeException | NotOpenException e) {
            return new InjectProbe(InjectVerdict.FAILED, e.getMessage());
        } catch (LinkageError e) {
            return new InjectProbe(InjectVerdict.FAILED, "Npcap/libpcap unavailable: " + e);
        } catch (Exception e) {
            return new InjectProbe(InjectVerdict.UNKNOWN, e.getMessage());
        }
    }

    /** @return 探测帧字节（EtherType=0x88B5，目的 MAC 广播） */
    private static byte[] buildProbeFrame() {
        byte[] frame = new byte[14 + 46];
        // 目的 MAC：广播
        for (int i = 0; i < 6; i++) {
            frame[i] = (byte) 0xFF;
        }
        // 源 MAC：本地管理地址（不冒充任何真实网卡）
        frame[6] = 0x02;
        frame[7] = 0x4A;
        frame[8] = 0x53;
        frame[9] = 0x48;
        frame[10] = 0x41;
        frame[11] = 0x52;
        // EtherType
        frame[12] = (byte) (PROBE_ETHERTYPE >> 8);
        frame[13] = (byte) PROBE_ETHERTYPE;
        // 载荷标记
        byte[] tag = "JSHARK-INJECT-SELFTEST".getBytes();
        System.arraycopy(tag, 0, frame, 14, tag.length);
        return frame;
    }

    private static boolean isProbeFrame(byte[] raw) {
        if (raw == null || raw.length < 14 + 8) {
            return false;
        }
        if ((raw[12] & 0xFF) != 0x88 || (raw[13] & 0xFF) != 0xB5) {
            return false;
        }
        byte[] tag = "JSHARK-INJECT-SELFTEST".getBytes();
        for (int i = 0; i < tag.length; i++) {
            if (raw[14 + i] != tag[i]) {
                return false;
            }
        }
        return true;
    }
}
