package com.jshark.parser;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.concurrent.TimeUnit;

/**
 * 浠ョ绾?pcap 鏂囦欢涓烘暟鎹簮鐨勫抚鏉ユ簮銆?
 *
 * <p>璇诲彇椤哄簭鍗虫枃浠堕『搴忥紝涔熷氨鏄姄鍖呮椂鐨勬椂闂撮『搴忥紝鍥犳 {@link #isOrderedByTimestamp()} 杩斿洖 true锛?
 * 寮曟搸鍙互鐩存帴鐢?pcap 棣栭儴鐨勭簿纭椂闂存埑鍋氫弗鏍煎€嶇巼鏃跺簭銆?/p>
 */
public class PcapFrameSource implements FrameSource {

    private static final Logger logger = LoggerFactory.getLogger(PcapFrameSource.class);

    private final String pcapFile;
    private PcapHandle handle;
    private long skippedWithoutFrame;
    private Long startAtMs;
    private Long endAtMs;
    /** 璺宠繃 {@code startAtMs} 涔嬪墠鐨勫抚鏃剁敤浜庝腑鏂殑鍒ゆ嵁锛坰top/seek锛夛紱榛樿涓嶄腑鏂€?*/
    private java.util.function.BooleanSupplier abortCondition = () -> false;

    /**
     * @param pcapFile pcap 鏂囦欢璺緞
     */
    public PcapFrameSource(String pcapFile) {
        this.pcapFile = pcapFile;
    }

    /**
     * 璁剧疆鈥滆烦杩囧墠瀵煎抚鈥濋樁娈电殑涓柇鍒ゆ嵁銆?
     *
     * <p>seek 鍒板ぇ鏂囦欢鐨勯潬鍚庝綅缃椂锛岃烦杩囪繃绋嬪彲鑳芥寔缁暟绉掞紱杩欓噷璁?stop/seek 鑳界珛鍒绘墦鏂€?/p>
     *
     * @param abortCondition 杩斿洖 true 琛ㄧず搴旂珛鍗虫斁寮冨綋鍓嶆锛沶ull 琛ㄧず涓嶄腑鏂?
     */
    public void setAbortCondition(java.util.function.BooleanSupplier abortCondition) {
        this.abortCondition = abortCondition == null ? () -> false : abortCondition;
    }

    /**
     * 璁剧疆鍥炴斁璧风偣锛坋poch ms锛屽惈锛夛紱涔嬪墠鐨勫抚鍙涓嶆敞鍏ャ€?
     *
     * @param startAtMs 璧风偣锛沶ull/璐熷€艰〃绀轰粠澶?
     */
    public void setStartAtMs(Long startAtMs) {
        this.startAtMs = startAtMs != null && startAtMs >= 0 ? startAtMs : null;
    }

    /**
     * 璁剧疆鍥炴斁缁堢偣锛坋poch ms锛屽惈锛夛紱涔嬪悗鐨勫抚涓嶆敞鍏ャ€?
     *
     * @param endAtMs 缁堢偣锛沶ull/璐熷€艰〃绀哄埌鏂囦欢鏈熬
     */
    public void setEndAtMs(Long endAtMs) {
        this.endAtMs = endAtMs != null && endAtMs >= 0 ? endAtMs : null;
    }

    @Override
    public void open() throws Exception {
        File file = new File(pcapFile);
        if (!file.isFile()) {
            throw new com.jshark.PacketCaptureException("PCAP file does not exist: " + pcapFile);
        }
        handle = Pcaps.openOffline(file.getAbsolutePath());
        logger.info("[JShark] Frame source: PCAP file {}", file.getAbsolutePath());
    }

    @Override
    public Frame next() throws Exception {
        if (handle == null) {
            return null;
        }
        long skippedForStart = 0;
        while (true) {
            Packet packet;
            try {
                packet = handle.getNextPacketEx();
            } catch (java.io.EOFException e) {
                return null;
            }
            if (packet == null) {
                return null;
            }

            byte[] frameData = packet.getRawData();
            if (frameData == null || frameData.length == 0) {
                skippedWithoutFrame++;
                continue;
            }

            long timestampNanos = System.currentTimeMillis() * 1_000_000L;
            try {
                java.sql.Timestamp ts = handle.getTimestamp();
                if (ts != null) {
                    timestampNanos = ReplayClock.PacketTime.of(ts).toEpochNanos();
                }
            } catch (Exception e) {
                logger.debug("Failed to read pcap timestamp: {}", e.getMessage());
            }

            long timestampMs = TimeUnit.NANOSECONDS.toMillis(timestampNanos);
            if (startAtMs != null && timestampMs < startAtMs) {
                // seek 鍚庡彲鑳借璺宠繃鍑犵櫨 MB锛氬繀椤诲懆鏈熸€у搷搴?stop/seek锛?
                // 鍚﹀垯 ui 鐨勨€滃仠姝⑩€濅細鍦ㄥぇ鏂囦欢涓婇潤榛樺崱浣忔暟绉掑埌鏁板崄绉掋€?
                if ((++skippedForStart & 0xFF) == 0 && abortCondition.getAsBoolean()) {
                    return null;
                }
                continue;
            }
            if (endAtMs != null && timestampMs > endAtMs) {
                return null;
            }

            // 鍏冩暟鎹竴寰嬩粠甯у瓧鑺傝В鏋愶細涓庢暟鎹簱甯ф潵婧愬叡鐢ㄥ悓涓€鏉¤矾寰勶紝
            // 閬垮厤 pcap4j 瀵硅薄妯″瀷涓庡師濮嬪瓧鑺傝В鏋愬湪 VLAN/鍒嗙墖绛夊満鏅笅缁欏嚭涓嶅悓缁撴灉銆?
            FrameMeta meta = extractMeta(frameData);
            return new Frame(frameData, timestampNanos,
                    meta.srcIp(), meta.dstIp(),
                    meta.srcPort(), meta.dstPort(),
                    meta.ipProtocol());
        }
    }

    @Override
    public boolean isOrderedByTimestamp() {
        return true;
    }

    @Override
    public String describe() {
        return "PCAP file " + pcapFile;
    }

    @Override
    public long skippedWithoutFrame() {
        return skippedWithoutFrame;
    }

    @Override
    public void close() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.close();
            } catch (Exception e) {
                logger.debug("Error closing pcap handle: {}", e.getMessage());
            }
        }
        handle = null;
    }

    // ==================== 鍏冩暟鎹彁鍙?====================

    /**
     * 浠庡畬鏁村抚瀛楄妭涓彁鍙栧湴鍧€鍏冩暟鎹紙渚涙墍鏈夊抚鏉ユ簮鍏辩敤锛夈€?
     *
     * <p>鍙В鏋愬埌"澶熷仛杩囨护涓庣洰鏍囨槧灏?涓烘锛欼Pv4/IPv6 鍦板潃銆乀CP/UDP 绔彛銆佸崗璁悕銆?
     * 涓嶄緷璧?pcap4j 鐨勫璞℃ā鍨嬶紝鍥犳鏁版嵁搴撻噷鐨?{@code frameData} 涔熻兘鐩存帴鐢ㄣ€?/p>
     *
     * @param frame 瀹屾暣甯у瓧鑺?
     * @return 鍏冩暟鎹紱闈?IP 甯х殑鍚勫瓧娈典负 null/绌轰覆
     */
    static FrameMeta extractMeta(byte[] frame) {
        String srcIp = null;
        String dstIp = null;
        String protocol = "";
        Integer srcPort = null;
        Integer dstPort = null;

        if (frame == null || frame.length < 14 + 20) {
            return new FrameMeta(null, null, "", null, null);
        }

        // 璺宠繃 VLAN 鏍囩
        int typeOffset = 12;
        int etherType = ((frame[typeOffset] & 0xFF) << 8) | (frame[typeOffset + 1] & 0xFF);
        int ipOffset = 14;
        while ((etherType == 0x8100 || etherType == 0x88A8) && frame.length >= ipOffset + 4) {
            etherType = ((frame[ipOffset + 2] & 0xFF) << 8) | (frame[ipOffset + 3] & 0xFF);
            ipOffset += 4;
        }

        if (etherType == 0x0800) {
            if (frame.length < ipOffset + 20) {
                return new FrameMeta(null, null, "", null, null);
            }
            int ihl = (frame[ipOffset] & 0x0F) * 4;
            int protocolNumber = frame[ipOffset + 9] & 0xFF;
            protocol = ipProtocolName(protocolNumber);
            srcIp = ipv4(frame, ipOffset + 12);
            dstIp = ipv4(frame, ipOffset + 16);
            int fragmentOffset = (((frame[ipOffset + 6] & 0xFF) << 8 | (frame[ipOffset + 7] & 0xFF)) & 0x1FFF) * 8;
            if (fragmentOffset == 0 && (protocolNumber == 6 || protocolNumber == 17)) {
                int l4 = ipOffset + ihl;
                if (frame.length >= l4 + 4) {
                    srcPort = ((frame[l4] & 0xFF) << 8) | (frame[l4 + 1] & 0xFF);
                    dstPort = ((frame[l4 + 2] & 0xFF) << 8) | (frame[l4 + 3] & 0xFF);
                }
            }
        } else if (etherType == 0x86DD) {
            if (frame.length < ipOffset + 40) {
                return new FrameMeta(null, null, "", null, null);
            }
            int nextHeader = frame[ipOffset + 6] & 0xFF;
            protocol = ipProtocolName(nextHeader);
            srcIp = ipv6(frame, ipOffset + 8);
            dstIp = ipv6(frame, ipOffset + 24);
            if (nextHeader == 6 || nextHeader == 17) {
                int l4 = ipOffset + 40;
                if (frame.length >= l4 + 4) {
                    srcPort = ((frame[l4] & 0xFF) << 8) | (frame[l4 + 1] & 0xFF);
                    dstPort = ((frame[l4 + 2] & 0xFF) << 8) | (frame[l4 + 3] & 0xFF);
                }
            }
        }

        return new FrameMeta(srcIp, dstIp, protocol, srcPort, dstPort);
    }

    private static String ipProtocolName(int number) {
        return switch (number) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            case 1 -> "ICMPV4";
            case 58 -> "ICMPV6";
            default -> String.valueOf(number);
        };
    }

    private static String ipv4(byte[] f, int off) {
        return String.format(java.util.Locale.ROOT, "%d.%d.%d.%d",
                f[off] & 0xFF, f[off + 1] & 0xFF, f[off + 2] & 0xFF, f[off + 3] & 0xFF);
    }

    private static String ipv6(byte[] f, int off) {
        try {
            return java.net.InetAddress.getByAddress(
                    java.util.Arrays.copyOfRange(f, off, off + 16)).getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

}
