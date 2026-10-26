package com.jshark;

import com.jshark.parser.FrameRewriter;
import com.jshark.parser.IpChecksum;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * B1 验收测试：帧改写器只改"寻址与校验和"。
 *
 * <h3>核心不变量（逐字节断言）</h3>
 * <ul>
 *   <li>no-op 时输出与输入**逐字节相同**</li>
 *   <li>改写后：源地址、源端口、seq/ack、flags、IP ID、TTL、payload **一个字节都不变**</li>
 *   <li>改写后：IP 头校验和与传输层校验和**必须通过**（用独立实现交叉验证）</li>
 *   <li>分片数据报拒绝改端口；截断帧拒绝改写；不合法校验和拒绝改写</li>
 * </ul>
 */
public class FrameRewriteTest {

    private static final Logger logger = LoggerFactory.getLogger(FrameRewriteTest.class);

    private static final MacAddress SRC_MAC = MacAddress.getByName("66:77:88:99:aa:bb");
    private static final MacAddress DST_MAC = MacAddress.getByName("00:11:22:33:44:55");

    private static int totalChecks;
    private static int failedChecks;

    @org.junit.jupiter.api.Test
    void frameRewriteRegression() throws Exception {
        logger.info("=================================================");
        logger.info("  B1 验收：帧改写（只改寻址与校验和）");
        logger.info("=================================================");

        checkChecksumPrimitive();
        checkNoOpIsByteIdentical();
        checkUdpAddressAndPortRewrite();
        checkTcpRewriteKeepsStreamFields();
        checkMacPolicy();
        checkFragmentedDatagramPortRefused();
        checkTruncatedRefused();
        checkBadChecksumRefused();
        checkUdpZeroChecksumPreserved();
        checkIpv6Rewrite();

        logger.info("");
        logger.info("检查 {}/{} 通过, {} 失败", totalChecks - failedChecks, totalChecks, failedChecks);
    }

    // ==================== 用例 ====================

    /** 用例 1：校验和原语 */
    private static void checkChecksumPrimitive() throws Exception {
        logger.info("---- [1] 校验和原语 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "192.168.1.200", 3000, 8200, new byte[]{1, 2, 3, 4});

        // IPv4 头自洽
        int ihl = (frame[14] & 0x0F) * 4;
        check(IpChecksum.verify(frame, 14, ihl), "IPv4 头校验和自洽");
        check(!IpChecksum.verify(frame, 14, ihl - 2), "截短后校验和不通过（验证函数有效）");

        // 传输层自洽：构造伪首部后交叉验证
        int transportLen = ((frame[16] & 0xFF) << 8 | (frame[17] & 0xFF)) - ihl;
        int transportOffset = 14 + ihl;
        byte[] pseudo = new byte[12];
        System.arraycopy(frame, 14 + 12, pseudo, 0, 8);
        pseudo[9] = (byte) 17;
        pseudo[10] = (byte) ((transportLen >> 8) & 0xFF);
        pseudo[11] = (byte) (transportLen & 0xFF);
        int sum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, transportOffset, transportLen);
        check(sum == 0, "UDP 校验和自洽（伪首部交叉验证，含字段求和校验和为 0）");

        // 分段计算 == 整段计算
        byte[] all = new byte[12 + transportLen];
        System.arraycopy(pseudo, 0, all, 0, 12);
        System.arraycopy(frame, transportOffset, all, 12, transportLen);
        check(IpChecksum.compute(all, 0, all.length) == sum, "两段拼接与整体计算一致");

        // 奇数长度
        byte[] odd = {0x12, 0x34, 0x56};
        byte[] odd2 = {0x12, 0x34, 0x56};
        check(IpChecksum.compute(odd, 0, 3) == IpChecksum.compute(odd2, 0, 3), "奇数长度计算稳定");
    }

    /** 用例 2：no-op 必须逐字节相同 */
    private static void checkNoOpIsByteIdentical() throws Exception {
        logger.info("---- [2] no-op 快路径 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "192.168.1.200", 3000, 8200, "payload-1".getBytes());
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        FrameRewriter.RewriteResult r = rw.rewrite(frame, "192.168.1.200", 8200);
        check(r.status() == FrameRewriter.Status.UNCHANGED,
                "目的地址与端口都未变 -> UNCHANGED (实际 " + r.status() + ")");
        check(r.bytes() == frame || Arrays.equals(r.bytes(), frame), "输出与输入逐字节相同（含引用相同）");
        check(r.modified() == false, "modified() == false");
    }

    /** 用例 3：UDP 改地址 + 改端口，只动该动的字节 */
    private static void checkUdpAddressAndPortRewrite() throws Exception {
        logger.info("---- [3] UDP 改地址与端口 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "10.0.0.5", 3000, 8200, "hello-jshark".getBytes());
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        // 只改端口
        FrameRewriter.RewriteResult portOnly = rw.rewrite(frame, "10.0.0.5", 9999);
        check(portOnly.status() == FrameRewriter.Status.REWRITTEN, "只改端口 -> REWRITTEN");
        check(portOnly.bytes()[14 + 20 + 2] == (byte) (9999 >> 8)
                        && portOnly.bytes()[14 + 20 + 3] == (byte) (9999 & 0xFF),
                "UDP 目的端口已被改写为 9999");
        checkUnchangedRegions(frame, portOnly.bytes(), "192.168.1.100", 3000,
                "10.0.0.5", "改端口：源/载荷/IP ID/TTL 不变");
        checkChecksumsValid(portOnly.bytes(), "改端口后校验和通过");

        // 改地址 + 改端口
        FrameRewriter.RewriteResult both = rw.rewrite(frame, "192.168.1.201", 9998);
        check(both.status() == FrameRewriter.Status.REWRITTEN, "改地址+端口 -> REWRITTEN");
        check(both.dstIp().equals("192.168.1.201"), "报告的目的 IP 正确 (" + both.dstIp() + ")");
        checkUnchangedRegions(frame, both.bytes(), "192.168.1.100", 3000,
                "192.168.1.201", "改地址：源/载荷/IP ID/TTL 不变");
        checkChecksumsValid(both.bytes(), "改地址后 IP 与 UDP 校验和均通过");
        check(both.bytes()[14 + 20 + 6] != 0 || both.bytes()[14 + 20 + 7] != 0, "UDP 校验和非零");

        // 只改地址
        FrameRewriter.RewriteResult addrOnly = rw.rewrite(frame, "192.168.1.202", 8200);
        check(addrOnly.status() == FrameRewriter.Status.REWRITTEN, "只改地址 -> REWRITTEN");
        check(addrOnly.bytes()[14 + 20 + 2] == frame[14 + 20 + 2]
                        && addrOnly.bytes()[14 + 20 + 3] == frame[14 + 20 + 3],
                "只改地址时目的端口不变");
        checkChecksumsValid(addrOnly.bytes(), "只改地址后校验和通过");
    }

    /** 用例 4：TCP 改写不得触碰流状态字段 */
    private static void checkTcpRewriteKeepsStreamFields() throws Exception {
        logger.info("---- [4] TCP 只改寻址，不动流状态 ----");
        byte[] frame = buildTcpFrame("192.168.1.100", "10.0.0.7", 54321, 5432,
                new byte[]{(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78},
                100L, 200L, true, true, new byte[]{'S', 'E', 'L', 'E', 'C', 'T'});
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        FrameRewriter.RewriteResult r = rw.rewrite(frame, "192.168.1.99", 6543);
        check(r.status() == FrameRewriter.Status.REWRITTEN, "TCP 改写 -> REWRITTEN");
        checkChecksumsValid(r.bytes(), "TCP 改写后校验和通过");

        int ip = 14;
        int ihl = (r.bytes()[ip] & 0x0F) * 4;
        int tcp = ip + ihl;
        check(Arrays.equals(Arrays.copyOfRange(frame, tcp + 4, tcp + 8),
                        Arrays.copyOfRange(r.bytes(), tcp + 4, tcp + 8)),
                "TCP 序号未变");
        check(Arrays.equals(Arrays.copyOfRange(frame, tcp + 8, tcp + 12),
                        Arrays.copyOfRange(r.bytes(), tcp + 8, tcp + 12)),
                "TCP 确认号未变");
        check(frame[tcp + 12] == r.bytes()[tcp + 12] && frame[tcp + 13] == r.bytes()[tcp + 13],
                "TCP flags 未变");
        check(Arrays.equals(Arrays.copyOfRange(frame, tcp + 14, tcp + 16),
                        Arrays.copyOfRange(r.bytes(), tcp + 14, tcp + 16)),
                "TCP 窗口未变");
        checkUnchangedRegions(frame, r.bytes(), "192.168.1.100", 54321,
                "192.168.1.99", "TCP 改写：源 IP/源端口/IP ID/TTL 不变");
    }

    /** 用例 5：目的 MAC 策略 */
    private static void checkMacPolicy() throws Exception {
        logger.info("---- [5] 目的 MAC 策略 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "10.0.0.5", 3000, 8200, "x".getBytes());

        // preserve：MAC 不变
        FrameRewriter preserve = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);
        byte[] out = preserve.rewrite(frame, "10.0.0.6", 9000).bytes();
        check(Arrays.equals(Arrays.copyOfRange(out, 0, 6), DST_MAC.getAddress()), "preserve：目的 MAC 不变");

        // replace：固定 MAC
        byte[] newMac = FrameRewriter.MacPolicy.parseMac("02:00:00:11:22:33");
        FrameRewriter replace = new FrameRewriter(FrameRewriter.MacPolicy.replace(newMac), null);
        out = replace.rewrite(frame, "10.0.0.6", 9000).bytes();
        check(Arrays.equals(Arrays.copyOfRange(out, 0, 6), newMac), "replace：目的 MAC 被覆盖");
        check(Arrays.equals(Arrays.copyOfRange(out, 6, 12), SRC_MAC.getAddress()), "源 MAC 不变");

        // per-ip：按目的 IP 命中
        Map<String, byte[]> map = new LinkedHashMap<>();
        map.put("10.0.0.6", newMac);
        FrameRewriter perIp = new FrameRewriter(FrameRewriter.MacPolicy.perIp(map), null);
        out = perIp.rewrite(frame, "10.0.0.6", 9000).bytes();
        check(Arrays.equals(Arrays.copyOfRange(out, 0, 6), newMac), "per-ip：命中映射");

        // auto：IPv4 组播公式 224.3.0.0 -> 01:00:5E:03:00:00
        FrameRewriter auto = new FrameRewriter(FrameRewriter.MacPolicy.auto(), null);
        out = auto.rewrite(frame, "224.3.0.0", 8200).bytes();
        check(Arrays.equals(Arrays.copyOfRange(out, 0, 6),
                        new byte[]{0x01, 0x00, 0x5E, 0x03, 0x00, 0x00}),
                "auto：224.3.0.0 -> 01:00:5E:03:00:00");

        // auto：广播
        out = auto.rewrite(frame, "255.255.255.255", 8200).bytes();
        check(Arrays.equals(Arrays.copyOfRange(out, 0, 6),
                        new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}),
                "auto：有限广播 -> ff:ff:ff:ff:ff:ff");

        // auto：IPv6 组播公式 ff02::1 -> 33:33:00:00:00:01
        byte[] v6 = buildUdp6Frame("2001:db8::1", "ff02::1", 3000, 8200, "y".getBytes());
        out = auto.rewrite(v6, "ff02::1", 8200).bytes();
        check(Arrays.equals(Arrays.copyOfRange(out, 0, 6),
                        new byte[]{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}),
                "auto：ff02::1 -> 33:33:00:00:00:01");

        // parse 形式
        check(FrameRewriter.MacPolicy.parse("preserve").mode() == FrameRewriter.MacPolicy.Mode.PRESERVE,
                "--dstMac=preserve 解析正确");
        check(FrameRewriter.MacPolicy.parse("auto").mode() == FrameRewriter.MacPolicy.Mode.AUTO,
                "--dstMac=auto 解析正确");
        check(FrameRewriter.MacPolicy.parse("02:00:00:11:22:33").mode() == FrameRewriter.MacPolicy.Mode.REPLACE,
                "--dstMac=<MAC> 解析正确");
        FrameRewriter.MacPolicy multi = FrameRewriter.MacPolicy.parse("10.0.0.6=02:00:00:11:22:33,10.0.0.7=02:00:00:44:55:66");
        check(multi.mode() == FrameRewriter.MacPolicy.Mode.PER_IP && multi.mapping().size() == 2,
                "--dstMac=IP=MAC,... 解析正确");
    }

    /** 用例 6：分片数据报拒绝改端口 */
    private static void checkFragmentedDatagramPortRefused() throws Exception {
        logger.info("---- [6] 分片数据报 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "10.0.0.5", 3000, 8200, new byte[100]);
        // 手工置位 MF=1（首片）。此时 IP 总长度只描述本片，与整帧长度一致。
        // 置位后必须重算 IP 头校验和，否则帧会先被"校验和不合法"预检拦下，测不到分片逻辑。
        frame[14 + 6] |= 0x20;
        recomputeIpChecksum(frame);
        check((u16(frame, 14 + 6) & 0x2000) != 0,
                "测试帧已置 MF 位（fragField=0x" + Integer.toHexString(u16(frame, 14 + 6)) + "）");
        check(IpChecksum.verify(frame, 14, (frame[14] & 0x0F) * 4), "分片测试帧 IP 头校验和自洽");
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        // 情形①：只有端口要改（地址不变）→ 无法达成目标，丢弃
        FrameRewriter.RewriteResult r1 = rw.rewrite(frame, "10.0.0.5", 9999);
        check(r1.status() == FrameRewriter.Status.SKIPPED_FRAGMENTED_PORT,
                "分片只改端口 -> SKIPPED_FRAGMENTED_PORT (实际 " + r1.status() + ")");
        check(Arrays.equals(r1.bytes(), frame), "分片只改端口：帧未被改动");

        // 情形②：地址与端口都要改 → 只改地址，端口保持原值，仍可注入
        FrameRewriter.RewriteResult r2 = rw.rewrite(frame, "10.0.0.9", 9999);
        check(r2.status() == FrameRewriter.Status.SKIPPED_FRAGMENTED_PORT,
                "分片地址+端口 -> 只改地址（实际 " + r2.status() + "）");
        check(r2.injectable(), "分片只改地址后仍可注入");
        check(r2.bytes()[14 + 20 + 2] == frame[14 + 20 + 2]
                        && r2.bytes()[14 + 20 + 3] == frame[14 + 20 + 3],
                "分片：目的端口未动");
        check(IpChecksum.verify(r2.bytes(), 14, 20), "分片改地址后 IP 头校验和通过");

        // 只改地址（端口与目标一致）：分片帧可以正常改写
        FrameRewriter.RewriteResult r3 = rw.rewrite(frame, "10.0.0.7", 8200);
        check(r3.status() == FrameRewriter.Status.REWRITTEN,
                "分片只改地址 -> REWRITTEN (实际 " + r3.status() + ")");
        check(IpChecksum.verify(r3.bytes(), 14, 20), "分片只改地址：IP 头校验和通过");
        check(r3.bytes()[14 + 20 + 2] == frame[14 + 20 + 2]
                        && r3.bytes()[14 + 20 + 3] == frame[14 + 20 + 3],
                "分片只改地址：目的端口不变");
    }

    /** 用例 7：截断帧拒绝改写 */
    private static void checkTruncatedRefused() throws Exception {
        logger.info("---- [7] 截断帧 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "10.0.0.5", 3000, 8200, new byte[200]);
        byte[] truncated = Arrays.copyOf(frame, frame.length - 50); // 人为截断，但 IP 总长度仍指向原始长度
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);
        FrameRewriter.RewriteResult r = rw.rewrite(truncated, "10.0.0.9", 9000);
        check(r.status() == FrameRewriter.Status.SKIPPED_TRUNCATED,
                "截断帧 -> SKIPPED_TRUNCATED (实际 " + r.status() + ")");
        check(!r.injectable(), "截断帧不注入");
    }

    /** 用例 8：原有传输层校验和不合法时拒绝改写（对应 checksum offload） */
    private static void checkBadChecksumRefused() throws Exception {
        logger.info("---- [8] 校验和不合法（offload 场景）----");
        byte[] frame = buildUdpFrame("192.168.1.100", "10.0.0.5", 3000, 8200, "offload".getBytes());
        // 破坏 UDP 校验和，模拟网卡卸载后的占位值
        frame[14 + 20 + 6] = 0x12;
        frame[14 + 20 + 7] = 0x34;
        // 只破坏传输层校验和，IP 头必须保持合法
        recomputeIpChecksum(frame);
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        FrameRewriter.RewriteResult r = rw.rewrite(frame, "10.0.0.5", 9999);
        check(r.status() == FrameRewriter.Status.SKIPPED_BAD_CHECKSUM,
                "改写端口时校验和不合法 -> SKIPPED_BAD_CHECKSUM (实际 " + r.status() + ")");
        check(!r.injectable(), "校验和不合法：不注入");

        // 只改地址同样需要可用的传输层校验和：伪首部含目的地址，必须重算；
        // 而原校验和不合法时无法可靠重算，因此也应拒绝（offload 场景统一走"禁止改写"）。
        FrameRewriter.RewriteResult addrOnly = rw.rewrite(frame, "10.0.0.9", 8200);
        check(addrOnly.status() == FrameRewriter.Status.SKIPPED_BAD_CHECKSUM,
                "改地址且原传输层校验和不合法 -> 一并拒绝 (实际 " + addrOnly.status() + ")");

        // no-op（地址与端口都不动）时不需要校验和，原样放行
        FrameRewriter.RewriteResult noop = rw.rewrite(frame, "10.0.0.5", 8200);
        check(noop.status() == FrameRewriter.Status.UNCHANGED,
                "no-op 不受校验和影响 -> UNCHANGED (实际 " + noop.status() + ")");
    }

    /** 用例 9：UDP 校验和为 0 时必须保持 0 */
    private static void checkUdpZeroChecksumPreserved() throws Exception {
        logger.info("---- [9] UDP 校验和为 0 ----");
        byte[] frame = buildUdpFrame("192.168.1.100", "10.0.0.5", 3000, 8200, "no-csum".getBytes());
        frame[14 + 20 + 6] = 0;
        frame[14 + 20 + 7] = 0;
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        FrameRewriter.RewriteResult r = rw.rewrite(frame, "10.0.0.5", 9999);
        check(r.status() == FrameRewriter.Status.REWRITTEN, "未计算校验和的 UDP 仍可改端口");
        check(r.bytes()[14 + 20 + 6] == 0 && r.bytes()[14 + 20 + 7] == 0,
                "UDP 校验和保持 0（不写入新值）");
        check(r.bytes()[14 + 20 + 2] == (byte) (9999 >> 8), "目的端口已改写");
    }

    /** 用例 10：IPv6 改写 */
    private static void checkIpv6Rewrite() throws Exception {
        logger.info("---- [10] IPv6 ----");
        byte[] frame = buildUdp6Frame("2001:db8::1", "2001:db8::99", 3000, 8200, "v6-payload".getBytes());
        FrameRewriter rw = new FrameRewriter(FrameRewriter.MacPolicy.preserve(), null);

        FrameRewriter.RewriteResult r = rw.rewrite(frame, "2001:db8::100", 9999);
        check(r.status() == FrameRewriter.Status.REWRITTEN, "IPv6 改写 -> REWRITTEN (实际 " + r.status() + ")");
        checkChecksumsValid(r.bytes(), "IPv6 改写后 UDP 校验和通过（伪首部含 16 字节地址）");
        // 源地址不变
        check(Arrays.equals(Arrays.copyOfRange(frame, 14 + 8, 14 + 24),
                        Arrays.copyOfRange(r.bytes(), 14 + 8, 14 + 24)),
                "IPv6 源地址未变");
        check(r.bytes()[14 + 40 + 2] == (byte) (9999 >> 8), "IPv6 UDP 目的端口已改写");

        // no-op
        FrameRewriter.RewriteResult noop = rw.rewrite(frame, "2001:db8::99", 8200);
        check(noop.status() == FrameRewriter.Status.UNCHANGED, "IPv6 no-op -> UNCHANGED");
    }

    // ==================== 断言助手 ====================

    /**
     * 断言"除目的地址/端口/校验和之外"的区域逐字节未变。
     *
     * @param before      原帧
     * @param after       改写后帧
     * @param srcIp       期望源 IP（字符串，用于确认未变）
     * @param srcPort     期望源端口
     * @param dstIp      改写后的目的 IP
     * @param label       断言标签
     */
    private static void checkUnchangedRegions(byte[] before, byte[] after,
                                              String srcIp, int srcPort, String dstIp, String label) {
        check(before.length == after.length, label + "：帧长不变");
        boolean ipv6 = ((before[14] & 0xF0) >> 4) == 6;
        int ipHeaderLen = ipv6 ? 40 : (before[14] & 0x0F) * 4;
        int transportOffset = 14 + ipHeaderLen;

        // 源地址
        int srcOff = 14 + (ipv6 ? 8 : 12);
        int srcLen = ipv6 ? 16 : 4;
        check(Arrays.equals(Arrays.copyOfRange(before, srcOff, srcOff + srcLen),
                        Arrays.copyOfRange(after, srcOff, srcOff + srcLen)),
                label + "：源 IP 未变 (" + srcIp + ")");

        // 源端口
        check(before[transportOffset] == after[transportOffset]
                        && before[transportOffset + 1] == after[transportOffset + 1],
                label + "：源端口未变 (" + srcPort + ")");

        // 载荷（传输层头之后到帧尾，含以太网填充；填充可能被实现保留）
        int payloadOff = transportOffset + (before[14 + 9] == 17 || ipv6 ? 8 : 20);
        if (after.length > payloadOff) {
            check(Arrays.equals(Arrays.copyOfRange(before, payloadOff, before.length),
                            Arrays.copyOfRange(after, payloadOff, after.length)),
                    label + "：payload 未变");
        }

        if (!ipv6) {
            // IP ID / TTL / protocol
            check(before[14 + 4] == after[14 + 4] && before[14 + 5] == after[14 + 5],
                    label + "：IP ID 未变");
            check(before[14 + 8] == after[14 + 8], label + "：TTL 未变");
            check(before[14 + 9] == after[14 + 9], label + "：协议号未变");
            check(before[14 + 6] == after[14 + 6] && before[14 + 7] == after[14 + 7],
                    label + "：分片字段未变");
        }
    }

    /** 用独立路径校验 IPv4/IPv6 与传输层校验和 */
    private static void checkChecksumsValid(byte[] frame, String label) {
        boolean ipv6 = ((frame[14] & 0xF0) >> 4) == 6;
        if (!ipv6) {
            int ihl = (frame[14] & 0x0F) * 4;
            check(IpChecksum.verify(frame, 14, ihl), label + "：IPv4 头校验和");
        }
        int ipHeaderLen = ipv6 ? 40 : (frame[14] & 0x0F) * 4;
        int protocol = ipv6 ? (frame[14 + 6] & 0xFF) : (frame[14 + 9] & 0xFF);
        int totalLen = ipv6
                ? ((frame[14 + 4] & 0xFF) << 8 | (frame[14 + 5] & 0xFF))
                : ((frame[16] & 0xFF) << 8 | (frame[17] & 0xFF));
        int transportOffset = 14 + ipHeaderLen;
        int transportLen = totalLen - ipHeaderLen;
        if (transportLen <= 0) {
            return;
        }

        byte[] pseudo;
        if (ipv6) {
            pseudo = new byte[40];
            System.arraycopy(frame, 14 + 8, pseudo, 0, 32);
            pseudo[32] = (byte) ((transportLen >> 24) & 0xFF);
            pseudo[33] = (byte) ((transportLen >> 16) & 0xFF);
            pseudo[34] = (byte) ((transportLen >> 8) & 0xFF);
            pseudo[35] = (byte) (transportLen & 0xFF);
            pseudo[39] = (byte) protocol;
        } else {
            pseudo = new byte[12];
            System.arraycopy(frame, 14 + 12, pseudo, 0, 8);
            pseudo[9] = (byte) protocol;
            pseudo[10] = (byte) ((transportLen >> 8) & 0xFF);
            pseudo[11] = (byte) (transportLen & 0xFF);
        }
        int checksum = IpChecksum.compute(pseudo, 0, pseudo.length, frame, transportOffset, transportLen);
        int stored = protocol == 17
                ? ((frame[transportOffset + 6] & 0xFF) << 8 | (frame[transportOffset + 7] & 0xFF))
                : ((frame[transportOffset + 16] & 0xFF) << 8 | (frame[transportOffset + 17] & 0xFF));
        if (protocol == 17 && stored == 0) {
            check(true, label + "：UDP 校验和为 0（不校验）");
            return;
        }
        check(checksum == 0, label + "：传输层校验和（独立交叉验证）");
    }

    // ==================== 帧构造 ====================

    private static byte[] buildUdpFrame(String srcIp, String dstIp, int srcPort, int dstPort,
                                        byte[] payload) throws Exception {
        Inet4Address s = (Inet4Address) InetAddress.getByName(srcIp);
        Inet4Address d = (Inet4Address) InetAddress.getByName(dstIp);
        UdpPacket.Builder udp = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) srcPort))
                .dstPort(UdpPort.getInstance((short) dstPort))
                .srcAddr(s).dstAddr(d)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4).tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0x1234).ttl((byte) 64).protocol(IpNumber.UDP)
                .srcAddr(s).dstAddr(d).payloadBuilder(udp)
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        return new EthernetPacket.Builder()
                .srcAddr(SRC_MAC).dstAddr(DST_MAC).type(EtherType.IPV4)
                .payloadBuilder(ip).paddingAtBuild(true).build().getRawData();
    }

    private static byte[] buildUdp6Frame(String srcIp, String dstIp, int srcPort, int dstPort,
                                         byte[] payload) throws Exception {
        Inet6Address s = (Inet6Address) InetAddress.getByName(srcIp);
        Inet6Address d = (Inet6Address) InetAddress.getByName(dstIp);
        UdpPacket.Builder udp = new UdpPacket.Builder()
                .srcPort(UdpPort.getInstance((short) srcPort))
                .dstPort(UdpPort.getInstance((short) dstPort))
                .srcAddr(s).dstAddr(d)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        IpV6Packet.Builder ip = new IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .trafficClass(org.pcap4j.packet.IpV6SimpleTrafficClass.newInstance((byte) 0))
                .flowLabel(org.pcap4j.packet.IpV6SimpleFlowLabel.newInstance(0))
                .nextHeader(IpNumber.UDP)
                .hopLimit((byte) 64)
                .srcAddr(s).dstAddr(d)
                .payloadBuilder(udp)
                .correctLengthAtBuild(true);
        return new EthernetPacket.Builder()
                .srcAddr(SRC_MAC).dstAddr(DST_MAC).type(EtherType.IPV6)
                .payloadBuilder(ip).paddingAtBuild(true).build().getRawData();
    }

    private static byte[] buildTcpFrame(String srcIp, String dstIp, int srcPort, int dstPort,
                                        byte[] seqBytes, long seq, long ack,
                                        boolean psh, boolean ackFlag, byte[] payload) throws Exception {
        Inet4Address s = (Inet4Address) InetAddress.getByName(srcIp);
        Inet4Address d = (Inet4Address) InetAddress.getByName(dstIp);
        TcpPacket.Builder tcp = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) srcPort))
                .dstPort(TcpPort.getInstance((short) dstPort))
                .srcAddr(s).dstAddr(d)
                .sequenceNumber((int) seq)
                .acknowledgmentNumber((int) ack)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .urg(false).ack(ackFlag).psh(psh).rst(false).syn(false).fin(false)
                .window((short) 65535)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        IpV4Packet.Builder ip = new IpV4Packet.Builder()
                .version(IpVersion.IPV4).tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .identification((short) 0x4321).ttl((byte) 64).protocol(IpNumber.TCP)
                .srcAddr(s).dstAddr(d).payloadBuilder(tcp)
                .correctChecksumAtBuild(true).correctLengthAtBuild(true);
        return new EthernetPacket.Builder()
                .srcAddr(SRC_MAC).dstAddr(DST_MAC).type(EtherType.IPV4)
                .payloadBuilder(ip).paddingAtBuild(true).build().getRawData();
    }

    /** 重算 IPv4 头校验和（测试辅助：手工改动 IP 头后使用） */
    private static void recomputeIpChecksum(byte[] frame) {
        int ihl = (frame[14] & 0x0F) * 4;
        frame[14 + 10] = 0;
        frame[14 + 11] = 0;
        int sum = IpChecksum.compute(frame, 14, ihl);
        frame[14 + 10] = (byte) ((sum >> 8) & 0xFF);
        frame[14 + 11] = (byte) (sum & 0xFF);
    }

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static void check(boolean condition, String message) {
        totalChecks++;
        if (condition) {
            logger.info("[通过] {}", message);
        }
        org.junit.jupiter.api.Assertions.assertTrue(condition, message);
    }
}
