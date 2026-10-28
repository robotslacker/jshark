package com.jshark.forwarder;

import java.nio.charset.StandardCharsets;

/**
 * UDP→TCP 的报文封装（固定格式，无开关）。
 *
 * <h3>发送端（本节点主动连出去的方向）</h3>
 * <p>
 * 连接建立后先发 {@link #MAGIC}，随后每个 UDP 包编码为
 * {@code [2 字节大端长度][原始 UDP 载荷]}。接收端每个 frame 还原成一个 UDP 包，
 * 报文边界和长度都不变——这是 DIS 这类“一个 UDP 包 = 一条消息”的协议需要的语义。
 * </p>
 *
 * <h3>接收端（本节点 TCP 服务端）</h3>
 * <p>
 * 不需要配置，也不要求对端同样是新版本：首字节匹配 {@link #MAGIC} 就按上面的 frame 解析，
 * 否则按旧的**连续字节流**处理（8 KiB 切片）。因此新服务端同时兼容新 datagram 客户端、
 * stream 客户端和旧客户端；只有“新客户端 → 旧服务端”不兼容（旧服务端会把 magic 当数据），
 * 两端同步升级即可。
 * </p>
 */
public final class ForwarderFraming {

    /**
     * datagram 模式的连接前缀。
     *
     * <p>末尾的 {@code 1} 是协议版本：以后改帧格式时可以换成 {@code 2}，旧服务端会把它
     * 当成不认识的流式数据，而不是静默按错误格式解析。</p>
     */
    public static final byte[] MAGIC = "JSHARKDG1".getBytes(StandardCharsets.US_ASCII);

    /** 一个 UDP 载荷的硬上限（IPv4 下 UDP 最大 65507 字节）。 */
    public static final int MAX_UDP_PAYLOAD = 65507;

    private ForwarderFraming() {
    }
}
