package com.jshark.parser;

/**
 * 记录来源类型。
 * <p>
 * 用于区分一条 {@code JSharkLog} 记录是否对应"线上真实存在的帧"，这是帧级原样重放的前提：
 * 只有 {@link #WIRE_FRAME} 与 {@link #IP_DEFRAG_SYNTH} 携带可注入的完整帧
 * （{@code frameData}），其余类型的 {@code frameData} 为空，重放时必须跳过并计数。
 * </p>
 *
 * <ul>
 *   <li>{@link #WIRE_FRAME} — 直接从网卡读到的原始帧，逐字节等价于线上内容</li>
 *   <li>{@link #IP_DEFRAG_SYNTH} — IP 分片重组后按重组结果合成的新帧。
 *       该帧在线上不存在，但头部字段齐全、校验和正确，可被任何协议栈正常接收</li>
 *   <li>{@link #TCP_REASSEMBLED} — TCP 流重组后的合并数据，不对应任何单帧</li>
 *   <li>{@link #BUFFER_FLUSH} — 连接关闭时冲刷出的缓冲区残留数据，不对应任何单帧</li>
 * </ul>
 */
public enum CaptureKind {

    /** 原始线路帧：{@code frameData} 即抓到的字节，可逐字节重放 */
    WIRE_FRAME((byte) 0, true),

    /** IP 分片重组后合成的帧：头部齐全、校验和正确，可重放（但线上原本不存在该帧） */
    IP_DEFRAG_SYNTH((byte) 1, true),

    /** TCP 流重组后的合并数据：无对应帧，不可重放 */
    TCP_REASSEMBLED((byte) 2, false),

    /** 连接关闭时冲刷出的缓冲区残留数据：无对应帧，不可重放 */
    BUFFER_FLUSH((byte) 3, false);

    private final byte code;
    private final boolean replayable;

    CaptureKind(byte code, boolean replayable) {
        this.code = code;
        this.replayable = replayable;
    }

    /** 数据库存储的数值编码 */
    public byte code() {
        return code;
    }

    /** 是否携带可注入的完整帧 */
    public boolean replayable() {
        return replayable;
    }

    /**
     * 由数据库数值还原枚举。
     *
     * @param code 数值编码
     * @return 对应枚举；未知编码返回 {@code null}（表示该记录不可重放）
     */
    public static CaptureKind fromCode(byte code) {
        for (CaptureKind kind : values()) {
            if (kind.code == code) {
                return kind;
            }
        }
        return null;
    }
}
