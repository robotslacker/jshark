package com.jshark.parser;

/**
 * 帧注入发送端的最小抽象。
 *
 * <p>生产实现是 {@link RawFrameSender}（真实网卡）；测试可用内存实现，
 * 从而在不碰网卡/管理员权限的情况下验证帧级 pause/seek/speed。</p>
 */
public interface FrameSender {

    /**
     * 注入一帧。
     *
     * @param frame 完整帧
     * @return 是否成功（具体含义由实现定义）
     */
    boolean send(byte[] frame);

    /** @return “调用报错但帧实际已发出”的次数 */
    long framesSentDespiteError();

    /** @return 真实失败次数 */
    long framesFailed();
}
