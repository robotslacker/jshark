package com.jshark.forwarder;

import java.util.List;

/**
 * 转发器的只读状态快照（UI 与 {@code --control stdio} 共用）。
 *
 * <p>三种模式共用同一结构：用不到的方向填 {@link Direction#ZERO}。</p>
 */
public final class ForwarderStatus {

    private ForwarderStatus() {
    }

    /** 一个方向的累计流量。 */
    public record Direction(long packets, long bytes) {
        public static final Direction ZERO = new Direction(0, 0);
    }

    /**
     * 一条连接。
     *
     * @param address  对端地址（host:port）
     * @param state    ready / connecting / reconnecting / connected
     * @param sinceMs  连接建立时刻（epoch ms；0 = 未知）
     */
    public record Peer(String address, String state, long sinceMs) {
    }

    /**
     * 一次状态快照。
     *
     * @param udpToTcp  UDP→TCP 方向（本地→远端）
     * @param tcpToUdp  TCP→UDP 方向（远端→本地）
     * @param dropped   未就绪/重连窗口内丢弃的包数
     * @param listen    本端 TCP 监听描述
     * @param udpLocal  UDP 组播端点描述
     * @param peers     连接列表（peer）
     * @param ingress   本地 UDP 入包总数（含被丢弃的），用于计算本地丢弃率
     */
    public record Snapshot(Direction udpToTcp, Direction tcpToUdp, long dropped,
                           String listen, String udpLocal, List<Peer> peers,
                           long ingress) {

        /** 兼容没有 ingress 统计的旧调用方。 */
        public Snapshot(Direction udpToTcp, Direction tcpToUdp, long dropped,
                        String listen, String udpLocal, List<Peer> peers) {
            this(udpToTcp, tcpToUdp, dropped, listen, udpLocal, peers, 0);
        }
    }

    /**
     * 可被 UI / 控制通道驱动的转发器。
     */
    public interface Source {
        /** 启动并阻塞，直到 {@link #stop()} 或内部关闭。 */
        void run() throws Exception;

        /** 请求停止（可重复调用）。 */
        void stop();

        /** @return 是否已经进入可转发状态（等待所有对端就绪） */
        boolean ready();

        /** 暂停转发（默认不实现；需要暂停能力的转发器覆写）。 */
        default void pause() {
        }

        /** 恢复转发（默认不实现；需要暂停能力的转发器覆写）。 */
        default void resume() {
        }

        /** @return 是否处于暂停状态（默认 false）。 */
        default boolean paused() {
            return false;
        }

        /** @return 当前快照（任意线程可调用） */
        Snapshot snapshot();
    }
}
