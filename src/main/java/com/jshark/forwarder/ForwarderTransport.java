package com.jshark.forwarder;

import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.ServerChannel;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerSocketChannel;
import io.netty.channel.epoll.EpollSocketChannel;
import io.netty.channel.kqueue.KQueue;
import io.netty.channel.kqueue.KQueueDatagramChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.kqueue.KQueueServerSocketChannel;
import io.netty.channel.kqueue.KQueueSocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

/**
 * 转发器的 I/O 传输选择：优先 Netty native transport，退化为 NIO。
 *
 * <h3>为什么值得区分</h3>
 * <p>
 * native epoll/kqueue 走直接系统调用，没有 JDK NIO selector 的中间层和堆外地址检查，
 * 在高包量 UDP 转发下通常能明显降低 CPU/延迟；Windows 上没有可用的 native 实现，
 * 就保持 NIO。native 库缺失或加载失败时也必须能启动，因此这里全部是“探测 + 回退”。
 * </p>
 *
 * <p>调用方只需要用 {@link #newEventLoopGroup(int)} 和三个 channel class，不关心具体实现。</p>
 */
final class ForwarderTransport {

    /** 当前实际使用的传输实现。 */
    enum Kind {
        EPOLL, KQUEUE, NIO
    }

    private static final Kind KIND = detect();

    private ForwarderTransport() {
    }

    private static Kind detect() {
        try {
            if (Epoll.isAvailable()) {
                return Kind.EPOLL;
            }
        } catch (Throwable ignored) {
            // 没打 native 库 / 平台不支持：继续尝试下一种
        }
        try {
            if (KQueue.isAvailable()) {
                return Kind.KQUEUE;
            }
        } catch (Throwable ignored) {
            // 同上
        }
        return Kind.NIO;
    }

    /** @return 实际使用的传输 */
    static Kind kind() {
        return KIND;
    }

    /** @return 供日志展示的传输名 */
    static String description() {
        return switch (KIND) {
            case EPOLL -> "epoll (native)";
            case KQUEUE -> "kqueue (native)";
            case NIO -> "NIO";
        };
    }

    /**
     * 创建事件循环组。
     *
     * @param threads 线程数；必须为正数
     * @return 事件循环组
     */
    static EventLoopGroup newEventLoopGroup(int threads) {
        return switch (KIND) {
            case EPOLL -> new EpollEventLoopGroup(threads);
            case KQUEUE -> new KQueueEventLoopGroup(threads);
            case NIO -> new NioEventLoopGroup(threads);
        };
    }

    /** @return TCP 服务端 channel 类型 */
    static Class<? extends ServerChannel> serverChannelClass() {
        return switch (KIND) {
            case EPOLL -> EpollServerSocketChannel.class;
            case KQUEUE -> KQueueServerSocketChannel.class;
            case NIO -> NioServerSocketChannel.class;
        };
    }

    /** @return TCP 客户端 channel 类型 */
    static Class<? extends Channel> clientChannelClass() {
        return switch (KIND) {
            case EPOLL -> EpollSocketChannel.class;
            case KQUEUE -> KQueueSocketChannel.class;
            case NIO -> NioSocketChannel.class;
        };
    }

    /** @return UDP channel 类型 */
    static Class<? extends DatagramChannel> datagramChannelClass() {
        return switch (KIND) {
            case EPOLL -> EpollDatagramChannel.class;
            case KQUEUE -> KQueueDatagramChannel.class;
            case NIO -> NioDatagramChannel.class;
        };
    }
}
