package com.jshark.forwarder;

import io.netty.channel.EventLoopGroup;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 传输选择的基本可用性：探测到的 native transport（若可用）必须能真正创建事件循环，
 * 否则要回退到 NIO；channel class 也必须非空，避免启动时才发现配置错误。
 */
public class ForwarderTransportTest {

    @Test
    void eventLoopGroupStartsAndStops() {
        EventLoopGroup group = ForwarderTransport.newEventLoopGroup(1);
        try {
            assertNotNull(group.next(), "事件循环组必须至少能提供一个 EventLoop");
        } finally {
            group.shutdownGracefully(0, 2, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }

    @Test
    void channelClassesAreResolved() {
        assertNotNull(ForwarderTransport.serverChannelClass());
        assertNotNull(ForwarderTransport.clientChannelClass());
        assertNotNull(ForwarderTransport.datagramChannelClass());
        assertTrue(ForwarderTransport.description() != null
                        && !ForwarderTransport.description().isBlank(),
                "日志里必须能看出实际传输");
    }
}
