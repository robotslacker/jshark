package com.jshark.parser;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

/**
 * Netty数据包发送器
 * 支持TCP和UDP协议的数据包发送
 * <p>
 * 修复：异步连接期间的数据缓存和去重机制。
 * 当连接正在建立时，后续的发送请求会被缓存到待发送队列中，
 * 连接建立后自动发送缓存的数据，避免数据丢失和重复创建连接。
 * </p>
 */
public class NettyPacketSender {
    private static final Logger logger = LoggerFactory.getLogger(NettyPacketSender.class);
    
    private final EventLoopGroup workerGroup;
    private Bootstrap tcpBootstrap;
    private Bootstrap udpBootstrap;
    
    // TCP连接缓存：key为"ip:port"，value为Channel
    private final ConcurrentHashMap<String, Channel> tcpChannelCache = new ConcurrentHashMap<>();
    // UDP通道缓存：key为"ip:port"，value为Channel
    private final ConcurrentHashMap<String, Channel> udpChannelCache = new ConcurrentHashMap<>();
    // 连接失败时间戳缓存：key为"ip:port"，value为失败时间戳（毫秒）
    private final ConcurrentHashMap<String, Long> connectionFailureCache = new ConcurrentHashMap<>();
    // 连接失败重试间隔：10秒
    private static final long RETRY_INTERVAL_MS = 10_000;
    
    // ========== 连接中状态管理 ==========
    
    /** 正在建立连接的标记集合（避免重复创建连接） */
    private final ConcurrentHashMap<String, Boolean> connectingSet = new ConcurrentHashMap<>();
    
    /** 连接建立中时缓存的数据队列 */
    private final ConcurrentHashMap<String, Queue<byte[]>> pendingDataQueues = new ConcurrentHashMap<>();
    
    /** 连接建立中时缓存的数据量计数器 */
    private final ConcurrentHashMap<String, AtomicInteger> pendingDataCounters = new ConcurrentHashMap<>();
    
    /** 单个连接最大缓存数据包数量 */
    private static final int MAX_PENDING_PACKETS = 1000;

    // ========== TCP 写背压（P0：让发送延迟可见） ==========

    /**
     * TCP 通道出站缓冲水位（低/高）。
     * <p>
     * 超过高水位后 {@code channel.isWritable()} 变为 false，直到排空到低水位才恢复。
     * 这是"发送方真实能力"唯一可靠的观测点：不设水位时 {@code writeAndFlush} 永远立即返回，
     * 延迟全部藏在 {@code ChannelOutboundBuffer} 里，回放循环测到的迟到量恒为 0。
     * </p>
     */
    private static final int TCP_WRITE_BUFFER_LOW_WATER_MARK = 64 * 1024;
    private static final int TCP_WRITE_BUFFER_HIGH_WATER_MARK = 256 * 1024;

    /**
     * 单次等待可写的上限（毫秒）。超时后<b>仍然写入</b>——宁可晚，不丢包；
     * 该上限也是"对端彻底停止读取"时的兜底：每包最多拖这么久，内存不会失控增长。
     */
    private static final long TCP_BACKPRESSURE_WAIT_TIMEOUT_MS = 2_000L;

    private static final long NANOS_PER_MILLI = 1_000_000L;
    /**
     * 前若干次轮询用自旋而非 parkNanos。
     * <p>
     * 实测（Windows 11 + JDK 21）{@code parkNanos(50µs)} 实际睡 14.6ms——会被系统定时器粒度取整。
     * 缓冲往往只差一点点就排空，这段时间用自旋探测能立刻恢复写入，而不是给每个包平白加 ~15ms。
     * 自旋次数有限，之后转为粗等，避免长时间占 CPU。
     * </p>
     */
    private static final int FINE_PROBE_SPINS = 200;
    /** 粗等间隔（纳秒）：控制环窗口是 500ms 量级，1ms 的观测粒度足够 */
    private static final long POLL_PARK_NANOS = 1_000_000L;

    /** 等待可写的次数（真实背压事件计数） */
    /** 等待可写的累计耗时（纳秒） */
    /** 等待超时次数（对端停滞或严重跟不上） */
    /** 观测到的最大待排空字节数（队列深度，比迟到量更早的前导指标） */
    
    public NettyPacketSender() {
        this.workerGroup = new NioEventLoopGroup(10, daemonThreadFactory("jshark-netty-sender-"));
        initializeBootstraps();
    }

    /**
     * Netty 线程工厂：全部创建为<b>守护线程</b>。
     * <p>
     * 为什么必须这样：{@code shutdownGracefully()} 默认带 2 秒静默期，且旧实现<b>不等待</b>结束。
     * 只要进程（或测试 JVM）在那段时间里想退出，非守护的 Netty 线程就会把 JVM 挂住 ——
     * 这是这套测试里最容易在慢 CI 上"卡住不返回"的一处。
     * 本工具的进程生命周期由主线程控制，这些 IO 线程不该有决定 JVM 能否退出的权力。
     * </p>
     */
    private static java.util.concurrent.ThreadFactory daemonThreadFactory(String prefix) {
        java.util.concurrent.atomic.AtomicInteger seq = new java.util.concurrent.atomic.AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + seq.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
    
    /**
     * 初始化Netty Bootstrap
     */
    private void initializeBootstraps() {
        // TCP Bootstrap
        tcpBootstrap = new Bootstrap();
        tcpBootstrap.group(workerGroup)
                   .channel(NioSocketChannel.class)
                   .option(ChannelOption.SO_KEEPALIVE, true)
                   // 出站缓冲水位：超过高水位即 isWritable()==false，配合 awaitTcpWritable 形成真实背压
                   .option(ChannelOption.WRITE_BUFFER_WATER_MARK,
                           new WriteBufferWaterMark(TCP_WRITE_BUFFER_LOW_WATER_MARK,
                                                    TCP_WRITE_BUFFER_HIGH_WATER_MARK))
                   .handler(new ChannelInitializer<io.netty.channel.socket.SocketChannel>() {
                       @Override
                       protected void initChannel(io.netty.channel.socket.SocketChannel ch) {
                           // 简单的处理器，直接发送数据
                           ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                               @Override
                               protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                                   // 不需要读取响应
                               }
                               
                               @Override
                               public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                   logger.error("TCP channel error", cause);
                                   ctx.close();
                               }
                           });
                       }
                   });
        
        // UDP Bootstrap
        udpBootstrap = new Bootstrap();
        udpBootstrap.group(workerGroup)
                   .channel(NioDatagramChannel.class)
                   .handler(new ChannelInitializer<NioDatagramChannel>() {
                       @Override
                       protected void initChannel(NioDatagramChannel ch) {
                           // UDP不需要复杂的处理器
                       }
                   });
    }
    
    /**
     * 生成缓存键：ip:port
     */
    private String generateCacheKey(String ip, int port) {
        return ip + ":" + port;
    }
    
    /**
     * 检查是否应该跳过连接（距离上次失败未超过重试间隔）
     */
    private boolean shouldSkipConnection(String cacheKey) {
        Long failureTime = connectionFailureCache.get(cacheKey);
        if (failureTime == null) {
            return false; // 没有失败记录，不跳过
        }
        long elapsed = System.currentTimeMillis() - failureTime;
        return elapsed < RETRY_INTERVAL_MS; // 失败时间在重试间隔内，跳过
    }
    
    /**
     * 记录连接失败
     */
    private void recordConnectionFailure(String cacheKey) {
        connectionFailureCache.put(cacheKey, System.currentTimeMillis());
        // 清除连接中标记
        connectingSet.remove(cacheKey);
        // 清除待发送队列
        pendingDataQueues.remove(cacheKey);
        pendingDataCounters.remove(cacheKey);
    }
    
    /**
     * 清除连接失败记录（连接成功时调用）
     */
    private void clearConnectionFailure(String cacheKey) {
        connectionFailureCache.remove(cacheKey);
    }
    
    /**
     * 缓存待发送数据（连接建立中时使用）
     */
    private boolean cachePendingData(String cacheKey, byte[] data) {
        Queue<byte[]> queue = pendingDataQueues.computeIfAbsent(cacheKey, k -> new ConcurrentLinkedQueue<>());
        AtomicInteger counter = pendingDataCounters.computeIfAbsent(cacheKey, k -> new AtomicInteger(0));
        
        if (counter.get() >= MAX_PENDING_PACKETS) {
            logger.warn("Pending data queue for {} is full ({} packets), dropping packet", cacheKey, MAX_PENDING_PACKETS);
            return false;
        }
        
        queue.offer(data);
        counter.incrementAndGet();
        logger.debug("Cached pending data for {} (total: {})", cacheKey, counter.get());
        return true;
    }
    
    /**
     * 发送所有缓存的待发送数据
     */
    private void flushPendingData(String cacheKey, Channel channel, boolean isTcp) {
        Queue<byte[]> queue = pendingDataQueues.remove(cacheKey);

        if (queue == null || queue.isEmpty()) {
            return;
        }
        
        int count = 0;
        byte[] data;
        while ((data = queue.poll()) != null) {
            sendDataViaChannel(channel, data, 
                    cacheKey.split(":")[0], 
                    Integer.parseInt(cacheKey.split(":")[1]), 
                    isTcp);
            count++;
        }
        
        if (count > 0) {
            logger.debug("Flushed {} pending packets for {}", count, cacheKey);
        }
    }
    
    /**
     * 发送TCP数据包（带连接缓存和连接中队列）
     */
    public void sendTcpPacket(String destinationIp, int destinationPort, byte[] data) {
        if (data == null || data.length == 0) {
            logger.warn("No data to send via TCP");
            return;
        }
        
        String cacheKey = generateCacheKey(destinationIp, destinationPort);
        
        // 检查是否需要跳过（最近连接失败且在重试间隔内）
        if (shouldSkipConnection(cacheKey)) {
            logger.debug("Skipping TCP connection to {}:{} due to recent failure", destinationIp, destinationPort);
            return;
        }
        
        // 检查是否有连接正在建立中
        if (connectingSet.containsKey(cacheKey)) {
            // 连接正在建立中，缓存数据
            cachePendingData(cacheKey, data);
            return;
        }
        
        // 尝试从缓存获取连接
        Channel cachedChannel = tcpChannelCache.get(cacheKey);
        if (cachedChannel != null && cachedChannel.isActive()) {
            // 使用缓存的连接发送数据
            sendDataViaChannel(cachedChannel, data, destinationIp, destinationPort, true);
            return;
        }
        
        // 没有缓存或连接已关闭，标记为连接中并创建新连接
        Boolean wasConnecting = connectingSet.putIfAbsent(cacheKey, Boolean.TRUE);
        if (wasConnecting != null) {
            // 其他线程已经发起了连接，缓存数据等待
            cachePendingData(cacheKey, data);
            return;
        }
        
        // 缓存当前数据（连接建立后一起发送）
        cachePendingData(cacheKey, data);
        
        // 创建新连接
        try {
            InetAddress address = InetAddress.getByName(destinationIp);
            InetSocketAddress socketAddress = new InetSocketAddress(address, destinationPort);
            
            ChannelFuture connectFuture = tcpBootstrap.connect(socketAddress);
            connectFuture.addListener((ChannelFuture future) -> {
                if (future.isSuccess()) {
                    Channel channel = future.channel();
                    // 将连接加入缓存
                    tcpChannelCache.put(cacheKey, channel);
                    clearConnectionFailure(cacheKey);
                    
                    // 监听连接关闭事件，从缓存中移除
                    channel.closeFuture().addListener(closeFuture -> {
                        tcpChannelCache.remove(cacheKey, channel);
                        logger.info("TCP connection to {}:{} closed and removed from cache",
                                    destinationIp, destinationPort);
                    });
                    
                    // 发送所有缓存的数据（TCP）
                    flushPendingData(cacheKey, channel, true);
                    
                    // 清除连接中标记
                    connectingSet.remove(cacheKey);
                } else {
                    logger.error("Failed to connect to {}:{} via TCP",
                                destinationIp, destinationPort, future.cause());
                    recordConnectionFailure(cacheKey);
                    // 从缓存中移除无效连接
                    tcpChannelCache.remove(cacheKey);
                }
            });
            
        } catch (UnknownHostException e) {
            logger.error("Invalid destination IP: {}", destinationIp, e);
            recordConnectionFailure(cacheKey);
        } catch (Exception e) {
            logger.error("Error sending TCP packet to {}:{}",
                        destinationIp, destinationPort, e);
            recordConnectionFailure(cacheKey);
        }
    }
    
    /**
     * 通过Channel发送数据（TCP或UDP）
     */
    private void sendDataViaChannel(Channel channel, byte[] data, String destinationIp,
                                   int destinationPort, boolean isTcp) {
        if (channel == null || !channel.isActive()) {
            logger.error("Channel is not active for {}:{}", destinationIp, destinationPort);
            return;
        }
        
        ByteBuf buffer = Unpooled.wrappedBuffer(data);
        
        if (isTcp) {
            // 写前等可写：把"套接字写不动"这件事变成回放循环能观测到的真实耗时。
            // 少了这一步，TCP 回放的迟到量恒为 0，自适应降速会误判为"我很健康"。
            awaitTcpWritable(channel);
            ChannelFuture writeFuture = channel.writeAndFlush(buffer);
            writeFuture.addListener((ChannelFuture future) -> {
                if (future.isSuccess()) {
                    logger.debug("TCP packet sent to {}:{} ({} bytes)",
                                destinationIp, destinationPort, data.length);
                } else {
                    logger.error("Failed to send TCP packet to {}:{}",
                                destinationIp, destinationPort, future.cause());
                    // 发送失败，关闭连接并从缓存中移除
                    channel.close();
                    String cacheKey = generateCacheKey(destinationIp, destinationPort);
                    tcpChannelCache.remove(cacheKey, channel);
                }
            });
        } else {
            // UDP处理
            try {
                InetAddress address = InetAddress.getByName(destinationIp);
                InetSocketAddress socketAddress = new InetSocketAddress(address, destinationPort);
                DatagramPacket packet = new DatagramPacket(buffer, socketAddress);
                
                ChannelFuture writeFuture = channel.writeAndFlush(packet);
                // 同步等待UDP发送完成，确保数据在shutdown前已发出
                writeFuture.sync();
                if (writeFuture.isSuccess()) {
                    logger.trace("UDP packet sent to {}:{} ({} bytes)",
                                destinationIp, destinationPort, data.length);
                } else {
                    logger.error("Failed to send UDP packet to {}:{}",
                                destinationIp, destinationPort, writeFuture.cause());
                }
                // UDP通道在发送后不关闭，保持打开状态以供重用
            } catch (UnknownHostException e) {
                logger.error("Invalid destination IP: {}", destinationIp, e);
            } catch (InterruptedException e) {
                logger.error("UDP send interrupted for {}:{}", destinationIp, destinationPort);
                Thread.currentThread().interrupt();
            }
        }
    }
    
    /**
     * 等待 TCP 通道可写（背压可见化，P0）。
     *
     * <h3>为什么需要</h3>
     * {@code writeAndFlush} 是异步的：只要出站缓冲没满就立刻返回，真实发送耗时不可见。
     * 回放循环据此计算"迟到量"，会得出"一切正常"的错误结论，而实际上数据只是在
     * {@code ChannelOutboundBuffer} 里堆积。等待水位恢复后，迟到量才等于发送方真实能力。
     *
     * <h3>为什么不阻塞事件循环</h3>
     * 可写状态由通道所属的事件循环自己推进（排空缓冲）。若在事件循环线程上等待，
     * 该线程永远没机会排空，只能死等到超时——{@code flushPendingData} 恰好跑在
     * 连接建立监听器（事件循环线程）里，所以这里必须显式挡掉。
     *
     * <h3>超时语义</h3>
     * 上限 {@value #TCP_BACKPRESSURE_WAIT_TIMEOUT_MS} ms，超时后调用方仍然写入：
     * 宁可晚，不丢包。这个上限同时是"对端完全停止读取"时的兜底（每包最多拖这么久）。
     *
     * @param channel 目标通道
     */
    private void awaitTcpWritable(Channel channel) {
        if (channel.eventLoop().inEventLoop() || channel.isWritable()) {
            return;
        }
        long start = System.nanoTime();
        long deadline = start + TCP_BACKPRESSURE_WAIT_TIMEOUT_MS * NANOS_PER_MILLI;
        int spins = 0;
        boolean timedOut = false;
        while (channel.isActive() && !channel.isWritable()) {
            long remain = deadline - System.nanoTime();
            if (remain <= 0) {
                timedOut = true;
                break;
            }
            if (spins < FINE_PROBE_SPINS) {
                spins++;
                Thread.onSpinWait();
            } else {
                LockSupport.parkNanos(Math.min(POLL_PARK_NANOS, remain));
            }
        }
        long waited = System.nanoTime() - start;
        if (timedOut) {
            logger.warn("TCP backpressure wait timed out after {} ms (pending≈{} bytes), writing anyway; "
                        + "the peer is not draining fast enough",
                    TCP_BACKPRESSURE_WAIT_TIMEOUT_MS, channel.bytesBeforeWritable());
        } else {
            logger.debug("TCP backpressure waited {} ms (pending≈{} bytes)",
                        waited / NANOS_PER_MILLI, channel.bytesBeforeWritable());
        }
    }

    /**
     * 发送UDP数据包（带通道缓存）
     */
    public void sendUdpPacket(String destinationIp, int destinationPort, byte[] data) {
        if (data == null || data.length == 0) {
            logger.warn("No data to send via UDP");
            return;
        }
        
        // 防御性校验：拒绝无效端口
        if (destinationPort <= 0 || destinationPort > 65535) {
            logger.error("Refusing to send UDP packet to invalid port: {}:{}", destinationIp, destinationPort);
            return;
        }
        
        String cacheKey = generateCacheKey(destinationIp, destinationPort);
        
        // 检查是否需要跳过（最近连接失败且在重试间隔内）
        if (shouldSkipConnection(cacheKey)) {
            logger.debug("Skipping UDP channel to {}:{} due to recent failure", destinationIp, destinationPort);
            return;
        }
        
        // 尝试从缓存获取UDP通道
        Channel cachedChannel = udpChannelCache.get(cacheKey);
        if (cachedChannel != null && cachedChannel.isActive()) {
            // 使用缓存的通道发送数据
            sendDataViaChannel(cachedChannel, data, destinationIp, destinationPort, false);
            return;
        }
        
        // 没有缓存或通道已关闭，标记为连接中并创建新通道
        Boolean wasConnecting = connectingSet.putIfAbsent(cacheKey, Boolean.TRUE);
        if (wasConnecting != null) {
            // 其他线程已经发起了绑定，缓存数据等待
            cachePendingData(cacheKey, data);
            return;
        }
        
        // 缓存当前数据（通道建立后一起发送）
        cachePendingData(cacheKey, data);
        
        // 创建新通道（同步等待绑定完成，确保后续数据能直接使用缓存通道）
        try {
            ChannelFuture bindFuture = udpBootstrap.bind(0); // 绑定到随机端口
            bindFuture.sync(); // 同步等待绑定完成
            
            if (bindFuture.isSuccess()) {
                Channel channel = bindFuture.channel();
                // 将通道加入缓存
                udpChannelCache.put(cacheKey, channel);
                clearConnectionFailure(cacheKey);

                // 监听通道关闭事件，从缓存中移除
                channel.closeFuture().addListener(closeFuture -> {
                    udpChannelCache.remove(cacheKey, channel);
                    logger.debug("UDP channel to {}:{} closed and removed from cache",
                                destinationIp, destinationPort);
                });

                // 发送所有缓存的数据（包括当前这个包，UDP）
                flushPendingData(cacheKey, channel, false);
                
                // 清除连接中标记
                connectingSet.remove(cacheKey);
            } else {
                logger.error("Failed to create UDP channel for sending to {}:{}",
                            destinationIp, destinationPort, bindFuture.cause());
                recordConnectionFailure(cacheKey);
                // 从缓存中移除无效通道
                udpChannelCache.remove(cacheKey);
            }
        } catch (Exception e) {
            logger.error("Error creating UDP channel for sending to {}:{}",
                        destinationIp, destinationPort, e);
            recordConnectionFailure(cacheKey);
        }
    }
    
    /**
     * 发送原始数据包（根据端口和协议自动选择TCP/UDP）
     */
    public void sendPacket(String destinationIp, int destinationPort, byte[] data, String ipProtocol) {
        if (ipProtocol.equalsIgnoreCase("TCP")) {
            sendTcpPacket(destinationIp, destinationPort, data);
        } else if (ipProtocol.equalsIgnoreCase("UDP")) {
            sendUdpPacket(destinationIp, destinationPort, data);
        }
    }
    
    /**
     * 关闭发送器
     */
    public void shutdown() {
        logger.info("Shutting down NettyPacketSender...");
        
        // 关闭所有缓存的TCP连接
        for (Channel channel : tcpChannelCache.values()) {
            if (channel != null && channel.isActive()) {
                try {
                    channel.close().sync();
                } catch (Exception e) {
                    logger.warn("Error closing cached TCP channel", e);
                }
            }
        }
        tcpChannelCache.clear();
        
        // 关闭所有缓存的UDP通道
        for (Channel channel : udpChannelCache.values()) {
            if (channel != null && channel.isActive()) {
                try {
                    channel.close().sync();
                } catch (Exception e) {
                    logger.warn("Error closing cached UDP channel", e);
                }
            }
        }
        udpChannelCache.clear();
        
        // 清空失败缓存
        connectionFailureCache.clear();
        
        // 清空连接中状态和待发送队列
        connectingSet.clear();
        pendingDataQueues.clear();
        pendingDataCounters.clear();
        
        if (workerGroup != null) {
            // 限时优雅关闭**并等待**：原来只调 shutdownGracefully() 就返回，调用方
            // （测试 / CLI 收尾）无法确定线程是否已经收尾，只能靠 sleep 或干脆不退。
            // 现在最多等 3 秒；即便超时也只是放弃等待 —— 线程是守护线程，不会阻止 JVM 退出。
            workerGroup.shutdownGracefully(0, 2, java.util.concurrent.TimeUnit.SECONDS);
            try {
                if (!workerGroup.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    logger.warn("NettyPacketSender worker group did not terminate within 3s (daemon threads, "
                            + "JVM exit is not blocked)");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        logger.info("NettyPacketSender shutdown completed");
    }
}
