package com.jshark.forwarder;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.kqueue.KQueueDatagramChannel;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.concurrent.GlobalEventExecutor;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;

/**
 * UDP 组播桥接节点
 * <p>
 * 将本地 UDP 组播与一个或多个远端节点进行双向桥接。
 * 内部自动管理两条数据通路：
 * <ul>
 *   <li><b>本地→远端</b>：监听本地 UDP 组播，通过 TCP 发送到远端</li>
 *   <li><b>远端→本地</b>：接收远端 TCP 数据，转发到本地 UDP 组播</li>
 * </ul>
 * <p>
 * 本类自动处理：
 * <ul>
 *   <li>端口分配与管理</li>
 *   <li>回环流量过滤（自动使用特殊本地端口，无需手动指定过滤端口）</li>
 *   <li>启动顺序（先启动 TCP 服务端，再连接远端）</li>
 *   <li>连接断开自动重连：后台常驻重试，直到对端恢复，不依赖业务流量触发</li>
 *   <li><b>Peer 就绪门控</b>：所有 Peer 就绪后才开始转发；未就绪期间数据丢弃并计数</li>
 * </ul>
 */
public class UdpBridgeNode implements ForwarderStatus.Source {

    private final Logger logger;

    // ========== 本地 UDP 组播配置 ==========
    private final String localUdpHost;
    private final int localUdpPort;
    private final String localMulticastIf;

    // ========== 本地 TCP 监听配置 ==========
    private final int listenPort;

    // ========== 远端对等节点列表 ==========
    private final List<PeerConfig> peers;

    // ========== Netty 线程模型 ==========
    /**
     * 所有 channel 共用同一个事件循环组。
     *
     * <p>以前 UDP listener、TCP server、peer 连接各用一个 {@code NioEventLoopGroup}（默认
     * {@code 2 × CPU} 个线程），但每个 UDP 包都要从 UDP 线程 {@code write} 到 peer 所在的
     * TCP 线程：跨线程任务队列 + 唤醒是热路径上最大的固定开销。默认只用 1 个线程，
     * 让 UDP 读、TCP 写、UDP 写都在同一线程内联完成；需要多核时可用
     * {@code -Djshark.forwarder.eventLoops=N} 调大（会重新引入跨线程 handoff）。</p>
     */
    private final EventLoopGroup ioGroup =
            ForwarderTransport.newEventLoopGroup(eventLoopThreads());

    /** 已接受的 TCP 连接，用于 UDP 写不出去时暂停 TCP 读（背压）。 */
    private final ChannelGroup tcpServerChannels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    // ========== 内部状态 ==========
    /** 本地 UDP 发送 Channel（用于将 TCP 收到的数据发到本地组播） */
    private Channel localUdpChannel;
    /** 用于发送 UDP 到本地组播的本地端口（用于回环过滤） */
    private int udpSenderLocalPort;
    /** 本地 UDP 目标地址（缓存，避免每个 TCP read 都解析/分配）。 */
    private final InetSocketAddress localUdpTarget;

    /** 到所有远端节点的 TCP 连接（用于本地→远端方向） */
    private final ConcurrentHashMap<PeerConfig, Channel> tcpOutboundChannels = new ConcurrentHashMap<>();
    /**
     * 热路径用的 peer channel 快照。
     *
     * <p>每收到一个 UDP 包都迭代 {@code ConcurrentHashMap.entrySet()} 会分配 Entry/Iterator，
     * 且弱一致迭代器在并发增删时开销更高。连接增删时重建一个不可变 List，热路径只做数组遍历。</p>
     */
    private volatile List<PeerChannel> outbound = List.of();
    /** 一个已连接 peer 的轻量快照。 */
    private record PeerChannel(PeerConfig peer, Channel channel) {
    }

    /**
     * 一批 UDP read 内按 peer 聚合的待写 frame。
     *
     * <p>只由 UDP listener 的 event loop 填充/消费；用锁而不是并发容器，是为了让
     * {@link #stop()} 能安全地取走并释放残留 batch（锁只在同线程内无竞争，开销可忽略）。</p>
     */
    private final Map<Channel, CompositeByteBuf> pendingBatches = new java.util.HashMap<>();
    /** 最近一次连接失败/断开的时间（用于重试节流） */
    private final ConcurrentHashMap<PeerConfig, Long> tcpDisconnectTime = new ConcurrentHashMap<>();
    /** 最近一次连接成功的时刻（UI 的 Since 列；断开后保留，用于区分 connecting / reconnecting） */
    private final ConcurrentHashMap<PeerConfig, Long> tcpConnectedTime = new ConcurrentHashMap<>();

    /** 单个 Peer 的重试间隔 */
    private static final long RECONNECT_INTERVAL_MS = 3_000;
    /** 建立 TCP 连接的超时时间（避免不可达地址把重连线程卡住几十秒） */
    private static final int CONNECT_TIMEOUT_MS = 3_000;
    /** 写协议 magic 的超时：写不出去就别把连接标成 ready。 */
    private static final long FRAME_MAGIC_WRITE_TIMEOUT_MS = 2_000L;
    /** Peer 管理线程的扫描间隔 */
    private static final long PEER_SWEEP_MS = 1_000;

    /** 本地 TCP 服务端 Channel（用于接收远端→本地方向的数据） */
    private Channel tcpServerChannel;

    /** 运行状态 */
    private volatile boolean running = false;

    /** 暂停转发标志：为 true 时停用两个方向的发送（本地→peer 与 peer→本地）。 */
    private volatile boolean paused = false;

    // ========== Peer 连接管理 ==========

    /** 是否已进入工作状态（所有需要主动连接的 Peer 都已就绪，开始转发数据） */
    private final AtomicBoolean working = new AtomicBoolean(false);

    /** 常驻的 Peer 连接/重连线程（运行到 stop 为止） */
    private Thread peerManagerThread;

    // ========== 流量统计 ==========

    /**
     * 过去半分钟内 UDP→TCP（本地→远端）的传输字节数。
     *
     * <p>热路径上的计数用 {@link LongAdder}：UDP 读线程和 TCP 读线程会同时更新，
     * {@code AtomicLong} 的 CAS 在竞争时会退化成自旋；{@code LongAdder} 按线程分槽，
     * 读侧（30s 打印 / UI 快照）再求和即可。</p>
     */
    private final LongAdder udpToTcpBytes = new LongAdder();
    /** 过去半分钟内 TCP→UDP（远端→本地）的传输字节数 */
    private final LongAdder tcpToUdpBytes = new LongAdder();
    /** 过去半分钟内 UDP→TCP（本地→远端）的传输包数 */
    private final LongAdder udpToTcpPackets = new LongAdder();
    /** 过去半分钟内 TCP→UDP（远端→本地）的传输包数 */
    private final LongAdder tcpToUdpPackets = new LongAdder();

    // ========== 累计统计（UI / --control stdio；不随 30s 打印重置） ==========

    private final LongAdder totalUdpToTcpBytes = new LongAdder();
    private final LongAdder totalTcpToUdpBytes = new LongAdder();
    private final LongAdder totalUdpToTcpPackets = new LongAdder();
    private final LongAdder totalTcpToUdpPackets = new LongAdder();
    private final LongAdder droppedNotReady = new LongAdder();
    /** 对端 TCP 写缓冲积压（{@code !ch.isWritable()}）时丢弃的包数：UDP 语义下宁可丢也不无限排队。 */
    private final LongAdder droppedBackpressure = new LongAdder();
    /** 超过 UDP 单包上限、无法装进 2 字节长度字段的包（正常 UDP 不会出现）。 */
    private final LongAdder droppedOversize = new LongAdder();
    /** 本地 UDP 入包（含未就绪被丢弃的），用于计算本地丢弃率。 */
    private final LongAdder udpIngressPackets = new LongAdder();

    /** UDP 收/发 socket 缓冲区（大流量灌包时避免突发丢包）。 */
    private static final int UDP_SOCKET_BUFFER_BYTES = 8 * 1024 * 1024;
    /** TCP socket 缓冲区：高吞吐下让内核多缓冲一点，减少写阻塞/窗口更新频率。 */
    private static final int TCP_SOCKET_BUFFER_BYTES = 1024 * 1024;
    /** TCP 写缓冲水位：超过 high 认为对端跟不上，UDP→TCP 方向开始丢包而不是无限排队。 */
    private static final WriteBufferWaterMark TCP_WRITE_WATERMARK =
            new WriteBufferWaterMark(64 * 1024, 256 * 1024);
    /**
     * 单批 TCP 聚合写上限：同一批 UDP read 的 frame 合并到这么多字节就提前写出，
     * 避免一次大突发把延迟拖到 readComplete 之后。
     */
    private static final int TCP_BATCH_MAX_BYTES = 64 * 1024;
    /**
     * 单批最多合并的 frame 数。每帧 = 头 + 载荷两个 component；限制 frame 数可避免
     * {@code CompositeByteBuf} 组件过多触发内部合并拷贝。
     */
    private static final int TCP_BATCH_MAX_FRAMES = 32;
    /** TCP accept backlog。 */
    private static final int TCP_BACKLOG = 128;
    /** TCP→UDP 重新切分的最大 UDP 载荷，避免超过 65507 上限和 IP 分片。 */
    private static final int UDP_CHUNK_BYTES = 8 * 1024;

    /**
     * I/O 线程数。
     *
     * <p>默认 1：UDP 读、peer TCP 写、本地 UDP 写都在同一线程内联执行，没有跨线程 handoff。
     * 需要多核时可用 {@code -Djshark.forwarder.eventLoops=N} 调大。</p>
     *
     * @return 大于 0 的线程数
     */
    private static int eventLoopThreads() {
        int threads = Integer.getInteger("jshark.forwarder.eventLoops", 1);
        return Math.max(1, threads);
    }

    /** 统计信息打印线程 */
    private Thread statsThread;

    // ========== 方向开关 ==========

    /** 是否启用 UDP→TCP（本地组播 → 远端 peer）。为 false 时停用该方向的发送。 */
    private final boolean udpToTcpEnabled;
    /** 是否启用 TCP→UDP（远端 peer → 本地组播）。为 false 时停用该方向的接收/发送。 */
    private final boolean tcpToUdpEnabled;

    // ========== 构造 ==========

    /**
     * 双向兼容构造器，默认两个方向都启用。
     *
     * @param localUdpHost     本地 UDP 组播地址
     * @param localUdpPort     本地 UDP 组播端口
     * @param localMulticastIf 本地组播网卡子网（CIDR 格式，如 "192.168.1.0/24"，可为 null）
     * @param listenPort       本地 TCP 监听端口（0 表示自动分配）
     * @param peers            远端对等节点列表
     * @param logger           日志记录器
     */
    public UdpBridgeNode(
            String localUdpHost, int localUdpPort,
            String localMulticastIf,
            int listenPort,
            List<PeerConfig> peers,
            Logger logger
    ) {
        this(localUdpHost, localUdpPort, localMulticastIf, listenPort, peers, true, true, logger);
    }

    /**
     * @param localUdpHost       本地 UDP 组播地址
     * @param localUdpPort       本地 UDP 组播端口
     * @param localMulticastIf   本地组播网卡子网（CIDR 格式，如 "192.168.1.0/24"，可为 null）
     * @param listenPort         本地 TCP 监听端口（0 表示自动分配；ttou 关闭时可不填）
     * @param peers              远端对等节点列表
     * @param udpToTcpEnabled    是否启用 UDP→TCP（本地组播发送到远端 peer）
     * @param tcpToUdpEnabled    是否启用 TCP→UDP（接收远端 peer 数据发到本地组播）
     * @param logger             日志记录器
     */
    public UdpBridgeNode(
            String localUdpHost, int localUdpPort,
            String localMulticastIf,
            int listenPort,
            List<PeerConfig> peers,
            boolean udpToTcpEnabled, boolean tcpToUdpEnabled,
            Logger logger
    ) {
        this.localUdpHost = localUdpHost;
        this.localUdpPort = localUdpPort;
        this.localMulticastIf = localMulticastIf;
        this.listenPort = listenPort;
        this.peers = new ArrayList<>(peers);
        this.udpToTcpEnabled = udpToTcpEnabled;
        this.tcpToUdpEnabled = tcpToUdpEnabled;
        this.logger = logger;
        this.localUdpTarget = new InetSocketAddress(localUdpHost, localUdpPort);
    }

    // ========== 启动 ==========

    /**
     * 启动桥接节点。
     * <p>
     * 启动顺序：
     * <ol>
     *   <li>初始化本地 UDP 发送 Channel</li>
     *   <li>启动本地 TCP 服务端（接收远端数据→转发到本地 UDP）</li>
     *   <li>启动常驻 Peer 管理线程：先启动的节点会持续重试，直到对端启动并连上</li>
     *   <li>所有 Peer 就绪后开始转发；监听器不等 Peer，立即加入组播组</li>
     * </ol>
     */
    public void start() throws InterruptedException, java.net.SocketException {
        logger.info("[BRIDGE] Starting UDP bridge node...");
        logger.info("[BRIDGE] I/O transport: {}, event loop threads: {}",
                ForwarderTransport.description(), eventLoopThreads());
        logger.info("[BRIDGE] Local UDP multicast: {}:{}", localUdpHost, localUdpPort);
        logger.info("[BRIDGE] Local listen port: {}", listenPort == 0 ? "auto" : listenPort);
        logger.info("[BRIDGE] Peers: {}", peers);

        running = true;

        // 1. 初始化本地 UDP 发送 Channel（仅 TCP→UDP 方向需要：把 peer 数据发到本地组播）
        if (tcpToUdpEnabled) {
            initLocalUdpChannel();
        }

        // 2. 启动本地 TCP 服务端（TCP→UDP：接收远端 TCP → 发到本地 UDP）。ttou 关闭时无需监听。
        if (tcpToUdpEnabled) {
            startTcpServer();
        } else {
            logger.info("[BRIDGE] TCP→UDP disabled, TCP listener skipped.");
        }

        // 3. 常驻 Peer 连接管理：持续重连，直到所有 Peer 就绪或 stop。
        //    utot 关闭（或没有 peer）时无需主动连接，直接视为就绪——否则状态会永远停在 WAITING。
        if (udpToTcpEnabled && !peers.isEmpty()) {
            startPeerManager();
        } else {
            if (!udpToTcpEnabled) {
                logger.info("[BRIDGE] UDP→TCP disabled, outbound peer connections skipped.");
            }
            working.set(true);
        }

        // 4. 启动统计信息打印线程
        startStatsThread();

        logger.info("[BRIDGE] UDP bridge node started successfully.");
    }

    /**
     * 初始化本地 UDP 发送 Channel
     * <p>
     * 此 Channel 仅用于将 TCP 收到的数据发送到本地 UDP 组播。
     * 注意：不设置 IP_MULTICAST_IF，因为：
     * <ul>
     *   <li>此 Channel 只用于发送数据，不加入组播组</li>
     *   <li>发送组播数据时操作系统会根据路由表自动选择网卡</li>
     *   <li>当系统禁用 IPv6 时，设置 IP_MULTICAST_IF 会导致 JDK 调用 setInterface6 失败</li>
     * </ul>
     * 加入组播组的网卡指定在 {@link #startUdpListener()} 中完成。
     */
    private void initLocalUdpChannel() throws InterruptedException, java.net.SocketException {
        // 强制要求必须指定 udpif，不再支持自动查找
        if (localMulticastIf == null || localMulticastIf.isEmpty()) {
            throw new IllegalArgumentException("[BRIDGE] localMulticastIf must be specified, auto-detection is not supported.");
        }
        NetworkInterface ni = Utils.getInterfaceByCidr(localMulticastIf);
        if (ni == null) {
            throw new IllegalArgumentException("[BRIDGE] Cannot find network interface for CIDR: " + localMulticastIf);
        }

        Bootstrap udpBootstrap = new Bootstrap();
        udpBootstrap.group(ioGroup)
                .channel(ForwarderTransport.datagramChannelClass())
                .option(ChannelOption.SO_SNDBUF, UDP_SOCKET_BUFFER_BYTES)
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, TCP_WRITE_WATERMARK)
                .handler(new ChannelInboundHandlerAdapter() {
                    @Override
                    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
                        // UDP 发送通道积压时暂停所有 TCP 连接的读取，把背压传回远端；
                        // 恢复可写后再打开 autoRead（setAutoRead(true) 会自动触发一次 read）。
                        applyTcpReadBackpressure(ctx.channel().isWritable());
                        ctx.fireChannelWritabilityChanged();
                    }
                });

        localUdpChannel = udpBootstrap.bind(0).sync().channel();

        udpSenderLocalPort = ((InetSocketAddress) localUdpChannel.localAddress()).getPort();
        logger.info("[BRIDGE] Local UDP sender bound to port: {}", udpSenderLocalPort);
    }

    /**
     * 启动本地 TCP 服务端，接收远端节点发来的数据并转发到本地 UDP 组播
     */
    private void startTcpServer() throws InterruptedException {
        // 启动 TCP 服务端
        io.netty.bootstrap.ServerBootstrap tcpBootstrap = new io.netty.bootstrap.ServerBootstrap();
        tcpBootstrap.group(ioGroup)
                .channel(ForwarderTransport.serverChannelClass())
                // Windows 上重启时，已关闭连接会以同一个本地端口进入 TIME_WAIT；
                // 不开 SO_REUSEADDR 会出现 “Address already in use”。
                .option(ChannelOption.SO_REUSEADDR, true)
                .option(ChannelOption.SO_BACKLOG, TCP_BACKLOG)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childOption(ChannelOption.SO_RCVBUF, TCP_SOCKET_BUFFER_BYTES)
                .childOption(ChannelOption.SO_SNDBUF, TCP_SOCKET_BUFFER_BYTES)
                .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, TCP_WRITE_WATERMARK)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        tcpServerChannels.add(ch);
                        // 如果本地 UDP 发送通道此刻已经积压，新连接也不要急着读。
                        if (localUdpChannel != null && !localUdpChannel.isWritable()) {
                            ch.config().setAutoRead(false);
                        }
                        ch.pipeline().addLast(new FrameToUdpHandler());
                    }
                });

        ChannelFuture future;
        if (listenPort == 0) {
            future = tcpBootstrap.bind(0).sync();
        } else {
            future = tcpBootstrap.bind(listenPort).sync();
        }
        tcpServerChannel = future.channel();
        int actualPort = ((InetSocketAddress) tcpServerChannel.localAddress()).getPort();
        logger.info("[BRIDGE] TCP server listening on port: {}", actualPort);
    }

    // ========== Peer 连接管理 ==========

    /**
     * TCP→UDP 的入站解码：先识别对端是否带 datagram magic，再按对应格式还原 UDP 包。
     *
     * <ul>
     *   <li><b>datagram</b>：magic 之后是 {@code [2B 长度][载荷]}，每个 frame 一个 UDP 包；</li>
     *   <li><b>stream</b>：magic 不匹配就是旧/连续流对端，按原来的 8 KiB 切片逻辑处理。</li>
     * </ul>
     *
     * <p>服务端无需配置就能同时服务新旧客户端：新客户端固定发 datagram，旧/连续流客户端
     * 不带 magic，自动走 stream。只有“新客户端 → 旧服务端”不兼容，两端同步升级即可。</p>
     */
    private final class FrameToUdpHandler extends ByteToMessageDecoder {

        private enum InboundMode { DETECT, DATAGRAM, STREAM }

        private InboundMode mode = InboundMode.DETECT;
        private boolean pendingFlush;

        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, java.util.List<Object> out) {
            if (paused) {
                in.skipBytes(in.readableBytes());
                return;
            }

            if (mode == InboundMode.DETECT) {
                int available = in.readableBytes();
                int compare = Math.min(available, ForwarderFraming.MAGIC.length);
                for (int i = 0; i < compare; i++) {
                    if (in.getByte(in.readerIndex() + i) != ForwarderFraming.MAGIC[i]) {
                        mode = InboundMode.STREAM;
                        break;
                    }
                }
                if (mode == InboundMode.DETECT) {
                    if (available < ForwarderFraming.MAGIC.length) {
                        return;   // 还看不出是 magic 还是碰巧同前缀的流数据
                    }
                    in.skipBytes(ForwarderFraming.MAGIC.length);
                    mode = InboundMode.DATAGRAM;
                    logger.debug("[BRIDGE] inbound framing: datagram");
                } else {
                    logger.debug("[BRIDGE] inbound framing: stream");
                }
            }

            if (mode == InboundMode.STREAM) {
                drainStream(in);
            } else {
                drainDatagrams(ctx, in);
            }
        }

        /** 旧行为：TCP 字节流按 8 KiB 切片发 UDP。 */
        private void drainStream(ByteBuf in) {
            int readable = in.readableBytes();
            if (readable == 0) {
                return;
            }
            int chunks = (readable + UDP_CHUNK_BYTES - 1) / UDP_CHUNK_BYTES;
            for (int off = 0; off < readable; off += UDP_CHUNK_BYTES) {
                int len = Math.min(UDP_CHUNK_BYTES, readable - off);
                sendUdp(in.readRetainedSlice(len));
            }
            tcpToUdpBytes.add(readable);
            tcpToUdpPackets.add(chunks);
            totalTcpToUdpBytes.add(readable);
            totalTcpToUdpPackets.add(chunks);
        }

        /** datagram 格式：每个长度前缀 frame 还原成一个 UDP 包。 */
        private void drainDatagrams(ChannelHandlerContext ctx, ByteBuf in) {
            while (in.readableBytes() >= 2) {
                int length = in.getUnsignedShort(in.readerIndex());
                if (length > ForwarderFraming.MAX_UDP_PAYLOAD) {
                    logger.error("[BRIDGE] Invalid datagram frame length {} (max {}); closing {}",
                            length, ForwarderFraming.MAX_UDP_PAYLOAD, ctx.channel().remoteAddress());
                    ctx.close();
                    return;
                }
                if (in.readableBytes() < 2 + length) {
                    return;   // 半帧，等下一次 read
                }
                in.skipBytes(2);
                ByteBuf payload = in.readRetainedSlice(length);
                sendUdp(payload);
                tcpToUdpBytes.add(length);
                tcpToUdpPackets.increment();
                totalTcpToUdpBytes.add(length);
                totalTcpToUdpPackets.increment();
            }
        }

        private void sendUdp(ByteBuf payload) {
            if (localUdpChannel == null || !localUdpChannel.isActive()) {
                payload.release();
                return;
            }
            try {
                localUdpChannel.write(new DatagramPacket(payload, localUdpTarget));
                pendingFlush = true;
            } catch (Exception e) {
                payload.release();
                logger.error("[BRIDGE] Failed to send UDP: {}", e.getMessage());
            }
        }

        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
            flushUdp();
            ctx.fireChannelReadComplete();
        }
        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            flushUdp();
            super.channelInactive(ctx);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            logger.error("[BRIDGE] TCP server handler error: {}", cause.getMessage());
            ctx.close();
        }

        private void flushUdp() {
            if (pendingFlush && localUdpChannel != null) {
                pendingFlush = false;
                localUdpChannel.flush();
            }
        }
    }

    /**
     * TCP→UDP 方向的背压：本地 UDP 发送通道积压时暂停所有 TCP 连接的读取。
     *
     * <p>UDP 发送是“尽力而为”的，但 TCP 是可靠字节流：直接丢分片会永久破坏对端的流；
     * 暂停 autoRead 让 TCP 窗口把压力传回远端，等 UDP 通道可写后自动恢复读取。</p>
     *
     * @param writable 本地 UDP 通道是否可写
     */
    private void applyTcpReadBackpressure(boolean writable) {
        for (Channel channel : tcpServerChannels) {
            if (channel.config().isAutoRead() != writable) {
                channel.config().setAutoRead(writable);
            }
        }
    }

    /**
     * 常驻 Peer 管理线程：每秒扫描一次，对未连接的 Peer 按固定间隔重试，直到 stop。
     *
     * <p>旧实现只在启动后的 60s 内重试，超时后线程退出；只要对端晚于这个窗口启动，
     * 或断线后没有组播流量触发重连，就会永远停在 reconnecting/connecting。这里改为
     * 常驻重试，并且每个连接都带超时，不会把线程卡在不可达地址上。</p>
     */
    @SuppressWarnings("BusyWait")
    private void startPeerManager() {
        peerManagerThread = new Thread(() -> {
            Bootstrap tcpBootstrap = createPeerBootstrap();
            logger.info("[BRIDGE] Peer manager started (retry every {}ms until stopped).",
                    RECONNECT_INTERVAL_MS);
            while (running) {
                for (PeerConfig peer : peers) {
                    Channel ch = tcpOutboundChannels.get(peer);
                    if (ch != null && ch.isActive()) {
                        continue;
                    }
                    if (!retryAllowed(peer)) {
                        continue;
                    }
                    connectPeer(peer, tcpBootstrap);
                }

                boolean allReady = peersReady();
                boolean was = working.getAndSet(allReady);
                if (allReady && !was) {
                    logger.info("[BRIDGE] All peers are ready; forwarding enabled.");
                } else if (!allReady && was) {
                    logger.warn("[BRIDGE] A peer connection is down; forwarding paused until it recovers.");
                }

                try {
                    Thread.sleep(PEER_SWEEP_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            logger.info("[BRIDGE] Peer manager stopped.");
        }, "peer-manager");
        peerManagerThread.setDaemon(true);
        peerManagerThread.start();
    }

    /** 所有需要主动连接的 Peer 是否都已连上（没有 Peer 时视为就绪）。 */
    private boolean peersReady() {
        if (peers.isEmpty()) {
            return true;
        }
        for (PeerConfig peer : peers) {
            Channel ch = tcpOutboundChannels.get(peer);
            if (ch == null || !ch.isActive()) {
                return false;
            }
        }
        return true;
    }

    private boolean retryAllowed(PeerConfig peer) {
        Long last = tcpDisconnectTime.get(peer);
        return last == null || System.currentTimeMillis() - last >= RECONNECT_INTERVAL_MS;
    }

    // ========== 统计信息打印 ==========

    /** 统计信息打印间隔（毫秒） */
    private static final long STATS_INTERVAL_MS = 30_000;

    /**
     * 启动统计信息打印线程，每半分钟打印一次 UDP 和 TCP 的传输量
     */
    @SuppressWarnings("BusyWait")
    private void startStatsThread() {
        statsThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(STATS_INTERVAL_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }

                if (!running) break;

                // 获取并重置统计计数器
                long udpBytes = udpToTcpBytes.sumThenReset();
                long tcpBytes = tcpToUdpBytes.sumThenReset();
                long udpPkts = udpToTcpPackets.sumThenReset();
                long tcpPkts = tcpToUdpPackets.sumThenReset();

                logger.info("[BRIDGE] === Traffic stats (last 30s) ===");
                logger.info("[BRIDGE] UDP→TCP (local→remote): {} packets, {}",
                        udpPkts, Utils.formatBytes(udpBytes));
                logger.info("[BRIDGE] TCP→UDP (remote→local): {} packets, {}",
                        tcpPkts, Utils.formatBytes(tcpBytes));
                logger.info("[BRIDGE] =================================");
            }
        }, "bridge-stats");
        statsThread.setDaemon(true);
        statsThread.start();
    }

    /**
     * 创建用于连接 Peer 的 Bootstrap
     */
    private Bootstrap createPeerBootstrap() {
        Bootstrap tcpBootstrap = new Bootstrap();
        tcpBootstrap.group(ioGroup)
                .channel(ForwarderTransport.clientChannelClass())
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
                .option(ChannelOption.SO_SNDBUF, TCP_SOCKET_BUFFER_BYTES)
                .option(ChannelOption.SO_RCVBUF, TCP_SOCKET_BUFFER_BYTES)
                .option(ChannelOption.WRITE_BUFFER_WATER_MARK, TCP_WRITE_WATERMARK)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // 出站连接不需要特殊 handler，数据由外部写入
                    }
                });
        return tcpBootstrap;
    }

    /** 连接一个 Peer；失败只记录时间，由 {@link #startPeerManager()} 按间隔重试。 */
    private void connectPeer(PeerConfig peer, Bootstrap tcpBootstrap) {
        // 同一轮“失败重试”只告警一次，避免对端没启动时每 3s 刷一条 WARN。
        boolean firstAttempt = !tcpDisconnectTime.containsKey(peer);
        ChannelFuture future = null;
        try {
            if (firstAttempt) {
                logger.info("[BRIDGE] Connecting to peer: {}", peer);
            }
            future = tcpBootstrap.connect(peer.getHost(), peer.getTcpPort());
            future.sync();
            Channel channel = future.channel();
            if (!future.isSuccess() || !channel.isActive()) {
                logConnectFailure(peer, firstAttempt, "not active");
                tcpDisconnectTime.put(peer, System.currentTimeMillis());
                tcpOutboundChannels.remove(peer);
                refreshOutbound();
                channel.close();
                return;
            }

            // 先把协议前缀发出去再暴露给转发线程：服务端靠它区分 datagram / legacy stream。
            ChannelFuture magic = channel.writeAndFlush(
                    Unpooled.wrappedBuffer(ForwarderFraming.MAGIC));
            if (!magic.awaitUninterruptibly(FRAME_MAGIC_WRITE_TIMEOUT_MS) || !magic.isSuccess()) {
                logConnectFailure(peer, firstAttempt, "failed to send framing magic");
                tcpDisconnectTime.put(peer, System.currentTimeMillis());
                tcpOutboundChannels.remove(peer);
                refreshOutbound();
                channel.close();
                return;
            }

            tcpOutboundChannels.put(peer, channel);
            refreshOutbound();
            tcpConnectedTime.put(peer, System.currentTimeMillis());
            tcpDisconnectTime.remove(peer);
            channel.closeFuture().addListener(cf -> onPeerClosed(peer, channel));
            logger.info("[BRIDGE] Connected to peer: {}", peer);
        } catch (InterruptedException e) {
            if (future != null) {
                future.channel().close();
            }
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            logConnectFailure(peer, firstAttempt, e.getMessage());
            tcpDisconnectTime.put(peer, System.currentTimeMillis());
            tcpOutboundChannels.remove(peer);
            refreshOutbound();
        }
    }

    private void logConnectFailure(PeerConfig peer, boolean firstAttempt, String reason) {
        if (firstAttempt) {
            logger.warn("[BRIDGE] Connect to peer {} failed: {}; retrying every {}ms",
                    peer, reason, RECONNECT_INTERVAL_MS);
        } else {
            logger.debug("[BRIDGE] Connect to peer {} still failing: {}", peer, reason);
        }
    }

    /** Peer 连接被对端/网络关闭：记录时间，管理线程会继续重连。 */
    private void onPeerClosed(PeerConfig peer, Channel channel) {
        if (!tcpOutboundChannels.remove(peer, channel)) {
            return; // 已被更新的连接替换
        }
        refreshOutbound();
        tcpDisconnectTime.put(peer, System.currentTimeMillis());
        if (running) {
            logger.warn("[BRIDGE] Peer connection closed: {} (reconnecting)", peer);
        }
    }

    /** 重建热路径使用的 peer channel 快照；连接增删时调用（频率极低）。 */
    private void refreshOutbound() {
        List<PeerChannel> snapshot = new ArrayList<>(tcpOutboundChannels.size());
        for (Map.Entry<PeerConfig, Channel> entry : tcpOutboundChannels.entrySet()) {
            snapshot.add(new PeerChannel(entry.getKey(), entry.getValue()));
        }
        outbound = List.copyOf(snapshot);
    }

    // ========== 数据发送（本地 UDP → 远端 TCP） ==========

    /**
     * 将数据从本地 UDP 组播转发到所有已连接的远端节点。
     *
     * @param data   UDP 数据内容
     * @param sender 发送方地址（用于回环检测）
     */
    public void forwardToPeers(byte[] data, InetSocketAddress sender) {
        ByteBuf buf = Unpooled.wrappedBuffer(data);
        try {
            forwardToPeers(buf, sender, true);
        } finally {
            buf.release();
        }
    }

    /**
     * 热路径：直接消费 Netty 的 {@link ByteBuf}，不再复制成 {@code byte[]}。
     *
     * <p>{@code immediate=false} 时不立刻写 channel，而是把 frame 追加到本批 UDP 读的
     * per-peer 缓冲；{@code channelReadComplete} 时每个 peer 只 {@code write+flush} 一次。
     * 注意这只是把**已经读到的同批报文**合并，不会跨 read 等待，因此小流量（一批 1 个包）
     * 的延迟与逐包写完全相同。</p>
     */
    private void forwardToPeers(ByteBuf data, InetSocketAddress sender, boolean immediate) {
        int length = prepareForward(data, sender);
        if (length < 0) {
            return;
        }

        for (PeerChannel entry : outbound) {
            Channel ch = entry.channel();
            if (!ch.isActive()) {
                // 重连交给 peer-manager；这里不能做阻塞式 connect（会卡住 UDP 事件循环）。
                continue;
            }
            if (!ch.isWritable()) {
                // 写缓冲已积压（对端慢/网络拥塞）：UDP 语义下直接丢，不能无限排队吃内存。
                droppedBackpressure.increment();
                continue;
            }
            if (length > ForwarderFraming.MAX_UDP_PAYLOAD) {
                droppedOversize.increment();
                continue;
            }

            if (immediate) {
                CompositeByteBuf frame = newFrame(ch, data, length);
                try {
                    ch.writeAndFlush(frame);
                } catch (Exception e) {
                    frame.release();
                    onForwardFailure(entry.peer(), e);
                }
            } else {
                appendToBatch(entry.peer(), ch, data, length);
            }
        }
    }

    /** 校验/计数一次本地 UDP 入包；返回载荷长度，-1 表示不转发。 */
    private int prepareForward(ByteBuf data, InetSocketAddress sender) {
        // 暂停或 UDP→TCP 方向关闭时，不做任何发送。
        if (paused || !udpToTcpEnabled) {
            return -1;
        }
        // 回环过滤：如果数据来自本节点的 UDP 发送端口，则丢弃
        if (sender.getPort() == udpSenderLocalPort) {
            return -1;
        }

        int length = data.readableBytes();
        udpIngressPackets.increment();

        // 如果节点尚未进入工作状态，丢弃数据（未就绪期间没有对端可转发）
        if (!working.get()) {
            droppedNotReady.increment();
            if (logger.isTraceEnabled()) {
                logger.trace("[BRIDGE] Node not ready yet, dropping {} bytes from {}:{}",
                        length, sender.getAddress(), sender.getPort());
            }
            return -1;
        }

        // 统计 UDP→TCP 方向的流量（本地→远端）
        udpToTcpBytes.add(length);
        udpToTcpPackets.increment();
        totalUdpToTcpBytes.add(length);
        totalUdpToTcpPackets.increment();
        return length;
    }

    /** 构造 {@code [2B 长度][载荷]} 的单帧（immediate 路径用）。 */
    private CompositeByteBuf newFrame(Channel ch, ByteBuf data, int length) {
        CompositeByteBuf frame = ch.alloc().compositeBuffer(2);
        frame.addComponents(true, header(ch, length), data.retainedDuplicate());
        return frame;
    }

    /** 2 字节大端长度头。 */
    private static ByteBuf header(Channel ch, int length) {
        ByteBuf header = ch.alloc().buffer(2, 2);
        header.writeShort(length);
        return header;
    }

    /**
     * 把一帧追加到该 peer 本批的聚合缓冲。
     *
     * <p>同一批 UDP read 的多个 frame 会合并成一次 channel write；达到
     * {@link #TCP_BATCH_MAX_BYTES} 时提前写出并 flush，避免一个大突发把延迟拖长。</p>
     */
    private void appendToBatch(PeerConfig peer, Channel ch, ByteBuf data, int length) {
        CompositeByteBuf full = null;
        synchronized (pendingBatches) {
            CompositeByteBuf batch = pendingBatches.get(ch);
            if (batch == null) {
                batch = ch.alloc().compositeBuffer(TCP_BATCH_MAX_FRAMES * 2);
                pendingBatches.put(ch, batch);
            }
            try {
                batch.addComponents(true, header(ch, length), data.retainedDuplicate());
            } catch (RuntimeException e) {
                pendingBatches.remove(ch);
                batch.release();
                onForwardFailure(peer, e);
                return;
            }
            if (batch.readableBytes() >= TCP_BATCH_MAX_BYTES
                    || batch.numComponents() >= TCP_BATCH_MAX_FRAMES * 2) {
                pendingBatches.remove(ch);
                full = batch;
            }
        }
        if (full != null) {
            writeBatch(peer, ch, full);
        }
    }

    /** 把本批所有 peer 的聚合缓冲各写一次并 flush。 */
    private void flushPeerBatches() {
        if (pendingBatches.isEmpty()) {
            return;
        }
        synchronized (pendingBatches) {
            for (Map.Entry<Channel, CompositeByteBuf> entry : pendingBatches.entrySet()) {
                Channel ch = entry.getKey();
                CompositeByteBuf batch = entry.getValue();
                if (!ch.isActive()) {
                    batch.release();
                    continue;
                }
                writeBatch(null, ch, batch);
            }
            pendingBatches.clear();
        }
    }

    private void writeBatch(PeerConfig peer, Channel ch, CompositeByteBuf batch) {
        try {
            ch.write(batch);
        } catch (Exception e) {
            batch.release();
            onForwardFailure(peer, e);
            return;
        }
        try {
            ch.flush();
        } catch (Exception e) {
            // 消息已交给 channel，不能再 release；记录即可。
            logger.error("[BRIDGE] Failed to flush peer {}: {}",
                    peer == null ? "?" : peer, e.getMessage());
        }
    }

    /** 释放未写出的聚合缓冲（stop 时调用；与 UDP 线程通过锁互斥）。 */
    private void releasePendingBatches() {
        synchronized (pendingBatches) {
            for (CompositeByteBuf batch : pendingBatches.values()) {
                batch.release();
            }
            pendingBatches.clear();
        }
    }

    private void onForwardFailure(PeerConfig peer, Exception e) {
        logger.error("[BRIDGE] Failed to send data to peer {}: {}",
                peer == null ? "?" : peer, e.getMessage());
        if (peer != null) {
            tcpDisconnectTime.put(peer, System.currentTimeMillis());
        }
    }

    // ========== UDP 组播监听 ==========

    /** 加入组播组；不同 transport 的 datagram channel 没有共同的 joinGroup 接口，这里按类型分派。 */
    private static ChannelFuture joinGroup(Channel channel, InetSocketAddress group,
                                           NetworkInterface networkInterface) {
        if (channel instanceof NioDatagramChannel nio) {
            return nio.joinGroup(group, networkInterface);
        }
        if (channel instanceof EpollDatagramChannel epoll) {
            return epoll.joinGroup(group, networkInterface);
        }
        if (channel instanceof KQueueDatagramChannel kqueue) {
            return kqueue.joinGroup(group, networkInterface);
        }
        throw new IllegalArgumentException(
                "Unsupported datagram channel for multicast: " + channel.getClass().getName());
    }

    /**
     * 启动 UDP 组播监听，将收到的数据转发到所有远端节点。
     * <p>
     * 这是一个阻塞调用。Peer 未就绪时数据会被丢弃（见 {@link #forwardToPeers}），
     * 但不阻塞监听本身——先启动的节点也能立即加入组播组，等对端起来后自动开始转发。
     * </p>
     */
    public void startUdpListener() throws InterruptedException {
        Bootstrap udpListenerBootstrap = new Bootstrap();
        udpListenerBootstrap.group(ioGroup)
                .channel(ForwarderTransport.datagramChannelClass())
                // 组播接收的标准做法：允许多个进程/连续重启绑定同一个组播端口。
                .option(ChannelOption.SO_REUSEADDR, true)
                .option(ChannelOption.SO_RCVBUF, UDP_SOCKET_BUFFER_BYTES)
                .handler(new SimpleChannelInboundHandler<DatagramPacket>() {
                    @Override
                    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
                        InetSocketAddress sender = packet.sender();
                        if (logger.isTraceEnabled()) {
                            logger.trace("[BRIDGE] UDP received {} bytes from {}:{}",
                                    packet.content().readableBytes(), sender.getAddress(), sender.getPort());
                        }

                        // 直接消费 ByteBuf（不复制成 byte[]），flush 合并到 readComplete。
                        // 同一批 UDP read 的多个包合并成一批 TCP write，readComplete 时统一 flush。
                        forwardToPeers(packet.content(), sender, false);
                    }

                    @Override
                    public void channelReadComplete(ChannelHandlerContext ctx) {
                        flushPeerBatches();
                        ctx.fireChannelReadComplete();
                    }
                });

        ChannelFuture future = udpListenerBootstrap.bind(localUdpPort).sync();
        Channel ch = future.channel();

        try {
            // 强制要求必须指定 udpif，不再支持自动查找
            if (localMulticastIf == null || localMulticastIf.isEmpty()) {
                throw new IllegalArgumentException("[BRIDGE] localMulticastIf must be specified, auto-detection is not supported.");
            }
            NetworkInterface ni = Utils.getInterfaceByCidr(localMulticastIf);
            if (ni == null) {
                throw new IllegalArgumentException("[BRIDGE] Cannot find network interface for CIDR: " + localMulticastIf);
            }
            try {
                InetSocketAddress group = new InetSocketAddress(
                        InetAddress.getByName(localUdpHost), localUdpPort);
                joinGroup(ch, group, ni).sync();
                logger.info("[BRIDGE] UDP listener joined multicast group {}:{}", localUdpHost, localUdpPort);
            } catch (Exception e) {
                throw new RuntimeException("[BRIDGE] Failed to join multicast group on interface '" + ni.getName() + "': " + e.getMessage(), e);
            }
        } catch (Exception e) {
            throw new RuntimeException("[BRIDGE] Failed to join multicast group.", e);
        }

        logger.info("[BRIDGE] UDP listener started on port: {}", localUdpPort);
        future.channel().closeFuture().sync();
    }

    // ========== 暂停 / 恢复 ==========

    /** 暂停转发：两个方向的发送（本地→peer 与 peer→本地）都会被停用，连接保持。 */
    @Override
    public void pause() {
        paused = true;
        logger.info("[BRIDGE] Forwarding paused.");
    }

    /** 恢复转发。 */
    @Override
    public void resume() {
        paused = false;
        logger.info("[BRIDGE] Forwarding resumed.");
    }

    @Override
    public boolean paused() {
        return paused;
    }

    // ========== 停止 ==========

    /**
     * 停止桥接节点，释放所有资源
     */
    public void stop() {
        logger.info("[BRIDGE] Stopping UDP bridge node...");
        running = false;
        working.set(false);

        // 中断 Peer 管理线程
        if (peerManagerThread != null) {
            peerManagerThread.interrupt();
        }

        // 中断统计信息打印线程
        if (statsThread != null) {
            statsThread.interrupt();
        }

        // 释放本批尚未写出的聚合缓冲（正常由 flushPeerBatches 写出）
        releasePendingBatches();

        // 关闭所有 TCP 出站连接
        for (Map.Entry<PeerConfig, Channel> entry : tcpOutboundChannels.entrySet()) {
            try {
                entry.getValue().close().sync();
            } catch (Exception e) {
                logger.warn("[BRIDGE] Failed to close TCP connection to {}: {}", entry.getKey(), e.getMessage());
            }
        }
        tcpOutboundChannels.clear();
        outbound = List.of();

        // 关闭 TCP 服务端
        if (tcpServerChannel != null) {
            try {
                tcpServerChannel.close().sync();
            } catch (Exception e) {
                logger.warn("[BRIDGE] Failed to close TCP server: {}", e.getMessage());
            }
        }
        // 关闭已接受的 TCP 连接（如果服务端 close 没有级联）
        try {
            tcpServerChannels.close().sync();
        } catch (Exception e) {
            logger.debug("[BRIDGE] Failed to close TCP server connections: {}", e.getMessage());
        }

        // 关闭 UDP Channel
        if (localUdpChannel != null) {
            try {
                localUdpChannel.close().sync();
            } catch (Exception e) {
                logger.warn("[BRIDGE] Failed to close UDP channel: {}", e.getMessage());
            }
        }

        // 关闭事件循环。quiet period 设为 0：stop 时我们已显式关闭数据通道，
        // 不必再等默认的 2s 静默期（否则 UI 的 Stopping… 会拖 3 秒）。
        ioGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS);

        logger.info("[BRIDGE] UDP bridge node stopped.");
    }

    public int getActualListenPort() {
        if (tcpServerChannel != null) {
            return ((InetSocketAddress) tcpServerChannel.localAddress()).getPort();
        }
        return listenPort;
    }

    // ========== ForwarderStatus.Source ==========

    @Override
    public void run() throws Exception {
        start();
        if (udpToTcpEnabled) {
            startUdpListener();
        } else {
            logger.info("[BRIDGE] UDP→TCP disabled, local UDP listener skipped.");
        }
    }

    @Override
    public boolean ready() {
        return working.get();
    }

    @Override
    public ForwarderStatus.Snapshot snapshot() {
        List<ForwarderStatus.Peer> list = new ArrayList<>();
        for (PeerConfig peer : peers) {
            Channel ch = tcpOutboundChannels.get(peer);
            String state;
            if (ch != null && ch.isActive()) {
                state = "ready";
            } else if (tcpConnectedTime.containsKey(peer)) {
                // 连上过又断了 → reconnecting；从未连上 → connecting。
                state = "reconnecting";
            } else {
                state = "connecting";
            }
            list.add(new ForwarderStatus.Peer(peer.toString(), state,
                    "ready".equals(state) ? tcpConnectedTime.getOrDefault(peer, 0L) : 0L));
        }
        return new ForwarderStatus.Snapshot(
                new ForwarderStatus.Direction(totalUdpToTcpPackets.sum(), totalUdpToTcpBytes.sum()),
                new ForwarderStatus.Direction(totalTcpToUdpPackets.sum(), totalTcpToUdpBytes.sum()),
                droppedNotReady.sum() + droppedBackpressure.sum() + droppedOversize.sum(),
                "0.0.0.0:" + getActualListenPort(),
                localUdpHost + ":" + localUdpPort,
                list,
                udpIngressPackets.sum());
    }
}
