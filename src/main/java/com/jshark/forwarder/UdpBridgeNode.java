package com.jshark.forwarder;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
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
import java.util.concurrent.atomic.AtomicLong;

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
    private final EventLoopGroup bossGroup = new NioEventLoopGroup(1);
    private final EventLoopGroup workerGroup = new NioEventLoopGroup();
    private final EventLoopGroup udpGroup = new NioEventLoopGroup();

    // ========== 内部状态 ==========
    /** 本地 UDP 发送 Channel（用于将 TCP 收到的数据发到本地组播） */
    private Channel localUdpChannel;
    /** 用于发送 UDP 到本地组播的本地端口（用于回环过滤） */
    private int udpSenderLocalPort;
    /** 本地 UDP 目标地址（缓存，避免每个 TCP read 都解析/分配）。 */
    private final InetSocketAddress localUdpTarget;

    /** 到所有远端节点的 TCP 连接（用于本地→远端方向） */
    private final ConcurrentHashMap<PeerConfig, Channel> tcpOutboundChannels = new ConcurrentHashMap<>();
    /** 最近一次连接失败/断开的时间（用于重试节流） */
    private final ConcurrentHashMap<PeerConfig, Long> tcpDisconnectTime = new ConcurrentHashMap<>();
    /** 最近一次连接成功的时刻（UI 的 Since 列；断开后保留，用于区分 connecting / reconnecting） */
    private final ConcurrentHashMap<PeerConfig, Long> tcpConnectedTime = new ConcurrentHashMap<>();

    /** 单个 Peer 的重试间隔 */
    private static final long RECONNECT_INTERVAL_MS = 3_000;
    /** 建立 TCP 连接的超时时间（避免不可达地址把重连线程卡住几十秒） */
    private static final int CONNECT_TIMEOUT_MS = 3_000;
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

    /** 过去半分钟内 UDP→TCP（本地→远端）的传输字节数 */
    private final AtomicLong udpToTcpBytes = new AtomicLong(0);
    /** 过去半分钟内 TCP→UDP（远端→本地）的传输字节数 */
    private final AtomicLong tcpToUdpBytes = new AtomicLong(0);
    /** 过去半分钟内 UDP→TCP（本地→远端）的传输包数 */
    private final AtomicLong udpToTcpPackets = new AtomicLong(0);
    /** 过去半分钟内 TCP→UDP（远端→本地）的传输包数 */
    private final AtomicLong tcpToUdpPackets = new AtomicLong(0);

    // ========== 累计统计（UI / --control stdio；不随 30s 打印重置） ==========

    private final AtomicLong totalUdpToTcpBytes = new AtomicLong(0);
    private final AtomicLong totalTcpToUdpBytes = new AtomicLong(0);
    private final AtomicLong totalUdpToTcpPackets = new AtomicLong(0);
    private final AtomicLong totalTcpToUdpPackets = new AtomicLong(0);
    private final AtomicLong droppedNotReady = new AtomicLong(0);
    /** 本地 UDP 入包（含未就绪被丢弃的），用于计算本地丢弃率。 */
    private final AtomicLong udpIngressPackets = new AtomicLong(0);

    /** UDP 收/发 socket 缓冲区（大流量灌包时避免突发丢包）。 */
    private static final int UDP_SOCKET_BUFFER_BYTES = 4 * 1024 * 1024;
    /** TCP→UDP 重新切分的最大 UDP 载荷，避免超过 65507 上限和 IP 分片。 */
    private static final int UDP_CHUNK_BYTES = 8 * 1024;

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
        udpBootstrap.group(udpGroup)
                .channel(NioDatagramChannel.class)
                .option(ChannelOption.SO_SNDBUF, UDP_SOCKET_BUFFER_BYTES)
                .handler(new ChannelInboundHandlerAdapter());

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
        tcpBootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                // Windows 上重启时，已关闭连接会以同一个本地端口进入 TIME_WAIT；
                // 不开 SO_REUSEADDR 会出现 “Address already in use”。
                .option(ChannelOption.SO_REUSEADDR, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                                // 从远端 TCP 收到数据 → 转发到本地 UDP 组播
                                if (paused) {
                                    return;
                                }
                                int readable = msg.readableBytes();
                                if (readable == 0) {
                                    return;
                                }

                                if (logger.isTraceEnabled()) {
                                    logger.trace("[BRIDGE] TCP→UDP: forwarding {} bytes to local multicast", readable);
                                }

                                // TCP 是字节流：一次 read 可能几十 KB，直接塞进一个 UDP 包会超过
                                // 65507 上限（message too long），也会触发 IP 分片。按固定大小切分。
                                int chunks = (readable + UDP_CHUNK_BYTES - 1) / UDP_CHUNK_BYTES;
                                int index = msg.readerIndex();
                                for (int off = 0; off < readable; off += UDP_CHUNK_BYTES) {
                                    int len = Math.min(UDP_CHUNK_BYTES, readable - off);
                                    // 零拷贝切片；msg 由 handler 释放后，切片的引用计数仍在。
                                    ByteBuf slice = msg.retainedSlice(index + off, len);
                                    try {
                                        localUdpChannel.write(new DatagramPacket(slice, localUdpTarget));
                                    } catch (Exception e) {
                                        slice.release();
                                        logger.error("[BRIDGE] Failed to send UDP chunk: {}", e.getMessage());
                                    }
                                }
                                localUdpChannel.flush();

                                // 统计 TCP→UDP 方向的流量（远端→本地）
                                tcpToUdpBytes.addAndGet(readable);
                                tcpToUdpPackets.addAndGet(chunks);
                                totalTcpToUdpBytes.addAndGet(readable);
                                totalTcpToUdpPackets.addAndGet(chunks);
                            }


                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                logger.error("[BRIDGE] TCP server handler error: {}", cause.getMessage());
                            }
                        });
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
                long udpBytes = udpToTcpBytes.getAndSet(0);
                long tcpBytes = tcpToUdpBytes.getAndSet(0);
                long udpPkts = udpToTcpPackets.getAndSet(0);
                long tcpPkts = tcpToUdpPackets.getAndSet(0);

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
        tcpBootstrap.group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
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
                channel.close();
                return;
            }

            tcpOutboundChannels.put(peer, channel);
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
        tcpDisconnectTime.put(peer, System.currentTimeMillis());
        if (running) {
            logger.warn("[BRIDGE] Peer connection closed: {} (reconnecting)", peer);
        }
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
     * <p>{@code flush=false} 时只 write、不 flush，由调用方在一批 UDP 读完后统一
     * flush（见 {@code channelReadComplete}），减少 TCP 小包和系统调用。</p>
     */
    private void forwardToPeers(ByteBuf data, InetSocketAddress sender, boolean flush) {
        // 暂停或 UDP→TCP 方向关闭时，不做任何发送。
        if (paused || !udpToTcpEnabled) {
            return;
        }

        // 回环过滤：如果数据来自本节点的 UDP 发送端口，则丢弃
        if (sender.getPort() == udpSenderLocalPort) {
            return;
        }

        int length = data.readableBytes();
        udpIngressPackets.incrementAndGet();

        // 如果节点尚未进入工作状态，丢弃数据（未就绪期间没有对端可转发）
        if (!working.get()) {
            droppedNotReady.incrementAndGet();
            if (logger.isTraceEnabled()) {
                logger.trace("[BRIDGE] Node not ready yet, dropping {} bytes from {}:{}",
                        length, sender.getAddress(), sender.getPort());
            }
            return;
        }

        // 统计 UDP→TCP 方向的流量（本地→远端）
        udpToTcpBytes.addAndGet(length);
        udpToTcpPackets.incrementAndGet();
        totalUdpToTcpBytes.addAndGet(length);
        totalUdpToTcpPackets.incrementAndGet();

        for (Map.Entry<PeerConfig, Channel> entry : tcpOutboundChannels.entrySet()) {
            PeerConfig peer = entry.getKey();
            Channel ch = entry.getValue();

            if (!ch.isActive()) {
                // 重连交给 peer-manager；这里不能做阻塞式 connect（会卡住 UDP 事件循环）。
                continue;
            }

            // 零拷贝：同一个 ByteBuf 可以被多个连接引用，各自 retain 一份。
            ByteBuf copy = data.retainedDuplicate();
            try {
                if (flush) {
                    ch.writeAndFlush(copy);
                } else {
                    ch.write(copy);
                }
            } catch (Exception e) {
                copy.release();
                logger.error("[BRIDGE] Failed to send data to peer {}: {}", peer, e.getMessage());
                tcpDisconnectTime.put(peer, System.currentTimeMillis());
            }
        }
    }

    /** 把一批 UDP 读产生的 TCP 写入合并 flush。 */
    private void flushPeerChannels() {
        for (Channel ch : tcpOutboundChannels.values()) {
            if (ch.isActive()) {
                ch.flush();
            }
        }
    }

    // ========== UDP 组播监听 ==========

    /**
     * 启动 UDP 组播监听，将收到的数据转发到所有远端节点。
     * <p>
     * 这是一个阻塞调用。Peer 未就绪时数据会被丢弃（见 {@link #forwardToPeers}），
     * 但不阻塞监听本身——先启动的节点也能立即加入组播组，等对端起来后自动开始转发。
     * </p>
     */
    public void startUdpListener() throws InterruptedException {
        Bootstrap udpListenerBootstrap = new Bootstrap();
        udpListenerBootstrap.group(udpGroup)
                .channel(NioDatagramChannel.class)
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
                        forwardToPeers(packet.content(), sender, false);
                    }

                    @Override
                    public void channelReadComplete(ChannelHandlerContext ctx) {
                        flushPeerChannels();
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
                ((NioDatagramChannel) ch).joinGroup(
                        InetAddress.getByName(localUdpHost),
                        ni,
                        null
                ).sync();
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

        // 关闭所有 TCP 出站连接
        for (Map.Entry<PeerConfig, Channel> entry : tcpOutboundChannels.entrySet()) {
            try {
                entry.getValue().close().sync();
            } catch (Exception e) {
                logger.warn("[BRIDGE] Failed to close TCP connection to {}: {}", entry.getKey(), e.getMessage());
            }
        }
        tcpOutboundChannels.clear();

        // 关闭 TCP 服务端
        if (tcpServerChannel != null) {
            try {
                tcpServerChannel.close().sync();
            } catch (Exception e) {
                logger.warn("[BRIDGE] Failed to close TCP server: {}", e.getMessage());
            }
        }

        // 关闭 UDP Channel
        if (localUdpChannel != null) {
            try {
                localUdpChannel.close().sync();
            } catch (Exception e) {
                logger.warn("[BRIDGE] Failed to close UDP channel: {}", e.getMessage());
            }
        }

        // 关闭线程池。quiet period 设为 0：stop 时我们已显式关闭数据通道，
        // 不必再等默认的 2s 静默期（否则 UI 的 Stopping… 会拖 3 秒）。
        bossGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS);
        workerGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS);
        udpGroup.shutdownGracefully(0, 2, TimeUnit.SECONDS);

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
                new ForwarderStatus.Direction(totalUdpToTcpPackets.get(), totalUdpToTcpBytes.get()),
                new ForwarderStatus.Direction(totalTcpToUdpPackets.get(), totalTcpToUdpBytes.get()),
                droppedNotReady.get(),
                "0.0.0.0:" + getActualListenPort(),
                localUdpHost + ":" + localUdpPort,
                list,
                udpIngressPackets.get());
    }
}
