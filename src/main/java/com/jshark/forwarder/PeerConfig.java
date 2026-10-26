package com.jshark.forwarder;

/**
 * 远端对等节点配置
 * <p>
 * 描述一个需要桥接的远端 UdpBridgeNode 节点。
 * 每个 PeerConfig 对应一个远端服务器，通过 TCP 连接进行 UDP 组播数据的双向桥接。
 */
public class PeerConfig {

    /** 远端节点的主机地址（IP 或域名） */
    private final String host;

    /** 远端节点的 TCP 端口（用于桥接数据传输） */
    private final int tcpPort;

    public PeerConfig(String host, int tcpPort) {
        this.host = host;
        this.tcpPort = tcpPort;
    }

    public String getHost() {
        return host;
    }

    public int getTcpPort() {
        return tcpPort;
    }

    @Override
    public String toString() {
        return host + ":" + tcpPort;
    }
}
