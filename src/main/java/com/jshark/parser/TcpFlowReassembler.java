package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 序列号驱动的 TCP 流重组器。
 *
 * <h3>为什么必须按序列号重组</h3>
 * <p>
 * 早期实现（{@code TcpStreamAssembler}）把每个 TCP 段的 payload 简单追加到缓冲区尾部，
 * 这在真实网络上是错的：
 * </p>
 * <ul>
 *   <li><b>重传</b>（极常见）→ 同一段字节被追加两次，解析出重复消息或坏消息；</li>
 *   <li><b>乱序</b>（多路径、无线）→ 按到达顺序拼接，字节流损坏；</li>
 *   <li><b>四元组复用</b>（短连接、端口复用）→ 两次会话的数据被拼成一条流。</li>
 * </ul>
 * <p>
 * 本实现按 TCP 语义处理：以序列号为索引缓存分段、只在<b>连续区间</b>上交付数据、
 * 丢弃完全重复的段、按序列号裁剪重叠部分、并用"连接代次"隔离四元组复用。
 * </p>
 *
 * <h3>关键语义</h3>
 * <ol>
 *   <li><b>只交付连续数据</b>：存在缺口时等待（乱序），直到缺口被后续段补上。</li>
 *   <li><b>重传去重</b>：完全落在已交付区间内的段直接丢弃；
 *       部分重叠的段裁掉重叠部分后按序入队。</li>
 *   <li><b>跨连接隔离</b>：见到第二次 SYN，或序列号相对已见值大幅跳变，都视为新连接。</li>
 *   <li><b>缺口可观测</b>：{@link StreamUpdate#waitingForGap()} 会如实报告缺口，
 *       便于区分"流未收全"与"协议解析失败"。</li>
 *   <li><b>SYN 占位</b>：SYN 消耗一个序列号（RFC 793），因此首个数据字节位于 {@code seq+1}。</li>
 * </ol>
 *
 * <p>本类只做数据重组，不做协议解析。</p>
 */
public class TcpFlowReassembler {

    private static final Logger logger = LoggerFactory.getLogger(TcpFlowReassembler.class);

    /** 流空闲超时（毫秒）：超过则清理缓冲区，防止内存泄漏 */
    private static final long STREAM_TIMEOUT_MS = 120_000L;
    /** 单条流允许缓存的最大字节数；超过则放弃最旧的缺口并强制交付 */
    private static final int MAX_STREAM_BUFFER_BYTES = 8 * 1024 * 1024;
    /** 最多同时跟踪的流数量 */
    private static final int MAX_STREAMS = 4096;

    /**
     * 判定"序列号大幅跳变"的阈值（字节），用于识别同一四元组上的新连接。
     * <p>
     * 取值需要在两者之间平衡：
     * </p>
     * <ul>
     *   <li><b>必须足够大</b>：重传/乱序的序列号偏移通常只有几 KB 到几 MB，
     *       不能把它们误判成新连接；</li>
     *   <li><b>必须足够小</b>：现代系统多用"线性递增 ISN"，同一四元组上下一次连接的
     *       ISN 相对上一次通常只跳进几十 MB。阈值若取 1 GiB 就会漏判这一最常见的复用场景。</li>
     * </ul>
     * <p>1 MiB 是两者之间的安全取值。</p>
     */
    private static final long SEQ_JUMP_THRESHOLD = 1L << 20;

    /**
     * 流标识：TCP 四元组（保留原始方向）。
     * <p>
     * 刻意<b>不含</b>连接代次：代次完全由本类内部维护——检测到新连接时直接重置该四元组的流状态，
     * 因此调用方只需按四元组查表，无需（也无从）知道当前是第几代。
     * </p>
     *
     * @param srcIp   源 IP
     * @param dstIp   目的 IP
     * @param srcPort 源端口
     * @param dstPort 目的端口
     */
    public record StreamKey(String srcIp, String dstIp, int srcPort, int dstPort) {

        /** @return 反向流标识（服务器→客户端） */
        public StreamKey reverse() {
            return new StreamKey(dstIp, srcIp, dstPort, srcPort);
        }

        /** @return 四元组描述，便于日志 */
        public String tuple() {
            return srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort;
        }
    }

    /** 交付状态 */
    public enum Delivery {
        /** 有连续字节可交给上层（本次新交付的，或上次返回后尚未被 consume 的残留） */
        DATA,
        /** 数据已收下，但被序列号缺口挡住，当前不可交付 */
        BUFFERED,
        /** 无数据：纯控制段、完全重复的段，或该段未带来任何可交付字节 */
        NOTHING
    }

    /**
     * 一次提交的结果。
     *
     * @param delivery      是否交付了新数据
     * @param data          连续可用的字节；无新数据时为 null
     * @param waitingForGap 是否有缺口在等待后续段
     * @param duplicate     本次提交是否为完全重复的段（重传）
     * @param newConnection 本次提交是否开启了新连接（代次推进）
     */
    public record StreamUpdate(Delivery delivery, byte[] data, boolean waitingForGap,
                               boolean duplicate, boolean newConnection) {
    }

    /** 单个流的缓冲状态 */
    private static final class Stream {
        private static final byte[] EMPTY = new byte[0];

        /** 已交付位置之后的下一个期望序列号（等于窗口末尾的序列号） */
        long deliveredUpTo;
        /** 已收到数据覆盖到的最大序列号（不含） */
        long highestSeen;
        /** 未交付的分段：seq -> bytes（按序列号升序） */
        final TreeMap<Long, byte[]> pending = new TreeMap<>();
        /** 未交付字节总数 */
        int pendingBytes;
        /**
         * 已交付但尚未被上层 consume 的字节窗口。
         * <p>
         * 这段数据<b>必须保留</b>：一条应用层消息可能跨越多个 TCP 段，
         * 若在交付时即丢弃，跨段的半条消息就再也拼不起来（早期实现的缺陷）。
         * </p>
         * <p>
         * 不变式：窗口内首字节的序列号 = {@code deliveredUpTo - windowLen}。
         * consume 从头部丢弃 n 字节后该式自动成立，无需额外记账。
         * </p>
         */
        byte[] window = EMPTY;
        /** 窗口内有效数据的起始偏移 */
        int windowOff;
        /** 窗口内有效字节数 */
        int windowLen;

        long lastActivityMs;
        int generation;
        boolean synSeen;
        /**
         * 本代次握手时记录的初始序列号（ISN）。
         * 存在此字段是为了区分"重传的 SYN"与"新连接的 SYN"：
         * 二者都带 SYN 标志，只有 ISN 不同才能证明是重新握手。
         */
        long initialSeq;
        /**
         * 本代次**见过的最早序列号**（不随消费而前移）。
         * 用来判断一个段是否落在"我们已知范围之前"——被动监听漏掉握手时，
         * 这类段无法定位，只能丢弃，但丢弃必须是可见的。
         */
        final long originSeq;
        /** 是否已就"未捕获 SYN 而丢弃起点之前的段"告警过（每流一次，避免刷日志） */
        boolean warnedNoSynDiscard;

        Stream(long initialSeq, int generation, long nowMs) {
            this.deliveredUpTo = initialSeq;
            this.highestSeen = initialSeq;
            this.initialSeq = initialSeq;
            this.originSeq = initialSeq;
            this.lastActivityMs = nowMs;
            this.generation = generation;
        }

        /** @return 窗口内字节的独立副本；窗口为空时返回 null */
        byte[] windowBytes() {
            if (windowLen == 0) {
                return null;
            }
            return java.util.Arrays.copyOfRange(window, windowOff, windowOff + windowLen);
        }

        /** 向窗口尾部追加数据 */
        void appendWindow(byte[] data, int off, int len) {
            if (len <= 0) {
                return;
            }
            // 空间不足时先回收已消费的前缀，避免窗口随 consume 无限增长
            if (windowOff + windowLen + len > window.length) {
                if (windowOff > 0) {
                    System.arraycopy(window, windowOff, window, 0, windowLen);
                    windowOff = 0;
                }
                if (windowLen + len > window.length) {
                    byte[] bigger = new byte[windowLen + len];
                    System.arraycopy(window, 0, bigger, 0, windowLen);
                    window = bigger;
                }
            }
            System.arraycopy(data, off, window, windowOff + windowLen, len);
            windowLen += len;
        }

        /** 从窗口头部丢弃 n 字节，返回实际丢弃数 */
        int dropWindow(int n) {
            int drop = Math.max(0, Math.min(n, windowLen));
            windowOff += drop;
            windowLen -= drop;
            if (windowLen == 0) {
                windowOff = 0;
            }
            return drop;
        }
    }

    /** 四元组 -> 当前代次（用于识别复用） */
    private final Map<String, Integer> generationByTuple = new ConcurrentHashMap<>();
    /** 流标识 -> 缓冲状态 */
    private final Map<StreamKey, Stream> streams = new ConcurrentHashMap<>();

    // 统计
    private final AtomicLong segmentsAccepted = new AtomicLong();
    private final AtomicLong segmentsDuplicate = new AtomicLong();
    private final AtomicLong segmentsOverlapTrimmed = new AtomicLong();
    private final AtomicLong bytesDelivered = new AtomicLong();
    private final AtomicLong bytesDiscardedOnClose = new AtomicLong();
    private final AtomicLong connectionsStarted = new AtomicLong();
    private final AtomicLong streamsExpired = new AtomicLong();
    private final AtomicLong buffersForceFlushed = new AtomicLong();
    /** 未捕获 SYN 时被丢弃在"已知起点之前"的段数（内容可能因此缺失，必须可见） */
    private final AtomicLong discardedBeforeOrigin = new AtomicLong();

    /**
     * 提交一个 TCP 段。
     *
     * @param key   流标识
     * @param seq   该段首字节的序列号
     * @param data  payload（null 或空表示纯控制段）
     * @param syn   是否为 SYN
     * @param fin   是否为 FIN
     * @param rst   是否为 RST
     * @param nowMs 当前时间（毫秒），用于超时清理
     * @return 交付结果
     */
    public StreamUpdate offer(StreamKey key, long seq, byte[] data, boolean syn, boolean fin, boolean rst,
                              long nowMs) {
        cleanupExpired(nowMs);

        int payloadLen = data == null ? 0 : data.length;
        Stream stream = streams.get(key);
        boolean newConnection = false;

        if (stream != null) {
            // 新连接判定（按可靠性排序）：
            //   (a) 收到一个"非重传"的 SYN —— 同一四元组上重新握手。这是最权威的信号，
            //       与 ISN 相差多少无关；旧代码只判 seqJumpedAhead，遇到
            //       ISN 只跳进几十 KB 的复用（如 1012 -> 90000）会漏判，
            //       导致两个会话的数据被拼进同一条流。
            //       重传的 SYN（ISN 与本代次记录相同）不算新连接，否则会把已经缓冲的
            //       数据误清空。
            //   (b) 序列号远高于已见序列号且带 payload —— 没有 SYN 可见时的兜底。
            // 只判"回退"会漏掉 (b)，只判 (b) 会漏掉 (a)，两者都要。
            boolean seqJumpedAhead = seq > stream.highestSeen + SEQ_JUMP_THRESHOLD;
            boolean synRetransmit = syn && stream.synSeen && stream.initialSeq == seq;
            boolean newConnectionDetected = (syn && !synRetransmit)
                    || (seqJumpedAhead && payloadLen > 0);

            if (newConnectionDetected) {
                logger.debug("TCP flow {} detected a new connection (syn={} seq={} oldISN={} deliveredUpTo={} highestSeen={}); resetting buffer",
                        key.tuple(), syn, seq, stream.initialSeq, stream.deliveredUpTo, stream.highestSeen);
                // 旧代次窗口里未消费的字节同样属于"被丢弃的数据"，如实计入
                bytesDiscardedOnClose.addAndGet(stream.pendingBytes + stream.windowLen);
                streams.remove(key);
                stream = null;
                newConnection = true;
            } else {
                stream.lastActivityMs = nowMs;
                if (syn) {
                    stream.synSeen = true;
                }
            }
        }

        if (stream == null) {
            // 新建流：交付位置即"首个被看到的序列号"。
            // 没有 SYN 时我们无从知道这个段是否位于缺口之后，
            // 因此 deliveredUpTo 只表示"从这里开始期待连续数据"。
            Stream s = new Stream(seq, nextGeneration(key), nowMs);
            s.synSeen = syn;
            // SYN 消耗一个序列号（RFC 793）：首个数据字节位于 seq+1。
            // 不推进的话，SYN 之后的第一个数据段会被误判为"缺口之后"而永不交付。
            if (syn) {
                s.deliveredUpTo = seq + 1;
                s.highestSeen = seq + 1;
            }
            streams.put(key, s);
            stream = s;
            connectionsStarted.incrementAndGet();
        }

        // 纯控制段：只更新状态
        if (payloadLen == 0) {
            if (fin || rst) {
                return closeAndDrain(key, stream, fin, rst, newConnection);
            }
            return windowUpdate(stream, newConnection, false);
        }

        // 完全重复：整段都落在已交付区间内。
        // 判据是 "seq < deliveredUpTo 且 segEnd <= deliveredUpTo"；
        // 若只写 "segEnd <= deliveredUpTo"，会把"起点早于交付位置、但尾巴带来新数据"的段
        // 误判为纯重传并整段丢弃，造成静默丢字节。
        long segEnd = seq + payloadLen;
        if (seq < stream.deliveredUpTo && segEnd <= stream.deliveredUpTo) {
            segmentsDuplicate.incrementAndGet();
            warnIfDiscardedBeforeOrigin(key, stream, seq, segEnd);
            if (fin || rst) {
                return closeAndDrain(key, stream, fin, rst, newConnection);
            }
            return windowUpdate(stream, newConnection, true);
        }

        // 部分重叠：裁掉已交付部分。
        // trim 必须夹到 [0, payloadLen]：当流刚被判定为新连接时，
        // deliveredUpTo 可能仍大于本段起点，直接按差值裁剪会产生负偏移而抛异常。
        byte[] toStore = data;
        long storeSeq = seq;
        if (seq < stream.deliveredUpTo) {
            long trimLong = stream.deliveredUpTo - seq;
            int trim = (int) Math.max(0, Math.min(trimLong, payloadLen));
            boolean trimOk = trim < payloadLen;
            if (!trimOk) {
                segmentsDuplicate.incrementAndGet();
                warnIfDiscardedBeforeOrigin(key, stream, seq, segEnd);
                if (fin || rst) {
                    return closeAndDrain(key, stream, fin, rst, newConnection);
                }
                return windowUpdate(stream, newConnection, true);
            }
            toStore = java.util.Arrays.copyOfRange(data, trim, payloadLen);
            storeSeq = seq + trim;
            segmentsOverlapTrimmed.incrementAndGet();
        }

        segmentsAccepted.incrementAndGet();
        insertPending(stream, storeSeq, toStore);
        drainContiguous(stream);

        if (fin || rst) {
            // 连接结束：窗口与残留一并交给上层（尽力而为），随后移除该流
            return closeAndDrain(key, stream, fin, rst, newConnection);
        }

        // 缓冲区超限：放弃最旧的缺口并强制交付，避免内存无界增长
        if (stream.pendingBytes > MAX_STREAM_BUFFER_BYTES && stream.pending.size() > 1) {
            buffersForceFlushed.incrementAndGet();
            logger.warn("TCP flow {} buffer exceeded limit ({} bytes); dropping oldest gap and forcing delivery",
                    key.tuple(), stream.pendingBytes);
            stream.pending.pollFirstEntry();
            stream.deliveredUpTo = stream.pending.firstKey();
            drainContiguous(stream);
        }

        return windowUpdate(stream, newConnection, false);
    }

    /**
     * 对"未捕获到 SYN，却丢弃了流的起点之前的段"给出一次性告警。
     *
     * <h3>为什么需要它</h3>
     * <p>
     * 被动监听（本项目的主要用途）常常从连接中途开始抓，抓不到三次握手。
     * 此时流的起点只能取"首个见到的数据段"。如果随后到达的段**完全落在该起点之前**，
     * 我们无从判断它是"很晚才到的重传"还是"乱序先到的真实数据"，只能按重传丢弃。
     * </p>
     * <p>
     * 这种情况下丢弃是不可避免的，但**不能是静默的**：否则内容缺了一块而使用者毫不知情。
     * 每个流只告警一次。
     * </p>
     */
    private void warnIfDiscardedBeforeOrigin(StreamKey key, Stream stream, long segStart, long segEnd) {
        if (stream.synSeen || stream.warnedNoSynDiscard || segEnd > stream.originSeq) {
            return;
        }
        stream.warnedNoSynDiscard = true;
        discardedBeforeOrigin.incrementAndGet();
        logger.warn("TCP flow {}: no SYN captured; segment [{}, {}) precedes known start {}; dropped as duplicate."
                        + "If this segment was actually out-of-order data, content will be missing (inherent limit of passive capture starting mid-connection).",
                key.tuple(), segStart, segEnd, stream.originSeq);
    }

    /**
     * 依据当前"窗口 + 缺口"状态构造返回结果。
     *
     * @param stream        流状态
     * @param newConnection 本次是否开启了新连接
     * @param duplicate     本次提交是否为重复段
     * @return 交付结果。窗口非空时一律返回 {@link Delivery#DATA}：
     *         上一次返回的残留可能尚未被 {@link #consume} 消费完，上层需要再次看到它
     */
    private StreamUpdate windowUpdate(Stream stream, boolean newConnection, boolean duplicate) {
        byte[] data = stream.windowBytes();
        if (data != null) {
            return new StreamUpdate(Delivery.DATA, data, false, duplicate, newConnection);
        }
        if (stream.pendingBytes > 0) {
            return new StreamUpdate(Delivery.BUFFERED, null, true, duplicate, newConnection);
        }
        return new StreamUpdate(Delivery.NOTHING, null, false, duplicate, newConnection);
    }

    /**
     * 表达"上层已消费若干字节"，从窗口头部丢弃对应字节。
     * <p>
     * 这是跨段消息拼接的关键：上层用 {@link #offer} 拿到连续字节后，
     * 只应 consume 它真正解析成完整消息的部分；剩余字节留在窗口里，
     * 下次 {@link #offer} 会连同新到的数据一起再交给它。
     * 若在这里丢掉全部字节，跨段的半条消息就永远拼不起来。
     * </p>
     *
     * @param key           流标识
     * @param consumedBytes 已消费字节数（超过窗口长度时按窗口长度截断）
     * @return 实际丢弃的字节数
     */
    public int consume(StreamKey key, int consumedBytes) {
        Stream stream = streams.get(key);
        if (stream == null || consumedBytes <= 0) {
            return 0;
        }
        return stream.dropWindow(consumedBytes);
    }

    /**
     * 强制结束某条流（连接超时等），返回窗口中剩余的字节。
     *
     * @param key 流标识
     * @return 剩余字节；无则返回 null
     */
    public byte[] closeStream(StreamKey key) {
        Stream stream = streams.remove(key);
        if (stream == null) {
            return null;
        }
        return drainAll(stream);
    }

    /** @return 当前活跃流数量 */
    public int activeStreams() {
        return streams.size();
    }

    /**
     * 结束所有流并返回各自的剩余字节。
     * <p>
     * 停机 / 收尾时调用：窗口里可能还留着"尚未凑成完整消息"的字节，
     * 直接丢掉就是静默丢数据，因此交由调用方按"未解析候选"记录一次。
     * </p>
     *
     * @return 四元组 → 剩余字节（只含非空项）
     */
    public Map<StreamKey, byte[]> drainAllStreams() {
        Map<StreamKey, byte[]> drained = new LinkedHashMap<>();
        for (StreamKey key : new ArrayList<>(streams.keySet())) {
            byte[] rest = closeStream(key);
            if (rest != null && rest.length > 0) {
                drained.put(key, rest);
            }
        }
        return drained;
    }

    /** @return 统计快照 */
    public Stats stats() {
        return new Stats(segmentsAccepted.get(), segmentsDuplicate.get(), segmentsOverlapTrimmed.get(),
                bytesDelivered.get(), bytesDiscardedOnClose.get(), connectionsStarted.get(),
                streamsExpired.get(), buffersForceFlushed.get(), discardedBeforeOrigin.get());
    }

    /**
     * 统计快照。
     *
     * @param segmentsAccepted       接受的段数
     * @param segmentsDuplicate      判为完全重传而丢弃的段数
     * @param segmentsOverlapTrimmed 裁剪掉重叠部分的段数
     * @param bytesDelivered         向上层交付的字节数
     * @param bytesDiscardedOnClose  连接结束/重置/超时时仍在缓冲区中的字节数（含缺口残留）
     * @param connectionsStarted     识别到的连接数（含四元组复用）
     * @param streamsExpired         因空闲超时被清理的流数
     * @param buffersForceFlushed    因缓冲区超限而强制交付的次数
     * @param discardedBeforeOrigin  未捕获 SYN 时被丢弃在已知起点之前的段数
     */
    public record Stats(long segmentsAccepted, long segmentsDuplicate, long segmentsOverlapTrimmed,
                        long bytesDelivered, long bytesDiscardedOnClose, long connectionsStarted,
                        long streamsExpired, long buffersForceFlushed, long discardedBeforeOrigin) {
    }

    // ==================== 内部实现 ====================

    /** 取得该四元组的下一个连接代次 */
    private int nextGeneration(StreamKey key) {
        String tuple = key.srcIp() + ":" + key.srcPort() + "-" + key.dstIp() + ":" + key.dstPort();
        return generationByTuple.merge(tuple, 1, Integer::sum);
    }

    /** 把分段插入 pending，保持"按序列号升序且互不重叠" */
    private void insertPending(Stream stream, long seq, byte[] data) {
        if (data.length == 0) {
            return;
        }
        long end = seq + data.length;

        // 与前一分段重叠：新段起点落在旧段半途时，裁掉与旧段重复的开头部分
        Map.Entry<Long, byte[]> before = stream.pending.floorEntry(seq);
        if (before != null) {
            long bEnd = before.getKey() + before.getValue().length;
            if (bEnd >= end) {
                return;
            }
            if (bEnd > seq) {
                int trim = (int) (bEnd - seq);
                data = java.util.Arrays.copyOfRange(data, trim, data.length);
                seq = bEnd;
            }
        }

        // 处理后继分段：与新段重叠的部分被新段取代，但**越出新段末尾的部分必须保留**。
        // 早期实现一见到 eStart < end 就整段删除，若后继分段比新段长，
        // 它末尾那些新段没覆盖到的字节就被静默丢掉了（表现为"缺口补齐后仍缺尾部"）。
        // 无法在遍历中改 TreeMap（fail-fast），先收集再回插。
        List<Map.Entry<Long, byte[]>> tails = new ArrayList<>();
        Iterator<Map.Entry<Long, byte[]>> it = stream.pending.tailMap(seq, true).entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<Long, byte[]> e = it.next();
            long eStart = e.getKey();
            if (eStart >= end) {
                break;
            }
            byte[] eData = e.getValue();
            long eEnd = eStart + eData.length;
            stream.pendingBytes -= eData.length;
            it.remove();
            if (eEnd > end) {
                int keepFrom = (int) (end - eStart);
                tails.add(Map.entry(end, java.util.Arrays.copyOfRange(eData, keepFrom, eData.length)));
                stream.highestSeen = Math.max(stream.highestSeen, eEnd);
            }
        }
        for (Map.Entry<Long, byte[]> t : tails) {
            stream.pending.put(t.getKey(), t.getValue());
            stream.pendingBytes += t.getValue().length;
        }

        stream.pending.put(seq, data);
        stream.pendingBytes += data.length;
        stream.highestSeen = Math.max(stream.highestSeen, end);
    }

    /**
     * 把 pending 中从 deliveredUpTo 起的连续分段追加进窗口。
     * <p>
     * 注意：字节进入窗口<b>不等于</b>已消费。窗口内容会一直保留到
     * {@link #consume} 显式丢弃，这样跨段的半条消息才能等到下一次交付补齐。
     * </p>
     */
    private void drainContiguous(Stream stream) {
        while (true) {
            Map.Entry<Long, byte[]> first = stream.pending.firstEntry();
            if (first == null || first.getKey() > stream.deliveredUpTo) {
                // 存在缺口：等待后续段，不越过缺口交付
                break;
            }
            long start = first.getKey();
            byte[] chunk = first.getValue();
            stream.pending.pollFirstEntry();
            stream.pendingBytes -= chunk.length;

            // 起点早于期望位置：裁掉已被交付过的前缀
            int trim = (int) Math.max(0, stream.deliveredUpTo - start);
            int useLen = chunk.length - trim;
            if (useLen > 0) {
                stream.appendWindow(chunk, trim, useLen);
                bytesDelivered.addAndGet(useLen);
            }
            stream.deliveredUpTo = start + chunk.length;
        }
    }

    /** 把 pending 中所有残留（含跨越缺口的部分）尽力追加进窗口，返回窗口内容 */
    private byte[] drainAll(Stream stream) {
        drainContiguous(stream);
        if (!stream.pending.isEmpty()) {
            // 仍有缺口：按序列号顺序把剩余分段尽力拼入窗口
            for (byte[] b : stream.pending.values()) {
                stream.appendWindow(b, 0, b.length);
                bytesDelivered.addAndGet(b.length);
            }
            stream.pending.clear();
            stream.pendingBytes = 0;
        }
        return stream.windowBytes();
    }

    /** 结束流并交付残留（不推进字节统计，由调用方处理） */
    private byte[] closeAndDrainData(StreamKey key, Stream stream) {
        byte[] remaining = drainAll(stream);
        streams.remove(key);
        return remaining;
    }

    /** 结束流并交付残留（字节统计已由 drainAll 计入） */
    private StreamUpdate closeAndDrain(StreamKey key, Stream stream, boolean fin, boolean rst,
                                       boolean newConnection) {
        byte[] remaining = closeAndDrainData(key, stream);
        if (remaining != null && remaining.length > 0) {
            logger.debug("TCP flow {} ended (fin={} rst={}); delivered {} residual bytes",
                    key.tuple(), fin, rst, remaining.length);
            return new StreamUpdate(Delivery.DATA, remaining, false, false, newConnection);
        }
        return new StreamUpdate(Delivery.NOTHING, null, false, false, newConnection);
    }

    /** 清理空闲超时的流（并把未交付字节如实计入统计） */
    private void cleanupExpired(long nowMs) {
        if (streams.isEmpty()) {
            return;
        }
        streams.entrySet().removeIf(e -> {
            boolean expired = nowMs - e.getValue().lastActivityMs > STREAM_TIMEOUT_MS;
            if (expired) {
                Stream s = e.getValue();
                streamsExpired.incrementAndGet();
                if (s.pendingBytes > 0) {
                    bytesDiscardedOnClose.addAndGet(s.pendingBytes);
                    logger.warn("TCP flow {} idle timeout ({} ms); dropped {} buffered bytes (unfilled gap)",
                            e.getKey().tuple(), STREAM_TIMEOUT_MS, s.pendingBytes);
                }
            }
            return expired;
        });
        if (streams.size() > MAX_STREAMS) {
            streams.entrySet().stream()
                    .sorted(java.util.Comparator.comparingLong(a -> a.getValue().lastActivityMs))
                    .limit(streams.size() - MAX_STREAMS)
                    .map(Map.Entry::getKey)
                    .toList()
                    .forEach(k -> {
                        Stream s = streams.remove(k);
                        if (s != null) {
                            bytesDiscardedOnClose.addAndGet(s.pendingBytes);
                        }
                    });
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

}
