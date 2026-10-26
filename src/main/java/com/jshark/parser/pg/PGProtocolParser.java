package com.jshark.parser.pg;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * PostgreSQL Wire Protocol 协议解析器
 * 用于解析PG协议的前端（客户端）和后端（服务器）消息
 * PG协议消息格式：
 * - 启动消息：Int32(长度) + Int32(协议版本) + [key-value对，以null结尾的字符串]
 * - 取消请求：Int32(16) + Int32(80877102) + Int32(processId) + Int32(secretKey)
 * - SSL请求：Int32(8) + Int32(80877103)
 * - 普通消息：Byte1(标签) + Int32(长度，包含自身4字节) + [payload]
 */
public class PGProtocolParser {
    private static final Logger logger = LoggerFactory.getLogger(PGProtocolParser.class);

    /**
     * 将字节数组转换为ASCII字符串（用于调试）
     */
    public static String bytesToAscii(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length);
        for (byte b : data) {
            if (b >= 32 && b < 127) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    /**
     * 将字节数组转换为十六进制字符串
     */
    private String bytesToHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }

    /**
     * 检查字节数组是否主要为可打印ASCII字符
     */
    private boolean isPrintableAscii(byte[] data) {
        if (data == null || data.length == 0) {
            return true;
        }
        int printableCount = 0;
        for (byte b : data) {
            int unsigned = b & 0xFF;
            if (unsigned >= 32 && unsigned < 127) {
                printableCount++;
            } else if (unsigned == 9 || unsigned == 10 || unsigned == 13) {
                // TAB, LF, CR
                printableCount++;
            }
        }
        // 如果超过80%是可打印字符，认为是文本
        return (double) printableCount / data.length > 0.8;
    }

    /**
     * 检测SQL语句类型
     */
    private String detectSQLType(String sql) {
        if (sql == null || sql.trim().isEmpty()) {
            return null;
        }
        String trimmed = sql.trim().toUpperCase();
        if (trimmed.startsWith("SELECT")) return "SELECT";
        if (trimmed.startsWith("INSERT")) return "INSERT";
        if (trimmed.startsWith("UPDATE")) return "UPDATE";
        if (trimmed.startsWith("DELETE")) return "DELETE";
        if (trimmed.startsWith("CREATE")) return "CREATE";
        if (trimmed.startsWith("DROP")) return "DROP";
        if (trimmed.startsWith("ALTER")) return "ALTER";
        if (trimmed.startsWith("TRUNCATE")) return "TRUNCATE";
        if (trimmed.startsWith("BEGIN")) return "BEGIN";
        if (trimmed.startsWith("COMMIT")) return "COMMIT";
        if (trimmed.startsWith("ROLLBACK")) return "ROLLBACK";
        if (trimmed.startsWith("SET")) return "SET";
        if (trimmed.startsWith("SHOW")) return "SHOW";
        if (trimmed.startsWith("GRANT")) return "GRANT";
        if (trimmed.startsWith("REVOKE")) return "REVOKE";
        if (trimmed.startsWith("COPY")) return "COPY";
        if (trimmed.startsWith("VACUUM")) return "VACUUM";
        if (trimmed.startsWith("EXPLAIN")) return "EXPLAIN";
        if (trimmed.startsWith("WITH")) return "WITH (CTE)";
        return null;
    }

    /**
     * 读取null结尾的字符串
     */
    private String readCString(ByteBuffer buffer) {
        StringBuilder sb = new StringBuilder();
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            if (b == 0) {
                break;
            }
            sb.append((char) (b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * 读取指定长度的字符串（UTF-8编码）
     */
    private String readString(ByteBuffer buffer, int length) {
        if (length <= 0) {
            return "";
        }
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * 检查数据是否为有效的PG协议数据
     * PG协议检测策略：
     * 1. 启动消息：前4字节为长度，紧接着4字节为协议版本(196608=3.0)
     * 2. 取消请求：前4字节=16，紧接着4字节=80877102
     * 3. SSL请求：前4字节=8，紧接着4字节=80877103
     * 4. 普通消息：第1字节为ASCII可打印字符，紧接着4字节为消息长度
     */
    public boolean isValidPGData(byte[] data) {
        if (data == null || data.length < 1) {
            return false;
        }

        try {
            // 检查是否为PG SSL响应（单字节：'S'=接受SSL，'N'=拒绝SSL）
            if (data.length == 1) {
                char sslResponse = (char) (data[0] & 0xFF);
                return sslResponse == 'S' || sslResponse == 'N';
            }

            if (data.length < 5) {
                return false;
            }

            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN);

            // 检查是否为启动消息（无标签，以Int32长度+Int32协议版本开头）
            if (data.length >= 8) {
                int firstInt = buffer.getInt(0); // 长度
                int secondInt = buffer.getInt(4); // 协议版本或特殊代码

                // 启动消息：协议版本 3.0 = 196608
                if (firstInt == data.length && secondInt == PGEnums.PROTOCOL_VERSION_3_0) {
                    return true;
                }

                // 取消请求：长度=16，特殊代码=80877102
                if (firstInt == 16 && secondInt == PGEnums.CANCEL_REQUEST_CODE) {
                    return true;
                }

                // SSL请求：长度=8，特殊代码=80877103
                if (firstInt == 8 && secondInt == PGEnums.SSL_REQUEST_CODE) {
                    return true;
                }
            }

            // 检查是否为普通消息（有标签）
            // 第1字节应为ASCII可打印字符（标签）
            byte tagByte = data[0];
            char tag = (char) (tagByte & 0xFF);

            // 检查标签是否为已知的前端或后端消息类型
            boolean isKnownFrontend = PGEnums.FrontendMessageType.fromTag(tag) != PGEnums.FrontendMessageType.UNKNOWN;
            boolean isKnownBackend = PGEnums.BackendMessageType.fromTag(tag) != PGEnums.BackendMessageType.UNKNOWN;

            if (!isKnownFrontend && !isKnownBackend) {
                return false;
            }

            // 检查长度字段（字节1-4，大端Int32，包含自身）
            int messageLength = buffer.getInt(1);
            // 消息长度至少为4（长度字段自身）
            return messageLength >= 4;
            // 如果消息长度超过数据总长度，说明是TCP分片（部分消息），仍然认为是有效的PG数据
            // 如果消息长度 <= 数据总长度，说明是完整消息或包含多条消息，也是有效的
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 检查数据开头是否包含至少一个完整的PG消息
     * 与 isValidPGData() 的区别：
     * - isValidPGData() 只检查数据是否以PG消息开头（允许不完整）
     * - isCompletePGData() 额外检查第一个PG消息是否完整（长度字段 <= 数据长度）
     * 用于TCP流重组场景：判断当前数据是否包含完整的PG消息，
     * 如果完整则清空缓冲区，如果不完整则保留缓冲区等待更多数据
     */
    public boolean isCompletePGData(byte[] data) {
        if (data == null || data.length < 1) {
            return false;
        }

        try {
            // 检查是否为PG SSL响应（单字节：'S'=接受SSL，'N'=拒绝SSL）
            if (data.length == 1) {
                char sslResponse = (char) (data[0] & 0xFF);
                return sslResponse == 'S' || sslResponse == 'N';
            }

            if (data.length < 5) {
                return false;
            }

            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN);

            // 检查是否为启动消息（无标签，以Int32长度+Int32协议版本开头）
            if (data.length >= 8) {
                int firstInt = buffer.getInt(0); // 长度
                int secondInt = buffer.getInt(4); // 协议版本或特殊代码

                // 启动消息：协议版本 3.0 = 196608
                if (secondInt == PGEnums.PROTOCOL_VERSION_3_0) {
                    return firstInt == data.length; // 必须完整
                }

                // 取消请求：长度=16，特殊代码=80877102
                if (secondInt == PGEnums.CANCEL_REQUEST_CODE) {
                    return firstInt == 16 && data.length >= 16;
                }

                // SSL请求：长度=8，特殊代码=80877103
                if (secondInt == PGEnums.SSL_REQUEST_CODE) {
                    return firstInt == 8;
                }
            }

            // 检查是否为普通消息（有标签）
            byte tagByte = data[0];
            char tag = (char) (tagByte & 0xFF);

            // 检查标签是否为已知的前端或后端消息类型
            boolean isKnownFrontend = PGEnums.FrontendMessageType.fromTag(tag) != PGEnums.FrontendMessageType.UNKNOWN;
            boolean isKnownBackend = PGEnums.BackendMessageType.fromTag(tag) != PGEnums.BackendMessageType.UNKNOWN;

            if (!isKnownFrontend && !isKnownBackend) {
                return false;
            }

            // 检查长度字段（字节1-4，大端Int32，包含自身）
            int messageLength = buffer.getInt(1);
            if (messageLength < 4 || messageLength > PGEnums.MAX_PLAUSIBLE_MESSAGE_LENGTH) {
                return false;
            }
            // 检查第一个消息是否完整（长度字段 + 1字节标签 <= 数据长度）
            return (1 + messageLength) <= data.length;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 扫描数据中是否包含至少一个完整的PG消息
     * 用于TCP重组后的数据，其头部可能不是PG标签开头（PG消息的中间部分）
     * 此方法为public，供ProtocolParser在检测重组数据时调用
     */
       /**
    * 解析PG协议数据（入口方法）
    * <p>
    * 根据数据内容自动判断消息类型并分发到对应的解析方法：
    * <ul>
    *   <li>1字节 → {@link #parseSSLResponse}（SSL响应 'S'/'N'）</li>
    *   <li>8字节以上且第二Int32为协议版本 → {@link #parseStartupMessage}（启动消息）</li>
    *   <li>8字节以上且第二Int32为取消码 → {@link #parseCancelRequest}（取消请求）</li>
    *   <li>8字节以上且第二Int32为SSL码 → {@link #parseSSLRequest}（SSL请求）</li>
    *   <li>以PG标签开头 → {@link #parseRegularMessage}（普通带标签消息）</li>
    *   <li>不以PG标签开头 → {@link #parseReassembledData}（TCP重组数据，扫描PG标签）</li>
    * </ul>
    * </p>
    * <p>
    * 所有解析完成后会设置 consumed_bytes 字段，表示实际消耗的字节数。
    * 上层（PacketCapture）根据 consumed_bytes 判断数据是否完整。
    * </p>
    *
    * @param data PG协议原始字节数据
    * @return 解析结果Map，包含协议类型、消息类型、详细字段等
    */
   public Map<String, Object> parse(byte[] data) {
       Map<String, Object> result = new HashMap<>();

       if (data == null || data.length == 0) {
           result.put("error", "No data available");
           return result;
       }

       try {
           // 检查是否为PG SSL响应（单字节：'S'=接受SSL，'N'=拒绝SSL）
           if (data.length == 1) {
               parseSSLResponse(data, result);
               result.put("consumed_bytes", 1);
               return result;
           }

           ByteBuffer buffer = ByteBuffer.wrap(data);
           buffer.order(ByteOrder.BIG_ENDIAN);

           // 判断消息类型
           if (data.length >= 8) {
               int firstInt = buffer.getInt(0);
               int secondInt = buffer.getInt(4);

               // 启动消息
               if (secondInt == PGEnums.PROTOCOL_VERSION_3_0) {
                   parseStartupMessage(data, result);
                   result.put("consumed_bytes", firstInt);
                   return result;
               }

               // 取消请求
               if (secondInt == PGEnums.CANCEL_REQUEST_CODE) {
                   parseCancelRequest(data, result);
                   result.put("consumed_bytes", firstInt);
                   return result;
               }

               // SSL请求
               if (secondInt == PGEnums.SSL_REQUEST_CODE) {
                   parseSSLRequest(data, result);
                   result.put("consumed_bytes", firstInt);
                   return result;
               }
           }

           // 检查数据是否以PG标签开头
           char firstByte = (char) (data[0] & 0xFF);
           boolean startsWithPGTag = PGEnums.FrontendMessageType.fromTag(firstByte) != PGEnums.FrontendMessageType.UNKNOWN
                   || PGEnums.BackendMessageType.fromTag(firstByte) != PGEnums.BackendMessageType.UNKNOWN;

           if (startsWithPGTag) {
               // 普通消息（有标签），直接从开头解析
               parseRegularMessage(data, result);
           } else {
               // 数据不以PG标签开头（可能是TCP重组后的数据，头部是PG消息的中间部分）
               // 扫描数据，找到第一个PG标签的位置，从那里开始解析
               parseReassembledData(data, result);
           }

       } catch (Exception e) {
           logger.error("Error parsing PG protocol data: {}", e.getMessage());
           result.put("parse.error", e.getMessage());
       }

       return result;
   }

    /**
     * 解析TCP重组后的PG数据
     * <p>
     * 当数据不以PG标签开头时调用（TCP重组场景，数据头部是PG消息的中间部分）。
     * 扫描数据找到第一个PG标签的位置，从那里开始解析。
     * </p>
     *
     * <h3>consumed_bytes 调整：</h3>
     * <p>
     * consumed_bytes = firstTagOffset + parseRegularMessage消耗的字节数
     * 因为跳过了 firstTagOffset 字节的非PG数据，所以需要在 parseRegularMessage
     * 返回的 consumed_bytes 基础上加上跳过的字节数。
     * </p>
     */
    private void parseReassembledData(byte[] data, Map<String, Object> result) {
        // 扫描数据，找到第一个PG标签的位置
        int firstTagOffset = findFirstPGTagOffset(data);
        if (firstTagOffset < 0) {
            result.put("parse.error", "No PG message found in reassembled data");
            return;
        }

        // 从第一个PG标签位置开始解析（拷贝从标签位置开始的数据）
        byte[] pgData = new byte[data.length - firstTagOffset];
        System.arraycopy(data, firstTagOffset, pgData, 0, pgData.length);

        result.put("reassembled.skip_bytes", firstTagOffset);
        parseRegularMessage(pgData, result);

        // 调整consumed_bytes为原始数据中的实际消耗字节数
        // 因为跳过了 firstTagOffset 字节，所以需要加上
        Object consumedObj = result.get("consumed_bytes");
        if (consumedObj instanceof Integer) {
            int consumed = (Integer) consumedObj;
            result.put("consumed_bytes", firstTagOffset + consumed);
        }
    }

    /**
     * 查找数据中第一个PG标签的位置
     * <p>
     * 扫描数据（最多前200字节），查找已知的PG前端/后端消息类型标签。
     * 找到标签后还需验证长度字段有效（messageLength >= 4 且不超出数据范围），
     * 避免二进制数据中的假阳性匹配。
     * </p>
     *
     * @param data 要扫描的数据
     * @return 第一个PG标签的偏移量，未找到返回 -1
     */
    private int findFirstPGTagOffset(byte[] data) {
        if (data == null || data.length < 5) {
            return -1;
        }

        for (int i = 0; i <= data.length - 5; i++) {
            char c = (char) (data[i] & 0xFF);
            boolean isKnownFrontend = PGEnums.FrontendMessageType.fromTag(c) != PGEnums.FrontendMessageType.UNKNOWN;
            boolean isKnownBackend = PGEnums.BackendMessageType.fromTag(c) != PGEnums.BackendMessageType.UNKNOWN;

            if (isKnownFrontend || isKnownBackend) {
                // 找到PG标签，检查长度字段是否有效
                try {
                    ByteBuffer bb = ByteBuffer.wrap(data, i + 1, data.length - i - 1);
                    bb.order(ByteOrder.BIG_ENDIAN);
                    int messageLength = bb.getInt();
                    if (messageLength >= 4 && (i + 1 + messageLength) <= data.length) {
                        return i;
                    }
                } catch (Exception e) {
                    // 继续扫描
                }
            }
        }

        return -1;
    }

    /**
     * 解析PG启动消息
     * 格式：Int32(长度) + Int32(协议版本) + [key0\0value0\0key1\0value1\0...\0]
     */
    private void parseStartupMessage(byte[] data, Map<String, Object> result) {
        result.put("message.type", "Startup");
        result.put("message.type.cn", "Startup Message");

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int length = buffer.getInt();
        int protocolVersion = buffer.getInt();

        result.put("startup.length", length);
        result.put("startup.protocol_version", protocolVersion);

        // 解析协议版本号
        int majorVersion = (protocolVersion >> 16) & 0xFFFF;
        int minorVersion = protocolVersion & 0xFFFF;
        result.put("startup.protocol_version.major", majorVersion);
        result.put("startup.protocol_version.minor", minorVersion);
        result.put("startup.protocol_version.display", majorVersion + "." + minorVersion);

        // 解析启动参数（key-value对，以null结尾）
        Map<String, String> startupOptions = new HashMap<>();
        while (buffer.hasRemaining()) {
            String key = readCString(buffer);
            if (key.isEmpty()) {
                break;
            }
            if (buffer.hasRemaining()) {
                String value = readCString(buffer);
                startupOptions.put(key, value);
            }
        }

        if (!startupOptions.isEmpty()) {
            result.put("startup.options", startupOptions);
            result.put("startup.options.count", startupOptions.size());

            // 提取常用参数
            if (startupOptions.containsKey("user")) {
                result.put("startup.user", startupOptions.get("user"));
            }
            if (startupOptions.containsKey("database")) {
                result.put("startup.database", startupOptions.get("database"));
            }
            if (startupOptions.containsKey("application_name")) {
                result.put("startup.application_name", startupOptions.get("application_name"));
            }
        }
    }

    /**
     * 解析取消请求
     * 格式：Int32(16) + Int32(80877102) + Int32(processId) + Int32(secretKey)
     */
    private void parseCancelRequest(byte[] data, Map<String, Object> result) {
        result.put("message.type", "CancelRequest");
        result.put("message.type.cn", "Cancel Request");

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int length = buffer.getInt();
        int cancelCode = buffer.getInt();
        int processId = buffer.getInt();
        int secretKey = buffer.getInt();

        result.put("cancel.length", length);
        result.put("cancel.code", cancelCode);
        result.put("cancel.process_id", processId);
        result.put("cancel.secret_key", secretKey);
    }

    /**
     * 解析SSL请求
     * 格式：Int32(8) + Int32(80877103)
     */
    private void parseSSLRequest(byte[] data, Map<String, Object> result) {
        result.put("message.type", "SSLRequest");
        result.put("message.type.cn", "SSL Request");

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int length = buffer.getInt();
        int sslCode = buffer.getInt();

        result.put("ssl.length", length);
        result.put("ssl.code", sslCode);
    }

    /**
     * 解析PG SSL响应（单字节）
     * 格式：Byte1('S'=接受SSL, 'N'=拒绝SSL)
     */
    private void parseSSLResponse(byte[] data, Map<String, Object> result) {
        char response = (char) (data[0] & 0xFF);
        result.put("message.type", "SSLResponse");
        result.put("message.type.cn", "SSL Response");

        if (response == 'S') {
            result.put("ssl.response", "S");
            result.put("ssl.response.name", "Accept");
            result.put("ssl.response.cn", "Accept SSL");
        } else if (response == 'N') {
            result.put("ssl.response", "N");
            result.put("ssl.response.name", "Reject");
            result.put("ssl.response.cn", "Reject SSL");
        } else {
            result.put("ssl.response", String.valueOf(response));
            result.put("ssl.response.name", "Unknown");
            result.put("ssl.response.cn", "Unknown Response");
        }
    }

    /**
     * 解析普通PG消息（带标签的消息）
     * <p>
     * PG消息格式：Byte1(标签) + Int32(长度，包含自身4字节) + [payload]
     * 一个TCP包中可能包含多个PG消息（批处理）。
     * </p>
     *
     * <h3>consumed_bytes 计算：</h3>
     * <p>
     * 解析完成后记录 consumed_bytes，表示实际消耗的字节数：
     * <ul>
     *   <li>consumed_bytes == data.length → 所有数据都被完整解析</li>
     *   <li>consumed_bytes < data.length → 有剩余字节未被解析（不完整消息）</li>
     *   <li>consumed_bytes == 0 → 没有解析出任何完整消息</li>
     * </ul>
     * </p>
     *
     * <h3>不完整消息处理：</h3>
     * <p>
     * 当消息长度字段 > 剩余数据长度时，说明消息不完整（TCP分片）。
     * 此时回退 buffer.position() 到消息头开始位置（headerStartPosition），
     * 不计算这5字节头，因为消息本身不完整。
     * 这样 consumed_bytes 只包含已完整解析的消息字节数。
     * </p>
     */
    private void parseRegularMessage(byte[] data, Map<String, Object> result) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);

        List<Map<String, Object>> messages = new ArrayList<>();
        int messageCount = 0;
        int startPosition = buffer.position();

        while (buffer.hasRemaining()) {
            if (buffer.remaining() < 5) {
                break; // 剩余数据不足以构成一个完整消息头
            }

            // 记录消息头开始位置，以便在消息不完整时回退
            int headerStartPosition = buffer.position();
            byte tagByte = buffer.get();
            char tag = (char) (tagByte & 0xFF);
            int length = buffer.getInt(); // 包含自身4字节

            if (length < 4 || length > buffer.remaining() + 4) {
                // 消息不完整（TCP分片），回退到消息头开始位置并退出
                // 不计算这5字节头，因为消息本身不完整
                buffer.position(headerStartPosition);
                break;
            }

            int payloadLength = length - 4;
            messageCount++;

            Map<String, Object> msg = new HashMap<>();
            msg.put("tag", String.valueOf(tag));
            msg.put("tag.hex", String.format("0x%02X", tagByte & 0xFF));
            msg.put("length", length);
            msg.put("payload_length", payloadLength);

            // 判断是前端还是后端消息
            PGEnums.FrontendMessageType frontendType = PGEnums.FrontendMessageType.fromTag(tag);
            PGEnums.BackendMessageType backendType = PGEnums.BackendMessageType.fromTag(tag);

            if (frontendType != PGEnums.FrontendMessageType.UNKNOWN) {
                msg.put("direction", "frontend");
                msg.put("direction.cn", "Client -> Server");
                msg.put("message.name", frontendType.name());
                msg.put("message.description", frontendType.getDescriptionCn());

                // 解析前端消息payload
                parseFrontendPayload(buffer, tag, payloadLength, msg);
            } else if (backendType != PGEnums.BackendMessageType.UNKNOWN) {
                msg.put("direction", "backend");
                msg.put("direction.cn", "Server -> Client");
                msg.put("message.name", backendType.name());
                msg.put("message.description", backendType.getDescriptionCn());

                // 解析后端消息payload
                parseBackendPayload(buffer, tag, payloadLength, msg);
            } else {
                msg.put("direction", "unknown");
                msg.put("direction.cn", "Unknown Direction");
                msg.put("message.name", "UNKNOWN");
                msg.put("message.description", "Unknown Message Type");

                // 跳过未知消息的payload
                if (payloadLength > 0) {
                    byte[] payload = new byte[payloadLength];
                    buffer.get(payload);
                    msg.put("payload.hex", bytesToHex(payload));
                    msg.put("payload.ascii", bytesToAscii(payload));
                }
            }

            messages.add(msg);
        }

        int consumedBytes = buffer.position() - startPosition;
        result.put("messages.count", messageCount);
        result.put("messages", messages);
        result.put("consumed_bytes", consumedBytes);

        if (messageCount == 1) {
            // 单条消息，将详细信息提升到顶层
            Map<String, Object> singleMsg = messages.get(0);
            result.putAll(singleMsg);
        }
    }

    /**
     * 解析前端消息payload（客户端 → 服务器）
     * <p>
     * 根据消息标签分发到对应的解析方法：
     * <ul>
     *   <li>'Q' → {@link #parseQueryPayload}：简单查询SQL</li>
     *   <li>'P' → {@link #parseParsePayload}：解析预备语句SQL</li>
     *   <li>'B' → {@link #parseBindPayload}：绑定参数</li>
     *   <li>'D' → {@link #parseDescribePayload}：描述语句/游标</li>
     *   <li>'E' → {@link #parseExecutePayload}：执行语句</li>
     *   <li>'C' → {@link #parseClosePayload}：关闭语句/游标</li>
     *   <li>'X' → Terminate：终止连接（无payload）</li>
     *   <li>'H' → Flush：刷新（无payload）</li>
     *   <li>'p' → {@link #parseSASLResponse}：密码消息/SASL响应</li>
     *   <li>'d' → {@link #parseCopyDataPayload}：复制数据</li>
     *   <li>'c' → CopyDone：复制完成（无payload）</li>
     *   <li>'f' → {@link #parseCopyFailPayload}：复制失败</li>
     *   <li>'F' → {@link #parseFunctionCallPayload}：函数调用（已废弃）</li>
     * </ul>
     * </p>
     *
     * @param buffer        数据缓冲区（position已在标签和长度之后）
     * @param tag           消息标签字符
     * @param payloadLength payload长度（不含标签和长度头）
     * @param msg           当前消息的解析结果Map
     */
    private void parseFrontendPayload(ByteBuffer buffer, char tag, int payloadLength, Map<String, Object> msg) {
        switch (tag) {
            case 'Q': // Query
                parseQueryPayload(buffer, payloadLength, msg);
                break;
            case 'P': // Parse
                parseParsePayload(buffer, payloadLength, msg);
                break;
            case 'B': // Bind
                parseBindPayload(buffer, payloadLength, msg);
                break;
            case 'D': // Describe
                parseDescribePayload(buffer, payloadLength, msg);
                break;
            case 'E': // Execute
                parseExecutePayload(buffer, payloadLength, msg);
                break;
            case 'C': // Close
                parseClosePayload(buffer, payloadLength, msg);
                break;
            case 'S': // Sync
                // Sync消息有payload：字符串（以null结尾的状态信息）
                if (payloadLength > 0) {
                    String syncPayload = readCString(buffer);
                    msg.put("payload", syncPayload);
                } else {
                    msg.put("payload", "(empty)");
                }
                break;
            case 'X': // Terminate
                // Terminate没有payload
                msg.put("payload", "(empty)");
                break;
            case 'H': // Flush
                // Flush没有payload
                msg.put("payload", "(empty)");
                break;
            case 'p': // PasswordMessage / SASL Initial Response
                // 格式: String(密码或SASL响应)
                String password = readCString(buffer);
                msg.put("password", password);
                // 检查是否为SASL响应（包含逗号分隔的SASL属性）
                if (password.startsWith("SCRAM-") || password.contains(",")) {
                    msg.put("message.name", "SASL_INITIAL_RESPONSE");
                    msg.put("message.description", "SASL Initial Response");
                    parseSASLResponse(password, msg);
                } else {
                    msg.put("message.name", "PASSWORD_MESSAGE");
                    msg.put("message.description", "Password Message");
                }
                break;
            case 'd': // CopyData
                parseCopyDataPayload(buffer, payloadLength, msg);
                break;
            case 'c': // CopyDone
                // CopyDone没有payload
                msg.put("payload", "(empty)");
                break;
            case 'f': // CopyFail
                parseCopyFailPayload(buffer, payloadLength, msg);
                break;
            case 'F': // FunctionCall (deprecated)
                parseFunctionCallPayload(buffer, payloadLength, msg);
                break;
            default:
                // 未知前端消息，跳过payload
                if (payloadLength > 0) {
                    byte[] payload = new byte[payloadLength];
                    buffer.get(payload);
                    msg.put("payload.hex", bytesToHex(payload));
                    msg.put("payload.ascii", bytesToAscii(payload));
                }
                break;
        }
    }

    /**
     * 解析后端消息payload（服务器 → 客户端）
     * <p>
     * 根据消息标签分发到对应的解析方法：
     * <ul>
     *   <li>'R' → {@link #parseAuthenticationPayload}：认证响应</li>
     *   <li>'K' → {@link #parseBackendKeyDataPayload}：后端密钥数据</li>
     *   <li>'S' → {@link #parseParameterStatusPayload}：参数状态</li>
     *   <li>'Z' → {@link #parseReadyForQueryPayload}：准备查询</li>
     *   <li>'T' → {@link #parseRowDescriptionPayload}：行描述</li>
     *   <li>'D' → {@link #parseDataRowPayload}：数据行</li>
     *   <li>'C' → {@link #parseCommandCompletePayload}：命令完成</li>
     *   <li>'I' → EmptyQueryResponse（无payload）</li>
     *   <li>'E' → {@link #parseErrorNoticePayload}：错误响应</li>
     *   <li>'N' → {@link #parseErrorNoticePayload}：通知响应（格式同错误）</li>
     *   <li>'1' → ParseComplete（无payload）</li>
     *   <li>'2' → BindComplete（无payload）</li>
     *   <li>'3' → CloseComplete（无payload）</li>
     *   <li>'s' → PortalSuspended（无payload）</li>
     *   <li>'n' → NoData（无payload）</li>
     *   <li>'t' → {@link #parseParameterDescriptionPayload}：参数描述</li>
     *   <li>'A' → {@link #parseNotificationResponsePayload}：通知响应</li>
     *   <li>'G'/'H'/'W' → {@link #parseCopyResponsePayload}：复制响应</li>
     *   <li>'d' → {@link #parseCopyDataPayload}：复制数据</li>
     *   <li>'V' → FunctionCallResponse（已废弃，简要解析）</li>
     * </ul>
     * </p>
     *
     * @param buffer        数据缓冲区（position已在标签和长度之后）
     * @param tag           消息标签字符
     * @param payloadLength payload长度（不含标签和长度头）
     * @param msg           当前消息的解析结果Map
     */
    private void parseBackendPayload(ByteBuffer buffer, char tag, int payloadLength, Map<String, Object> msg) {
        switch (tag) {
            case 'R': // Authentication
                parseAuthenticationPayload(buffer, payloadLength, msg);
                break;
            case 'K': // BackendKeyData
                parseBackendKeyDataPayload(buffer, payloadLength, msg);
                break;
            case 'S': // ParameterStatus
                parseParameterStatusPayload(buffer, payloadLength, msg);
                break;
            case 'Z': // ReadyForQuery
                parseReadyForQueryPayload(buffer, payloadLength, msg);
                break;
            case 'T': // RowDescription
                parseRowDescriptionPayload(buffer, payloadLength, msg);
                break;
            case 'D': // DataRow
                parseDataRowPayload(buffer, payloadLength, msg);
                break;
            case 'C': // CommandComplete
                parseCommandCompletePayload(buffer, payloadLength, msg);
                break;
            case 'I': // EmptyQueryResponse
                // 没有payload
                msg.put("payload", "(empty)");
                break;
            case 'E': // ErrorResponse
                parseErrorNoticePayload(buffer, payloadLength, msg);
                break;
            case 'N': // NoticeResponse
                parseErrorNoticePayload(buffer, payloadLength, msg); // 与ErrorResponse格式相同
                break;
            case '1': // ParseComplete
                // 没有payload
                msg.put("payload", "(empty)");
                break;
            case '2': // BindComplete
                // 没有payload
                msg.put("payload", "(empty)");
                break;
            case '3': // CloseComplete
                // 没有payload
                msg.put("payload", "(empty)");
                break;
            case 's': // PortalSuspended
                // 没有payload
                msg.put("payload", "(empty)");
                break;
            case 'n': // NoData
                // 没有payload
                msg.put("payload", "(empty)");
                break;
            case 't': // ParameterDescription
                parseParameterDescriptionPayload(buffer, payloadLength, msg);
                break;
            case 'A': // NotificationResponse
                parseNotificationResponsePayload(buffer, payloadLength, msg);
                break;
            case 'G': // CopyInResponse
            case 'H': // CopyOutResponse
            case 'W': // CopyBothResponse
                parseCopyResponsePayload(buffer, payloadLength, msg);
                break;
            case 'd': // CopyData
                parseCopyDataPayload(buffer, payloadLength, msg);
                break;
            case 'V': // FunctionCallResponse (deprecated)
                if (payloadLength > 0) {
                    byte[] payload = new byte[payloadLength];
                    buffer.get(payload);
                    msg.put("payload.hex", bytesToHex(payload));
                    msg.put("payload.ascii", bytesToAscii(payload));
                }
                break;
            default:
                // 未知后端消息，跳过payload
                if (payloadLength > 0) {
                    byte[] payload = new byte[payloadLength];
                    buffer.get(payload);
                    msg.put("payload.hex", bytesToHex(payload));
                    msg.put("payload.ascii", bytesToAscii(payload));
                }
                break;
        }
    }

    // ========================================================================
    //  前端消息（客户端 → 服务器）Payload 解析方法
    //  每个方法对应一种PG前端消息类型的payload解析
    // ========================================================================

    /**
     * 解析Query消息
     * 格式：String(查询SQL)
     */
    private void parseQueryPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String query = readCString(buffer);
        msg.put("query.sql", query);
        msg.put("query.sql.length", query.length());

        // SQL语句类型检测
        String sqlType = detectSQLType(query);
        if (sqlType != null) {
            msg.put("query.sql_type", sqlType);
        }
    }

    /**
     * 解析Parse消息
     * 格式：String(预备语句名) + String(SQL) + Int16(参数类型数量) + Int32[](参数类型OID)
     */
    private void parseParsePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String stmtName = readCString(buffer);
        String query = readCString(buffer);

        msg.put("parse.statement_name", stmtName);
        msg.put("parse.statement_name.empty", stmtName.isEmpty());
        msg.put("parse.sql", query);

        if (buffer.hasRemaining()) {
            short numParams = buffer.getShort();
            msg.put("parse.num_parameters", numParams & 0xFFFF);

            if (numParams > 0 && buffer.remaining() >= numParams * 4) {
                List<Integer> paramTypes = new ArrayList<>();
                for (int i = 0; i < numParams; i++) {
                    int paramOid = buffer.getInt();
                    paramTypes.add(paramOid);
                }
                msg.put("parse.parameter_types", paramTypes);

                // 解析参数类型名称
                List<String> paramTypeNames = new ArrayList<>();
                for (int oid : paramTypes) {
                    PGEnums.PGTypeOID typeOid = PGEnums.PGTypeOID.fromOid(oid);
                    paramTypeNames.add(typeOid.getDisplayName());
                }
                msg.put("parse.parameter_type_names", paramTypeNames);
            }
        }
    }

    /**
     * 解析Bind消息
     * 格式：String(目标游标名) + String(预备语句名)
     *       + Int16(参数格式码数量) + Int16[](参数格式码)
     *       + Int16(参数值数量) + Int32[](参数值长度) + byte[](参数值)
     *       + Int16(结果列格式码数量) + Int16[](结果列格式码)
     */
    private void parseBindPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String portalName = readCString(buffer);
        String stmtName = readCString(buffer);

        msg.put("bind.portal_name", portalName);
        msg.put("bind.portal_name.empty", portalName.isEmpty());
        msg.put("bind.statement_name", stmtName);
        msg.put("bind.statement_name.empty", stmtName.isEmpty());

        // 参数格式码
        if (buffer.hasRemaining()) {
            short numFormatCodes = buffer.getShort();
            msg.put("bind.num_parameter_formats", numFormatCodes & 0xFFFF);

            if (numFormatCodes > 0) {
                List<Short> formatCodes = new ArrayList<>();
                for (int i = 0; i < numFormatCodes; i++) {
                    formatCodes.add(buffer.getShort());
                }
                msg.put("bind.parameter_formats", formatCodes);

                List<String> formatNames = new ArrayList<>();
                for (short fc : formatCodes) {
                    formatNames.add(PGEnums.FormatCode.fromCode(fc).getDescriptionCn());
                }
                msg.put("bind.parameter_format_names", formatNames);
            }
        }

        // 参数值
        if (buffer.hasRemaining()) {
            short numParams = buffer.getShort();
            msg.put("bind.num_parameters", numParams & 0xFFFF);

            if (numParams > 0) {
                List<Object> paramValues = new ArrayList<>();
                for (int i = 0; i < numParams && buffer.hasRemaining(); i++) {
                    int paramLen = buffer.getInt();
                    if (paramLen == -1) {
                        paramValues.add("NULL");
                    } else if (paramLen == 0) {
                        paramValues.add("(empty)");
                    } else if (paramLen > 0 && buffer.remaining() >= paramLen) {
                        byte[] paramData = new byte[paramLen];
                        buffer.get(paramData);
                        // 尝试以UTF-8字符串显示
                        String paramStr = new String(paramData, StandardCharsets.UTF_8);
                        // 检查是否为可打印文本
                        if (isPrintableAscii(paramData)) {
                            paramValues.add(paramStr);
                        } else {
                            paramValues.add(bytesToHex(paramData));
                        }
                    }
                }
                msg.put("bind.parameter_values", paramValues);
            }
        }

        // 结果列格式码
        if (buffer.hasRemaining()) {
            short numResultFormats = buffer.getShort();
            msg.put("bind.num_result_formats", numResultFormats & 0xFFFF);

            if (numResultFormats > 0) {
                List<Short> resultFormats = new ArrayList<>();
                for (int i = 0; i < numResultFormats; i++) {
                    resultFormats.add(buffer.getShort());
                }
                msg.put("bind.result_formats", resultFormats);
            }
        }
    }

    /**
     * 解析Describe消息
     * 格式：Byte1('S'/'P') + String(名称)
     */
    private void parseDescribePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (buffer.hasRemaining()) {
            byte objectType = buffer.get();
            char objTypeChar = (char) (objectType & 0xFF);
            String name = readCString(buffer);

            PGEnums.DescribeObjectType objType = PGEnums.DescribeObjectType.fromType(objTypeChar);
            msg.put("describe.object_type", String.valueOf(objTypeChar));
            msg.put("describe.object_type.name", objType.getDescriptionCn());
            msg.put("describe.name", name);
        }
    }

    /**
     * 解析Execute消息
     * 格式：String(游标名) + Int32(最大行数)
     */
    private void parseExecutePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String portalName = readCString(buffer);
        msg.put("execute.portal_name", portalName);
        msg.put("execute.portal_name.empty", portalName.isEmpty());

        if (buffer.hasRemaining()) {
            int maxRows = buffer.getInt();
            msg.put("execute.max_rows", maxRows);
            if (maxRows == 0) {
                msg.put("execute.max_rows.description", "Unlimited (return all rows)");
            } else {
                msg.put("execute.max_rows.description", "At most " + maxRows + " rows");
            }
        }
    }

    /**
     * 解析Close消息
     * 格式：Byte1('S'/'P') + String(名称)
     */
    private void parseClosePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (buffer.hasRemaining()) {
            byte objectType = buffer.get();
            char objTypeChar = (char) (objectType & 0xFF);
            String name = readCString(buffer);

            PGEnums.DescribeObjectType objType = PGEnums.DescribeObjectType.fromType(objTypeChar);
            msg.put("close.object_type", String.valueOf(objTypeChar));
            msg.put("close.object_type.name", objType.getDescriptionCn());
            msg.put("close.name", name);
        }
    }

    /**
     * 解析CopyData消息
     * 格式：byte[](数据)
     */
    private void parseCopyDataPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength > 0) {
            byte[] payload = new byte[payloadLength];
            buffer.get(payload);
            msg.put("copy.data_length", payloadLength);
            msg.put("copy.data.hex", bytesToHex(payload));
            if (isPrintableAscii(payload)) {
                msg.put("copy.data.text", new String(payload, StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * 解析CopyFail消息
     * 格式：String(错误消息)
     */
    private void parseCopyFailPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String errorMsg = readCString(buffer);
        msg.put("copy_fail.message", errorMsg);
    }

    /**
     * 解析FunctionCall消息（已废弃）
     * 格式：Int16(函数OID) + ...（复杂格式，简要解析）
     */
    private void parseFunctionCallPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength >= 2) {
            short functionOid = buffer.getShort();
            msg.put("function_call.oid", functionOid & 0xFFFF);
            msg.put("function_call.oid.name", PGEnums.PGTypeOID.fromOid(functionOid & 0xFFFF).getDisplayName());

            // 剩余数据作为参数
            int remaining = payloadLength - 2;
            if (remaining > 0) {
                byte[] remainingData = new byte[remaining];
                buffer.get(remainingData);
                msg.put("function_call.remaining.hex", bytesToHex(remainingData));
            }
        }
    }

    /**
     * 解析SASL响应（客户端发送的SASL初始响应或SASL响应）
     * 格式：String(SASL响应内容)
     * SASL SCRAM-SHA-256 响应格式: n,,n=*,r=foobar
     */
    private void parseSASLResponse(String saslResponse, Map<String, Object> msg) {
        msg.put("sasl.response", saslResponse);

        // 解析SCRAM-SHA-256 SASL响应中的属性
        if (saslResponse != null) {
            // 检查是否为SCRAM-SHA-256客户端首次响应格式: n,,n=用户名,r=nonce
            if (saslResponse.startsWith("n,,") || saslResponse.startsWith("n ")) {
                msg.put("sasl.mechanism", "SCRAM-SHA-256");
                // 提取gs2-header
                int gs2End = saslResponse.indexOf(",,");
                if (gs2End >= 0) {
                    String gs2Header = saslResponse.substring(0, gs2End + 2);
                    msg.put("sasl.gs2_header", gs2Header);
                    String remainder = saslResponse.substring(gs2End + 2);
                    // 解析剩余属性 (n=*, r=*)
                    for (String attr : remainder.split(",")) {
                        if (attr.startsWith("n=")) {
                            msg.put("sasl.client_username", attr.substring(2));
                        } else if (attr.startsWith("r=")) {
                            msg.put("sasl.client_nonce", attr.substring(2));
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    //  后端消息（服务器 → 客户端）Payload 解析方法
    //  每个方法对应一种PG后端消息类型的payload解析
    // ========================================================================

    /**
     * 解析Authentication消息
     * 格式：Int32(认证类型) + [认证数据]
     */
    private void parseAuthenticationPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength < 4) {
            return;
        }

        int authType = buffer.getInt();
        PGEnums.AuthenticationType authTypeEnum = PGEnums.AuthenticationType.fromCode(authType);

        msg.put("auth.type", authType);
        msg.put("auth.type.name", authTypeEnum.getDescriptionCn());

        switch (authType) {
            case 0: // OK
                break;
            case 3: // CleartextPassword
                break;
            case 5: // MD5Password
                if (buffer.remaining() >= 4) {
                    byte[] salt = new byte[4];
                    buffer.get(salt);
                    msg.put("auth.md5_salt", bytesToHex(salt));
                }
                break;
            case 7: // GSS
            case 9: // SSPI
                break;
            case 8: // GSS Continue
            case 11: // SASL Continue
                if (buffer.hasRemaining()) {
                    byte[] authData = new byte[buffer.remaining()];
                    buffer.get(authData);
                    msg.put("auth.data", new String(authData, StandardCharsets.UTF_8));
                }
                break;
            case 10: // SASL
                if (buffer.hasRemaining()) {
                    List<String> mechanisms = new ArrayList<>();
                    while (buffer.hasRemaining()) {
                        String mechanism = readCString(buffer);
                        if (mechanism.isEmpty()) {
                            break;
                        }
                        mechanisms.add(mechanism);
                    }
                    msg.put("auth.sasl_mechanisms", mechanisms);
                }
                break;
            case 12: // SASL Final
                if (buffer.hasRemaining()) {
                    byte[] finalData = new byte[buffer.remaining()];
                    buffer.get(finalData);
                    msg.put("auth.sasl_final", new String(finalData, StandardCharsets.UTF_8));
                }
                break;
        }
    }

    /**
     * 解析BackendKeyData消息
     * 格式：Int32(进程ID) + Int32(密钥)
     */
    private void parseBackendKeyDataPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength >= 8) {
            int processId = buffer.getInt();
            int secretKey = buffer.getInt();
            msg.put("backend_key_data.process_id", processId);
            msg.put("backend_key_data.secret_key", secretKey);
        }
    }

    /**
     * 解析ParameterStatus消息
     * 格式：String(参数名) + String(参数值)
     */
    private void parseParameterStatusPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String paramName = readCString(buffer);
        String paramValue = readCString(buffer);
        msg.put("parameter_status.name", paramName);
        msg.put("parameter_status.value", paramValue);
    }

    /**
     * 解析ReadyForQuery消息
     * 格式：Byte1(事务状态)
     */
    private void parseReadyForQueryPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength >= 1) {
            byte statusByte = buffer.get();
            char status = (char) (statusByte & 0xFF);
            PGEnums.TransactionStatus txStatus = PGEnums.TransactionStatus.fromStatus(status);

            msg.put("ready_for_query.status", String.valueOf(status));
            msg.put("ready_for_query.status.name", txStatus.getDescriptionCn());
        }
    }

    /**
     * 解析RowDescription消息
     * 格式：Int16(列数) + [String(列名) + Int32(表OID) + Int16(列号) + Int32(类型OID) + Int16(类型大小) + Int32(类型修饰符) + Int16(格式码)] * N
     */
    private void parseRowDescriptionPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength < 2) {
            return;
        }

        short numColumns = buffer.getShort();
        msg.put("row_description.num_columns", numColumns & 0xFFFF);

        List<Map<String, Object>> columns = new ArrayList<>();
        for (int i = 0; i < numColumns && buffer.hasRemaining(); i++) {
            Map<String, Object> column = new HashMap<>();
            String columnName = readCString(buffer);
            column.put("name", columnName);

            if (buffer.remaining() >= 18) {
                int tableOid = buffer.getInt();
                short columnIndex = buffer.getShort();
                int typeOid = buffer.getInt();
                short typeSize = buffer.getShort();
                int typeModifier = buffer.getInt();
                short formatCode = buffer.getShort();

                column.put("table_oid", tableOid);
                column.put("column_index", columnIndex & 0xFFFF);
                column.put("type_oid", typeOid);
                column.put("type_name", PGEnums.PGTypeOID.fromOid(typeOid).getDisplayName());
                column.put("type_size", typeSize);
                column.put("type_modifier", typeModifier);
                column.put("format_code", formatCode);
                column.put("format_name", PGEnums.FormatCode.fromCode(formatCode).getDescriptionCn());
            }

            columns.add(column);
        }

        msg.put("row_description.columns", columns);
    }

    /**
     * 解析DataRow消息
     * 格式：Int16(列数) + [Int32(值长度) + byte[](值)] * N
     */
    private void parseDataRowPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength < 2) {
            return;
        }

        short numColumns = buffer.getShort();
        msg.put("data_row.num_columns", numColumns & 0xFFFF);

        List<Object> values = new ArrayList<>();
        for (int i = 0; i < numColumns && buffer.hasRemaining(); i++) {
            int valueLength = buffer.getInt();
            if (valueLength == -1) {
                values.add("NULL");
            } else if (valueLength == 0) {
                values.add("(empty)");
            } else if (valueLength > 0 && buffer.remaining() >= valueLength) {
                byte[] valueData = new byte[valueLength];
                buffer.get(valueData);
                // 尝试以UTF-8字符串显示
                String valueStr = new String(valueData, StandardCharsets.UTF_8);
                if (isPrintableAscii(valueData)) {
                    values.add(valueStr);
                } else {
                    values.add("[binary: " + valueLength + " bytes]");
                }
            }
        }

        msg.put("data_row.values", values);
    }

    /**
     * 解析CommandComplete消息
     * 格式：String(命令标签)
     */
    private void parseCommandCompletePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        String commandTag = readCString(buffer);
        msg.put("command_complete.tag", commandTag);

        // 解析命令标签中的影响行数
        // 格式如：INSERT 0 1, SELECT 100, UPDATE 5, DELETE 3
        String[] parts = commandTag.split("\\s+");
        if (parts.length > 0) {
            msg.put("command_complete.command", parts[0]);
            if (parts.length >= 2) {
                try {
                    long rows = Long.parseLong(parts[parts.length - 1]);
                    msg.put("command_complete.rows_affected", rows);
                } catch (NumberFormatException ignored) {
                }
            }
        }
    }

    /**
     * 解析ErrorResponse/NoticeResponse消息
     * 格式：[Byte1(字段类型) + String(字段值)] * N + Byte1(0)
     */
    private void parseErrorNoticePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        Map<String, String> fields = new HashMap<>();
        while (buffer.hasRemaining()) {
            byte fieldTypeByte = buffer.get();
            char fieldType = (char) (fieldTypeByte & 0xFF);
            if (fieldType == 0) {
                break; // 终止符
            }
            String fieldValue = readCString(buffer);

            PGEnums.ErrorFieldType errorField = PGEnums.ErrorFieldType.fromType(fieldType);
            String fieldKey = "error_field." + errorField.name().toLowerCase();
            fields.put(fieldKey, fieldValue);

            // 提取关键字段到顶层
            if (fieldType == 'S') {
                msg.put("error.severity", fieldValue);
            } else if (fieldType == 'C') {
                msg.put("error.code", fieldValue);
            } else if (fieldType == 'M') {
                msg.put("error.message", fieldValue);
            } else if (fieldType == 'D') {
                msg.put("error.detail", fieldValue);
            } else if (fieldType == 'H') {
                msg.put("error.hint", fieldValue);
            }
        }
        if (!fields.isEmpty()) {
            msg.put("error.fields", fields);
        }
    }

    /**
     * 解析ParameterDescription消息
     * 格式：Int16(参数数量) + Int32[](参数类型OID)
     */
    private void parseParameterDescriptionPayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength < 2) {
            return;
        }

        short numParams = buffer.getShort();
        msg.put("parameter_description.num_parameters", numParams & 0xFFFF);

        if (numParams > 0) {
            List<Integer> paramTypes = new ArrayList<>();
            List<String> paramTypeNames = new ArrayList<>();
            for (int i = 0; i < numParams && buffer.remaining() >= 4; i++) {
                int typeOid = buffer.getInt();
                paramTypes.add(typeOid);
                paramTypeNames.add(PGEnums.PGTypeOID.fromOid(typeOid).getDisplayName());
            }
            msg.put("parameter_description.parameter_types", paramTypes);
            msg.put("parameter_description.parameter_type_names", paramTypeNames);
        }
    }

    /**
     * 解析NotificationResponse消息
     * 格式：Int32(进程ID) + String(通道名) + String(负载)
     */
    private void parseNotificationResponsePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength >= 4) {
            int processId = buffer.getInt();
            String channel = readCString(buffer);
            String payload = readCString(buffer);

            msg.put("notification.process_id", processId);
            msg.put("notification.channel", channel);
            msg.put("notification.payload", payload);
        }
    }

    /**
     * 解析CopyInResponse/CopyOutResponse/CopyBothResponse消息
     * 格式：Byte1(整体格式) + Int16(列数) + Int16[](列格式码)
     */
    private void parseCopyResponsePayload(ByteBuffer buffer, int payloadLength, Map<String, Object> msg) {
        if (payloadLength < 3) {
            return;
        }

        byte overallFormat = buffer.get();
        short numColumns = buffer.getShort();

        msg.put("copy_response.overall_format", overallFormat & 0xFF);
        msg.put("copy_response.overall_format.name", PGEnums.FormatCode.fromCode(overallFormat).getDescriptionCn());
        msg.put("copy_response.num_columns", numColumns & 0xFFFF);

        if (numColumns > 0) {
            List<Short> columnFormats = new ArrayList<>();
            for (int i = 0; i < numColumns && buffer.hasRemaining(); i++) {
                columnFormats.add(buffer.getShort());
            }
            msg.put("copy_response.column_formats", columnFormats);
        }
    }
}