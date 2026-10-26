package com.jshark.parser.dis;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64;

/**
 * DIS（分布式交互仿真）协议解析器
 * 用于解析DIS协议数据单元（PDU）
 */
public class DISProtocolParser {
    /**
     * 将字节数组转换为可读的 ASCII 字符串，不可见字符用点号(.)代替
     * * @param data 原始字节数组
     * @return 清洗后的字符串
     */
    public static String bytesToAscii(byte[] data) {
        if (data == null) return "";
        StringBuilder sb = new StringBuilder(data.length);
        for (byte b : data) {
            // ASCII 可见字符范围是 32 (空格) 到 126 (~)
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
            } else {
                // 不可见字符、控制字符或扩展 ASCII 统一替换为点
                sb.append('.');
            }
        }
        return sb.toString();
    }

    /**
     * 将字节数组转换为 Base64 编码字符串
     * @param bytes 原始字节数组
     * @return Base64 编码字符串
     */
    public static String bytesToBase64(byte[] bytes) {
        if (bytes == null) return "";
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 解析DIS PDU数据
     *
     * @param data 原始DIS协议数据
     * @return 解析结果映射
     */
    public Map<String, Object> parse(byte[] data) {
        Map<String, Object> result = new HashMap<>();
        
        if (data == null) {
            result.put("error", "DIS PDU data is null");
            result.put("parsed.successfully", false);
            return result;
        }
        
        if (data.length < 12) {
            result.put("error", String.format("Invalid DIS PDU data: too short (expected at least 12 bytes, got %d)", data.length));
            result.put("data.length", data.length);
            result.put("parsed.successfully", false);
            return result;
        }
        
        ByteBuffer buffer = null;
        DISEnums.PDUType type = null;
        try {
            buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN); // DIS协议使用大端字节序

            // 解析PDU头部
            //  偏移 (Byte)	数据	对应字段	说明
            //  0	        Protocol Version
            //  1	        Exercise ID
            //  2	        PDU Type
            //  3	        Protocol Family
            //  4-7	        Timestamp	时间戳
            //  8-9	        PDU Length
            //  10-11	    Padding	填充位

            // 根据DIS标准（IEEE 1278.1）解析PDU头部
            // 字节0: 协议版本 (Protocol Version)
            int protocolVersion = buffer.get() & 0xFF;
            result.put("protocol.version", protocolVersion);
            
            // 字节1: 演习ID (Exercise ID)
            int exerciseId = buffer.get() & 0xFF;
            result.put("exercise.id", exerciseId);
            
            // 字节2: PDU类型 (PDU Type)
            int pduType = buffer.get() & 0xFF;
            type = DISEnums.PDUType.fromValue(pduType);
            result.put("pdu.type", pduType);
            
            // 字节3: 协议族 (Protocol Family)
            int protocolFamily = buffer.get() & 0xFF;
            result.put("protocol.family", protocolFamily);

            // 字节4-7: 时间戳 (Timestamp)
            long timestamp = buffer.getInt() & 0xFFFFFFFFL;
            result.put("timestamp", timestamp);
            
            // 字节8-9: PDU长度 (PDU Length)
            int pduLength = buffer.getShort() & 0xFFFF;
            result.put("pdu.length", pduLength);
            
            // 验证PDU长度 - 根据DIS标准，长度字段必须大于0
            if (pduLength == 0)
            {
                result.put("error", "Invalid PDU length: length field is 0 (must be > 0 according to DIS standard)");
                result.put("parsed.successfully", false);
                return result;
            }
            
            // 验证PDU长度与实际数据长度是否匹配
            if (pduLength != data.length) {
                result.put("warning", String.format("PDU length mismatch: header says %d bytes, actual data is %d bytes", pduLength, data.length));
            }
            
            // 字节10-11: 填充位 (Padding)
            buffer.getShort();

            // 记录剩余字节数
            int remainingBeforeParse = buffer.remaining();
            result.put("remaining.bytes.before.parse", remainingBeforeParse);
            
            // PDU类型特定解析
            switch (type) {
                case ENTITY_STATE -> parseEntityStatePDU(buffer, result);
                case FIRE -> parseFirePDU(buffer, result);
                case DETONATION -> parseDetonationPDU(buffer, result);
                case COLLISION -> parseCollisionPDU(buffer, result);
                case SERVICE_REQUEST -> parseServiceRequestPDU(buffer, result);
                case RESUPPLY_OFFER -> parseResupplyOfferPDU(buffer, result);
                case RESUPPLY_RECEIVED -> parseResupplyReceivedPDU(buffer, result);
                case RESUPPLY_CANCEL -> parseResupplyCancelPDU(buffer, result);
                case REPAIR_COMPLETE -> parseRepairCompletePDU(buffer, result);
                case REPAIR_RESPONSE -> parseRepairResponsePDU(buffer, result);
                case CREATE_ENTITY -> parseCreateEntityPDU(buffer, result);
                case REMOVE_ENTITY -> parseRemoveEntityPDU(buffer, result);
                case START_RESUME -> parseStartResumePDU(buffer, result);
                case STOP_FREEZE -> parseStopFreezePDU(buffer, result);
                case ACKNOWLEDGE -> parseAcknowledgePDU(buffer, result);
                case ACTION_REQUEST -> parseActionRequestPDU(buffer, result);
                case ACTION_RESPONSE -> parseActionResponsePDU(buffer, result);
                case DATA_QUERY -> parseDataQueryPDU(buffer, result);
                case DATA_SET -> parseDataSetPDU(buffer, result);
                case EVENT_REPORT -> parseEventReportPDU(buffer, result);
                case COMMENT -> parseCommentPDU(buffer, result);
                case ELECTROMAGNETIC_EMISSION -> parseElectromagneticEmissionPDU(buffer, result);
                case DESIGNATOR -> parseDesignatorPDU(buffer, result);
                case AGGREGATE_STATE -> parseAggregateStatePDU(buffer, result);
                case ENTITY_STATE_UPDATE -> parseEntityStateUpdatePDU(buffer, result);
                case TRANSMITTER -> parseTransmitterPDU(buffer, result);
                case RECEIVER -> parseReceiverPDU(buffer, result);
                case IFF_ATC_NAVAIDS -> parseIffAtcNavaidsPDU(buffer, result);
                case SIGNAL -> parseSignalPDU(buffer, result);
                case UNDERWATER_ACOUSTIC -> parseUnderwaterAcousticPDU(buffer, result);
                case SUPPLEMENTAL_EMISSION_ENTITY_STATE -> parseSupplementalEmissionEntityStatePDU(buffer, result);
                case INTERCOM_SIGNAL -> parseIntercomSignalPDU(buffer, result);
                case INTERCOM_CONTROL -> parseIntercomControlPDU(buffer, result);
                case IS_GROUP_OF -> parseIsGroupOfPDU(buffer, result);
                case TRANSFER_CONTROL -> parseTransferControlPDU(buffer, result);
                case IS_PART_OF -> parseIsPartOfPDU(buffer, result);
                case MINEFIELD_STATE -> parseMinefieldStatePDU(buffer, result);
                case ARTICULATED_PARTS -> parseArticulatedPartsPDU(buffer, result);
                case APPEARANCE -> parseAppearancePDU(buffer, result);
                case MINEFIELD_QUERY -> parseMinefieldQueryPDU(buffer, result);
                case MINEFIELD_DATA -> parseMinefieldDataPDU(buffer, result);
                case ENVIRONMENTAL_PROCESS -> parseEnvironmentalProcessPDU(buffer, result);
                case GRIDDED_DATA -> parseGriddedDataPDU(buffer, result);
                case POINT_OBJECT_STATE -> parsePointObjectStatePDU(buffer, result);
                case DATA -> parseDataPDU(buffer, result);
                case LINEAR_OBJECT_STATE -> parseLinearObjectStatePDU(buffer, result);
                case AREAL_OBJECT_STATE -> parseArealObjectStatePDU(buffer, result);
                case TSPI -> parseTSPIPDU(buffer, result);

                // 处理R版本PDU - 使用对应的非R版本解析方法
                case CREATE_ENTITY_R -> {
                    parseCreateEntityPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case REMOVE_ENTITY_R -> {
                    parseRemoveEntityPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case START_RESUME_R -> {
                    parseStartResumePDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case STOP_FREEZE_R -> {
                    parseStopFreezePDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case ACKNOWLEDGE_R -> {
                    parseAcknowledgePDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case ACTION_REQUEST_R -> {
                    parseActionRequestPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case ACTION_RESPONSE_R -> {
                    parseActionResponsePDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case DATA_QUERY_R -> {
                    parseDataQueryPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case DATA_SET_R -> {
                    parseDataSetPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case EVENT_REPORT_R -> {
                    parseEventReportPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case COMMENT_R -> {
                    parseCommentPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                case RECORD_R -> {
                    parseRecordPDU(buffer, result);
                    result.put("pdu.version", "R");
                }
                default ->
                    // 对于其他PDU类型，解析通用信息
                        parseGenericPDU(buffer, result, type);
            }
            
            // 记录解析后的剩余字节数
            int remainingAfterParse = buffer.remaining();
            result.put("remaining.bytes.after.parse", remainingAfterParse);
            
            // 检查是否有未解析的数据
            if (remainingAfterParse > 0) {
                result.put("warning.unparsed.bytes", remainingAfterParse);
            }

            // 检查解析是否成功标记
            if (!result.containsKey("parsed.successfully")) {
                result.put("parsed.successfully", true);
            }
            
            // 添加原始数据大小信息
            result.put("raw.data.size", data.length);

        } catch (Exception e) {
            // 提供更详细的错误信息，包括PDU类型和当前位置
            String errorDetail = String.format("Failed to parse DIS PDU (type: %s, position: %d/%d): %s",
                type != null ? type.getDescription() : "unknown",
                buffer != null ? buffer.position() : 0, data.length,
                e.getMessage());
            result.put("error", errorDetail);
            result.put("exception", e.getClass().getSimpleName());
            result.put("stack.trace", e.getStackTrace()[0].toString());
            result.put("parsed.successfully", false);
            
            // 如果可能，添加更多上下文信息
            if (type != null) {
                result.put("error.pdu.type", type.getDescription());
                result.put("error.pdu.type.value", type.ordinal());
            }
            if (buffer != null) {
                result.put("error.buffer.position", buffer.position());
                result.put("error.buffer.remaining", buffer.remaining());
            }
        }
        
        return result;
    }
    
    /**
     * 解析实体状态PDU
     */
    private void parseEntityStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 实体ID
            result.put("entity.site", buffer.getShort() & 0xFFFF);
            result.put("entity.application", buffer.getShort() & 0xFFFF);
            result.put("entity.entity", buffer.getShort() & 0xFFFF);
            
            // 力量标识
            int forceIdValue = buffer.get() & 0xFF;
            result.put("force.id", forceIdValue);

            DISEnums.ForceId forceId = DISEnums.ForceId.fromValue(forceIdValue);
            result.put("force.id.description", forceId.getDescription());
            int articulationCount = buffer.get() & 0xFF;
            result.put("articulation.parameter.count", articulationCount);

            // 实体类型
            int entityKindValue = buffer.get() & 0xFF;
            result.put("entity.kind", entityKindValue);
            DISEnums.EntityKind entityKind = DISEnums.EntityKind.fromValue(entityKindValue);
            result.put("entity.kind.description", entityKind.getDescription());
            
            int entityDomainValue = buffer.get() & 0xFF;
            result.put("entity.domain", entityDomainValue);
            DISEnums.EntityDomain entityDomain = DISEnums.EntityDomain.fromValue(entityDomainValue);
            result.put("entity.domain.description", entityDomain.getDescription());
            
            result.put("entity.country", buffer.getShort() & 0xFFFF);
            result.put("entity.category", buffer.get() & 0xFF);
            result.put("entity.subcategory", buffer.get() & 0xFF);
            result.put("entity.specific", buffer.get() & 0xFF);
            result.put("entity.extra", buffer.get() & 0xFF);
            
            // 备用实体类型
            int altEntityKindValue = buffer.get() & 0xFF;
            result.put("alternative.entity.kind", altEntityKindValue);
            DISEnums.EntityKind altEntityKind = DISEnums.EntityKind.fromValue(altEntityKindValue);
            result.put("alternative.entity.kind.description", altEntityKind.getDescription());
            
            int altEntityDomainValue = buffer.get() & 0xFF;
            result.put("alternative.entity.domain", altEntityDomainValue);
            DISEnums.EntityDomain altEntityDomain = DISEnums.EntityDomain.fromValue(altEntityDomainValue);
            result.put("alternative.entity.domain.description", altEntityDomain.getDescription());
            
            result.put("alternative.entity.country", buffer.getShort() & 0xFFFF);
            result.put("alternative.entity.category", buffer.get() & 0xFF);
            result.put("alternative.entity.subcategory", buffer.get() & 0xFF);
            result.put("alternative.entity.specific", buffer.get() & 0xFF);
            result.put("alternative.entity.extra", buffer.get() & 0xFF);
            
            // 实体线性速度
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());
            
            // 实体位置
            result.put("position.x", buffer.getDouble());
            result.put("position.y", buffer.getDouble());
            result.put("position.z", buffer.getDouble());

            // 实体方向
            result.put("orientation.psi", buffer.getFloat());
            result.put("orientation.theta", buffer.getFloat());
            result.put("orientation.phi", buffer.getFloat());
            
            // 实体外观
            result.put("appearance", buffer.getInt() & 0xFFFFFFFFL);

            // 航位推算参数
            int deadReckoningAlgorithmValue = buffer.get() & 0xFF;
            result.put("dead.reckoning.algorithm", deadReckoningAlgorithmValue);
            DISEnums.DeadReckoningAlgorithm deadReckoningAlgorithm = DISEnums.DeadReckoningAlgorithm.fromValue(deadReckoningAlgorithmValue);
            result.put("dead.reckoning.algorithm.description", deadReckoningAlgorithm.getDescription());
            
            // 其他参数（15字节）
            byte[] otherParams = new byte[15];
            buffer.get(otherParams);
            result.put("dead.reckoning.other.parameters", otherParams);
            
            result.put("dead.reckoning.linear.acceleration.x", buffer.getFloat());
            result.put("dead.reckoning.linear.acceleration.y", buffer.getFloat());
            result.put("dead.reckoning.linear.acceleration.z", buffer.getFloat());
            result.put("dead.reckoning.angular.velocity.x", buffer.getFloat());
            result.put("dead.reckoning.angular.velocity.y", buffer.getFloat());
            result.put("dead.reckoning.angular.velocity.z", buffer.getFloat());
            
            // 实体标记（12字节ASCII字符串）
            byte[] marking = new byte[12];
            buffer.get(marking);
            String markingStr = new String(marking, StandardCharsets.US_ASCII).trim();
            result.put("entity.marking", markingStr);
            
            // 能力
            result.put("capabilities", buffer.getInt() & 0xFFFFFFFFL);

            List<Map<String, Object>> articulationList = new ArrayList<>();
            for (int i = 0; i < articulationCount; i++) {
                Map<String, Object> ap = new HashMap<>();

                ap.put("parameter.type.designator", buffer.get());
                ap.put("change.indicator", buffer.get());
                ap.put("part.attached.to", buffer.getShort() & 0xFFFF);
                ap.put("parameter.type", buffer.getInt());
                ap.put("parameter.value", buffer.getDouble());

                articulationList.add(ap);
            }

            result.put("articulation.parameters", articulationList);
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Entity State");
            
        } catch (Exception e) {
            result.put("entity.state.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析开火PDU
     */
    private void parseFirePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 1. 发射实体 ID (6)
            result.put("firing.entity.site", buffer.getShort() & 0xFFFF);
            result.put("firing.entity.application", buffer.getShort() & 0xFFFF);
            result.put("firing.entity.entity", buffer.getShort() & 0xFFFF);

            // 2. 目标实体 ID (6)
            result.put("target.entity.site", buffer.getShort() & 0xFFFF);
            result.put("target.entity.application", buffer.getShort() & 0xFFFF);
            result.put("target.entity.entity", buffer.getShort() & 0xFFFF);

            // 3. 弹药 ID (6)
            result.put("munition.id.site", buffer.getShort() & 0xFFFF);
            result.put("munition.id.application", buffer.getShort() & 0xFFFF);
            result.put("munition.id.entity", buffer.getShort() & 0xFFFF);

            // 4. 事件 ID (6)
            Map<String, Object> eventId = new HashMap<>();
            eventId.put("site", buffer.getShort() & 0xFFFF);
            eventId.put("application", buffer.getShort() & 0xFFFF);
            eventId.put("event.number", buffer.getShort() & 0xFFFF);
            result.put("event.id", eventId);

            // 5. 开火任务索引 (4)
            result.put("fire.mission.index", buffer.getInt() & 0xFFFFFFFFL);

            // 6. 世界坐标 (24)
            result.put("location.x", buffer.getDouble());
            result.put("location.y", buffer.getDouble());
            result.put("location.z", buffer.getDouble());

            // 7. 爆发描述符 (Burst Descriptor) (8)
            // 包含 Munition Type (8字节)
            result.put("burst.munition.kind", buffer.get() & 0xFF);
            result.put("burst.munition.domain", buffer.get() & 0xFF);
            result.put("burst.munition.country", buffer.getShort() & 0xFFFF);
            result.put("burst.munition.category", buffer.get() & 0xFF);
            result.put("burst.munition.subcategory", buffer.get() & 0xFF);
            result.put("burst.munition.specific", buffer.get() & 0xFF);
            result.put("burst.munition.extra", buffer.get() & 0xFF);

            result.put("burst.munition.warhead", buffer.getShort() & 0xFFFF);
            result.put("burst.munition.fuse", buffer.getShort() & 0xFFFF);
            result.put("burst.munition.quantity", buffer.getShort() & 0xFFFF);
            result.put("burst.munition.rate", buffer.getShort() & 0xFFFF);

            // 8. 弹药速度向量 (Velocity) (12)
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());

            // 9. 射程 (4)
            result.put("range", buffer.getFloat());

            result.put("parsed.successfully", true);
            result.put("pdu.description", "Fire Event");

        } catch (Exception e) {
            result.put("fire.pdu.parse.error", e.getMessage());
        }
    }

    /**
     * 解析爆炸PDU
     */
    private void parseDetonationPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 爆炸实体ID
            result.put("detonating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("detonating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("detonating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 目标实体ID
            result.put("target.entity.site", buffer.getShort() & 0xFFFF);
            result.put("target.entity.application", buffer.getShort() & 0xFFFF);
            result.put("target.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 弹药ID
            result.put("munition.id.site", buffer.getShort() & 0xFFFF);
            result.put("munition.id.application", buffer.getShort() & 0xFFFF);
            result.put("munition.id.entity", buffer.getShort() & 0xFFFF);
            
            // 事件ID
            result.put("event.id.site", buffer.getShort() & 0xFFFF);
            result.put("event.id.application", buffer.getShort() & 0xFFFF);
            result.put("event.id.entity", buffer.getShort() & 0xFFFF);

            // 速度
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());
            
            // 世界坐标系中的位置
            result.put("location.world.x", buffer.getDouble());
            result.put("location.world.y", buffer.getDouble());
            result.put("location.world.z", buffer.getDouble());
            
            // 爆发描述符
            result.put("detonation.description.kind", buffer.get() & 0xFF);
            result.put("detonation.description.domain", buffer.get() & 0xFF);
            result.put("detonation.description.country", buffer.getShort() & 0xFFFF);
            result.put("detonation.description.category", buffer.get() & 0xFF);
            result.put("detonation.description.subcategory", buffer.get() & 0xFF);
            result.put("detonation.description.specific", buffer.get() & 0xFF);
            result.put("detonation.description.extra", buffer.get() & 0xFF);

            result.put("detonation.description.explosive.material", buffer.get() & 0xFF);
            buffer.getShort();
            result.put("detonation.description.explosive.force", buffer.getFloat());

            result.put("location.entity.x", buffer.getFloat());
            result.put("location.entity.y", buffer.getFloat());
            result.put("location.entity.z", buffer.getFloat());

            // 爆炸结果
            int detonationResultValue = buffer.get() & 0xFF;
            result.put("detonation.result", detonationResultValue);
            DISEnums.DetonationResult detonationResult = DISEnums.DetonationResult.fromValue(detonationResultValue);
            result.put("detonation.result.description", detonationResult.getDescription());

            // 可变记录数
            int variableDatumRecordCount = buffer.getInt();
            result.put("variable.record.count", variableDatumRecordCount);
            buffer.getShort();

            int fixedVariableRecordCount = buffer.getShort() & 0xFFFF;
            for (int i=0;i<fixedVariableRecordCount;i++)
            {
                int recordType = buffer.get() & 0xFF;
                byte[] raw = new byte[120];
                buffer.get(raw);
                result.put("variable." + i + ".type", recordType);
                result.put("variable" + i + ".value", bytesToBase64(raw));
            }

            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Detonation Event");
            
        } catch (Exception e) {
            result.put("detonation.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析通用PDU - 为其他PDU类型提供基本解析
     */
    private void parseGenericPDU(ByteBuffer buffer, Map<String, Object> result, DISEnums.PDUType type) {
        try {
            // 尝试解析实体ID（如果存在）
            if (buffer.remaining() >= 6) {
                result.put("entity.site", buffer.getShort() & 0xFFFF);
                result.put("entity.application", buffer.getShort() & 0xFFFF);
                result.put("entity.entity", buffer.getShort() & 0xFFFF);
            }
            
            // 记录剩余数据大小
            result.put("remaining.bytes", buffer.remaining());
            result.put("parsed.successfully", true);
            result.put("pdu.description", type.getDescription() + " (basic parse)");
            
        } catch (Exception e) {
            result.put("generic.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析碰撞PDU
     */
    private void parseCollisionPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 碰撞实体ID
            result.put("issuing.entity.site", buffer.getShort() & 0xFFFF);
            result.put("issuing.entity.application", buffer.getShort() & 0xFFFF);
            result.put("issuing.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 碰撞实体ID
            result.put("colliding.entity.site", buffer.getShort() & 0xFFFF);
            result.put("colliding.entity.application", buffer.getShort() & 0xFFFF);
            result.put("colliding.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 事件ID
            result.put("event.id", buffer.getShort() & 0xFFFF);
            
            // 碰撞类型
            result.put("collision.type", buffer.get() & 0xFF);
            
            // 速度
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());
            
            // 质量
            result.put("mass", buffer.getFloat());
            
            // 位置
            result.put("location.x", buffer.getFloat());
            result.put("location.y", buffer.getFloat());
            result.put("location.z", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Collision Event");
            
        } catch (Exception e) {
            result.put("collision.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析服务请求PDU
     */
    private void parseServiceRequestPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 请求实体ID
            result.put("requesting.entity.site", buffer.getShort() & 0xFFFF);
            result.put("requesting.entity.application", buffer.getShort() & 0xFFFF);
            result.put("requesting.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 服务类型
            result.put("service.type", buffer.get() & 0xFF);
            
            // 补给类型
            result.put("supply.type", buffer.get() & 0xFF);
            
            // 数量
            result.put("quantity", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Service Request");
            
        } catch (Exception e) {
            result.put("service.request.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析创建实体PDU
     */
    private void parseCreateEntityPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 创建实体ID
            result.put("creating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("creating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("creating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 实体类型
            result.put("entity.kind", buffer.get() & 0xFF);
            result.put("entity.domain", buffer.get() & 0xFF);
            result.put("entity.country", buffer.getShort() & 0xFFFF);
            result.put("entity.category", buffer.get() & 0xFF);
            result.put("entity.subcategory", buffer.get() & 0xFF);
            result.put("entity.specific", buffer.get() & 0xFF);
            result.put("entity.extra", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Create Entity");
            
        } catch (Exception e) {
            result.put("create.entity.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析移除实体PDU
     */
    private void parseRemoveEntityPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 移除实体ID
            result.put("removing.entity.site", buffer.getShort() & 0xFFFF);
            result.put("removing.entity.application", buffer.getShort() & 0xFFFF);
            result.put("removing.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Remove Entity");
            
        } catch (Exception e) {
            result.put("remove.entity.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析开始/恢复PDU
     */
    private void parseStartResumePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 仿真时间
            result.put("simulation.time", buffer.getInt() & 0xFFFFFFFFL);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Start/Resume Simulation");
            
        } catch (Exception e) {
            result.put("start.resume.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析停止/冻结PDU
     */
    private void parseStopFreezePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 原因
            result.put("reason", buffer.get() & 0xFF);
            
            // 冻结模式
            result.put("freeze.mode", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Stop/Freeze Simulation");
            
        } catch (Exception e) {
            result.put("stop.freeze.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析确认PDU
     */
    private void parseAcknowledgePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 确认类型
            result.put("acknowledge.flag", buffer.getShort() & 0xFFFF);
            
            // 响应标志
            result.put("response.flag", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Acknowledge Response");
            
        } catch (Exception e) {
            result.put("acknowledge.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析动作请求PDU
     */
    private void parseActionRequestPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 动作ID
            result.put("action.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 动作类型
            result.put("action.type", buffer.get() & 0xFF);
            
            // 固定记录数
            result.put("fixed.datum.record.count", buffer.getShort() & 0xFFFF);
            
            // 可变记录数
            result.put("variable.datum.record.count", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Action Request");
            
        } catch (Exception e) {
            result.put("action.request.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析动作响应PDU
     */
    private void parseActionResponsePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 响应状态
            result.put("response.status", buffer.getInt() & 0xFFFFFFFFL);
            
            // 固定记录数
            result.put("fixed.datum.record.count", buffer.getShort() & 0xFFFF);
            
            // 可变记录数
            result.put("variable.datum.record.count", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Action Response");
            
        } catch (Exception e) {
            result.put("action.response.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析数据查询PDU
     */
    private void parseDataQueryPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 时间间隔
            result.put("time.interval", buffer.getInt() & 0xFFFFFFFFL);
            
            // 固定记录数
            result.put("fixed.datum.record.count", buffer.getShort() & 0xFFFF);
            
            // 可变记录数
            result.put("variable.datum.record.count", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Data Query");
            
        } catch (Exception e) {
            result.put("data.query.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析数据集PDU
     */
    private void parseDataSetPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            // Padding
            buffer.getInt();
            
            // 固定记录数
            int fixedDatumRecordCount = buffer.getInt();
            result.put("fixed.datum.record.count", fixedDatumRecordCount);
            
            // 可变记录数
            int variableDatumRecordCount = buffer.getInt();
            result.put("variable.datum.record.count", variableDatumRecordCount);

            for (int i=0;i<fixedDatumRecordCount;i++)
            {
                long datumId = buffer.getInt() & 0xFFFFFFFFL;
                // 根据 DIS 标准，Fixed Datum 的 Value 始终占用 32位 (4字节)
                int datumValue = buffer.getInt();

                result.put("fixed.datum." + i + ".id", datumId);
                result.put("fixed.datum." + i + ".type", DISEnums.DatumIdentifier.fromInt((int)datumId));
                result.put("fixed.datum." + i + ".value", datumValue);
            }

            // 5. 解析可变参数 (Variable Datums)
            for (int i=0;i<variableDatumRecordCount;i++)
            {
                long datumId = buffer.getInt() & 0xFFFFFFFFL;
                int datumLengthInBits = buffer.getInt(); // 长度以 bit 为单位
                int datumLengthInBytes = (datumLengthInBits + 7) / 8;

                byte[] datumValue = new byte[datumLengthInBytes];
                buffer.get(datumValue);

                // 关键：Variable Datum 必须按 64 位(8字节)对齐填充
                int paddingNeeded = (8 - (datumLengthInBytes % 8)) % 8;
                if (paddingNeeded > 0) {
                    buffer.position(buffer.position() + paddingNeeded);
                }
                result.put("variable.datum." + i + ".id", datumId);
                result.put("variable.datum." + i + ".value_asc", bytesToAscii(datumValue));
                result.put("variable.datum." + i + ".value_base64", bytesToBase64(datumValue));
            }

            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Set Data");
            
        } catch (Exception e) {
            result.put("data.set.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析事件报告PDU
     */
    private void parseEventReportPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 1. 发起实体ID (6 bytes)
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);

            // 2. 接收实体ID (6 bytes)
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);

            // 3. 事件类型 (Event Type) - 修正：必须是 Int (4 bytes)
            result.put("event.type", buffer.getInt() & 0xFFFFFFFFL);

            buffer.getInt();

            // 5. 固定参数数量 (Fixed Datum Count) - 修正：必须是 Int (4 bytes)
            long fixedDatumCount = buffer.getInt() & 0xFFFFFFFFL;
            result.put("fixed.datum.count", fixedDatumCount);

            // 6. 可变参数数量 (Variable Datum Count) - 修正：必须是 Int (4 bytes)
            long variableDatumCount = buffer.getInt() & 0xFFFFFFFFL;
            result.put("variable.datum.count", variableDatumCount);

            result.put("parsed.successfully", true);
            result.put("pdu.description", "Event Report PDU");

            // 后续同样需要循环解析 Datum 列表...
            // 4. 解析固定参数 (Fixed Datums)
            for (int i = 0; i < fixedDatumCount; i++) {
                long datumId = buffer.getInt() & 0xFFFFFFFFL;
                // 根据 DIS 标准，Fixed Datum 的 Value 始终占用 32位 (4字节)
                int datumValue = buffer.getInt();

                result.put("fixed.datum." + i + ".id", datumId);
                result.put("fixed.datum." + i + ".type", DISEnums.DatumIdentifier.fromInt((int)datumId));
                result.put("fixed.datum." + i + ".value", datumValue);
            }

            // 5. 解析可变参数 (Variable Datums)
            for (int i = 0; i < variableDatumCount; i++) {
                long datumId = buffer.getInt() & 0xFFFFFFFFL;
                int datumLengthInBits = buffer.getInt(); // 长度以 bit 为单位
                int datumLengthInBytes = (datumLengthInBits + 7) / 8;

                byte[] datumValue = new byte[datumLengthInBytes];
                buffer.get(datumValue);

                // 关键：Variable Datum 必须按 64 位(8字节)对齐填充
                int paddingNeeded = (8 - (datumLengthInBytes % 8)) % 8;
                if (paddingNeeded > 0) {
                    buffer.position(buffer.position() + paddingNeeded);
                }

                result.put("variable.datum." + i + ".id", datumId);
                result.put("variable.datum." + i + ".value_asc", bytesToAscii(datumValue));
                result.put("variable.datum." + i + ".value_base64", bytesToBase64(datumValue));
            }
        } catch (Exception e) {
            result.put("event.report.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析注释PDU
     */
    private void parseCommentPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 注释类型
            result.put("comment.type", buffer.getShort() & 0xFFFF);
            
            // 注释长度
            int commentLength = buffer.getShort() & 0xFFFF;
            result.put("comment.length", commentLength);
            
            // 注释内容
            if (commentLength > 0 && buffer.remaining() >= commentLength) {
                byte[] commentBytes = new byte[commentLength];
                buffer.get(commentBytes);
                String comment = new String(commentBytes, StandardCharsets.UTF_8);
                result.put("comment.text", comment);
            }
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Comment");
            
        } catch (Exception e) {
            result.put("comment.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析电磁辐射PDU
     */
    private void parseElectromagneticEmissionPDU(ByteBuffer buffer, Map<String, Object> result)
    {
        try {

            /* ================= Emitting Entity ID (6) ================= */
            Map<String, Object> emitting = new HashMap<>();
            emitting.put("site", buffer.getShort() & 0xFFFF);
            emitting.put("application", buffer.getShort() & 0xFFFF);
            emitting.put("entity", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity", emitting);

            /* ================= Event ID (6) ================= */
            Map<String, Object> eventId = new HashMap<>();
            eventId.put("site", buffer.getShort() & 0xFFFF);
            eventId.put("application", buffer.getShort() & 0xFFFF);
            eventId.put("event.number", buffer.getShort() & 0xFFFF);
            result.put("event.id", eventId);

            /* ================= State + System Count ================= */
            result.put("state.update.indicator", buffer.get() & 0xFF);

            int systemCount = buffer.get() & 0xFF;
            result.put("system.count", systemCount);

            buffer.getShort(); // padding (2)

            List<Map<String, Object>> systems = new ArrayList<>();

            /* ================= Parse Systems ================= */
            for (int i = 0; i < systemCount; i++) {

                Map<String, Object> system = new HashMap<>();

                int systemDataLength = buffer.get() & 0xFF; // 以32位字为单位的长度
                system.put("system.data.length", systemDataLength);

                int beamCount = buffer.get() & 0xFF;
                system.put("beam.count", beamCount);

                buffer.getShort(); // padding (2)

                system.put("emitter.name", buffer.getShort() & 0xFFFF);
                system.put("emitter.function", buffer.get() & 0xFF);
                system.put("emitter.id.number", buffer.get() & 0xFF);

                Map<String, Object> location = new HashMap<>();
                location.put("x", buffer.getFloat());
                location.put("y", buffer.getFloat());
                location.put("z", buffer.getFloat());
                system.put("emitter.location", location);

                List<Map<String, Object>> beams = new ArrayList<>();

                for (int b = 0; b < beamCount; b++) {
                    Map<String, Object> beam = new HashMap<>();

                    // 波束记录头部
                    // 根据测试数据，可能需要对齐填充
                    // 先读取波束数据长度
                    int beamDataLength = buffer.get() & 0xFF; // 以32位字为单位的长度
                    beam.put("beam.data.length", beamDataLength);

                    int beamParameterNumber = buffer.get() & 0xFF;
                    beam.put("beam.parameter.number", beamParameterNumber);

                    int beamParameterIndex = buffer.getShort() & 0xFFFF;
                    beam.put("beam.parameter.index", beamParameterIndex);

                    Map<String, Object> fundamental = new HashMap<>();
                    fundamental.put("frequency", buffer.getFloat());
                    fundamental.put("frequency.range", buffer.getFloat());
                    fundamental.put("effective.power", buffer.getFloat());
                    fundamental.put("pulse.repetition.frequency", buffer.getFloat());
                    fundamental.put("pulse.width", buffer.getFloat());

                    beam.put("fundamental.parameters", fundamental);

                    Map<String, Object> beamData = new HashMap<>();
                    beamData.put("azimuth.center", buffer.getFloat());
                    beamData.put("azimuth.sweep", buffer.getFloat());
                    beamData.put("elevation.center", buffer.getFloat());
                    beamData.put("elevation.sweep", buffer.getFloat());
                    beamData.put("sweep.sync", buffer.getFloat());

                    beam.put("beam.data", beamData);

                    int beamFunction = buffer.get() & 0xFF;
                    beam.put("beam.function", beamFunction);

                    int numberOfTarget = buffer.get() & 0xFF;
                    beam.put("beam.target.number", numberOfTarget);

                    int highDensityJam = buffer.get() & 0xFF;
                    beam.put("beam.high.density.jam", highDensityJam);

                    int beamStatus = buffer.get() & 0xFF;
                    beam.put("beam.status", beamStatus);

                    int jamKind = buffer.get() & 0xFF;
                    beam.put("beam.jam.kind", jamKind);

                    int jamCategory = buffer.get() & 0xFF;
                    beam.put("beam.jam.category", jamCategory);

                    int jamSubCategory = buffer.get() & 0xFF;
                    beam.put("beam.jam.sub.category", jamSubCategory);

                    int jamSpecific = buffer.get() & 0xFF;
                    beam.put("beam.jam.specific", jamSpecific);

                    List<Map<String, Object>> targets = new ArrayList<>();
                    for (int t = 0; t < numberOfTarget; t++) {
                        Map<String, Object> target = new HashMap<>();

                        target.put("site", buffer.getShort() & 0xFFFF);
                        target.put("application", buffer.getShort() & 0xFFFF);
                        target.put("entity", buffer.getShort() & 0xFFFF);
                        target.put("emitter.id", buffer.get() & 0xFF);
                        target.put("beam.id", buffer.get() & 0xFF);

                        targets.add(target);
                    }
                    beam.put("track.jam.targets", targets);
                    beams.add(beam);
                }

                system.put("beams", beams);
                systems.add(system);
            }

            result.put("systems", systems);
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Electromagnetic Emission");

        } catch (Exception e) {
            result.put("electromagnetic.emission.pdu.parse.error", e.getMessage());
            result.put("electromagnetic.emission.pdu.parse.exception", e.getClass().getName());
            result.put("electromagnetic.emission.pdu.parse.stacktrace", e.getStackTrace());
            result.put("parsed.successfully", false);
        }
    }

    /**
     * 解析指示器PDU
     */
    private void parseDesignatorPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 指示实体ID
            result.put("designating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("designating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("designating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 目标实体ID
            result.put("target.entity.site", buffer.getShort() & 0xFFFF);
            result.put("target.entity.application", buffer.getShort() & 0xFFFF);
            result.put("target.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 指示器代码
            result.put("designator.code", buffer.getInt() & 0xFFFFFFFFL);
            
            // 指示器功率
            result.put("designator.power", buffer.getFloat());
            
            // 波长
            result.put("wavelength", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Designator");
            
        } catch (Exception e) {
            result.put("designator.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析聚合状态PDU
     */
    private void parseAggregateStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 聚合实体ID
            result.put("aggregate.id.site", buffer.getShort() & 0xFFFF);
            result.put("aggregate.id.application", buffer.getShort() & 0xFFFF);
            result.put("aggregate.id.entity", buffer.getShort() & 0xFFFF);
            
            // 力量标识
            result.put("force.id", buffer.get() & 0xFF);
            
            // 聚合类型
            result.put("aggregate.type", buffer.get() & 0xFF);
            
            // 聚合子类型
            result.put("aggregate.subtype", buffer.get() & 0xFF);
            
            // 聚合形态
            result.put("aggregate.formation", buffer.get() & 0xFF);
            
            // 聚合状态
            result.put("aggregate.state", buffer.get() & 0xFF);
            
            // 位置
            result.put("position.x", buffer.getFloat());
            result.put("position.y", buffer.getFloat());
            result.put("position.z", buffer.getFloat());
            
            // 方向
            result.put("orientation.x", buffer.getFloat());
            result.put("orientation.y", buffer.getFloat());
            result.put("orientation.z", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Aggregate State");
            
        } catch (Exception e) {
            result.put("aggregate.state.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析实体状态更新PDU
     */
    private void parseEntityStateUpdatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 实体ID
            result.put("entity.site", buffer.getShort() & 0xFFFF);
            result.put("entity.application", buffer.getShort() & 0xFFFF);
            result.put("entity.entity", buffer.getShort() & 0xFFFF);
            
            // 力量标识
            result.put("force.id", buffer.get() & 0xFF);
            
            // 实体类型
            result.put("entity.kind", buffer.get() & 0xFF);
            result.put("entity.domain", buffer.get() & 0xFF);
            result.put("entity.country", buffer.getShort() & 0xFFFF);
            result.put("entity.category", buffer.get() & 0xFF);
            result.put("entity.subcategory", buffer.get() & 0xFF);
            result.put("entity.specific", buffer.get() & 0xFF);
            result.put("entity.extra", buffer.get() & 0xFF);
            
            // 实体线性速度
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());
            
            // 实体位置
            result.put("position.x", buffer.getFloat());
            result.put("position.y", buffer.getFloat());
            result.put("position.z", buffer.getFloat());
            
            // 实体方向
            result.put("orientation.psi", buffer.getFloat());
            result.put("orientation.theta", buffer.getFloat());
            result.put("orientation.phi", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Entity State Update");
            
        } catch (Exception e) {
            result.put("entity.state.update.pdu.parse.error", e.getMessage());
        }
    }

    private void parseTransmitterPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 1. 发射实体 ID (6字节)
            result.put("transmitting.entity.site", buffer.getShort() & 0xFFFF);
            result.put("transmitting.entity.application", buffer.getShort() & 0xFFFF);
            result.put("transmitting.entity.entity", buffer.getShort() & 0xFFFF);

            // 2. 无线电编号 (2字节)
            result.put("radio.number", buffer.getShort() & 0xFFFF);

            // 3. 无线电类型 (Radio Type - 8字节实体类型结构)
            Map<String, Object> radioType = new HashMap<>();
            radioType.put("kind", buffer.get() & 0xFF);
            radioType.put("domain", buffer.get() & 0xFF);
            radioType.put("country", buffer.getShort() & 0xFFFF);
            radioType.put("category", buffer.get() & 0xFF);
            radioType.put("subcategory", buffer.get() & 0xFF);
            radioType.put("specific", buffer.get() & 0xFF);
            radioType.put("extra", buffer.get() & 0xFF);
            result.put("radio.type", radioType);

            // 4. 发射状态与输入源 (各1字节 + 2字节对齐)
            result.put("transmit.state", buffer.get() & 0xFF);
            result.put("input.source", buffer.get() & 0xFF);
            result.put("transmit.parameter.count", buffer.getShort() & 0xFFFF);

            // 5. 天线世界坐标 (3个 Double = 24字节)
            result.put("antenna.location.x", buffer.getDouble());
            result.put("antenna.location.y", buffer.getDouble());
            result.put("antenna.location.z", buffer.getDouble());

            // 6. 天线相对位置 (3个 Float = 12字节)
            result.put("relative.location.x", buffer.getFloat());
            result.put("relative.location.y", buffer.getFloat());
            result.put("relative.location.z", buffer.getFloat());

            // 7. 天线模式头部 (8字节)
            result.put("antenna.pattern.type", buffer.getShort() & 0xFFFF);
            result.put("antenna.pattern.length", buffer.getShort() & 0xFFFF);

            // 8. 频率与带宽
            result.put("frequency", buffer.getLong()); // 64-bit Frequency
            result.put("frequency.bandwidth", buffer.getFloat());
            result.put("power", buffer.getFloat());

            result.put("modulation.spread.spectrum", buffer.getShort() & 0xFFFF);
            result.put("modulation.major.enumeration", buffer.getShort() & 0xFFFF);
            result.put("modulation.detail", buffer.getShort() & 0xFFFF);
            result.put("modulation.ratio.system", buffer.getShort() & 0xFFFF);

            result.put("crypto.system", buffer.getShort() & 0xFFFF);
            result.put("crypto.key", buffer.getShort() & 0xFFFF);
            result.put("modulation.parameter.length", buffer.get() & 0xFF);

            // padding
            buffer.get();
            buffer.getShort();

            switch ((int) result.get("modulation.major.enumeration")) {
                case 7 -> {  // Coded 编码调制（数字信号）
                    result.put("modulation.type", "Coded");
                    result.put("modulation.scheme", buffer.getShort() & 0xFFFF);
                    result.put("modulation.version", buffer.getShort() & 0xFFFF);
                    result.put("modulation.extra", buffer.getInt() & 0xFFFFFFFFL);
                }
                case 5 -> { // Pulse
                    result.put("modulation.type", "Pulse");
                    result.put("modulation.prf", buffer.getFloat());
                    result.put("modulation.pulseWidth", buffer.getFloat());
                }
                default -> {
                    byte[] raw = new byte[(int) result.get("modulation.parameter.length")];
                    buffer.get(raw);
                    result.put("modulation.value_base64", bytesToBase64(raw));
                }
            }
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Transmitter");
        } catch (Exception e) {
            result.put("transmitter.parse.error", e.getMessage());
        }
    }

    /**
     * 解析接收器PDU
     */
    private void parseReceiverPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 无线电编号
            result.put("radio.number", buffer.getShort() & 0xFFFF);
            
            // 无线电类型
            result.put("radio.type", buffer.getShort() & 0xFFFF);
            
            // 接收状态
            result.put("receive.state", buffer.getShort() & 0xFFFF);
            
            // 接收功率
            result.put("received.power", buffer.getFloat());
            
            // 天线位置
            result.put("antenna.location.x", buffer.getFloat());
            result.put("antenna.location.y", buffer.getFloat());
            result.put("antenna.location.z", buffer.getFloat());
            
            // 天线方向
            result.put("antenna.azimuth", buffer.getFloat());
            result.put("antenna.elevation", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Receiver");
            
        } catch (Exception e) {
            result.put("receiver.pdu.parse.error", e.getMessage());
        }
    }

    /**
     * 解析IFF/ATC导航辅助PDU
     */
    private void parseIffAtcNavaidsPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 1. 发射实体 ID (48 字节)
            result.put("emitting.entity.site", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity.application", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity.entity", buffer.getShort() & 0xFFFF);

            // 2. 事件 ID (48 字节)
            Map<String, Object> eventId = new HashMap<>();
            eventId.put("site", buffer.getShort() & 0xFFFF);
            eventId.put("application", buffer.getShort() & 0xFFFF);
            eventId.put("event.number", buffer.getShort() & 0xFFFF);
            result.put("event.id", eventId);

            // 3. 天线相对位置 (Relative Antenna Location)
            result.put("antenna.location.x", buffer.getFloat());
            result.put("antenna.location.y", buffer.getFloat());
            result.put("antenna.location.z", buffer.getFloat());

            // 4. 系统 ID (System ID) (48)
            // 包含 System Type (16-bit), System Name (16-bit)
            result.put("system.type", buffer.getShort() & 0xFFFF);
            result.put("system.name", buffer.getShort() & 0xFFFF);
            result.put("system.mode", buffer.get() & 0xFF);
            result.put("system.options", buffer.get() & 0xFF);
            buffer.getShort();

            // 5. 基础数据 (Fundamental Data) (16 字节)
            result.put("system.designator", buffer.get() & 0xFF);
            result.put("system.specific.data", buffer.get() & 0xFF);

            // 6. Layer1
            result.put("fundamental.system.status", buffer.get() & 0xFF);
            result.put("fundamental.alternative.parameter", buffer.get() & 0xFF);
            result.put("fundamental.information.layers", buffer.get() & 0xFF);
            result.put("fundamental.modifier", buffer.get() & 0xFF);
            result.put("fundamental.parameter.1", buffer.getShort() & 0xFFFF);
            result.put("fundamental.parameter.2", buffer.getShort() & 0xFFFF);
            result.put("fundamental.parameter.3", buffer.getShort() & 0xFFFF);
            result.put("fundamental.parameter.4", buffer.getShort() & 0xFFFF);
            result.put("fundamental.parameter.5", buffer.getShort() & 0xFFFF);
            result.put("fundamental.parameter.6", buffer.getShort() & 0xFFFF);

            if (buffer.remaining() >= 28)
            {
                buffer.getShort();
                buffer.getInt();

                result.put("layer2.number", buffer.get() & 0xFF);
                result.put("layer2.specific.information", buffer.get() & 0xFF);
                result.put("layer2.length", buffer.getShort() & 0xFFFF);

                result.put("layer2.azimuth.center", buffer.getFloat());
                result.put("layer2.azimuth.sweep", buffer.getFloat());
                result.put("layer2.elevation.center", buffer.getFloat());
                result.put("layer2.elevation.sweep", buffer.getFloat());
                result.put("layer2.sweep.sync", buffer.getFloat());

                result.put("layer2.secondary.operational.parameter1", buffer.get() & 0xFF);
                result.put("layer2.secondary.operational.parameter2", buffer.get() & 0xFF);
                result.put("layer2.secondary.operational.data.record.number", buffer.getShort() & 0xFFFF);
            }
            buffer.position(buffer.limit());

            result.put("parsed.successfully", true);
            result.put("pdu.description", "IFF");

        } catch (Exception e) {
            result.put("iff.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析外观PDU
     */
    private void parseAppearancePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 实体ID
            result.put("entity.site", buffer.getShort() & 0xFFFF);
            result.put("entity.application", buffer.getShort() & 0xFFFF);
            result.put("entity.entity", buffer.getShort() & 0xFFFF);
            
            // 外观值
            result.put("appearance.value", buffer.getInt() & 0xFFFFFFFFL);
            
            // 外观类型
            result.put("appearance.type", buffer.getShort() & 0xFFFF);
            
            // 外观子类型
            result.put("appearance.subtype", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Appearance");
            
        } catch (Exception e) {
            result.put("appearance.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析补给提供PDU
     */
    private void parseResupplyOfferPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 补给类型
            result.put("supply.type", buffer.getShort() & 0xFFFF);
            
            // 补给数量
            result.put("supply.quantity", buffer.getShort() & 0xFFFF);
            
            // 补给位置
            result.put("supply.location.x", buffer.getFloat());
            result.put("supply.location.y", buffer.getFloat());
            result.put("supply.location.z", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Resupply Offer");
            
        } catch (Exception e) {
            result.put("resupply.offer.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析补给接收PDU
     */
    private void parseResupplyReceivedPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 补给类型
            result.put("supply.type", buffer.getShort() & 0xFFFF);
            
            // 补给数量
            result.put("supply.quantity", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Resupply Received");
            
        } catch (Exception e) {
            result.put("resupply.received.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析补给取消PDU
     */
    private void parseResupplyCancelPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Resupply Cancel");
            
        } catch (Exception e) {
            result.put("resupply.cancel.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析修理完成PDU
     */
    private void parseRepairCompletePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 修理类型
            result.put("repair.type", buffer.getShort() & 0xFFFF);
            
            // 修理位置
            result.put("repair.location.x", buffer.getFloat());
            result.put("repair.location.y", buffer.getFloat());
            result.put("repair.location.z", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Repair Complete");
            
        } catch (Exception e) {
            result.put("repair.complete.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析修理响应PDU
     */
    private void parseRepairResponsePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 修理状态
            result.put("repair.status", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Repair Response");
            
        } catch (Exception e) {
            result.put("repair.response.pdu.parse.error", e.getMessage());
        }
    }

    private void parseSignalPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // Entity ID (6 bytes)
            result.put("emitting.entity.site", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity.application", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity.entity", buffer.getShort() & 0xFFFF);

            // Radio ID
            result.put("radio.number", buffer.getShort() & 0xFFFF);

            // Encoding Scheme
            result.put("encoding.scheme", buffer.getShort() & 0xFFFF);

            // TDL Type
            result.put("tdl.type", buffer.getShort() & 0xFFFF);

            // Sample Rate
            result.put("sample.rate", buffer.getInt());

            // Data Length 是 16 bit (单位：bits)
            int dataLengthInBits = buffer.getShort() & 0xFFFF;
            result.put("data.length.bits", dataLengthInBits);

            // Samples (16 bit)
            int samples = buffer.getShort() & 0xFFFF;
            result.put("samples.count", samples);

            // 计算数据长度（bytes）
            int dataLengthInBytes = (dataLengthInBits + 7) / 8;

            if (dataLengthInBytes > 0) {
                byte[] data = new byte[dataLengthInBytes];
                buffer.get(data);

                result.put("signal.data_base64", bytesToBase64(data));
                result.put("signal.data_ascii", bytesToAscii(data));
            }
            if (buffer.remaining() > 0)
            {
                byte[] padding = new byte[buffer.remaining()];
                buffer.get(padding);
            }

            result.put("parsed.successfully", true);
            result.put("pdu.description", "Signal PDU");

        } catch (Exception e) {
            result.put("signal.pdu.parse.error", e.getMessage());
        }
    }

    /**
     * 解析水下声学PDU
     */
    private void parseUnderwaterAcousticPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发射实体ID
            result.put("emitting.entity.site", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity.application", buffer.getShort() & 0xFFFF);
            result.put("emitting.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 事件ID
            result.put("event.id", buffer.getShort() & 0xFFFF);
            
            // 声源状态
            result.put("acoustic.source.state", buffer.get() & 0xFF);
            
            // 声源索引
            result.put("acoustic.source.index", buffer.get() & 0xFF);
            
            // 声源数量
            result.put("acoustic.source.count", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Underwater Acoustic PDU");
            
        } catch (Exception e) {
            result.put("underwater.acoustic.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析补充辐射/实体状态PDU
     */
    private void parseSupplementalEmissionEntityStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 实体ID
            result.put("entity.site", buffer.getShort() & 0xFFFF);
            result.put("entity.application", buffer.getShort() & 0xFFFF);
            result.put("entity.entity", buffer.getShort() & 0xFFFF);
            
            // 辐射状态
            result.put("emission.state", buffer.get() & 0xFF);
            
            // 辐射索引
            result.put("emission.index", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Supplemental Emission/Entity State PDU");
            
        } catch (Exception e) {
            result.put("supplemental.emission.entity.state.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析内部通信信号PDU
     */
    private void parseIntercomSignalPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发射实体ID
            result.put("transmitting.entity.site", buffer.getShort() & 0xFFFF);
            result.put("transmitting.entity.application", buffer.getShort() & 0xFFFF);
            result.put("transmitting.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 通信ID
            result.put("communication.id", buffer.getShort() & 0xFFFF);
            
            // 通信类型
            result.put("communication.type", buffer.getShort() & 0xFFFF);
            
            // 数据长度
            int dataLength = buffer.getShort() & 0xFFFF;
            result.put("data.length", dataLength);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Intercom Signal PDU");
            
        } catch (Exception e) {
            result.put("intercom.signal.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析内部通信控制PDU
     */
    private void parseIntercomControlPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 控制实体ID
            result.put("controlling.entity.site", buffer.getShort() & 0xFFFF);
            result.put("controlling.entity.application", buffer.getShort() & 0xFFFF);
            result.put("controlling.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 通信ID
            result.put("communication.id", buffer.getShort() & 0xFFFF);
            
            // 控制类型
            result.put("control.type", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Intercom Control PDU");
            
        } catch (Exception e) {
            result.put("intercom.control.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析分组PDU
     */
    private void parseIsGroupOfPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 分组实体ID
            result.put("group.entity.site", buffer.getShort() & 0xFFFF);
            result.put("group.entity.application", buffer.getShort() & 0xFFFF);
            result.put("group.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 分组类型
            result.put("group.type", buffer.get() & 0xFF);
            
            // 分组形态
            result.put("group.formation", buffer.get() & 0xFF);
            
            // 成员数量
            result.put("member.count", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "IsGroupOf PDU");
            
        } catch (Exception e) {
            result.put("is.group.of.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析传输控制PDU
     */
    private void parseTransferControlPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 控制实体ID
            result.put("controlling.entity.site", buffer.getShort() & 0xFFFF);
            result.put("controlling.entity.application", buffer.getShort() & 0xFFFF);
            result.put("controlling.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 传输控制类型
            result.put("transfer.control.type", buffer.get() & 0xFF);
            
            // 传输状态
            result.put("transfer.status", buffer.get() & 0xFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Transfer Control PDU");
            
        } catch (Exception e) {
            result.put("transfer.control.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析部分PDU
     */
    private void parseIsPartOfPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 整体实体ID
            result.put("whole.entity.site", buffer.getShort() & 0xFFFF);
            result.put("whole.entity.application", buffer.getShort() & 0xFFFF);
            result.put("whole.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 部分实体ID
            result.put("part.entity.site", buffer.getShort() & 0xFFFF);
            result.put("part.entity.application", buffer.getShort() & 0xFFFF);
            result.put("part.entity.entity", buffer.getShort() & 0xFFFF);
            
            // 关系类型
            result.put("relationship.type", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "IsPartOf PDU");
            
        } catch (Exception e) {
            result.put("is.part.of.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析雷场状态PDU
     */
    private void parseMinefieldStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 雷场ID
            result.put("minefield.id.site", buffer.getShort() & 0xFFFF);
            result.put("minefield.id.application", buffer.getShort() & 0xFFFF);
            result.put("minefield.id.entity", buffer.getShort() & 0xFFFF);
            
            // 雷场类型
            result.put("minefield.type", buffer.get() & 0xFF);
            
            // 雷场状态
            result.put("minefield.state", buffer.get() & 0xFF);
            
            // 地雷数量
            result.put("mine.count", buffer.getShort() & 0xFFFF);
            
            // 位置
            result.put("position.x", buffer.getFloat());
            result.put("position.y", buffer.getFloat());
            result.put("position.z", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Minefield State PDU");
            
        } catch (Exception e) {
            result.put("minefield.state.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析关节部件PDU
     */
    private void parseArticulatedPartsPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 实体ID
            result.put("entity.site", buffer.getShort() & 0xFFFF);
            result.put("entity.application", buffer.getShort() & 0xFFFF);
            result.put("entity.entity", buffer.getShort() & 0xFFFF);
            
            // 关节参数类型
            result.put("articulated.parts.type", buffer.get() & 0xFF);
            
            // 关节参数值
            result.put("articulated.parts.value", buffer.getFloat());
            
            // 关节参数变化率
            result.put("articulated.parts.rate", buffer.getFloat());
            
            // 关节部件数量
            result.put("articulated.parts.count", buffer.getShort() & 0xFFFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Articulated Part PDU");
            
        } catch (Exception e) {
            result.put("articulated.parts.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 检查数据是否为有效的DIS PDU
     */
    public boolean isValidDISPDU(byte[] data) {
        if (data == null || data.length < 12) {
            return false;
        }
        
        try {
            int pduType = data[0] & 0xFF;
            DISEnums.PDUType type = DISEnums.PDUType.fromValue(pduType);
            return type != DISEnums.PDUType.UNKNOWN;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 解析雷场查询PDU
     */
    private void parseMinefieldQueryPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 请求者ID
            result.put("requester.id.site", buffer.getShort() & 0xFFFF);
            result.put("requester.id.application", buffer.getShort() & 0xFFFF);
            result.put("requester.id.entity", buffer.getShort() & 0xFFFF);
            
            // 目标雷场ID
            result.put("target.minefield.id.site", buffer.getShort() & 0xFFFF);
            result.put("target.minefield.id.application", buffer.getShort() & 0xFFFF);
            result.put("target.minefield.id.entity", buffer.getShort() & 0xFFFF);
            
            // 查询类型
            result.put("query.type", buffer.get() & 0xFF);
            
            // 查询参数
            result.put("query.parameters", buffer.getInt() & 0xFFFFFFFFL);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Minefield Query PDU");
            
        } catch (Exception e) {
            result.put("minefield.query.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析雷场数据PDU
     */
    private void parseMinefieldDataPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 雷场ID
            result.put("minefield.id.site", buffer.getShort() & 0xFFFF);
            result.put("minefield.id.application", buffer.getShort() & 0xFFFF);
            result.put("minefield.id.entity", buffer.getShort() & 0xFFFF);
            
            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 序列号
            result.put("sequence.number", buffer.getShort() & 0xFFFF);
            
            // 数据长度
            int dataLength = buffer.getShort() & 0xFFFF;
            result.put("data.length", dataLength);
            
            // 雷场数据
            byte[] minefieldData = new byte[dataLength];
            buffer.get(minefieldData);
            result.put("minefield.data", minefieldData);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Minefield Data PDU");
            
        } catch (Exception e) {
            result.put("minefield.data.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析环境过程PDU
     */
    private void parseEnvironmentalProcessPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 环境过程类型
            result.put("environment.process.type", buffer.get() & 0xFF);
            
            // 过程ID
            result.put("process.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 位置
            result.put("position.x", buffer.getFloat());
            result.put("position.y", buffer.getFloat());
            result.put("position.z", buffer.getFloat());
            
            // 参数数量
            int paramCount = buffer.get() & 0xFF;
            result.put("parameter.count", paramCount);
            
            // 参数列表
            List<Map<String, Object>> parameters = new ArrayList<>();
            for (int i = 0; i < paramCount; i++) {
                Map<String, Object> param = new HashMap<>();
                param.put("type", buffer.get() & 0xFF);
                param.put("value", buffer.getFloat());
                parameters.add(param);
            }
            result.put("parameters", parameters);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Environmental Process PDU");
            
        } catch (Exception e) {
            result.put("environmental.process.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析网格数据PDU
     */
    private void parseGriddedDataPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 网格ID
            result.put("grid.id", buffer.getInt() & 0xFFFFFFFFL);
            
            // 网格类型
            result.put("grid.type", buffer.get() & 0xFF);
            
            // 网格尺寸
            result.put("grid.width", buffer.getShort() & 0xFFFF);
            result.put("grid.height", buffer.getShort() & 0xFFFF);
            result.put("grid.depth", buffer.getShort() & 0xFFFF);
            
            // 原点位置
            result.put("origin.x", buffer.getFloat());
            result.put("origin.y", buffer.getFloat());
            result.put("origin.z", buffer.getFloat());
            
            // 网格间距
            result.put("grid.spacing.x", buffer.getFloat());
            result.put("grid.spacing.y", buffer.getFloat());
            result.put("grid.spacing.z", buffer.getFloat());
            
            // 数据点数量
            int dataPointCount = buffer.getShort() & 0xFFFF;
            result.put("data.point.count", dataPointCount);
            
            // 数据点列表
            List<Float> dataPoints = new ArrayList<>();
            for (int i = 0; i < dataPointCount; i++) {
                dataPoints.add(buffer.getFloat());
            }
            result.put("data.points", dataPoints);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Gridded Data PDU");
            
        } catch (Exception e) {
            result.put("gridded.data.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析点对象状态PDU
     */
    private void parsePointObjectStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 对象ID
            result.put("object.id.site", buffer.getShort() & 0xFFFF);
            result.put("object.id.application", buffer.getShort() & 0xFFFF);
            result.put("object.id.entity", buffer.getShort() & 0xFFFF);
            
            // 对象类型
            result.put("object.type", buffer.get() & 0xFF);
            
            // 位置
            result.put("position.x", buffer.getFloat());
            result.put("position.y", buffer.getFloat());
            result.put("position.z", buffer.getFloat());
            
            // 方向
            result.put("orientation.psi", buffer.getFloat());
            result.put("orientation.theta", buffer.getFloat());
            result.put("orientation.phi", buffer.getFloat());
            
            // 速度
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());
            
            // 对象状态
            result.put("object.state", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Point Object State PDU");
            
        } catch (Exception e) {
            result.put("point.object.state.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析数据PDU
     *
     */
    private void parseDataPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 1. 发起实体ID (6 bytes)
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);

            // 2. 接收实体ID (6 bytes)
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);

            // 3. 请求ID (4 bytes)
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);

            // padding
            buffer.getInt();

            // 4. 固定参数数量 (Fixed Datum Count) (4 bytes)
            int fixedDatumCount = buffer.getInt();
            result.put("fixed.datum.count", fixedDatumCount);

            // 5. 可变参数数量 (Variable Datum Count) (4 bytes)
            int variableDatumCount = buffer.getInt();
            result.put("variable.datum.count", variableDatumCount);

            // 标记信息
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Data PDU");

            // 4. 解析固定参数 (Fixed Datums)
            for (int i = 0; i < fixedDatumCount; i++) {
                long datumId = buffer.getInt() & 0xFFFFFFFFL;
                // 根据 DIS 标准，Fixed Datum 的 Value 始终占用 32位 (4字节)
                int datumValue = buffer.getInt();

                result.put("fixed.datum." + i + ".id", datumId);
                result.put("fixed.datum." + i + ".type", DISEnums.DatumIdentifier.fromInt((int)datumId));
                result.put("fixed.datum." + i + ".value", datumValue);
            }

            // 5. 解析可变参数 (Variable Datums)
            for (int i = 0; i < variableDatumCount; i++) {
                long datumId = buffer.getInt() & 0xFFFFFFFFL;
                int datumLengthInBits = buffer.getInt(); // 长度以 bit 为单位
                int datumLengthInBytes = (datumLengthInBits + 7) / 8;

                byte[] datumValue = new byte[datumLengthInBytes];
                buffer.get(datumValue);

                // 关键：Variable Datum 必须按 64 位(8字节)对齐填充
                int paddingNeeded = (8 - (datumLengthInBytes % 8)) % 8;
                if (paddingNeeded > 0) {
                    buffer.position(buffer.position() + paddingNeeded);
                }

                result.put("variable.datum." + i + ".id", datumId);
                result.put("variable.datum." + i + ".value_asc", bytesToAscii(datumValue));
                result.put("variable.datum." + i + ".value_base64", bytesToBase64(datumValue));
            }

        } catch (Exception e) {
            result.put("dis.data.pdu.parse.error", e.getMessage());
        }
    }

    /**
     * 解析记录PDU
     */
    private void parseRecordPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 发起实体ID
            result.put("originating.entity.site", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.application", buffer.getShort() & 0xFFFF);
            result.put("originating.entity.entity", buffer.getShort() & 0xFFFF);

            // 接收实体ID
            result.put("receiving.entity.site", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.application", buffer.getShort() & 0xFFFF);
            result.put("receiving.entity.entity", buffer.getShort() & 0xFFFF);

            // 请求ID
            result.put("request.id", buffer.getInt() & 0xFFFFFFFFL);

            // 记录类型
            result.put("record.type", buffer.getShort() & 0xFFFF);

            // 记录数量
            int recordCount = buffer.getShort() & 0xFFFF;
            result.put("record.count", recordCount);

            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Record PDU");

        } catch (Exception e) {
            result.put("record.pdu.parse.error", e.getMessage());
        }
    }

    /**
     * 解析线性对象状态PDU
     */
    private void parseLinearObjectStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 对象ID
            result.put("object.id.site", buffer.getShort() & 0xFFFF);
            result.put("object.id.application", buffer.getShort() & 0xFFFF);
            result.put("object.id.entity", buffer.getShort() & 0xFFFF);
            
            // 对象类型
            result.put("object.type", buffer.get() & 0xFF);
            
            // 线段数量
            int segmentCount = buffer.getShort() & 0xFFFF;
            result.put("segment.count", segmentCount);
            
            // 线段列表
            List<Map<String, Object>> segments = new ArrayList<>();
            for (int i = 0; i < segmentCount; i++) {
                Map<String, Object> segment = new HashMap<>();
                segment.put("start.x", buffer.getFloat());
                segment.put("start.y", buffer.getFloat());
                segment.put("start.z", buffer.getFloat());
                segment.put("end.x", buffer.getFloat());
                segment.put("end.y", buffer.getFloat());
                segment.put("end.z", buffer.getFloat());
                segment.put("width", buffer.getFloat());
                segments.add(segment);
            }
            result.put("segments", segments);
            
            // 对象状态
            result.put("object.state", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Linear Object State PDU");
            
        } catch (Exception e) {
            result.put("linear.object.state.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析区域对象状态PDU
     */
    private void parseArealObjectStatePDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 对象ID
            result.put("object.id.site", buffer.getShort() & 0xFFFF);
            result.put("object.id.application", buffer.getShort() & 0xFFFF);
            result.put("object.id.entity", buffer.getShort() & 0xFFFF);
            
            // 对象类型
            result.put("object.type", buffer.get() & 0xFF);
            
            // 区域顶点数量
            int vertexCount = buffer.getShort() & 0xFFFF;
            result.put("vertex.count", vertexCount);
            
            // 顶点列表
            List<Map<String, Object>> vertices = new ArrayList<>();
            for (int i = 0; i < vertexCount; i++) {
                Map<String, Object> vertex = new HashMap<>();
                vertex.put("x", buffer.getFloat());
                vertex.put("y", buffer.getFloat());
                vertex.put("z", buffer.getFloat());
                vertices.add(vertex);
            }
            result.put("vertices", vertices);
            
            // 对象状态
            result.put("object.state", buffer.get() & 0xFF);
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "Area Object State PDU");
            
        } catch (Exception e) {
            result.put("areal.object.state.pdu.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析时间空间位置信息PDU
     */
    private void parseTSPIPDU(ByteBuffer buffer, Map<String, Object> result) {
        try {
            // 实体ID
            result.put("entity.site", buffer.getShort() & 0xFFFF);
            result.put("entity.application", buffer.getShort() & 0xFFFF);
            result.put("entity.entity", buffer.getShort() & 0xFFFF);
            
            // 时间戳
            result.put("timestamp", buffer.getInt() & 0xFFFFFFFFL);
            
            // 位置
            result.put("position.x", buffer.getFloat());
            result.put("position.y", buffer.getFloat());
            result.put("position.z", buffer.getFloat());
            
            // 方向
            result.put("orientation.psi", buffer.getFloat());
            result.put("orientation.theta", buffer.getFloat());
            result.put("orientation.phi", buffer.getFloat());
            
            // 速度
            result.put("velocity.x", buffer.getFloat());
            result.put("velocity.y", buffer.getFloat());
            result.put("velocity.z", buffer.getFloat());
            
            // 加速度
            result.put("acceleration.x", buffer.getFloat());
            result.put("acceleration.y", buffer.getFloat());
            result.put("acceleration.z", buffer.getFloat());
            
            // 标记为已成功解析
            result.put("parsed.successfully", true);
            result.put("pdu.description", "TSPI PDU");
            
        } catch (Exception e) {
            result.put("tspi.pdu.parse.error", e.getMessage());
        }
    }
}
