package com.jshark.parser.dis;

/**
 * DIS协议枚举定义
 * 包含所有DIS协议中使用的常量枚举，每个枚举都包含描述信息
 */
public class DISEnums {
    
    /**
     * 力量标识枚举
     */
    public enum ForceId {
        OTHER(0, "Other"),
        FRIENDLY(1, "Friendly"),
        OPPOSING(2, "Opposing"),
        NEUTRAL(3, "Neutral");
        
        private final int value;
        private final String description;
        
        ForceId(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static ForceId fromValue(int value) {
            for (ForceId forceId : values()) {
                if (forceId.value == value) {
                    return forceId;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 实体类型枚举
     */
    public enum EntityKind {
        OTHER(0, "Other"),
        PLATFORM(1, "Platform"),
        MUNITION(2, "Munition"),
        LIFEFORM(3, "Life Form"),
        ENVIRONMENTAL(4, "Environmental"),
        CULTURAL_FEATURE(5, "Cultural Feature"),
        SUPPLY(6, "Supply"),
        RADIO(7, "Radio"),
        EXPENDABLE(8, "Expendable"),
        SENSOR_EMITTER(9, "Sensor/Emitter");
        
        private final int value;
        private final String description;
        
        EntityKind(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static EntityKind fromValue(int value) {
            for (EntityKind entityKind : values()) {
                if (entityKind.value == value) {
                    return entityKind;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 实体域枚举
     */
    public enum EntityDomain {
        OTHER(0, "Other"),
        LAND(1, "Land"),
        AIR(2, "Air"),
        SURFACE(3, "Surface"),
        SUBSURFACE(4, "Subsurface"),
        SPACE(5, "Space");
        
        private final int value;
        private final String description;
        
        EntityDomain(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static EntityDomain fromValue(int value) {
            for (EntityDomain entityDomain : values()) {
                if (entityDomain.value == value) {
                    return entityDomain;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 碰撞类型枚举
     */
    public enum CollisionType {
        INELASTIC(0, "Inelastic Collision"),
        ELASTIC(1, "Elastic Collision");
        
        private final int value;
        private final String description;
        
        CollisionType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static CollisionType fromValue(int value) {
            for (CollisionType collisionType : values()) {
                if (collisionType.value == value) {
                    return collisionType;
                }
            }
            return INELASTIC;
        }
    }
    
    /**
     * 爆炸结果枚举
     */
    public enum DetonationResult {
        OTHER(0, "Other"),
        ENTITY_IMPACT(1, "Entity Impact"),
        ENTITY_PROXIMATE(2, "Entity Proximity"),
        GROUND_IMPACT(3, "Ground Impact"),
        GROUND_PROXIMATE(4, "Ground Proximity"),
        DETONATION(5, "Detonation"),
        NONE(6, "None"),
        HE_HIT_SMALL(7, "High Explosive Hit-Small"),
        HE_HIT_MEDIUM(8, "High Explosive Hit-Medium"),
        HE_HIT_LARGE(9, "High Explosive Hit-Large");
        
        private final int value;
        private final String description;
        
        DetonationResult(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static DetonationResult fromValue(int value) {
            for (DetonationResult detonationResult : values()) {
                if (detonationResult.value == value) {
                    return detonationResult;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 服务类型枚举
     */
    public enum ServiceType {
        OTHER(0, "Other"),
        RESUPPLY(1, "Supply"),
        REPAIR(2, "Repair");
        
        private final int value;
        private final String description;
        
        ServiceType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static ServiceType fromValue(int value) {
            for (ServiceType serviceType : values()) {
                if (serviceType.value == value) {
                    return serviceType;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 补给类型枚举
     */
    public enum SupplyType {
        OTHER(0, "Other"),
        FUEL(1, "Fuel"),
        AMMUNITION(2, "Munition");
        
        private final int value;
        private final String description;
        
        SupplyType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static SupplyType fromValue(int value) {
            for (SupplyType supplyType : values()) {
                if (supplyType.value == value) {
                    return supplyType;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 航位推算算法枚举
     */
    public enum DeadReckoningAlgorithm {
        OTHER(0, "Other"),
        STATIC(1, "Static"),
        DRM_FPW(2, "DRM_FPW"),
        DRM_RPW(3, "DRM_RPW"),
        DRM_RVW(4, "DRM_RVW"),
        DRM_FVW(5, "DRM_FVW"),
        DRM_FPB(6, "DRM_FPB"),
        DRM_RPB(7, "DRM_RPB"),
        DRM_RVB(8, "DRM_RVB"),
        DRM_FVB(9, "DRM_FVB");
        
        private final int value;
        private final String description;
        
        DeadReckoningAlgorithm(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static DeadReckoningAlgorithm fromValue(int value) {
            for (DeadReckoningAlgorithm algorithm : values()) {
                if (algorithm.value == value) {
                    return algorithm;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 雷场类型枚举
     */
    public enum MinefieldType {
        OTHER(0, "Other"),
        ANTI_TANK(1, "Anti-Tank"),
        ANTI_PERSONNEL(2, "Anti-Personnel"),
        MIXED(3, "Mixed");
        
        private final int value;
        private final String description;
        
        MinefieldType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static MinefieldType fromValue(int value) {
            for (MinefieldType minefieldType : values()) {
                if (minefieldType.value == value) {
                    return minefieldType;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 环境过程类型枚举
     */
    public enum EnvironmentProcessType {
        OTHER(0, "Other"),
        WEATHER(1, "Weather"),
        TERRAIN(2, "Terrain"),
        VISIBILITY(3, "Visibility"),
        ACOUSTIC(4, "Acoustic");
        
        private final int value;
        private final String description;
        
        EnvironmentProcessType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static EnvironmentProcessType fromValue(int value) {
            for (EnvironmentProcessType processType : values()) {
                if (processType.value == value) {
                    return processType;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 网格类型枚举
     */
    public enum GridType {
        OTHER(0, "Other"),
        REGULAR(1, "Regular Grid"),
        IRREGULAR(2, "Irregular Grid"),
        SPARSE(3, "Sparse Grid");
        
        private final int value;
        private final String description;
        
        GridType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static GridType fromValue(int value) {
            for (GridType gridType : values()) {
                if (gridType.value == value) {
                    return gridType;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 对象类型枚举
     */
    public enum ObjectType {
        OTHER(0, "Other"),
        VEHICLE(1, "Vehicle"),
        STRUCTURE(2, "Structure"),
        SENSOR(3, "Sensor"),
        OBSTACLE(4, "Obstacle");
        
        private final int value;
        private final String description;
        
        ObjectType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static ObjectType fromValue(int value) {
            for (ObjectType objectType : values()) {
                if (objectType.value == value) {
                    return objectType;
                }
            }
            return OTHER;
        }
    }
    
    /**
     * 查询类型枚举
     */
    public enum QueryType {
        OTHER(0, "Other"),
        STATUS(1, "Status"),
        LOCATION(2, "Position"),
        CAPABILITY(3, "Capability"),
        THREAT(4, "Threat");
        
        private final int value;
        private final String description;
        
        QueryType(int value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public int getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static QueryType fromValue(int value) {
            for (QueryType queryType : values()) {
                if (queryType.value == value) {
                    return queryType;
                }
            }
            return OTHER;
        }
    }

    /**
     * DIS PDU类型枚举 - 根据IEEE 1278.1标准扩展
     */
    public enum PDUType {
        ENTITY_STATE(1, "Entity State PDU"),
        FIRE(2, "Fire PDU"),
        DETONATION(3, "Detonation PDU"),
        COLLISION(4, "Collision PDU"),
        SERVICE_REQUEST(5, "Service Request PDU"),
        RESUPPLY_OFFER(6, "Resupply Offer PDU"),
        RESUPPLY_RECEIVED(7, "Resupply Received PDU"),
        RESUPPLY_CANCEL(8, "Resupply Cancel PDU"),
        REPAIR_COMPLETE(9, "Repair Complete PDU"),
        REPAIR_RESPONSE(10, "Repair Response PDU"),

        // --- 仿真管理 (Simulation Management) ---
        CREATE_ENTITY(11, "Create Entity PDU"),
        REMOVE_ENTITY(12, "Remove Entity PDU"),
        START_RESUME(13, "Start/Resume PDU"),
        STOP_FREEZE(14, "Stop/Freeze PDU"),
        ACKNOWLEDGE(15, "Acknowledge PDU"),
        ACTION_REQUEST(16, "Action Request PDU"),
        ACTION_RESPONSE(17, "Action Response PDU"),
        DATA_QUERY(18, "Data Query PDU"),
        DATA_SET(19, "Set Data PDU"),
        DATA(20, "Data PDU"),
        EVENT_REPORT(21, "Event Report PDU"),
        COMMENT(22, "Comment PDU"),

        // --- 分布式发射/辐射 ---
        ELECTROMAGNETIC_EMISSION(23, "Electromagnetic Emission PDU"),
        DESIGNATOR(24, "Designator PDU"),
        TRANSMITTER(25, "Transmitter PDU"),
        SIGNAL(26, "Signal PDU"),
        RECEIVER(27, "Receiver PDU"),

        // --- 2012标准扩展与特殊 PDU ---
        IFF_ATC_NAVAIDS(28, "IFF/ATC/NAVAIDS PDU"),
        UNDERWATER_ACOUSTIC(29, "Underwater Acoustic PDU"),
        SUPPLEMENTAL_EMISSION_ENTITY_STATE(30, "Supplemental Emission/Entity State PDU"),
        INTERCOM_SIGNAL(31, "Intercom Signal PDU"),
        INTERCOM_CONTROL(32, "Intercom Control PDU"),
        AGGREGATE_STATE(33, "Aggregate State PDU"),
        IS_GROUP_OF(34, "IsGroupOf PDU"),
        TRANSFER_CONTROL(35, "Transfer Control PDU"),
        IS_PART_OF(36, "IsPartOf PDU"),
        MINEFIELD_STATE(37, "Minefield State PDU"),
        MINEFIELD_QUERY(38, "Minefield Query PDU"),
        MINEFIELD_DATA(39, "Minefield Data PDU"),
        MINEFIELD_RESPONSE_NACK(40, "Minefield Response NACK PDU"),
        ENVIRONMENTAL_PROCESS(41, "Environmental Process PDU"),
        GRIDDED_DATA(42, "Gridded Data PDU"),
        POINT_OBJECT_STATE(43, "Point Object State PDU"),
        LINEAR_OBJECT_STATE(44, "Linear Object State PDU"),
        AREAL_OBJECT_STATE(45, "Area Object State PDU"),
        TSPI(46, "TSPI PDU"),
        APPEARANCE(47, "Appearance PDU"),
        ARTICULATED_PARTS(48, "Articulated Part PDU"),
        LE_FIRE(49, "LE Fire PDU"),
        LE_DETONATION(50, "LE Detonation PDU"),

        // --- 可靠性传输系列 (Reliable Simulation Management) ---
        CREATE_ENTITY_R(51, "Create Entity-R PDU"),
        REMOVE_ENTITY_R(52, "Remove Entity-R PDU"),
        START_RESUME_R(53, "Start/Resume-R PDU"),
        STOP_FREEZE_R(54, "Stop/Freeze-R PDU"),
        ACKNOWLEDGE_R(55, "Acknowledge-R PDU"),
        ACTION_REQUEST_R(56, "Action Request-R PDU"),
        ACTION_RESPONSE_R(57, "Action Response-R PDU"),
        DATA_QUERY_R(58, "Data Query-R PDU"),
        DATA_SET_R(59, "Set Data-R PDU"),
        DATA_R(60, "Data-R PDU"),               // 对应 Type 20
        EVENT_REPORT_R(61, "Event Report-R PDU"),     // 对应 Type 21
        COMMENT_R(62, "Comment-R PDU"),            // 对应 Type 22
        RECORD_R(63, "Record-R PDU"),             // 传输 Record 数据
        SET_RECORD_R(64, "Set Record-R PDU"),      // 指令：设置记录
        RECORD_QUERY_R(65, "Record Query-R PDU"),    // 指令：查询记录

        COLLISION_ELASTIC(66, "Elastic Collision PDU"),
        ENTITY_STATE_UPDATE(67, "Entity State Update PDU"),
        DIRECTED_ENERGY_FIRE(68, "Directed Energy Fire PDU"),
        ENTITY_DAMAGE_STATUS(69, "Entity Damage Status PDU"),

        UNKNOWN(0, "Unknown PDU Type");
        private final int value;
        private final String description;

        PDUType(int value, String description) {
            this.value = value;
            this.description = description;
        }

        public String getDescription() {
            return description;
        }

        public static PDUType fromValue(int value) {
            for (PDUType type : values()) {
                if (type.value == value) {
                    return type;
                }
            }
            return UNKNOWN;
        }
    }

    public enum DatumIdentifier {
        // --- 1. 时间与仿真管理 (1000 - 1999) ---
        TIME(1000, "Time"),
        SIMULATION_TIME(1601, "Simulation Time"),
        UTC_TIME(1602, "UTC Time"),
        TIME_OF_DAY(1607, "Time of Day"), // 你遇到的 1607
        TIME_OF_DAY_OFFSET(1608, "Time of Day Offset"),
        SIMULATION_START_TIME(1620, "Simulation Start Time"),
        EXERCISE_DURATION(1630, "Exercise Duration"),

        // --- 2. 空间与运动学 (3000 - 4999) ---
        VELOCITY_X(3000, "X Velocity"),
        VELOCITY_Y(3001, "Y Velocity"),
        VELOCITY_Z(3002, "Z Velocity"),
        ACCELERATION_X(3100, "X Acceleration"),
        ACCELERATION_Y(3101, "Y Acceleration"),
        ACCELERATION_Z(3102, "Z Acceleration"),
        LATITUDE(3200, "Latitude"),
        LONGITUDE(3201, "Longitude"),
        ALTITUDE(3202, "Altitude"),
        ROLL(3300, "Roll"),
        PITCH(3301, "Pitch"),
        YAW(3302, "Yaw"),
        HEADING(3303, "Heading"),

        // --- 3. 后勤与实体状态 (2000 - 2999, 3500 - 3999) ---
        FUEL_QUANTITY(2000, "Remaining Fuel"),
        FUEL_CAPACITY(2001, "Total Fuel Capacity"),
        AMMO_COUNT(2100, "Munition Count"),
        CARGO_WEIGHT(2200, "Cargo Mass"),
        ENTITY_HEALTH(3500, "Entity Health"),
        DAMAGE_STATE(3501, "Damage Status"),
        ENGINE_STATUS(3600, "Engine Status"),
        RADAR_STATUS(3700, "Radar Status"),
        FIRE_CONTROL_STATUS(3800, "Fire Control Status"),

        // --- 4. 传感器与电子战 (4000 - 5999) ---
        HORIZONTAL_RANGE(4000, "Horizontal Distance"),
        VERTICAL_RANGE(4001, "Vertical Distance"),
        BEARING(4002, "Azimuth"),
        ELEVATION(4003, "Elevation"),
        TARGET_ID(4100, "Target Entity ID"),
        SCAN_RATE(4500, "Scan Rate"),
        TRANSMIT_FREQUENCY(4600, "Transmit Frequency"),
        RECEIVE_FREQUENCY(4601, "Receive Frequency"),

        // --- 5. 环境与气象 (6000 - 6999) ---
        AIR_TEMPERATURE(6000, "Air Temperature"),
        WATER_TEMPERATURE(6001, "Water Temperature"),
        WIND_SPEED(6100, "Wind Speed"),
        WIND_DIRECTION(6101, "Wind Direction"),
        BAROMETRIC_PRESSURE(6200, "Barometric Pressure"),
        VISIBILITY(6300, "Visibility"),
        PRECIPITATION_TYPE(6400, "Precipitation Type"),

        // --- 6. 标识与网络 (10000 - 11000) ---
        HOST_ID(10001, "Host ID"),
        SITE_ID(10002, "Site ID"),
        APPLICATION_ID(10003, "Application ID"),
        ENTITY_ID(10004, "Entity Number"),

        UNKNOWN(-1, "Unknown Identifier");

        private final int code;
        private final String description;

        DatumIdentifier(int code, String description) {
            this.code = code;
            this.description = description;
        }

        public int getCode() {
            return code;
        }

        public String getDescription() {
            return description;
        }

        /**
         * 根据代码获取枚举
         */
        public static DatumIdentifier fromInt(int code) {
            for (DatumIdentifier di : values()) {
                if (di.code == code) return di;
            }
            return UNKNOWN;
        }
    }
}