package com.jshark.parser.pg;

/**
 * PostgreSQL Wire Protocol 协议枚举定义
 * 包含PG协议中使用的各种消息类型、认证方式、状态码等枚举
 */
public class PGEnums {

    /**
     * PG前端消息类型（客户端 -> 服务器）
     * 每个消息类型对应一个ASCII字符标签
     */
    public enum FrontendMessageType {
        QUERY('Q', "Simple Query", "Simple Query"),
        PARSE('P', "Parse", "Parse"),
        BIND('B', "Bind", "Bind"),
        DESCRIBE('D', "Describe", "Describe"),
        EXECUTE('E', "Execute", "Execute"),
        CLOSE('C', "Close", "Close"),
        SYNC('S', "Sync", "Sync"),
        FLUSH('H', "Flush", "Flush"),
        TERMINATE('X', "Terminate", "Terminate"),
        PASSWORD('p', "Password Message/SASL Response", "Password Message / SASL Response"),
        COPY_DATA('d', "Copy Data", "Copy Data"),
        COPY_DONE('c', "Copy Done", "Copy Done"),
        COPY_FAIL('f', "Copy Fail", "Copy Fail"),
        FUNCTION_CALL('F', "Function Call", "Function Call (deprecated)"),
        UNKNOWN('\0', "Unknown", "Unknown");

        private final char tag;
        private final String descriptionCn;
        private final String descriptionEn;

        FrontendMessageType(char tag, String descriptionCn, String descriptionEn) {
            this.tag = tag;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public char getTag() {
            return tag;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        /**
         * 根据标签字符查找前端消息类型
         */
        public static FrontendMessageType fromTag(char tag) {
            for (FrontendMessageType type : values()) {
                if (type.tag == tag) {
                    return type;
                }
            }
            return UNKNOWN;
        }

        /**
         * 根据字节值查找前端消息类型
         */
        public static FrontendMessageType fromByte(byte b) {
            return fromTag((char) (b & 0xFF));
        }
    }

    /**
     * PG后端消息类型（服务器 -> 客户端）
     */
    public enum BackendMessageType {
        AUTHENTICATION('R', "Authentication Request", "Authentication"),
        BACKEND_KEY_DATA('K', "Backend Key Data", "Backend Key Data"),
        PARAMETER_STATUS('S', "Parameter Status", "Parameter Status"),
        READY_FOR_QUERY('Z', "Prepared Query", "Ready for Query"),
        ROW_DESCRIPTION('T', "Row Description", "Row Description"),
        DATA_ROW('D', "Data Row", "Data Row"),
        COMMAND_COMPLETE('C', "Command Complete", "Command Complete"),
        EMPTY_QUERY_RESPONSE('I', "Empty Query Response", "Empty Query Response"),
        ERROR_RESPONSE('E', "Error Response", "Error Response"),
        NOTICE_RESPONSE('N', "Notification Response", "Notice Response"),
        PARSE_COMPLETE('1', "Parse Complete", "Parse Complete"),
        BIND_COMPLETE('2', "Bind Complete", "Bind Complete"),
        CLOSE_COMPLETE('3', "Close Complete", "Close Complete"),
        PORTAL_SUSPENDED('s', "Portal Suspended", "Portal Suspended"),
        NO_DATA('n', "No Data", "No Data"),
        PARAMETER_DESCRIPTION('t', "Parameter Description", "Parameter Description"),
        NOTIFICATION_RESPONSE('A', "Notification Response", "Notification Response"),
        COPY_IN_RESPONSE('G', "Copy In Response", "Copy In Response"),
        COPY_OUT_RESPONSE('H', "Copy Out Response", "Copy Out Response"),
        COPY_BOTH_RESPONSE('W', "Copy Both Response", "Copy Both Response"),
        COPY_DATA('d', "Copy Data", "Copy Data"),
        FUNCTION_CALL_RESPONSE('V', "Function Call Response", "Function Call Response (deprecated)"),
        UNKNOWN('\0', "Unknown", "Unknown");

        private final char tag;
        private final String descriptionCn;
        private final String descriptionEn;

        BackendMessageType(char tag, String descriptionCn, String descriptionEn) {
            this.tag = tag;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public char getTag() {
            return tag;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        /**
         * 根据标签字符查找后端消息类型
         */
        public static BackendMessageType fromTag(char tag) {
            for (BackendMessageType type : values()) {
                if (type.tag == tag) {
                    return type;
                }
            }
            return UNKNOWN;
        }

        /**
         * 根据字节值查找后端消息类型
         */
        public static BackendMessageType fromByte(byte b) {
            return fromTag((char) (b & 0xFF));
        }
    }

    /**
     * PG认证方式
     */
    public enum AuthenticationType {
        OK(0, "Authentication OK", "Authentication OK"),
        KERBEROS_V5(2, "Kerberos V5", "Kerberos V5"),
        CLEARTEXT_PASSWORD(3, "Cleartext Password", "Cleartext Password"),
        MD5_PASSWORD(5, "MD5 Password", "MD5 Password"),
        SCM_CREDENTIAL(6, "SCM Credential", "SCM Credential"),
        GSS(7, "GSS API", "GSS API"),
        GSS_CONTINUE(8, "GSS Continue", "GSS Continue"),
        SSPI(9, "SSPI", "SSPI"),
        SASL(10, "SASL", "SASL"),
        SASL_CONTINUE(11, "SASL Continue", "SASL Continue"),
        SASL_FINAL(12, "SASL Final", "SASL Final"),
        UNKNOWN(-1, "Unknown", "Unknown");

        private final int code;
        private final String descriptionCn;
        private final String descriptionEn;

        AuthenticationType(int code, String descriptionCn, String descriptionEn) {
            this.code = code;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public int getCode() {
            return code;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        public static AuthenticationType fromCode(int code) {
            for (AuthenticationType type : values()) {
                if (type.code == code) {
                    return type;
                }
            }
            return UNKNOWN;
        }
    }

    /**
     * PG错误/通知字段类型
     */
    public enum ErrorFieldType {
        SEVERITY('S', "Severity", "Severity"),
        CODE('C', "SQLSTATE", "SQL State Code"),
        MESSAGE('M', "Message", "Message"),
        DETAIL('D', "Detail", "Detail"),
        HINT('H', "Hint", "Hint"),
        POSITION('P', "Position", "Position"),
        INTERNAL_POSITION('p', "Internal Position", "Internal Position"),
        INTERNAL_QUERY('q', "Internal Query", "Internal Query"),
        WHERE('W', "Where", "Where"),
        SCHEMA_NAME('s', "Schema Name", "Schema Name"),
        TABLE_NAME('t', "Table Name", "Table Name"),
        COLUMN_NAME('c', "Column Name", "Column Name"),
        DATA_TYPE_NAME('d', "Data Type Name", "Data Type Name"),
        CONSTRAINT_NAME('n', "Constraint Name", "Constraint Name"),
        FILE('F', "File", "File"),
        LINE('L', "Line", "Line"),
        ROUTINE('R', "Function", "Routine"),
        UNKNOWN('\0', "Unknown", "Unknown");

        private final char type;
        private final String descriptionCn;
        private final String descriptionEn;

        ErrorFieldType(char type, String descriptionCn, String descriptionEn) {
            this.type = type;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public char getType() {
            return type;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        public static ErrorFieldType fromType(char type) {
            for (ErrorFieldType field : values()) {
                if (field.type == type) {
                    return field;
                }
            }
            return UNKNOWN;
        }
    }

    /**
     * PG事务状态（ReadyForQuery消息）
     */
    public enum TransactionStatus {
        IDLE('I', "Idle", "Idle (not in a transaction block)"),
        TRANSACTION('T', "In Transaction", "In a transaction block"),
        ERROR('E', "In Failed Transaction", "In a failed transaction block"),
        UNKNOWN('\0', "Unknown", "Unknown");

        private final char status;
        private final String descriptionCn;
        private final String descriptionEn;

        TransactionStatus(char status, String descriptionCn, String descriptionEn) {
            this.status = status;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public char getStatus() {
            return status;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        public static TransactionStatus fromStatus(char status) {
            for (TransactionStatus ts : values()) {
                if (ts.status == status) {
                    return ts;
                }
            }
            return UNKNOWN;
        }
    }

    /**
     * PG格式码
     */
    public enum FormatCode {
        TEXT((short) 0, "Text", "Text"),
        BINARY((short) 1, "Binary", "Binary"),
        UNKNOWN((short) -1, "Unknown", "Unknown");

        private final short code;
        private final String descriptionCn;
        private final String descriptionEn;

        FormatCode(short code, String descriptionCn, String descriptionEn) {
            this.code = code;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public short getCode() {
            return code;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        public static FormatCode fromCode(short code) {
            for (FormatCode fc : values()) {
                if (fc.code == code) {
                    return fc;
                }
            }
            return UNKNOWN;
        }
    }

    /**
     * PG描述类型（Describe/Close消息中的对象类型）
     */
    public enum DescribeObjectType {
        STATEMENT('S', "Prepared Statement", "Prepared Statement"),
        PORTAL('P', "Portal", "Portal"),
        UNKNOWN('\0', "Unknown", "Unknown");

        private final char type;
        private final String descriptionCn;
        private final String descriptionEn;

        DescribeObjectType(char type, String descriptionCn, String descriptionEn) {
            this.type = type;
            this.descriptionCn = descriptionCn;
            this.descriptionEn = descriptionEn;
        }

        public char getType() {
            return type;
        }

        public String getDescriptionCn() {
            return descriptionCn;
        }

        public String getDescriptionEn() {
            return descriptionEn;
        }

        public static DescribeObjectType fromType(char type) {
            for (DescribeObjectType ot : values()) {
                if (ot.type == type) {
                    return ot;
                }
            }
            return UNKNOWN;
        }
    }

    /**
     * PG协议版本常量
     */
    public static final int PROTOCOL_VERSION_3_0 = 196608; // 0x00030000
    public static final int CANCEL_REQUEST_CODE = 80877102; // 0x04D2162E
    public static final int SSL_REQUEST_CODE = 80877103; // 0x04D2162F

    /**
     * 单个 PG 消息长度的合理上限（字节）。
     * <p>
     * 用于协议识别阶段的假阳性排除：文本载荷的首字母可能恰好是 PG 标签
     * （例如 {@code "HELLO"} 的 {@code 'H'}），此时紧随其后的字节会被解释成一个
     * 巨大的"消息长度"。若不设上限，这类载荷会被误判为 PG，进而被判为
     * "PG 消息不完整"，最终<b>整帧被丢弃</b>。
     * </p>
     * <p>
     * 10 MiB 远大于实际观测到的 PG 消息（含 COPY 数据），但足以排除把 ASCII 文本
     * 当作长度字段的情形。
     * </p>
     */
    public static final int MAX_PLAUSIBLE_MESSAGE_LENGTH = 10 * 1024 * 1024;

    /**
     * PG常见数据类型OID
     */
    public enum PGTypeOID {
        INT2(21, "int2", "smallint"),
        INT4(23, "int4", "integer"),
        INT8(20, "int8", "bigint"),
        FLOAT4(700, "float4", "real"),
        FLOAT8(701, "float8", "double precision"),
        NUMERIC(1700, "numeric", "numeric"),
        BOOL(16, "bool", "boolean"),
        CHAR(18, "char", "char"),
        VARCHAR(1043, "varchar", "character varying"),
        TEXT(25, "text", "text"),
        BYTEA(17, "bytea", "bytea"),
        DATE(1082, "date", "date"),
        TIME(1083, "time", "time without time zone"),
        TIMETZ(1266, "timetz", "time with time zone"),
        TIMESTAMP(1114, "timestamp", "timestamp without time zone"),
        TIMESTAMPTZ(1184, "timestamptz", "timestamp with time zone"),
        INTERVAL(1186, "interval", "interval"),
        UUID(2950, "uuid", "uuid"),
        JSON(114, "json", "json"),
        JSONB(3802, "jsonb", "jsonb"),
        UNKNOWN(-1, "unknown", "unknown");

        private final int oid;
        private final String name;
        private final String displayName;

        PGTypeOID(int oid, String name, String displayName) {
            this.oid = oid;
            this.name = name;
            this.displayName = displayName;
        }

        public int getOid() {
            return oid;
        }

        public String getName() {
            return name;
        }

        public String getDisplayName() {
            return displayName;
        }

        public static PGTypeOID fromOid(int oid) {
            for (PGTypeOID type : values()) {
                if (type.oid == oid) {
                    return type;
                }
            }
            return UNKNOWN;
        }
    }
}
