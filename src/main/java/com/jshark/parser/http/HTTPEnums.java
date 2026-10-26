package com.jshark.parser.http;

/**
 * HTTP协议枚举定义
 * 包含HTTP协议中使用的常量枚举，每个枚举都包含描述信息
 */
public class HTTPEnums {
    
    /**
     * HTTP方法枚举
     */
    public enum HttpMethod {
        GET("GET", "GET Request"),
        POST("POST", "POST Request"),
        PUT("PUT", "PUT Request"),
        DELETE("DELETE", "DELETE Request"),
        HEAD("HEAD", "HEAD Request"),
        OPTIONS("OPTIONS", "OPTIONS Request"),
        PATCH("PATCH", "PATCH Request"),
        TRACE("TRACE", "TRACE Request"),
        CONNECT("CONNECT", "CONNECT Request"),
        UNKNOWN("UNKNOWN", "Unknown HTTP Method");
        
        private final String value;
        private final String description;
        
        HttpMethod(String value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public String getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static HttpMethod fromValue(String value) {
            if (value == null) {
                return UNKNOWN;
            }
            
            for (HttpMethod method : values()) {
                if (method.value.equalsIgnoreCase(value)) {
                    return method;
                }
            }
            return UNKNOWN;
        }
    }
    
    /**
     * HTTP版本枚举
     */
    public enum HttpVersion {
        HTTP_0_9("HTTP/0.9", "HTTP/0.9"),
        HTTP_1_0("HTTP/1.0", "HTTP/1.0"),
        HTTP_1_1("HTTP/1.1", "HTTP/1.1"),
        HTTP_2_0("HTTP/2.0", "HTTP/2.0"),
        HTTP_3_0("HTTP/3.0", "HTTP/3.0"),
        UNKNOWN("UNKNOWN", "Unknown HTTP Version");
        
        private final String value;
        private final String description;
        
        HttpVersion(String value, String description) {
            this.value = value;
            this.description = description;
        }
        
        public String getValue() {
            return value;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static HttpVersion fromValue(String value) {
            if (value == null) {
                return UNKNOWN;
            }
            
            for (HttpVersion version : values()) {
                if (version.value.equalsIgnoreCase(value)) {
                    return version;
                }
            }
            return UNKNOWN;
        }
    }
    
    /**
     * HTTP状态码枚举
     */
    public enum HttpStatusCode {
        // 1xx Informational
        CONTINUE(100, "Continue", "Continue"),
        SWITCHING_PROTOCOLS(101, "Switching Protocols", "Switching Protocols"),
        PROCESSING(102, "Processing", "Processing"),
        
        // 2xx Success
        OK(200, "OK", "OK"),
        CREATED(201, "Created", "Created"),
        ACCEPTED(202, "Accepted", "Accepted"),
        NO_CONTENT(204, "No Content", "No Content"),
        RESET_CONTENT(205, "Reset Content", "Reset Content"),
        PARTIAL_CONTENT(206, "Partial Content", "Partial Content"),
        
        // 3xx Redirection
        MULTIPLE_CHOICES(300, "Multiple Choices", "Multiple Choices"),
        MOVED_PERMANENTLY(301, "Moved Permanently", "Moved Permanently"),
        FOUND(302, "Found", "Found"),
        SEE_OTHER(303, "See Other", "See Other"),
        NOT_MODIFIED(304, "Not Modified", "Not Modified"),
        TEMPORARY_REDIRECT(307, "Temporary Redirect", "Temporary Redirect"),
        PERMANENT_REDIRECT(308, "Permanent Redirect", "Permanent Redirect"),
        
        // 4xx Client Error
        BAD_REQUEST(400, "Bad Request", "Bad Request"),
        UNAUTHORIZED(401, "Unauthorized", "Unauthorized"),
        FORBIDDEN(403, "Forbidden", "Forbidden"),
        NOT_FOUND(404, "Not Found", "Not Found"),
        METHOD_NOT_ALLOWED(405, "Method Not Allowed", "Method Not Allowed"),
        REQUEST_TIMEOUT(408, "Request Timeout", "Request Timeout"),
        CONFLICT(409, "Conflict", "Conflict"),
        GONE(410, "Gone", "Gone"),
        PAYLOAD_TOO_LARGE(413, "Payload Too Large", "Payload Too Large"),
        URI_TOO_LONG(414, "URI Too Long", "URI Too Long"),
        UNSUPPORTED_MEDIA_TYPE(415, "Unsupported Media Type", "Unsupported Media Type"),
        TOO_MANY_REQUESTS(429, "Too Many Requests", "Too Many Requests"),
        
        // 5xx Server Error
        INTERNAL_SERVER_ERROR(500, "Internal Server Error", "Internal Server Error"),
        NOT_IMPLEMENTED(501, "Not Implemented", "Not Implemented"),
        BAD_GATEWAY(502, "Bad Gateway", "Bad Gateway"),
        SERVICE_UNAVAILABLE(503, "Service Unavailable", "Service Unavailable"),
        GATEWAY_TIMEOUT(504, "Gateway Timeout", "Gateway Timeout"),
        HTTP_VERSION_NOT_SUPPORTED(505, "HTTP Version Not Supported", "HTTP Version Not Supported"),
        
        // Unknown
        UNKNOWN(0, "Unknown", "Unknown Status Code");
        
        private final int code;
        private final String reasonPhrase;
        private final String description;
        
        HttpStatusCode(int code, String reasonPhrase, String description) {
            this.code = code;
            this.reasonPhrase = reasonPhrase;
            this.description = description;
        }
        
        public int getCode() {
            return code;
        }
        
        public String getReasonPhrase() {
            return reasonPhrase;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static HttpStatusCode fromCode(int code) {
            for (HttpStatusCode statusCode : values()) {
                if (statusCode.code == code) {
                    return statusCode;
                }
            }
            return UNKNOWN;
        }
        
        public static String getCategory(int code) {
            if (code >= 100 && code < 200) {
                return "Informational";
            } else if (code >= 200 && code < 300) {
                return "Success";
            } else if (code >= 300 && code < 400) {
                return "Redirection";
            } else if (code >= 400 && code < 500) {
                return "Client Error";
            } else if (code >= 500 && code < 600) {
                return "Server Error";
            } else {
                return "Unknown";
            }
        }
    }
    
    /**
     * HTTP内容类型枚举（常见类型）
     */
    public enum ContentType {
        TEXT_HTML("text/html", "HTML Document"),
        TEXT_PLAIN("text/plain", "Plain Text"),
        TEXT_CSS("text/css", "CSS Stylesheet"),
        TEXT_JAVASCRIPT("text/javascript", "JavaScript"),
        APPLICATION_JSON("application/json", "JSON Data"),
        APPLICATION_XML("application/xml", "XML Data"),
        APPLICATION_FORM_URLENCODED("application/x-www-form-urlencoded", "Form Data"),
        MULTIPART_FORM_DATA("multipart/form-data", "Multipart Form Data"),
        APPLICATION_OCTET_STREAM("application/octet-stream", "Binary Stream"),
        IMAGE_JPEG("image/jpeg", "JPEG Image"),
        IMAGE_PNG("image/png", "PNG Image"),
        IMAGE_GIF("image/gif", "GIF Image"),
        UNKNOWN("unknown", "Unknown Content Type");
        
        private final String mimeType;
        private final String description;
        
        ContentType(String mimeType, String description) {
            this.mimeType = mimeType;
            this.description = description;
        }
        
        public String getMimeType() {
            return mimeType;
        }
        
        public String getDescription() {
            return description;
        }
        
        public static ContentType fromMimeType(String mimeType) {
            if (mimeType == null) {
                return UNKNOWN;
            }
            
            // 处理可能包含字符集的MIME类型（如 "text/html; charset=utf-8"）
            String baseMimeType = mimeType.split(";")[0].trim();
            
            for (ContentType contentType : values()) {
                if (contentType.mimeType.equalsIgnoreCase(baseMimeType)) {
                    return contentType;
                }
            }
            return UNKNOWN;
        }
    }
}