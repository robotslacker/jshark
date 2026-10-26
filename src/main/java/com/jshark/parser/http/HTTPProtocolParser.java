package com.jshark.parser.http;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;

/**
 * HTTP协议解析器
 * 用于解析HTTP请求和响应
 */
public class HTTPProtocolParser {
    
    /**
     * 将字节数组转换为可读的ASCII字符串，不可见字符用点号(.)代替
     */
    public static String bytesToAscii(byte[] data) {
        if (data == null) return "";
        StringBuilder sb = new StringBuilder(data.length);
        for (byte b : data) {
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }
    
    /**
     * 格式化字节大小为人类可读的格式
     */
    private String formatBytes(int bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        } else {
            return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }
    
    /**
     * 检查数据是否为有效的HTTP数据
     */
    public boolean isValidHTTPData(byte[] data) {
        if (data == null || data.length < 4) {
            return false;
        }
        
        try {
            String dataStr = new String(data, StandardCharsets.US_ASCII);
            
            // 检查是否为HTTP请求
            if (dataStr.startsWith("GET ") || dataStr.startsWith("POST ") || 
                dataStr.startsWith("PUT ") || dataStr.startsWith("DELETE ") ||
                dataStr.startsWith("HEAD ") || dataStr.startsWith("OPTIONS ") ||
                dataStr.startsWith("PATCH ") || dataStr.startsWith("TRACE ") ||
                dataStr.startsWith("CONNECT ")) {
                return true;
            }
            
            // 检查是否为HTTP响应
            return dataStr.startsWith("HTTP/1.0 ") || dataStr.startsWith("HTTP/1.1 ") ||
                    dataStr.startsWith("HTTP/2 ") || dataStr.startsWith("HTTP/3 ");
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 解析HTTP数据
     */
    public Map<String, Object> parse(byte[] data) {
        Map<String, Object> result = new HashMap<>();
        
        if (data == null) {
            result.put("error", "HTTP data is null");
            result.put("parsed.successfully", false);
            return result;
        }
        
        if (data.length < 4) {
            result.put("error", String.format("Invalid HTTP data: too short (expected at least 4 bytes, got %d)", data.length));
            result.put("data.length", data.length);
            result.put("parsed.successfully", false);
            return result;
        }
        
        try {
            String httpText = new String(data, StandardCharsets.UTF_8);
            result.put("raw.text", httpText);
            result.put("raw.text.ascii", bytesToAscii(data));
            result.put("raw.data.size", data.length);
            
            // 检测是请求还是响应
            boolean isRequest = detectIfRequest(httpText);
            result.put("http.type", isRequest ? "Request" : "Response");
            
            if (isRequest) {
                parseHttpRequest(httpText, result);
            } else {
                parseHttpResponse(httpText, result);
            }
            
            // 解析HTTP头部
            parseHttpHeaders(httpText, result);
            
            // 解析HTTP正文
            parseHttpBody(httpText, result);
            
            // 标记解析成功
            result.put("parsed.successfully", true);
            
        } catch (Exception e) {
            String errorDetail = String.format("Failed to parse HTTP data: %s", e.getMessage());
            result.put("error", errorDetail);
            result.put("exception", e.getClass().getSimpleName());
            result.put("parsed.successfully", false);
        }
        
        return result;
    }
    
    /**
     * 检测是否为HTTP请求
     */
    private boolean detectIfRequest(String httpText) {
        if (httpText == null || httpText.length() < 3) {
            return false;
        }
        
        String[] httpMethods = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", 
                               "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "};
        
        for (String method : httpMethods) {
            if (httpText.startsWith(method)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 解析HTTP请求
     */
    private void parseHttpRequest(String httpText, Map<String, Object> result) {
        try {
            int firstLineEnd = httpText.indexOf("\r\n");
            if (firstLineEnd == -1) {
                firstLineEnd = httpText.indexOf('\n');
                if (firstLineEnd == -1) {
                    firstLineEnd = httpText.length();
                }
            }
            
            String requestLine = httpText.substring(0, firstLineEnd).trim();
            result.put("http.request.line", requestLine);
            
            String[] parts = requestLine.split("\\s+", 3);
            if (parts.length >= 3) {
                String method = parts[0];
                HTTPEnums.HttpMethod httpMethod = HTTPEnums.HttpMethod.fromValue(method);
                result.put("http.method", method);
                result.put("http.method.description", httpMethod.getDescription());
                
                String uri = parts[1];
                result.put("http.uri", uri);
                
                String version = parts[2];
                HTTPEnums.HttpVersion httpVersion = HTTPEnums.HttpVersion.fromValue(version);
                result.put("http.version", version);
                result.put("http.version.description", httpVersion.getDescription());
                
                parseUriParameters(uri, result);
                parseUriComponents(uri, result);
            }
            
        } catch (Exception e) {
            result.put("http.request.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析HTTP响应
     */
    private void parseHttpResponse(String httpText, Map<String, Object> result) {
        try {
            int firstLineEnd = httpText.indexOf("\r\n");
            if (firstLineEnd == -1) {
                firstLineEnd = httpText.indexOf('\n');
                if (firstLineEnd == -1) {
                    firstLineEnd = httpText.length();
                }
            }
            
            String statusLine = httpText.substring(0, firstLineEnd).trim();
            result.put("http.status.line", statusLine);
            
            String[] parts = statusLine.split("\\s+", 3);
            if (parts.length >= 3) {
                String version = parts[0];
                HTTPEnums.HttpVersion httpVersion = HTTPEnums.HttpVersion.fromValue(version);
                result.put("http.version", version);
                result.put("http.version.description", httpVersion.getDescription());
                
                try {
                    int statusCode = Integer.parseInt(parts[1]);
                    HTTPEnums.HttpStatusCode httpStatusCode = HTTPEnums.HttpStatusCode.fromCode(statusCode);
                    result.put("http.status.code", statusCode);
                    result.put("http.status.reason", httpStatusCode.getReasonPhrase());
                    result.put("http.status.description", httpStatusCode.getDescription());
                    result.put("http.status.category", HTTPEnums.HttpStatusCode.getCategory(statusCode));
                } catch (NumberFormatException e) {
                    result.put("http.status.code.parse.error", e.getMessage());
                }

                result.put("http.reason.phrase", parts[2]);
            }
            
        } catch (Exception e) {
            result.put("http.response.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析URI参数
     */
    private void parseUriParameters(String uri, Map<String, Object> result) {
        try {
            int queryStart = uri.indexOf('?');
            if (queryStart == -1) {
                return;
            }
            
            String queryString = uri.substring(queryStart + 1);
            result.put("http.query.string", queryString);
            
            Map<String, List<String>> params = new HashMap<>();
            String[] paramPairs = queryString.split("&");
            
            for (String paramPair : paramPairs) {
                String[] keyValue = paramPair.split("=", 2);
                if (keyValue.length >= 1) {
                    String key = keyValue[0];
                    String value = keyValue.length >= 2 ? keyValue[1] : "";
                    params.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
                }
            }
            
            if (!params.isEmpty()) {
                result.put("http.query.parameters", params);
                result.put("http.query.parameter.count", params.size());
            }
            
        } catch (Exception e) {
            result.put("http.uri.parameters.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析URI组件
     */
    private void parseUriComponents(String uri, Map<String, Object> result) {
        try {
            String path = uri;
            int queryStart = uri.indexOf('?');
            if (queryStart != -1) {
                path = uri.substring(0, queryStart);
            }
            
            result.put("http.path", path);
            
            if (path.startsWith("/")) {
                String[] components = path.substring(1).split("/");
                if (components.length > 0 && !components[0].isEmpty()) {
                    result.put("http.path.components", components);
                    result.put("http.path.depth", components.length);
                }
            }
            
        } catch (Exception e) {
            result.put("http.uri.components.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析HTTP头部
     */
    private void parseHttpHeaders(String httpText, Map<String, Object> result) {
        try {
            int headerEnd = httpText.indexOf("\r\n\r\n");
            if (headerEnd == -1) {
                headerEnd = httpText.indexOf("\n\n");
                if (headerEnd == -1) {
                    headerEnd = httpText.length();
                }
            }
            
            int firstLineEnd = httpText.indexOf("\r\n");
            if (firstLineEnd == -1) {
                firstLineEnd = httpText.indexOf('\n');
                if (firstLineEnd == -1) {
                    firstLineEnd = 0;
                }
            }
            
            String headersText = httpText.substring(firstLineEnd + 2, headerEnd);
            String[] headerLines = headersText.split("\r\n|\n");
            
            Map<String, List<String>> headers = new HashMap<>();
            int headerCount = 0;
            
            for (String line : headerLines) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                
                int colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    String name = line.substring(0, colonIndex).trim();
                    String value = line.substring(colonIndex + 1).trim();
                    
                    headers.computeIfAbsent(name.toLowerCase(), k -> new ArrayList<>()).add(value);
                    headerCount++;
                    
                    parseSpecificHeader(name, value, result);
                }
            }
            
            result.put("http.headers", headers);
            result.put("http.header.count", headerCount);
            
        } catch (Exception e) {
            result.put("http.headers.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析特定HTTP头部
     */
    private void parseSpecificHeader(String name, String value, Map<String, Object> result) {
        try {
            String lowerName = name.toLowerCase();
            
            switch (lowerName) {
                case "content-type":
                    HTTPEnums.ContentType contentType = HTTPEnums.ContentType.fromMimeType(value);
                    result.put("http.content.type", value);
                    result.put("http.content.type.description", contentType.getDescription());
                    break;
                    
                case "content-length":
                    try {
                        int contentLength = Integer.parseInt(value);
                        result.put("http.content.length", contentLength);
                        result.put("http.content.length.formatted", formatBytes(contentLength));
                    } catch (NumberFormatException e) {
                        result.put("http.content.length.parse.error", e.getMessage());
                    }
                    break;
                    
                case "user-agent":
                    result.put("http.user.agent", value);
                    break;
                    
                case "host":
                    result.put("http.host", value);
                    break;
                    
                case "referer":
                    result.put("http.referer", value);
                    break;
                    
                case "cookie":
                    parseCookies(value, result);
                    break;
                    
                case "set-cookie":
                    parseSetCookies(value, result);
                    break;
                    
                case "authorization":
                    result.put("http.authorization.present", true);
                    parseAuthorization(value, result);
                    break;
                    
                case "server":
                    result.put("http.server", value);
                    break;
                    
                case "date":
                    result.put("http.date", value);
                    break;
                    
                case "connection":
                    result.put("http.connection", value);
                    break;
            }
            
        } catch (Exception e) {
            // 忽略错误
        }
    }
    
    /**
     * 解析Cookie头部
     */
    private void parseCookies(String cookieHeader, Map<String, Object> result) {
        try {
            Map<String, String> cookies = new HashMap<>();
            String[] cookiePairs = cookieHeader.split(";");
            
            for (String cookiePair : cookiePairs) {
                String[] keyValue = cookiePair.trim().split("=", 2);
                if (keyValue.length >= 1) {
                    String key = keyValue[0].trim();
                    String value = keyValue.length >= 2 ? keyValue[1].trim() : "";
                    cookies.put(key, value);
                }
            }
            
            if (!cookies.isEmpty()) {
                result.put("http.cookies", cookies);
                result.put("http.cookie.count", cookies.size());
            }
            
        } catch (Exception e) {
            result.put("http.cookies.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析Set-Cookie头部
     */
    private void parseSetCookies(String setCookieHeader, Map<String, Object> result) {
        try {
            List<Map<String, String>> setCookies = new ArrayList<>();
            Map<String, String> cookie = new HashMap<>();
            
            String[] parts = setCookieHeader.split(";");
            if (parts.length > 0) {
                String[] nameValue = parts[0].trim().split("=", 2);
                if (nameValue.length >= 1) {
                    String name = nameValue[0].trim();
                    String value = nameValue.length >= 2 ? nameValue[1].trim() : "";
                    cookie.put("name", name);
                    cookie.put("value", value);
                }
                
                for (int i = 1; i < parts.length; i++) {
                    String attr = parts[i].trim();
                    String[] attrParts = attr.split("=", 2);
                    if (attrParts.length >= 1) {
                        String attrName = attrParts[0].trim().toLowerCase();
                        String attrValue = attrParts.length >= 2 ? attrParts[1].trim() : "";
                        cookie.put(attrName, attrValue);
                    }
                }
                
                setCookies.add(cookie);
                result.put("http.set.cookies", setCookies);
            }
            
        } catch (Exception e) {
            result.put("http.set.cookies.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析Authorization头部
     */
    private void parseAuthorization(String authHeader, Map<String, Object> result) {
        try {
            if (authHeader.startsWith("Basic ")) {
                result.put("http.auth.type", "Basic");
                String encoded = authHeader.substring(6);
                result.put("http.auth.basic.encoded", encoded);
                
                try {
                    String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
                    result.put("http.auth.basic.decoded", decoded);
                    
                    String[] credentials = decoded.split(":", 2);
                    if (credentials.length >= 1) {
                        result.put("http.auth.username", credentials[0]);
                        if (credentials.length >= 2) {
                            result.put("http.auth.password.present", true);
                        }
                    }
                } catch (Exception e) {
                    result.put("http.auth.basic.decode.error", e.getMessage());
                }
                
            } else if (authHeader.startsWith("Bearer ")) {
                result.put("http.auth.type", "Bearer");
                String token = authHeader.substring(7);
                result.put("http.auth.bearer.token", token);
                result.put("http.auth.bearer.token.length", token.length());
                
            } else {
                result.put("http.auth.type", "Other");
                result.put("http.auth.value", authHeader);
            }
            
        } catch (Exception e) {
            result.put("http.authorization.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析HTTP正文
     */
    private void parseHttpBody(String httpText, Map<String, Object> result) {
        try {
            int headerEnd = httpText.indexOf("\r\n\r\n");
            if (headerEnd == -1) {
                headerEnd = httpText.indexOf("\n\n");
                if (headerEnd == -1) {
                    return;
                }
            }
            
            String body = httpText.substring(headerEnd + 4);
            if (!body.isEmpty()) {
                result.put("http.body.present", true);
                result.put("http.body.length", body.length());
                
                // 尝试解析JSON或表单数据
                try {
                    String trimmedBody = body.trim();
                    if (trimmedBody.startsWith("{") && trimmedBody.endsWith("}")) {
                        result.put("http.body.format", "JSON");
                        // 解析JSON内容
                        parseJsonBody(trimmedBody, result);
                    } else if (body.contains("=") && body.contains("&")) {
                        result.put("http.body.format", "Form URL-encoded");
                        // 非JSON格式，记录完整内容到http.content.string
                        result.put("http.content.string", body);
                    } else {
                        // 其他格式，记录完整内容到http.content.string
                        result.put("http.content.string", body);
                    }
                } catch (Exception e) {
                    // 解析失败时，记录原始内容到http.content.string
                    result.put("http.content.string", body);
                    result.put("http.body.parse.warning", "Failed to parse body: " + e.getMessage());
                }
            } else {
                result.put("http.body.present", false);
            }
        } catch (Exception e) {
            result.put("http.body.parse.error", e.getMessage());
        }
    }
    
    /**
     * 解析JSON格式的HTTP正文
     */
    private void parseJsonBody(String jsonBody, Map<String, Object> result) {
        try {
            // 使用FastJSON2解析JSON
            JSONObject jsonObject = JSON.parseObject(jsonBody);
            
            // 将JSON的所有字段添加到结果中，前缀为http.content.
            for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                
                // 将键名转换为小写并用点号分隔，避免特殊字符问题
                String safeKey = key.replaceAll("[^a-zA-Z0-9_]", "_").toLowerCase();
                result.put("http.content." + safeKey, value);
                
                // 同时保留原始键名（如果不同）
                if (!safeKey.equals(key)) {
                    result.put("http.content." + key, value);
                }
            }
            
            // 记录JSON解析成功
            result.put("http.json.parsed", true);
            
        } catch (Exception e) {
            // JSON解析失败，记录原始内容到http.content.string
            result.put("http.content.string", jsonBody);
            result.put("http.json.parse.error", e.getMessage());
            result.put("http.json.parsed", false);
        }
    }
}