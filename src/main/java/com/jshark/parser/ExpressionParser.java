package com.jshark.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 轻量级表达式解析器 - "FilterNinja"（过滤忍者）
 * 专为数据包过滤设计，高效、简洁、带点小趣味
 * 支持功能：
 * 1. 括号分组：()
 * 2. 逻辑运算：&& (AND), || (OR)
 * 3. 比较运算：=, !=, >, <, >=, <=
 * 4. 字符串匹配：like (支持通配符 * 和 ?)
 * 语法示例：
 *   dis.pdu.type=28 && dis.exercise.id=17
 *   (dis.pdu.type=28 || dis.pdu.type=1) && dis.exercise.id!=0
 *   dis.pdu.type>20 && dis.pdu.type<30
 *   dis.entity.name like "*tank*"
 *   (dis.pdu.type=28 && dis.exercise.id=17) || dis.entity.id=100
 * 设计原则：KISS (Keep It Simple, Stupid!)
 * 实现策略：递归下降解析器
 */
public class ExpressionParser {
    private static final Logger logger = LoggerFactory.getLogger(ExpressionParser.class);
    
    private final String expression;
    private int pos;
    private final int length;
    
    /**
     * 构造函数
     */
    private ExpressionParser(String expression) {
        this.expression = expression != null ? expression.trim() : "";
        this.pos = 0;
        this.length = this.expression.length();
    }
    
    /**
     * 表达式求值 - 主入口方法
     * @param expression 过滤表达式
     * @param context 上下文数据（键值对）
     * @return 是否匹配
     */
    public static boolean evaluate(String expression, Map<String, Object> context) {
        if (expression == null || expression.trim().isEmpty()) {
            return true; // 空表达式总是匹配
        }
        
        try {
            ExpressionParser parser = new ExpressionParser(expression);
            return parser.parseExpression(context);
        } catch (Exception e) {
            logger.warn("Expression parse failed: {} - {}", expression, e.getMessage());
            return false; // 解析失败时默认不匹配
        }
    }
    
    /**
     * 解析表达式：expression ::= orExpression
     */
    private boolean parseExpression(Map<String, Object> context) {
        return parseOrExpression(context);
    }
    
    /**
     * 解析或表达式：orExpression ::= andExpression ('||' andExpression)*
     */
    private boolean parseOrExpression(Map<String, Object> context) {
        boolean result = parseAndExpression(context);
        
        while (match("||")) {
            consume("||");
            boolean right = parseAndExpression(context);
            result = result || right;
        }
        
        return result;
    }
    
    /**
     * 解析与表达式：andExpression ::= term ('&&' term)*
     */
    private boolean parseAndExpression(Map<String, Object> context) {
        boolean result = parseTerm(context);
        
        while (match("&&")) {
            consume("&&");
            boolean right = parseTerm(context);
            result = result && right;
        }
        
        return result;
    }
    
    /**
     * 解析项：term ::= '(' expression ')' | comparison
     */
    private boolean parseTerm(Map<String, Object> context) {
        skipWhitespace();
        
        if (match("(")) {
            consume("(");
            boolean result = parseExpression(context);
            if (!match(")")) {
                throw new IllegalArgumentException("Expected '" + ")" + "', but found: " +
                        (pos < length ? expression.substring(pos, Math.min(pos + ")".length() + 5, length)) : "EOF"));
            }
            consume(")");
            return result;
        } else {
            return parseComparison(context);
        }
    }
    
    /**
     * 解析比较表达式：comparison ::= key operator value
     */
    private boolean parseComparison(Map<String, Object> context) {
        skipWhitespace();
        
        // 解析key
        String key = parseIdentifier();
        
        skipWhitespace();
        
        // 解析操作符
        String operator = parseOperator();
        
        skipWhitespace();
        
        // 解析值
        String value = parseValue();
        
        // 求值比较
        return evaluateComparison(key, operator, value, context);
    }
    
    /**
     * 解析标识符（key）
     */
    private String parseIdentifier() {
        StringBuilder sb = new StringBuilder();
        
        while (pos < length) {
            char c = expression.charAt(pos);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '.') {
                sb.append(c);
                pos++;
            } else {
                break;
            }
        }
        
        if (sb.isEmpty()) {
            throw new IllegalArgumentException("Expected identifier, but found: " + (pos < length ? expression.charAt(pos) : "EOF"));
        }
        
        return sb.toString();
    }
    
    /**
     * 解析操作符
     */
    private String parseOperator() {
        // 检查多字符操作符
        if (pos + 1 < length) {
            String twoChar = expression.substring(pos, pos + 2);
            if (twoChar.equals("!=") || twoChar.equals(">=") || twoChar.equals("<=")) {
                pos += 2;
                return twoChar;
            }
        }
        
        // 检查like操作符
        if (pos + 4 < length && expression.substring(pos, pos + 4).equalsIgnoreCase("like")) {
            pos += 4;
            return "like";
        }
        
        // 单字符操作符
        if (pos < length) {
            char c = expression.charAt(pos);
            if (c == '=' || c == '>' || c == '<') {
                pos++;
                return String.valueOf(c);
            }
        }
        
        throw new IllegalArgumentException("Expected operator, but found: " + (pos < length ? expression.charAt(pos) : "EOF"));
    }
    
    /**
     * 解析值
     */
    private String parseValue() {
        if (pos >= length) {
            throw new IllegalArgumentException("Expected value, but found EOF");
        }
        
        // 检查引号字符串
        char firstChar = expression.charAt(pos);
        if (firstChar == '"' || firstChar == '\'') {
            return parseQuotedString(firstChar);
        }
        
        // 解析普通值（标识符或数字）
        StringBuilder sb = new StringBuilder();
        
        while (pos < length) {
            char c = expression.charAt(pos);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '*') {
                sb.append(c);
                pos++;
            } else if (c == '?' && expression.substring(pos, Math.min(pos + 4, length)).startsWith("? ")) {
                // 通配符?，但后面有空格时停止
                sb.append(c);
                pos++;
            } else {
                break;
            }
        }
        
        if (sb.isEmpty()) {
            throw new IllegalArgumentException("Expected value, but found: " + (pos < length ? expression.charAt(pos) : "EOF"));
        }
        
        return sb.toString();
    }
    
    /**
     * 解析引号字符串
     */
    private String parseQuotedString(char quoteChar) {
        StringBuilder sb = new StringBuilder();
        pos++; // 跳过开头的引号
        
        while (pos < length) {
            char c = expression.charAt(pos);
            if (c == quoteChar) {
                pos++; // 跳过结尾的引号
                return sb.toString();
            } else if (c == '\\' && pos + 1 < length) {
                // 转义字符
                sb.append(expression.charAt(pos + 1));
                pos += 2;
            } else {
                sb.append(c);
                pos++;
            }
        }
        
        throw new IllegalArgumentException("Unterminated string literal");
    }
    
    /**
     * 求值比较表达式
     */
    private boolean evaluateComparison(String key, String operator, String expected, Map<String, Object> context) {
        // 获取实际值
        Object actualObj = context.get(key);
        if (actualObj == null) {
            return false; // 键不存在
        }
        
        String actual = actualObj.toString();
        
        // 根据操作符类型比较
        switch (operator) {
            case "=" -> {
                return actual.equals(expected);
            }
            case "!=" -> {
                return !actual.equals(expected);
            }
            case "like" -> {
                return likeMatch(actual, expected);
            }
            default -> {
                // 数值比较
                try {
                    double actualNum = Double.parseDouble(actual);
                    double expectedNum = Double.parseDouble(expected);

                    return switch (operator) {
                        case ">" -> actualNum > expectedNum;
                        case "<" -> actualNum < expectedNum;
                        case ">=" -> actualNum >= expectedNum;
                        case "<=" -> actualNum <= expectedNum;
                        default -> throw new IllegalArgumentException("Unknown operator: " + operator);
                    };
                } catch (NumberFormatException e) {
                    // 不是数字，尝试字符串比较
                    logger.debug("Numeric comparison failed; falling back to string comparison: {} {}", actual, expected);
                    return false; // 类型不匹配，返回false
                }
            }
        }
    }
    
    /**
     * like模式匹配：支持通配符 * 和 ?
     * * 匹配0个或多个字符
     * ? 匹配1个字符
     */
    private static boolean likeMatch(String text, String pattern) {
        // 将like模式转换为正则表达式
        // 注意转义顺序：先转义正则特殊字符，再替换通配符
        String regex = pattern
            .replace("\\", "\\\\")  // 转义反斜杠
            .replace(".", "\\.")    // 转义点号
            .replace("*", "\\*")    // 临时转义星号（避免与通配符混淆）
            .replace("?", "\\?")    // 临时转义问号（避免与通配符混淆）
            .replace("\\*", ".*")   // 通配符 * → 正则 .*
            .replace("\\?", ".");   // 通配符 ? → 正则 .
        
        try {
            return Pattern.matches(regex, text);
        } catch (PatternSyntaxException e) {
            logger.warn("Invalid LIKE pattern: {}", pattern);
            return false;
        }
    }
    
    /**
     * 跳过空白字符
     */
    private void skipWhitespace() {
        while (pos < length && Character.isWhitespace(expression.charAt(pos))) {
            pos++;
        }
    }
    
    /**
     * 检查是否匹配指定的字符串
     */
    private boolean match(String expected) {
        skipWhitespace();
        
        if (pos + expected.length() > length) {
            return false;
        }
        
        for (int i = 0; i < expected.length(); i++) {
            if (expression.charAt(pos + i) != expected.charAt(i)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 消费指定的字符串
     */
    private void consume(String expected) {
        if (!match(expected)) {
            throw new IllegalArgumentException("Expected '" + expected + "', but found: " + 
                (pos < length ? expression.substring(pos, Math.min(pos + expected.length() + 5, length)) : "EOF"));
        }
        
        pos += expected.length();
        skipWhitespace();
    }
}