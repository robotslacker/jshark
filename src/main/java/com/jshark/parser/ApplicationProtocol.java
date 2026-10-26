package com.jshark.parser;

/**
 * 应用层协议枚举
 * 用于标识检测到的应用层协议类型
 */
public enum ApplicationProtocol
{
    /** 分布式交互仿真协议 */
    DIS,
    /** HTTP协议 */
    HTTP,
    /** PostgreSQL Wire Protocol */
    PG,
    /** 未知协议 */
    UNKNOWN
}
