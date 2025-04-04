package com.wgcloud.analysis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SqlInjectionAnalysis {

    @Autowired
    private AlarmInfoService alarmStorageService;

    // SQL注入特征正则表达式
    private static final Pattern SQL_INJECTION_PATTERNS = Pattern.compile(
            "(?i)" +  // 忽略大小写
                    "(" +
                    // 特征1: 单引号结合逻辑运算符
                    "'\\s+(OR|AND)\\s+[\\w\\d]+\\s*=\\s*[\\w\\d]+" +
                    "|" +
                    // 特征2: SQL关键字
                    "\\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE)?|INSERT( +INTO)?|MERGE|SELECT|UPDATE|UNION( +ALL)?)\\b" +
                    "|" +
                    // 特征3: 注释或语句分隔符
                    ";|--|/\\*.*?\\*/" +
                    "|" +
                    // 特征4: 永真条件
                    "\\bOR\\b\\s*\\d+\\s*=\\s*\\d+" +
                    ")"
    );

    // 文件上传请求标识（新增）
    private static final Pattern FILE_UPLOAD_INDICATORS = Pattern.compile(
            "(?i)" +
                    "(Content-Type:\\s*multipart/form-data|" +
                    "filename\\s*=\\s*\"[^\"]+\\.\\w+\")"
    );

    /**
     * 分析流量数据，检测SQL注入攻击
     */
    public void analyzeAndSaveSqlInjection(Map<String, StringBuilder> streamData) {
        for (Map.Entry<String, StringBuilder> entry : streamData.entrySet()) {
            String streamKey = entry.getKey();
            String payload = getPayloadAsString(entry.getValue());

            // 新增：排除文件上传请求（先检查是否为上传请求）
            if (isFileUploadRequest(payload)) {
                continue; // 跳过文件上传请求的SQL注入检测
            }

            List<String> detectedPatterns = detectSqlInjectionPatterns(payload);

            if (!detectedPatterns.isEmpty()) {
                String sourceIp = extractIpFromStream(streamKey);
                alarmStorageService.saveSecurityAlert(
                        0,
                        payload,
                        sourceIp,
                        streamKey
                );
            }
        }
    }

    /**
     * 检测是否为文件上传请求（新增方法）
     */
    private boolean isFileUploadRequest(String payload) {
        if (payload == null || payload.isEmpty()) {
            return false;
        }
        return FILE_UPLOAD_INDICATORS.matcher(payload).find();
    }

    /**
     * 提取SQL注入特征（重构为独立方法）
     */
    private List<String> detectSqlInjectionPatterns(String payload) {
        List<String> patterns = new ArrayList<>();
        if (payload == null || payload.isEmpty()) {
            return patterns;
        }

        Matcher matcher = SQL_INJECTION_PATTERNS.matcher(payload);
        while (matcher.find()) {
            patterns.add(matcher.group());
        }
        return patterns;
    }

    private String extractIpFromStream(String streamKey) {
        if (streamKey == null || streamKey.isEmpty()) return "未知IP";
        String[] parts = streamKey.split("->")[0].split(":");
        return (parts.length > 0) ? parts[0] : "未知IP";
    }

    private String getPayloadAsString(StringBuilder sb) {
        return (sb != null) ? sb.toString() : "";
    }
}