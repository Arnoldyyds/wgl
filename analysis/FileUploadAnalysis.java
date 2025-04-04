package com.wgcloud.analysis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class FileUploadAnalysis {

    @Autowired
    private AlarmInfoService alarmStorageService; // 复用报警服务

    // 文件上传特征正则表达式
    private static final Pattern FILE_UPLOAD_PATTERNS = Pattern.compile(
            "(?i)" +  // 忽略大小写
                    "(" +
                    // 特征1: 危险文件扩展名
                    "\\b(filename|name)=\\s*\"[^\"]*\\.(php|jsp|asp|aspx|exe|sh|bat|dll|jar|war)\\b" +
                    "|" +
                    // 特征2: 可疑的 Content-Type
                    "Content-Type:\\s*(application/x-php|application/x-jsp-application|application/x-msdownload|application/x-asp)" +
                    "|" +
                    // 特征3: 多部分表单上传标识
                    "multipart/form-data;\\s*boundary=" +
                    "|" +
                    // 特征4: 一句话木马（PHP/JSP/ASP）
                    "(\\b(eval\\(|assert\\(|system\\(|passthru\\(|exec\\(|shell_exec\\(|popen\\(|proc_open\\()" +
                    "|" +
                    "<%@\\s*page\\s*.*%>|<%\\s*.*%>|\\$_(GET|POST|REQUEST)\\s*\\[)" +
                    ")"
    );

    /**
     * 分析流量数据，检测文件上传攻击
     */
    public void analyzeAndSaveUploadAttack(Map<String, StringBuilder> streamData) {
        for (Map.Entry<String, StringBuilder> entry : streamData.entrySet()) {
            String streamKey = entry.getKey();
            String payload = getPayloadAsString(entry.getValue());

            // 检测文件上传特征
            List<String> detectedPatterns = new ArrayList<>();
            Matcher matcher = FILE_UPLOAD_PATTERNS.matcher(payload);
            while (matcher.find()) {
                detectedPatterns.add(matcher.group());
            }

            // 如果检测到特征，存储报警信息
            if (!detectedPatterns.isEmpty()) {
                String sourceIp = extractIpFromStream(streamKey);
                alarmStorageService.saveSecurityAlert(
                        1, // 文件上传攻击的索引
                        payload,
                        sourceIp,
                        streamKey
                );
            }
        }
    }

    // 复用 SQL 注入分析类中的工具方法 ---------------
    private String extractIpFromStream(String streamKey) {
        if (streamKey == null || streamKey.isEmpty()) return "未知IP";
        String[] parts = streamKey.split("->")[0].split(":");
        return (parts.length > 0) ? parts[0] : "未知IP";
    }

    private String getPayloadAsString(StringBuilder sb) {
        return (sb != null) ? sb.toString() : "";
    }
}