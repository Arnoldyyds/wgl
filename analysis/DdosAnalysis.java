package com.wgcloud.analysis;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Component
public class DdosAnalysis {

    @Autowired
    private AlarmInfoService alarmStorageService;

    // DDoS 检测参数（可配置化）
    private static final int TIME_WINDOW_SECONDS = 10; // 检测时间窗口（秒）
    private static final int SYN_THRESHOLD = 1000;     // SYN包阈值（10秒内超过1000次）
    private static final int UDP_THRESHOLD = 5000;     // UDP包阈值（10秒内超过5000次）
    private static final int REQUEST_THRESHOLD = 100;  // 单IP请求阈值（10秒内超过100次）

    // 文件上传请求标识（新增）
    private static final Pattern FILE_UPLOAD_INDICATORS = Pattern.compile(
            "(?i)(Content-Type:\\s*multipart/form-data|filename\\s*=\\s*\"[^\"]+\\.\\w+\")");

    /**
     * 分析流量数据，检测 DDoS 攻击
     */
    public void analyzeAndSaveDdosAlert(Map<String, List<Long>> trafficData, String protocolType) {
        Map<String, Integer> sourceIpCounts = new HashMap<>();
        int totalPackets = 0;

        // 统计每个源IP的请求次数（排除文件上传）
        for (Map.Entry<String, List<Long>> entry : trafficData.entrySet()) {
            String streamKey = entry.getKey();
            String payload = extractPayloadFromStreamKey(streamKey); // 假设可以从streamKey获取payload

            // 排除文件上传请求（新增）
            if (isFileUploadRequest(payload)) {
                continue;
            }

            String sourceIp = extractIpFromStream(streamKey);
            sourceIpCounts.put(sourceIp, sourceIpCounts.getOrDefault(sourceIp, 0) + 1);
            totalPackets++;
        }

        // 检测高频请求攻击（单IP）
        detectHighFrequencyAttacks(sourceIpCounts, protocolType);

        // 检测 SYN/UDP Flood（总包数）
        detectFloodAttacks(totalPackets, protocolType);
    }

    /**
     * 检测高频请求攻击（重构为独立方法）
     */
    private void detectHighFrequencyAttacks(Map<String, Integer> sourceIpCounts, String protocolType) {
        sourceIpCounts.entrySet().stream()
                .filter(entry -> entry.getValue() > REQUEST_THRESHOLD)
                .forEach(entry -> {
                    alarmStorageService.saveSecurityAlert(
                            1,
                            String.format("[高频请求] 源IP %s 在 %d 秒内发送 %d 次请求（非文件上传）",
                                    entry.getKey(), TIME_WINDOW_SECONDS, entry.getValue()),
                            entry.getKey(),
                            "协议类型: " + protocolType
                    );
                });
    }

    /**
     * 检测Flood攻击（重构为独立方法）
     */
    private void detectFloodAttacks(int totalPackets, String protocolType) {
        if ("TCP".equals(protocolType) && totalPackets > SYN_THRESHOLD) {
            alarmStorageService.saveSecurityAlert(
                    2,
                    String.format("[SYN Flood] 在 %d 秒内检测到 %d 个 SYN 包（非文件上传）",
                            TIME_WINDOW_SECONDS, totalPackets),
                    "N/A",
                    "协议类型: " + protocolType
            );
        } else if ("UDP".equals(protocolType) && totalPackets > UDP_THRESHOLD) {
            alarmStorageService.saveSecurityAlert(
                    2,
                    String.format("[UDP Flood] 在 %d 秒内检测到 %d 个 UDP 包（非文件上传）",
                            TIME_WINDOW_SECONDS, totalPackets),
                    "N/A",
                    "协议类型: " + protocolType
            );
        }
    }

    /**
     * 检测是否为文件上传请求（新增方法）
     */
    private boolean isFileUploadRequest(String payload) {
        return payload != null && FILE_UPLOAD_INDICATORS.matcher(payload).find();
    }

    /**
     * 从streamKey中提取payload（示例方法，需根据实际实现调整）
     */
    private String extractPayloadFromStreamKey(String streamKey) {
        // 实际实现应根据streamKey的结构获取对应的payload
        // 这里只是示例，可能需要从其他数据源获取
        return "";
    }

    private String extractIpFromStream(String streamKey) {
        if (streamKey == null || streamKey.isEmpty()) return "未知IP";
        String[] parts = streamKey.split("->")[0].split(":");
        return (parts.length > 0) ? parts[0] : "未知IP";
    }
}