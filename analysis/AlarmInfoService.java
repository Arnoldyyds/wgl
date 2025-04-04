package com.wgcloud.analysis;

import com.wgcloud.entity.AlarmInfo;
import com.wgcloud.mapper.AlarmInfoMapper;
import com.wgcloud.util.IpLocationUtils;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AlarmInfoService {
    private static final Logger logger = LoggerFactory.getLogger(AlarmInfoService.class);
    private static final String UNKNOWN_IP = "未知IP";
    private final List<String> alarmTypeList = Arrays.asList("SQL注入攻击", "文件上传攻击", "DDos攻击");

    @Autowired
    private AlarmInfoMapper alarmInfoMapper;
    @Autowired
    private IpLocationUtils ipLocationUtils;

    /**
     * 分页查询报警信息（修复版）
     */
    public PageInfo<AlarmInfo> selectByParams(Map<String, Object> params, Integer page, Integer pageSize) throws Exception {
        try {
            PageHelper.startPage(page, pageSize);
            List<AlarmInfo> list = alarmInfoMapper.selectByParams(params);

            // 确保数据不为null且包含必要字段
            if (list != null) {
                for (AlarmInfo alarm : list) {
                    // 处理可能为null的字段
                    if (alarm.getIpAddress() == null) {
                        alarm.setIpAddress(UNKNOWN_IP);
                    }
                    if (alarm.getIpLocation() == null && !UNKNOWN_IP.equals(alarm.getIpAddress())) {
                        // 对已有IP但无位置信息的进行补充查询
                        alarm.setIpLocation(ipLocationUtils.getLocation(alarm.getIpAddress()));
                    }
                    if (alarm.getAlarmType() == null) {
                        alarm.setAlarmType("未知攻击类型");
                    }
                }
            }
            return new PageInfo<>(list);
        } catch (Exception e) {
            logger.error("查询报警信息失败", e);
            throw new Exception("查询报警信息失败: " + e.getMessage());
        }
    }

    /**
     * 查询所有符合条件的报警记录（用于导出）
     */
    public List<AlarmInfo> selectAllByParams(Map<String, Object> params) throws Exception {
        try {
            List<AlarmInfo> list = alarmInfoMapper.selectByParams(params);

            // 数据校验和处理
            if (list != null) {
                for (AlarmInfo alarm : list) {
                    if (alarm.getIpAddress() == null) {
                        alarm.setIpAddress(UNKNOWN_IP);
                    }
                    if (alarm.getIpLocation() == null) {
                        alarm.setIpLocation(ipLocationUtils.getLocation(alarm.getIpAddress()));
                    }
                }
            }
            return list;
        } catch (Exception e) {
            logger.error("查询所有报警信息失败", e);
            throw new Exception("查询所有报警信息失败: " + e.getMessage());
        }
    }

    /**
     * 根据ID查询单条记录（修复版）
     */
    public AlarmInfo selectById(String id) throws Exception {
        try {
            AlarmInfo alarm = alarmInfoMapper.selectById(id);
            if (alarm == null) {
                throw new Exception("未找到ID为" + id + "的报警记录");
            }

            // 确保关键字段不为null
            if (alarm.getIpAddress() == null) {
                alarm.setIpAddress(UNKNOWN_IP);
            }
            if (alarm.getIpLocation() == null) {
                alarm.setIpLocation(ipLocationUtils.getLocation(alarm.getIpAddress()));
            }
            if (alarm.getAlarmType() == null) {
                alarm.setAlarmType("未知攻击类型");
            }
            if (alarm.getRequestContent() == null) {
                alarm.setRequestContent("无详细内容");
            }

            return alarm;
        } catch (Exception e) {
            logger.error("查询报警详情失败", e);
            throw new Exception("查询报警详情失败: " + e.getMessage());
        }
    }

    /**
     * 批量删除报警记录
     */
    public void deleteById(String[] ids) throws Exception {
        try {
            if (ids != null && ids.length > 0) {
                int count = alarmInfoMapper.deleteById(ids);
                logger.info("成功删除{}条报警记录", count);
            }
        } catch (Exception e) {
            logger.error("删除报警记录失败", e);
            throw new Exception("删除报警记录失败: " + e.getMessage());
        }
    }

    /**
     * 通用报警存储方法（增强版）
     */
    public boolean saveSecurityAlert(int alarmTypeIndex,
                                     String requestContent,
                                     String sourceIp,
                                     String streamKey) {
        validateAlarmTypeIndex(alarmTypeIndex);

        try {
            String selectedAlarmType = alarmTypeList.get(alarmTypeIndex);
            AlarmInfo alarm = buildAlarmInfo(selectedAlarmType,
                    requestContent,
                    sourceIp,
                    streamKey);

            // 验证必要字段
            if (alarm.getIpAddress() == null) {
                throw new IllegalArgumentException("IP地址不能为空");
            }
            if (alarm.getAlarmType() == null) {
                throw new IllegalArgumentException("报警类型不能为空");
            }

            int result = alarmInfoMapper.save(alarm);
            if (result > 0) {
                logger.info("成功保存报警信息: {}", alarm);
                return true;
            }
            return false;
        } catch (Exception e) {
            logger.error("存储报警信息失败", e);
            return false;
        }
    }

    /**
     * 更新黑名单状态（增强版）
     */
    public int updateBlacklistStatusByIp(String ipAddress,int status) {
        Map<String, Object> params = new HashMap<>();
        params.put("ipAddress", ipAddress);
        params.put("isBlacklist", status);
        return alarmInfoMapper.updateBlacklistStatusByIp(params);
    }

    /**
     * 构建报警信息实体（增强版）
     */
    private AlarmInfo buildAlarmInfo(String alarmType,
                                     String content,
                                     String sourceIp,
                                     String streamKey) {
        AlarmInfo alarm = new AlarmInfo();
        alarm.setId(generateId());
        alarm.setAlarmType(alarmType);
        alarm.setRequestContent(content);
        alarm.setCreateTime(new Timestamp(System.currentTimeMillis()));
        alarm.setIsBlacklist(0);  // 默认非黑名单

        String finalIp = determineIpAddress(sourceIp, streamKey);
        alarm.setIpAddress(finalIp);

        // 确保IP位置信息不为null
        String location = ipLocationUtils.getLocation(finalIp);
        alarm.setIpLocation(location != null ? location : "未知位置");

        return alarm;
    }

    // 以下方法保持不变...
    private String generateId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private String determineIpAddress(String sourceIp, String streamKey) {
        if (StringUtils.hasText(sourceIp)) {
            return sourceIp;
        }
        return extractIpFromStream(streamKey);
    }

    private String extractIpFromStream(String streamKey) {
        if (!StringUtils.hasText(streamKey)) {
            return UNKNOWN_IP;
        }
        try {
            String[] parts = streamKey.split("->")[0].split(":");
            return parts.length > 0 ? parts[0] : UNKNOWN_IP;
        } catch (Exception e) {
            logger.warn("解析流标识失败: {}", streamKey, e);
            return UNKNOWN_IP;
        }
    }

    private void validateAlarmTypeIndex(int index) {
        if (index < 0 || index >= alarmTypeList.size()) {
            throw new IllegalArgumentException("无效的报警类型索引: " + index);
        }
    }

    private void handleStorageError(String message, Exception e) {
        logger.error("[ALARM STORAGE ERROR] {}: {}", message, e.getMessage(), e);
    }
}