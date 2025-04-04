package com.wgcloud.entity;

import java.sql.Timestamp;
import java.util.Objects;
import java.util.UUID;

/**
 * 报警信息实体类
 */
public class AlarmInfo {
    private String id;                // 主键ID（32位UUID）
    private String alarmType;        // 报警类型（如SQL注入、文件上传等）
    private String ipAddress;        // IP地址（IPv4/IPv6）
    private String ipLocation;       // IP地理位置信息
    private String requestContent;   // 请求内容（原始数据或摘要）
    private Timestamp createTime;    // 创建时间（带时区）
    private Integer isBlacklist;     // 黑名单状态（0-否，1-是）

    // 空构造器（MyBatis等框架需要）
    public AlarmInfo() {
        this.id = generateUUID(); // 构造时自动生成ID
        this.createTime = new Timestamp(System.currentTimeMillis()); // 自动设置当前时间
        this.isBlacklist = 0; // 默认非黑名单
    }

    // 带参构造器（可选）
    public AlarmInfo(String alarmType, String ipAddress) {
        this(); // 调用无参构造器初始化公共字段
        this.alarmType = alarmType;
        this.ipAddress = ipAddress;
    }

    // 生成32位UUID
    private String generateUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    // Getters and Setters
    public String getId() {
        return id;
    }

     public void setId(String id) {
         this.id = id;
     }

    public String getAlarmType() {
        return alarmType;
    }

    public void setAlarmType(String alarmType) {
        this.alarmType = alarmType;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getIpLocation() {
        return ipLocation;
    }

    public void setIpLocation(String ipLocation) {
        this.ipLocation = ipLocation;
    }

    public String getRequestContent() {
        return requestContent;
    }

    public void setRequestContent(String requestContent) {
        this.requestContent = requestContent;
    }

    public Timestamp getCreateTime() {
        return createTime;
    }

    // 移除了setCreateTime方法，防止外部修改创建时间
     public void setCreateTime(Timestamp createTime) {
         this.createTime = createTime;
     }

    public Integer getIsBlacklist() {
        return isBlacklist;
    }

    public void setIsBlacklist(Integer isBlacklist) {
        this.isBlacklist = isBlacklist;
    }

    // 更完善的toString()
    @Override
    public String toString() {
        return "AlarmInfo{" +
                "id='" + id + '\'' +
                ", alarmType='" + alarmType + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", ipLocation='" + ipLocation + '\'' +
                ", requestContentLength=" + (requestContent != null ? requestContent.length() : 0) +
                ", createTime=" + createTime +
                ", isBlacklist=" + isBlacklist +
                '}';
    }

    // 重写equals和hashCode（用于集合操作）
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AlarmInfo alarmInfo = (AlarmInfo) o;
        return Objects.equals(id, alarmInfo.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    // 实用构建方法（可选）
    public static AlarmInfo quickCreate(String alarmType, String ipAddress, String requestContent) {
        AlarmInfo info = new AlarmInfo();
        info.setAlarmType(alarmType);
        info.setIpAddress(ipAddress);
        info.setRequestContent(requestContent);
        return info;
    }
}