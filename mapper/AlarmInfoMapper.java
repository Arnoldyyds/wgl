package com.wgcloud.mapper;

import com.wgcloud.entity.AlarmInfo;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public interface AlarmInfoMapper {

    // 查询所有报警信息（带参数）
    List<AlarmInfo> selectAllByParams(Map<String, Object> map);

    // 根据条件查询报警信息（分页用）
    List<AlarmInfo> selectByParams(Map<String, Object> params);

    // 根据ID查询报警信息
    AlarmInfo selectById(String id);

    // 根据条件查询报警信息的数量
    int selectByParamsCount(Map<String, Object> map);

    // 保存一条报警信息
    int save(AlarmInfo alarmInfo);

    // 批量插入报警信息
    void insertList(List<AlarmInfo> recordList);

    // 根据报警类型删除报警信息
    int deleteByAlarmType(String alarmType);

    // 根据日期删除报警信息
    int deleteByDate(Map<String, Object> map);

    // 根据ID批量删除报警信息
    int deleteById(@Param("ids") String[] id);

    // 新增：根据IP更新黑名单状态（参数修正为Map）
    int updateBlacklistStatusByIp(Map<String, Object> params);
}