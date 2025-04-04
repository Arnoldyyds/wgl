package com.wgcloud.controller;

import com.github.pagehelper.PageInfo;
import com.wgcloud.analysis.AlarmInfoService;
import com.wgcloud.entity.AlarmInfo;
import com.wgcloud.service.LogInfoService;
import com.wgcloud.util.*;
import com.wgcloud.util.staticvar.StaticKeys;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/alarm")
public class AlarmInfoController {

    private static final Logger logger = LoggerFactory.getLogger(AlarmInfoController.class);

    @Resource
    private AlarmInfoService alarmInfoService;
    @Resource
    private LogInfoService logInfoService;
    @Resource
    private TokenUtils tokenUtils;

    /**
     * 报警信息分页列表（匹配前端表格）
     */
    @GetMapping("/list")
    public String list(
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer pageSize,
            @RequestParam(required = false) String alarmType,
            @RequestParam(required = false) String ipAddress,
            Model model) {

        Map<String, Object> params = new HashMap<>();
        try {
            // 构建查询参数
            if (StringUtils.isNotBlank(alarmType)) {
                params.put("alarmType", alarmType.trim());
            }
            if (StringUtils.isNotBlank(ipAddress)) {
                params.put("ipAddress", ipAddress.trim());
            }

            // 分页查询
            PageInfo<AlarmInfo> pageInfo = alarmInfoService.selectByParams(params, page, pageSize);

            // 分页参数处理
            model.addAttribute("page", pageInfo);
            model.addAttribute("searchAlarmType", alarmType);
            model.addAttribute("searchIpAddress", ipAddress);
        } catch (Exception e) {
            logger.error("查询报警信息错误", e);
            logInfoService.save("查询报警信息错误", e.toString(), StaticKeys.LOG_ERROR);
        }
        return "alarm/list"; // 对应前端模板路径
    }

    /**
     * 添加黑名单（匹配前端AJAX请求）
     */
    @ResponseBody
    @PostMapping("/blacklist/add")
    public Map<String, Object> addBlacklist(@RequestParam String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        try {
            int count = alarmInfoService.updateBlacklistStatusByIp(ipAddress,1);
            logInfoService.save("添加黑名单", "IP：" + ipAddress, StaticKeys.LOG_SUCCESS);

            result.put("success", true);
            result.put("message", "已屏蔽" + count + "条相关记录");
        } catch (Exception e) {
            logger.error("添加黑名单失败", e);
            logInfoService.save("添加黑名单失败", e.toString(), StaticKeys.LOG_ERROR);
            result.put("success", false);
            result.put("message", "操作失败：" + e.getMessage());
        }
        return result;
    }

    @ResponseBody
    @PostMapping("/blacklist/remove")
    public Map<String, Object> removeBlacklist(@RequestParam String ipAddress) {
        Map<String, Object> result = new HashMap<>();
        try {
            int count = alarmInfoService.updateBlacklistStatusByIp(ipAddress,0);
            logInfoService.save("移出黑名单", "IP：" + ipAddress, StaticKeys.LOG_SUCCESS);

            result.put("success", true);
            result.put("message", "已经移出" + count + "条相关记录");
        } catch (Exception e) {
            logger.error("移出黑名单失败", e);
            logInfoService.save("移出黑名单失败", e.toString(), StaticKeys.LOG_ERROR);
            result.put("success", false);
            result.put("message", "操作失败：" + e.getMessage());
        }
        return result;
    }

    /**
     * 查看详情（匹配前端URL）
     */
    @GetMapping("/detail")
    public String detail(@RequestParam String id, Model model) {
        try {
            AlarmInfo alarm = alarmInfoService.selectById(id);
            model.addAttribute("alarmInfo", alarm);
        } catch (Exception e) {
            logger.error("查看报警详情错误", e);
            logInfoService.save("查看报警详情错误", e.toString(), StaticKeys.LOG_ERROR);
        }
        return "alarm/detail";
    }

    /**
     * 批量删除（支持前端多选删除）
     */
    @ResponseBody
    @PostMapping("/delete")
    public Map<String, Object> delete(@RequestParam("ids") String[] ids) {
        Map<String, Object> result = new HashMap<>();
        try {
            if (ids != null && ids.length > 0) {
                alarmInfoService.deleteById(ids);
                logInfoService.save("删除报警记录", "删除数量：" + ids.length, StaticKeys.LOG_SUCCESS);
                result.put("success", true);
            }
        } catch (Exception e) {
            logger.error("删除报警记录失败", e);
            logInfoService.save("删除报警记录失败", e.toString(), StaticKeys.LOG_ERROR);
            result.put("success", false);
        }
        return result;
    }

//    /**
//     * 导出数据（匹配前端导出功能）
//     */
//    @GetMapping("/export")
//    public void export(HttpServletRequest request,
//                       HttpServletResponse response,
//                       @RequestParam(required = false) String alarmType,
//                       @RequestParam(required = false) String ipAddress) {
//
//        try {
//            Map<String, Object> params = new HashMap<>();
//            if (StringUtils.isNotBlank(alarmType)) {
//                params.put("alarmType", alarmType);
//            }
//            if (StringUtils.isNotBlank(ipAddress)) {
//                params.put("ipAddress", ipAddress);
//            }
//
//            // 实现导出逻辑（示例使用Excel导出工具）
//            List<AlarmInfo> list = alarmInfoService.selectAllByParams(params);
//            ExcelUtil.exportAlarmInfo(list, response);
//
//        } catch (Exception e) {
//            logger.error("导出报警数据错误", e);
//            logInfoService.save("导出报警数据错误", e.toString(), StaticKeys.LOG_ERROR);
//        }
//    }
}