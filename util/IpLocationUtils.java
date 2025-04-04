package com.wgcloud.util;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * IP 地理信息工具类
 * 使用 ip-api.com 提供的免费 API 查询 IP 地理位置
 */
@Component
public class IpLocationUtils {

    private static final String API_URL = "http://ip-api.com/json/";

    /**
     * 获取 IP 的地理位置信息
     *
     * @param ip IP 地址
     * @return 地理位置信息（格式：国家-城市），如果查询失败则返回 "未知地理位置"
     */
    public static String getLocation(String ip) {
        if (ip == null || ip.isEmpty() || ip.equals("未知IP")) {
            return "未知地理位置";
        }

        HttpURLConnection connection = null;
        BufferedReader reader = null;

        try {
            // 构建 URL
            URL url = new URL(API_URL + ip + "?lang=zh-CN");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000); // 设置连接超时时间为 5 秒
            connection.setReadTimeout(5000);    // 设置读取超时时间为 5 秒

            // 发送请求并获取响应
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                return parseLocationFromJson(response.toString());
            } else {
                return "API 请求失败，状态码: " + responseCode;
            }
        } catch (Exception e) {
            return "地理位置查询失败: " + e.getMessage();
        } finally {
            // 关闭资源
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * 从 JSON 数据中解析地理位置信息
     *
     * @param json API 返回的 JSON 数据
     * @return 地理位置信息（格式：国家-城市）
     */
    private static String parseLocationFromJson(String json) {
        try {
            // 简单解析 JSON（实际项目中可以使用 Gson 或 Jackson）
            String country = extractField(json, "country");
            String city = extractField(json, "city");
            return country + "-" + city;
        } catch (Exception e) {
            return "JSON 解析失败";
        }
    }

    /**
     * 从 JSON 字符串中提取指定字段的值
     *
     * @param json  JSON 字符串
     * @param field 字段名
     * @return 字段值
     */
    private static String extractField(String json, String field) {
        int start = json.indexOf("\"" + field + "\":\"") + field.length() + 4;
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

//    测试
//    public static void main(String[] args) {
//        String ip = "182.137.51.45"; // 测试 IP
//        String location = getLocation(ip);
//        System.out.println("IP: " + ip + ", 地理位置: " + location);
//    }
}