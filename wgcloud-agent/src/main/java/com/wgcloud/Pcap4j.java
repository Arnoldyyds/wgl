package com.wgcloud;

import cn.hutool.json.JSONObject;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
public class Pcap4j {
    @Autowired
    private RestTemplate restTemplate;

    private final int snapshotLength;
    private final int timeout;
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyyMMddHHmmss");

    private final PcapNetworkInterface networkInterface;
    private volatile boolean capturing = false;
    private final List<Packet> packetBuffer = new CopyOnWriteArrayList<>();
    private PcapHandle handle;
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    private final CommonConfig commonConfig;

    @Autowired
    public Pcap4j(CommonConfig commonConfig) throws PcapNativeException {
        this.commonConfig = commonConfig;
        if (this.commonConfig == null) {
            throw new IllegalArgumentException("CommonConfig 不能为空");
        }

        String networkName = this.commonConfig.getNetworkName();
        this.snapshotLength = this.commonConfig.getSnapshotLength();
        this.timeout = this.commonConfig.getTimeout();

        if (networkName == null || networkName.isEmpty()) {
            throw new IllegalArgumentException("配置的网卡名字为空或null！");
        }

        networkInterface = Pcaps.getDevByName(networkName);
        if (networkInterface == null) {
            throw new IllegalArgumentException("没有找到配置的网卡，网卡名为: " + networkName);
        }

        System.out.println("设置网卡为: " + networkInterface.getName());
        startCapture();
    }

    public void startCapture() {
        if (capturing) {
            System.out.println("Pcap 监听已经在运行！");
            return;
        }
        capturing = true;

        executorService.submit(() -> {
            try (PcapHandle handle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout)) {
                this.handle = handle;
                System.out.println("开始监听: " + networkInterface.getName());

                handle.loop(-1, (PacketListener) packet -> {
                    if (capturing) {
                        packetBuffer.add(packet);
                    } else {
                        try {
                            handle.breakLoop();
                        } catch (NotOpenException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                System.err.println("Pcap 监听失败: " + e.getMessage());
                Thread.currentThread().interrupt();
            }
        });
    }

    public String saveCaptureToFile() {
        if (packetBuffer.isEmpty()) {
            System.out.println("没有捕获到数据包，无法保存！");
            return "";
        }

        String outputFile = "capture_" + DATE_FORMAT.format(new Date()) + ".pcap";
        try (PcapHandle dummyHandle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
             PcapDumper dumper = dummyHandle.dumpOpen(outputFile)) {

            for (Packet packet : packetBuffer) {
                dumper.dump(packet);
            }
            packetBuffer.clear();
            System.out.println("Pcap 文件已保存: " + outputFile);
        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("保存 Pcap 失败: " + e.getMessage());
        }
        return outputFile;
    }

    public void uploadPcapFile(String filePath) {
        String serverUrl = this.commonConfig.getServerUrl() + "/wgcloud/agent/uploadPcap";
        if (filePath.isEmpty()) {
            System.err.println("文件路径为空，无法上传！");
            return;
        }

        File file = new File(filePath);
        if (!file.exists()) {
            System.err.println("Pcap 文件不存在: " + filePath);
            return;
        }

        // 获取并验证 Token
        String wgToken = commonConfig.getWgToken();
        if (wgToken == null || wgToken.isEmpty()) {
            System.err.println("WgToken 为空，无法上传 Pcap 文件！");
            return;
        }
        String hashedToken = MD5Utils.GetMD5Code(wgToken);

        // 组装 metadata JSON
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("wgToken", hashedToken);
        String metadataJson = jsonObject.toString();

        try {
            // 读取文件内容，使用 ByteArrayResource 避免 Spring 解析错误
            byte[] fileBytes = java.nio.file.Files.readAllBytes(file.toPath());
            ByteArrayResource fileResource = new ByteArrayResource(fileBytes) {
                @Override
                public String getFilename() {
                    return file.getName();
                }
            };

            // 构造 Multipart 请求
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("file", fileResource);
            body.add("metadata", metadataJson); // 直接传递 JSON 字符串

            HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);

            // 确保 RestTemplate 具备 FormHttpMessageConverter
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getMessageConverters().add(new FormHttpMessageConverter());

            // 发送请求
            ResponseEntity<String> response = restTemplate.postForEntity(serverUrl, requestEntity, String.class);

            // 处理响应
            if (response.getStatusCode() == HttpStatus.OK) {
                System.out.println("Pcap 文件上传成功: " + filePath);
            } else {
                System.err.println("Pcap 文件上传失败, 响应码: " + response.getStatusCodeValue() + "，响应内容: " + response.getBody());
            }
        } catch (IOException e) {
            System.err.println("读取 Pcap 文件失败: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Pcap 文件上传失败，异常信息: " + e.getMessage());
        }
    }



    public void stopCapture() {
        capturing = false;
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        executorService.shutdown();
        System.out.println("Pcap 监听已停止！");
    }
}