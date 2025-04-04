package com.wgcloud;

import oshi.SystemInfo;
import oshi.hardware.NetworkIF;
import org.pcap4j.core.Pcaps;
import java.util.List;

public class NetworkInfo {
    public static void main(String[] args) {
        SystemInfo systemInfo = new SystemInfo();
        List<NetworkIF> networkIFs = systemInfo.getHardware().getNetworkIFs();

        System.out.println("=== OSHI 获取的网卡信息 ===");
        for (NetworkIF net : networkIFs) {
            System.out.println("网卡名称 (OSHI): " + net.getName());
            System.out.println("网卡显示名称: " + net.getDisplayName());
            System.out.println("MAC 地址: " + net.getMacaddr());
            System.out.println("IP 地址: " + String.join(", ", net.getIPv4addr()));
            System.out.println("-------------------------------------------------");
        }

        // 额外获取 Pcap4j 可用的网卡名称（适用于 WinPcap/Npcap）
        System.out.println("\n=== Pcap4j 可用的网卡名称（适用于抓包） ===");
        try {
            List<org.pcap4j.core.PcapNetworkInterface> pcapInterfaces = Pcaps.findAllDevs();
            for (org.pcap4j.core.PcapNetworkInterface pcapIf : pcapInterfaces) {
                System.out.println("Pcap4j 网卡名称: " + pcapIf.getName());
                System.out.println("描述: " + pcapIf.getDescription());
                System.out.println("-------------------------------------------------");
            }
        } catch (Exception e) {
            System.err.println("无法获取 Pcap4j 网卡列表，请确保已安装 WinPcap/Npcap: " + e.getMessage());
        }
    }
}