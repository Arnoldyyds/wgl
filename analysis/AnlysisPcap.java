package com.wgcloud.analysis;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.EOFException;
import java.util.*;
import java.util.concurrent.TimeoutException;
@Component
public class AnlysisPcap {

    @Autowired
    SqlInjectionAnalysis sqlInjectionAnalysis;

    @Autowired
    private FileUploadAnalysis fileUploadAnalysis;

    @Autowired
    private DdosAnalysis ddosAnalysis;
    private static final Map<String, ProtocolFilter> PROTOCOL_FILTER_MAP = new HashMap<>();

    static {
        // 可以用于过滤的协议类型，通过端口来区分TCP中的http和https
        PROTOCOL_FILTER_MAP.put("HTTP", new ProtocolFilter(TcpPacket.class, Arrays.asList(80, 8080)));
        PROTOCOL_FILTER_MAP.put("HTTPS", new ProtocolFilter(TcpPacket.class, Collections.singletonList(443)));
        PROTOCOL_FILTER_MAP.put("DNS", new ProtocolFilter(UdpPacket.class, Collections.singletonList(53)));
        PROTOCOL_FILTER_MAP.put("TCP", new ProtocolFilter(TcpPacket.class, null));
        PROTOCOL_FILTER_MAP.put("UDP", new ProtocolFilter(UdpPacket.class, null));
    }

//    测试函数
//    public static void main(String[] args) {
//        String pcapFilePath = "D:\\Program\\easyjava\\wgcloud-3.5.7\\upload\\pcap\\sql_injection.pcap";
//        List<String> protocols;
//        String targetIp = "192.168.1.1"; // 默认不指定目标IP
//
//        if (args.length > 1) {
//            protocols = Arrays.asList(args).subList(1, args.length);
//            if (args.length > 2) {
//                targetIp = args[2]; // 第三个参数为目标IP
//            }
//        } else {
//            protocols = Arrays.asList("HTTP"); // 默认分析 HTTP
//        }
//        uploadAttackCheck(pcapFilePath,targetIp);
//        // 获取过滤后的流量包内容
//        Map<String, StringBuilder> filteredPackets = analyzePcap(pcapFilePath, protocols, targetIp);
//
//        // 外部处理过滤后的数据（例如打印或存储）
//        for (Map.Entry<String, StringBuilder> entry : filteredPackets.entrySet()) {
//            System.out.println("Stream: " + entry.getKey());
//            System.out.println("Data:");
//            System.out.println(entry.getValue());
//            System.out.println("-----------------------------");
//        }
//    }

//    public AnlysisPcap(String pcapFilePath){
////        List<String> protocols = null;
//        String targetIp = "192.168.1.1"; // 默认不指定目标IP，后面通过Commconfig来直接获取配置文件中的配置，无法进行手动获取，除非进行对ip的频次匹配，但是频次匹配的话，存在一定的误报可能，还不如直接手动配置算了
////        // 获取过滤后的流量包内容
////        Map<String, StringBuilder> filteredPackets = analyzePcap(pcapFilePath, protocols, targetIp);
////        //然后直接基于不同的协议，获取不同的消息流，然后用对应的处理函数处理，处理完后，如果存在问题，就存入数据库，打上特征，然后将这些显示出来，走一次ip检测。
//        sqlInjectionCheck(pcapFilePath,targetIp);
//        ddosAttackCheck(pcapFilePath,targetIp);
//        uploadAttackCheck(pcapFilePath,targetIp);
//    }
    public void analyzePcapFile(String pcapFilePath) {
        String targetIp = "192.168.1.1";
        uploadAttackCheck(pcapFilePath, targetIp);
        sqlInjectionCheck(pcapFilePath, targetIp);
        ddosAttackCheck(pcapFilePath, targetIp);
    }


    //单独提一个函数出来，方便查看逻辑
    private void sqlInjectionCheck(String pcapFilePath, String targetIp){
        List<String> sqlProtocolsFilter = Arrays.asList("HTTP","HTTPS");
        Map<String,StringBuilder> sqlInjectionFilterPackets = analyzePcap(pcapFilePath,sqlProtocolsFilter,targetIp); //通过过滤了HTTP和HTTPS协议，筛选出所有可能具有SQL注入攻击的请求包
        this.sqlInjectionAnalysis.analyzeAndSaveSqlInjection(sqlInjectionFilterPackets);
    }

    //文件上传检测函数
    private void uploadAttackCheck(String pcapFilePath, String targetIp) {
        List<String> uploadProtocolsFilter = Arrays.asList("HTTP", "HTTPS");
        Map<String, StringBuilder> uploadFilterPackets = analyzePcap(pcapFilePath, uploadProtocolsFilter, targetIp);
        this.fileUploadAnalysis.analyzeAndSaveUploadAttack(uploadFilterPackets);
    }

    // DDoS 攻击检测函数
    private void ddosAttackCheck(String pcapFilePath, String targetIp) {
        Map<String, List<Long>> tcpTraffic = collectTrafficData(pcapFilePath, "TCP", targetIp);
        Map<String, List<Long>> udpTraffic = collectTrafficData(pcapFilePath, "UDP", targetIp);
        ddosAnalysis.analyzeAndSaveDdosAlert(tcpTraffic, "TCP");
        ddosAnalysis.analyzeAndSaveDdosAlert(udpTraffic, "UDP");
    }

    /**
     * 收集流量数据（按流分组，记录时间戳）
     */
    private static Map<String, List<Long>> collectTrafficData(String pcapFilePath, String protocol, String targetIp) {
        Map<String, List<Long>> trafficData = new HashMap<>(128); // 预设初始容量

        try (PcapHandle handle = Pcaps.openOffline(pcapFilePath)) { // 使用try-with-resources自动关闭
            final boolean filterTcp = "TCP".equals(protocol);
            final boolean filterUdp = "UDP".equals(protocol);
            final boolean filterIp = targetIp != null;

            Packet packet;
            while ((packet = handle.getNextPacketEx()) != null) {
                IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                if (ipv4Packet == null) continue;

                // 优化IP过滤逻辑
                if (filterIp && !targetIp.equals(ipv4Packet.getHeader().getDstAddr().getHostAddress())) {
                    continue;
                }

                TransportPacket transportPacket = getTransportPacket(packet);
                if (transportPacket == null) continue;

                // 优化协议过滤逻辑
                if ((filterTcp && !(transportPacket instanceof TcpPacket)) ||
                        (filterUdp && !(transportPacket instanceof UdpPacket))) {
                    continue;
                }

                // 优化流标识构建和时间戳记录
                String streamKey = buildStreamKey(ipv4Packet, transportPacket);
                trafficData.computeIfAbsent(streamKey, k -> new ArrayList<>(16)) // 预设初始容量
                        .add(System.currentTimeMillis());
            }
        } catch (PcapNativeException e) {
            System.err.println("PCAP本地错误: " + e.getMessage());
        } catch (EOFException e) {
            // 正常结束pcap文件的读取，免得报错
        } catch (Exception e) {
            System.err.println("解析数据包错误: " + e.getMessage());
        }

        return trafficData;
    }

    /**
     * 分析 pcap 文件并返回过滤后的流量包内容
     *
     * @param pcapFilePath pcap 文件路径
     * @param protocols    需要过滤的协议列表
     * @param targetIp     目标IP地址，只显示向该IP发送的请求的流量包
     * @return 过滤后的流量包内容（按流分组）
     */
    public static Map<String, StringBuilder> analyzePcap(String pcapFilePath, List<String> protocols, String targetIp) {
        try {
            PcapHandle handle = Pcaps.openOffline(pcapFilePath);
            Map<String, StringBuilder> streamData = filterPacketsByProtocol(handle, protocols, targetIp);
            handle.close();
            return streamData;
        } catch (PcapNativeException e) {
            e.printStackTrace();
            return Collections.emptyMap(); // 返回空结果
        }
    }

    /**
     * 根据协议过滤流量包，并返回过滤后的内容
     *
     * @param handle    PcapHandle 对象
     * @param protocols 需要过滤的协议列表
     * @param targetIp  目标IP地址，只显示向该IP发送的请求的流量包
     * @return 过滤后的流量包内容（按流分组）
     */
    private static Map<String, StringBuilder> filterPacketsByProtocol(PcapHandle handle, List<String> protocols, String targetIp) {
        Map<String, StringBuilder> streamData = new HashMap<>();
        List<ProtocolFilter> filters = getProtocolFilters(protocols);

        while (true) {
            try {
                Packet packet = handle.getNextPacketEx();
                if (!matchesAnyProtocol(packet, filters)) continue;

                // 获取网络层信息
                IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                if (ipv4Packet == null) continue;

                // 如果指定了目标IP，且目标IP不匹配，则跳过
                if (targetIp != null && !targetIp.equals(ipv4Packet.getHeader().getDstAddr().getHostAddress())) {
                    continue;
                }

                TransportPacket transportPacket = getTransportPacket(packet);
                if (transportPacket == null) continue;

                // 构建流标识
                String streamKey = buildStreamKey(ipv4Packet, transportPacket);

                // 提取负载数据
                byte[] payload = getPayload(transportPacket);
                if (payload != null && payload.length > 0) {
                    streamData.computeIfAbsent(streamKey, k -> new StringBuilder())
                            .append(new String(payload));
                }

            } catch (TimeoutException e) {
                e.printStackTrace();
            } catch (EOFException e) {
                break; // 文件读取完毕
            } catch (NotOpenException e) {
                throw new RuntimeException(e);
            } catch (PcapNativeException e) {
                throw new RuntimeException(e);
            }
        }

        return streamData;
    }

    private static boolean matchesAnyProtocol(Packet packet, List<ProtocolFilter> filters) {
        for (ProtocolFilter filter : filters) {
            if (filter.matches(packet)) return true;
        }
        return false;
    }

    private static List<ProtocolFilter> getProtocolFilters(List<String> protocolNames) {
        List<ProtocolFilter> filters = new ArrayList<>();
        for (String name : protocolNames) {
            ProtocolFilter filter = PROTOCOL_FILTER_MAP.get(name.toUpperCase());
            if (filter != null) filters.add(filter);
            else System.err.println("Unknown protocol: " + name);
        }
        return filters;
    }

    private static TransportPacket getTransportPacket(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            return packet.get(TcpPacket.class);
        } else if (packet.contains(UdpPacket.class)) {
            return packet.get(UdpPacket.class);
        }
        return null;
    }

    private static String buildStreamKey(IpV4Packet ipv4Packet, TransportPacket transportPacket) {
        String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
        int srcPort = getPort(transportPacket, true);
        int dstPort = getPort(transportPacket, false);
        return String.format("%s:%d -> %s:%d (%s)",
                srcIp, srcPort, dstIp, dstPort, transportPacket.getClass().getSimpleName());
    }

    private static int getPort(TransportPacket transportPacket, boolean isSrc) {
        if (transportPacket instanceof TcpPacket) {
            TcpPacket tcp = (TcpPacket) transportPacket;
            return isSrc ? tcp.getHeader().getSrcPort().valueAsInt()
                    : tcp.getHeader().getDstPort().valueAsInt();
        } else if (transportPacket instanceof UdpPacket) {
            UdpPacket udp = (UdpPacket) transportPacket;
            return isSrc ? udp.getHeader().getSrcPort().valueAsInt()
                    : udp.getHeader().getDstPort().valueAsInt();
        }
        return -1;
    }

    private static byte[] getPayload(TransportPacket transportPacket) {
        if (transportPacket.getPayload() != null) {
            return transportPacket.getPayload().getRawData();
        }
        return null;
    }

    static class ProtocolFilter {
        private final Class<? extends Packet> transportLayerClass;
        private final List<Integer> ports;

        public ProtocolFilter(Class<? extends Packet> transportLayerClass, List<Integer> ports) {
            this.transportLayerClass = transportLayerClass;
            this.ports = ports;
        }

        public boolean matches(Packet packet) {
            if (!packet.contains(transportLayerClass)) return false;

            if (ports == null || ports.isEmpty()) return true;

            TransportPacket tp = (TransportPacket) packet.get(transportLayerClass);
            int srcPort = getPort(tp, true);
            int dstPort = getPort(tp, false);
            return ports.contains(srcPort) || ports.contains(dstPort);
        }
    }
}