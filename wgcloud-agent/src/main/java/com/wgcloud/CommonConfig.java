package com.wgcloud;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "base")
public class CommonConfig {
    private String serverUrl;
    private String bindIp;
    private String wgToken;
    private String networkName;
    private int snapshotLength;
    private int timeout;
}
