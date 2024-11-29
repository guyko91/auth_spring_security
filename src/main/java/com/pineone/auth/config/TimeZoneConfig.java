package com.pineone.auth.config;

import jakarta.annotation.PostConstruct;
import java.time.ZoneId;
import java.util.TimeZone;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TimeZoneConfig {

    @PostConstruct
    public void init() {
        TimeZone.setDefault(TimeZone.getTimeZone(ZoneId.of("Asia/Seoul")));
    }

}
