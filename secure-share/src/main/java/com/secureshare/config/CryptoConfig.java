package com.secureshare.config;

import com.secureshare.crypto.CryptoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** CryptoService is plain Java (shared with the CLI), so it is registered as a bean here. */
@Configuration
public class CryptoConfig {
    @Bean
    public CryptoService cryptoService() {
        return new CryptoService();
    }
}
