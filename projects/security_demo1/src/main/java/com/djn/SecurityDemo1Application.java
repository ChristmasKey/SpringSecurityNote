package com.djn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityDemo1Application {

    public static void main(String[] args) {
        SpringApplication.run(SecurityDemo1Application.class, args);
    }

}
