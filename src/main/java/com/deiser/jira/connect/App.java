package com.deiser.jira.connect;

import com.deiser.jira.connect.infrastructure.config.spring.SpringWebMvcConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class App {
    public static void main(String[] args) {
        new SpringApplication(App.class).run(args);
    }

    @Bean
    WebMvcConfigurer webMvcConfigurer() {
        return new SpringWebMvcConfig();
    }
}