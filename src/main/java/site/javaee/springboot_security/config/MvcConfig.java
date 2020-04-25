package site.javaee.springboot_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author JunTao
 * @create 2020/4/23 23:11
 */
@Configuration
public class MvcConfig {
    @Bean
    public WebMvcConfigurer webMvcConfigurer() {
        WebMvcConfigurer configurer = new WebMvcConfigurer() {
            //请求转发
            @Override
            public void addViewControllers(ViewControllerRegistry registry) {
                registry.addViewController("/").setViewName("index");
            }

            //SpringBoot1.x访问静态文件只需要把文件放入static中即可，在SpringBoot2中需要配置addResourceHandlers
            @Override
            public void addResourceHandlers(ResourceHandlerRegistry registry) {
                registry.addResourceHandler("/static/**").addResourceLocations("classpath:/static/");

            }
        };
        return configurer;
    }
}
