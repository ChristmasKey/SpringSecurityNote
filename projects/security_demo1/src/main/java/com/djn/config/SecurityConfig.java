package com.djn.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Name: SecurityConfig
 * Description: Spring Security配置类
 * Copyright: Copyright (c) 2022 MVWCHINA All rights Reserved
 * Company: 江苏医视教育科技发展有限公司
 *
 * @author 丁佳男
 * @version 1.0
 * @since 2022/10/7 19:11
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

    /**
     * 向Spring容器中注入 UserDetailsService
     *
     * @return org.springframework.security.core.userdetails.UserDetailsService
     * @date 2022/10/7 19:15
     */
    // @Bean
    public UserDetailsService getUserDetailsService() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encode = encoder.encode("1111");
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(
                User.withUsername("SpringStone")
                        .password(encode)
                        .roles("admin")
                        .build()
        );
        return users;
    }

    /**
     * 向Spring容器中注入 PasswordEncoder
     *
     * @return org.springframework.security.crypto.password.PasswordEncoder
     * @date 2022/10/7 19:13
     */
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 向Spring容器中注入 SecurityFilterChain
     * （*************特别声明：此处 HttpSecurity 需要通过 @EnableWebSecurity注解 注册到Spring容器中，才能获取到**************）
     *
     * @param http HttpSecurity 一个HTTP安全策略配置器
     * @return org.springframework.security.web.SecurityFilterChain
     * @date 2022/10/9 20:30
     */
    @Bean
    public SecurityFilterChain getSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin()    //自定义登录页面
                .loginPage("/login.html")   //设置登录页
                .loginProcessingUrl("/user/login")  //设置登录访问路径
                .defaultSuccessUrl("/test/index")   //设置登录成功之后，默认跳转路径
                .permitAll()    //设置访问权限级别：全部允许
                .and()
                .authorizeRequests()    //请求授权（设置哪些路径可以不需要登录直接访问）
                .antMatchers("/", "/test/hello") //设置匹配的路径
                .permitAll()    //设置访问权限级别：全部允许
                //当前登录用户，只有具有admin权限才可以访问这个路径
                // .antMatchers("/test/index").hasAuthority("admin")
                //当前登录用户，具有提供的权限列表中的任一权限即可访问这个路径
                .antMatchers("/test/index").hasAnyAuthority("admin", "user", "visitor")
                .anyRequest().authenticated()   //限制任何请求必须是“被认证的”
                .and()
                .csrf().disable()   //关闭CSRF防护
        ;
        return http.build();
    }
}
