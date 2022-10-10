package com.djn.config;

import com.djn.service.MyUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;

/**
 * Name: OldSecurityConfig
 * Description: 老版的 Spring Security 配置类（适用于低版本的Spring Boot整合Spring Security）
 * Copyright: Copyright (c) 2022 MVWCHINA All rights Reserved
 * Company: 江苏医视教育科技发展有限公司
 *
 * @author 丁佳男
 * @version 1.0
 * @since 2022/10/9 21:14
 */
// @Configuration
public class OldSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private MyUserDetailsService myUserDetailsService;

    // @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //用户添加在内存中
        // String encodedPwd = getPasswordEncoder().encode("6666");
        // auth.inMemoryAuthentication().withUser("SpringStone").password(encodedPwd).roles("admin,user");

        //用户从数据库中查询
        auth.userDetailsService(myUserDetailsService).passwordEncoder(getPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/user/login")
                .defaultSuccessUrl("/test/index")
                .permitAll()
                .and()
                .authorizeRequests()
                .antMatchers("/", "/test/hello")
                .permitAll()
                // .antMatchers("/test/index").hasAuthority("admin")
                .antMatchers("/test/index").hasAnyAuthority("admin", "user", "visitor")
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
        ;
    }
}
