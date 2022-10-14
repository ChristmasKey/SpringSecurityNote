package com.djn.config;

import com.djn.service.MyUserDetailsService;
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
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;
import javax.sql.DataSource;

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
     * 注入自定义的UserDetailsService
     */
    @Resource
    private MyUserDetailsService myUserDetailsService;

    /**
     * 注入配置文件中的数据源
     */
    @Resource
    private DataSource dataSource;

    /**
     * 向Spring容器中注入 PersistentTokenRepository对象，用于操作数据库（向表中存储 token 和 username）
     *
     * @return org.springframework.security.web.authentication.rememberme.PersistentTokenRepository
     * @date 2022/10/14 16:23
     */
    @Bean
    public PersistentTokenRepository getPersistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        //设置数据源
        jdbcTokenRepository.setDataSource(dataSource);
        //设置项目启动时是否在数据库中建表
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }

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
    //@Bean
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
                //.defaultSuccessUrl("/test/index")   //设置登录成功之后，默认跳转路径
                .defaultSuccessUrl("/success.html")   //设置登录成功之后，默认跳转资源页面
                .permitAll()    //设置访问权限级别：全部允许
                .and()
                .authorizeRequests()    //请求授权（设置哪些路径可以不需要登录直接访问）
                .antMatchers("/", "/test/hello") //设置匹配的路径
                .permitAll()    //设置访问权限级别：全部允许
                //当前登录用户，只有具有admin权限才可以访问这个路径
                // .antMatchers("/test/index").hasAuthority("admin")
                //当前登录用户，具有提供的权限列表中的任一权限即可访问这个路径
                // .antMatchers("/test/index").hasAnyAuthority("admin", "user", "visitor")
                //当前登录的用户，只有是sale角色时才可以访问这个路径
                // .antMatchers("/test/index").hasRole("sale")
                //当前登录用户，是提供的角色列表中的任意角色即可访问这个路径
                // .antMatchers("/test/index").hasAnyRole("sale", "manage")
                .anyRequest().authenticated()   //限制任何请求必须是“被认证的”
                .and()
                //开启“记住我”功能
                .rememberMe()
                .tokenRepository(getPersistentTokenRepository())  //设置数据库操作对象
                .tokenValiditySeconds(60) //设置token有效期（单位：秒）
                .userDetailsService(myUserDetailsService)  //设置查询数据库的UserDetailsService对象
                .and()
                .csrf().disable()   //关闭CSRF防护
        ;
        //自定义没有访问权限时的跳转页面
        http.exceptionHandling().accessDeniedPage("/unauth.html");
        //自定义用户退出登录
        http.logout().logoutUrl("/user/logout").logoutSuccessUrl("/test/hello").permitAll();
        return http.build();
    }
}
