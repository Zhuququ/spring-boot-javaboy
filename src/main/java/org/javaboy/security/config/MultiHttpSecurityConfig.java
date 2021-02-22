package org.javaboy.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.TreeMap;

/**
 * @Author Zero
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MultiHttpSecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    protected void config(AuthenticationManagerBuilder authBuilder) throws Exception {
        authBuilder.inMemoryAuthentication()
                .withUser("javaboy").password("$2a$10$tx1wMYUbjc7ielK92/3BuOxryIxtgPR6hNN88o9nUsRPlpBD/0rbe").roles("admin")
                .and()
                .withUser("猪小衢").password("$2a$10$tx1wMYUbjc7ielK92/3BuOxryIxtgPR6hNN88o9nUsRPlpBD/0rbe").roles("user");

    }

    // 静态内部类
    @Configuration
    // 设置优先顺
    @Order(1)
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // /admin/路径下所有请求要有admin权限
            http.antMatcher("/admin/**").authorizeRequests().anyRequest().hasRole("admin");
        }
    }

    // 静态内部类
    @Configuration
    public static class OtherSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated()
                    .and()
                    // 登录form设置
                    .formLogin()
                    .loginProcessingUrl("/doLogin")
                    .passwordParameter("pass")
                    .usernameParameter("uname")
                    .loginPage("/login")
                    .permitAll()
                    .and()
                    .logout()
                    .logoutUrl("/logout")
                    .permitAll()
                    .and()
                    .csrf().disable();
        }
    }
}
