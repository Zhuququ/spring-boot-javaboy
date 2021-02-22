package org.javaboy.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

/**
 * @Author Zero
 */
//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("javaboy").password("123").roles("admin")
                .and()
                .withUser("猪小衢").password("zero").roles("user");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                // 其他请求都允许
                .anyRequest().authenticated()
                .and()
                // 使用postman等进行登录操作时的url
                .formLogin()
                .loginProcessingUrl("/doLogin")
                // 自定义登录页面url
                .loginPage("/login")
                // 设置使用url登录时，username的key
                .usernameParameter("uname")
                // 设置使用url登录时，password
                .passwordParameter("pass")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = resp.getWriter();
                        HashMap<String, Object> hashMap = new HashMap<>();
                        hashMap.put("status", "200");
                        hashMap.put("msg", auth.getDetails());
                        writer.write(new ObjectMapper().writeValueAsString(hashMap));
                        writer.flush();
                        writer.close();
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = resp.getWriter();
                        HashMap<String, Object> hashMap = new HashMap<>();
                        hashMap.put("status", 401);

                        if (e instanceof LockedException) {
                            hashMap.put("msg", "账户被锁定，登录失败！");
                        } else if (e instanceof BadCredentialsException) {
                            hashMap.put("msg", "用户名或者密码错误，登录失败！");
                        } else if (e instanceof DisabledException) {
                            hashMap.put("msg", "账户被禁用，登录失败！");
                        } else if (e instanceof AccountExpiredException) {
                            hashMap.put("msg", "账户已过期，登录失败！");
                        } else if (e instanceof CredentialsExpiredException) {
                            hashMap.put("msg", "密码已过期，登录失败！");
                        }

                        writer.write(new ObjectMapper().writeValueAsString(hashMap));
                        writer.flush();
                        writer.close();
                    }
                })
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication auth) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter writer = resp.getWriter();
                        HashMap<String, Object> hashMap = new HashMap<>();
                        hashMap.put("status", "200");
                        hashMap.put("msg", "注销成功！");
                        writer.write(new ObjectMapper().writeValueAsString(hashMap));
                        writer.flush();
                        writer.close();
                    }
                })
                .permitAll()
                .and()
                // 使用postman等要关掉csrf保护
                .csrf().disable();
    }
}
