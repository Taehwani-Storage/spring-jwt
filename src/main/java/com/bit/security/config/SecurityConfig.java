package com.bit.security.config;

import com.bit.security.filter.JwtAuthFilter;
import com.bit.security.provider.JwtProvider;
import com.bit.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
        security.authorizeHttpRequests(req -> req
                .requestMatchers("/", "/WEB-INF/views/**", "/resources/**", "/user/register").permitAll()
                .requestMatchers("/user/arrive").authenticated()
                .anyRequest().permitAll()
        );
        // HTTP 기본 인증을 막는다(JWT를 사용하기 때문)
        security.httpBasic(HttpBasicConfigurer::disable);
        // CSRF 인증 비활성화
        security.csrf(CsrfConfigurer::disable);
        // SESSION 기반 인증 빟활성화
        security.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // formLogIn 비활성화
        security.formLogin(FormLoginConfigurer::disable);
        // JwtAuthFilter 추가
        security.addFilterBefore(new JwtAuthFilter(userDetailsService, jwtProvider), UsernamePasswordAuthenticationFilter.class);

        return security.build();
    }

}
