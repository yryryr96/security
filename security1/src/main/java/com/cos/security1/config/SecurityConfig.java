package com.cos.security1.config;

import com.cos.security1.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
        )
                .formLogin(
                        formLogin ->
                                formLogin
                                        .loginPage("/loginForm")
                                        .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
                                        .defaultSuccessUrl("/")
                )
                .oauth2Login(
                        oauthLogin ->
                                oauthLogin
                                        .loginPage("/loginForm")
                                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                                .userService(principalOauth2UserService)) // Tip : 코드X, (액세스 토큰 + 유저 프로필 정보)

                );
        return http.build();
    }
}
