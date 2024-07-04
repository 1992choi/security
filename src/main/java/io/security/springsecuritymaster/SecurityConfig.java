package io.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - SessionManagementFilter
              • 요청이 시작된 이후 사용자가 인증되었는지 감지하고, 인증된 경우에는 세션 고정 보호 메커니즘을 활성화하거나 동시 다중 로그인을 확인하는 등 세션 관련 활동을 수행하기 위해 설정된 세션 인증 전략(SessionAuthenticationStrategy)을 호출하는 필터 클래스이다.
              • 스프링 시큐리티 6 이상에서는 SessionManagementFilter 가 기본적으로 설정 되지 않으며 세션관리 API 를 설정을 통해 생성할 수 있다.

            - ConcurrentSessionFilter
              • 각 요청에 대해 SessionRegistry에서 SessionInformation 을 검색하고 세션이 만료로 표시되었는지 확인하고 만료로 표시된 경우 로그아웃 처리를 수행한다(세션 무효화)
              • 각 요청에 대해 SessionRegistry.refreshLastRequest(String)를 호출하여 등록된 세션들이 항상 '마지막 업데이트' 날짜/시간을 가지도록 한다
         */

        http.authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .sessionManagement(session -> session   // 시큐리티 6 이상에서는 SessionManagementFilter를 활성화하기 위해서는 sessionManagement()를 명시적으로 기술해야한다.
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() { // 해당 설정은 yml에서도 가능. 우선순위는 자바 설정이 더 높음.
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails user2 = User.withUsername("user2")
                .password("{noop}2222")
                .roles("USER")
                .build();

        UserDetails user3 = User.withUsername("user3")
                .password("{noop}3333")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user, user2, user3);
    }

}
