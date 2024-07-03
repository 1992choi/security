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
            - 동시 세션 제어
              • 동시 세션 제어는 동일한 사용자가 동시에 여러 세션을 생성하는 것을 관리하는 전략이다.
              • 이 전략은 사용자의 인증 후에 활성화된 세션의 수가 설정된 maximumSessions 값과 비교하여 제어 여부를 결정한다.

            - 종류
              • CASE 1. 최대 허용 개수가 넘으면, 이전 세션을 만료시킨다.
              • CASE 2. 최대 허용 개수가 넘으면, 인증 시도를 차단한다.
         */
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/invalidSessionUrl", "/expired").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .sessionManagement(session -> session
                        .invalidSessionUrl("/invalidSessionUrl") // 만료된 세션으로 요청 시 리다이렉션 될 URL
                        .maximumSessions(1) // 사용자당 허용되는 최대 세션 수
                        .maxSessionsPreventsLogin(true) // true면 [CASE 2], false면 [CASE 1]. false가 기본값이다.
                        .expiredUrl("/expired") // 세션이 만료된 후 리다이렉션 될 URL
                );

        // invalidSessionUrl()과 expiredUrl()는 조합에 따라 호출되는 URI가 달라지므로 리다이렉션 전략을 상세하게 확인해봐야한다.

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
