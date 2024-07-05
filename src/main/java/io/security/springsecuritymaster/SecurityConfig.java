package io.security.springsecuritymaster;

import io.security.springsecuritymaster.cookie.CsrfCookieFilter;
import io.security.springsecuritymaster.cookie.SpaCsrfTokenRequestHandler;
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
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
        - 개요
          • CSRF 공격을 방지하기 위한 토큰 패턴을 사용하려면 실제 CSRF 토큰을 HTTP 요청에 포함해야 한다
          • 그래서 브라우저에 의해 HTTP 요청에 자동으로 포함되지 않는 요청 부분(폼 매개변수, HTTP 헤더 또는 기타 부분) 중 하나에 포함되어야 한다
          • 클라이언트 어플리케이션이 CSRF로 보호된 백엔드 애플리케이션과 통합하는 방법에는 크게 'HTML Form'방식과 'Javascript 방식'이 있다.

        - HTML Form (Form 방식으로 구현된 예제코드)
          • HTML 폼을 서버에 제출하려면 CSRF 토큰을 hidden 값으로 Form 에 포함해야 한다

        - JavaScript (Single Page Application과 Multi Page Application로 나뉨)
            1. Single Page Application (Cookie 방식으로 구현된 예제코드)
               ① CookieCsrfTokenRepository.withHttpOnlyFalse 를 사용해서 클라이언트가 서버가 발행한 쿠키로 부터 CSRF 토큰을 읽을 수 있도록 한다
               ② 사용자 정의 CsrfTokenRequestHandler 을 만들어 클라이언트가 요청 헤더나 요청 파라미터로 CSRF 토큰을 제출할 경우 이를 검증하도록 구현한다
               ③ 클라이언트의 요청에 대해 CSRF 토큰을 쿠키에 렌더링해서 응답할 수 있도록 필터를 구현한다

            2. Multi Page Application (여기서는 해당 예제는 다루지 않음)
               • JavaScript 가 각 페이지에서 로드되는 멀티 페이지 애플리케이션의 경우 CSRF 토큰을 쿠키에 노출시키는 대신 HTML 메타 태그 내에 CSRF 토큰을 포함시킬 수 있다
     */

    // Form 방식
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/csrf","/form","/formCsrf").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .csrf(Customizer.withDefaults());
//
//        return http.build();
//    }

    // Cookie 방식
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        SpaCsrfTokenRequestHandler csrfTokenRequestHandler = new SpaCsrfTokenRequestHandler();

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/csrf","/cookie", "/cookieCsrf").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfTokenRequestHandler)
                );
        http.addFilterBefore(new CsrfCookieFilter(), BasicAuthenticationFilter.class);

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
