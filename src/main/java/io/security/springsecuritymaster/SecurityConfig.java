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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
            - CSRF 토큰 유지와 CsrfTokenRepository
              • CsrfToken은 CsrfTokenRepository 를 사용하여 영속화 하며 HttpSessionCsrfTokenRepository(기본 사용) 와 CookieCsrfTokenRepository 를 지원한다
              • 두 군데 중 원하는 위치에 토큰을 저장하도록 설정을 통해 지정할 수 있다

            - 세션에 토큰 저장 - HttpSessionCsrfTokenRepository (기본 동작)
              • 기본적으로 토큰을 세션에 저장하기 위해 HttpSessionCsrfTokenRepository를 사용한다
              • HttpSessionCsrfTokenRepository는 기본적으로 HTTP 요청 헤더인 X-CSRF-TOKEN 또는 요청 매개변수인 _csrf에서 토큰을 읽는다
              • Ex) HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
                    http.csrf(csrf -> csrf.csrfTokenRepository(repository));

            - 쿠키에 토큰 저장 - CookieCsrfTokenRepository
              • JavaScript 기반 애플리케이션을 지원하기 위해 CsrfToken 을 쿠키에 유지할 수 있으며 구현체로 CookieCsrfTokenRepository를 사용할 수 있다
              • CookieCsrfTokenRepository 는 기본적으로 XSRF-TOKEN 명을 가진 쿠키에 작성하고 HTTP 요청 헤더인 X-XSRF-TOKEN 또는 요청 매개변수인 _csrf에서 읽는다
              • JavaScript 에서 쿠키를 읽을 수 있도록 HttpOnly를 명시적으로 false로 설정할 수 있다
              • JavaScript로 직접 쿠키를 읽을 필요가 없는 경우 보안을 개선하기 위해 HttpOnly 를 생략하는 것이 좋다
              • Ex) CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
                    http.csrf(csrf -> csrf.csrfTokenRepository(repository)); 아래 코드로 사용할 수 있으나 보안에 취약할 수 있으므로 지양
                    // http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

            - CSRF 토큰 처리 - CsrfTokenRequestHandler
              • CsrfToken 은 CsrfTokenRequestHandler 를 사용하여 토큰을 생성 및 응답하고 HTTP 헤더 또는 요청 매개변수로부터 토큰의 유효성을 검증하도록 한다
              • XorCsrfTokenRequestAttributeHandler 와 CsrfTokenRequestAttributeHandler 를 제공하며 사용자 정의 핸들러를 구현할 수 있다

            - CSRF 토큰 지연 로딩
              • 기본적으로 Spring Security 는 CsrfToken 을 필요할 때까지 로딩을 지연시키는 전략을 사용한다. 그러므로 CsrfToken 은 HttpSession 에 저장되어 있기 때문에 매 요청마다 세션으로부터 CsrfToken 을 로드할 필요가 없어져 성능을 향상시킬 수 있다
              • CsrfToken 은 POST 와 같은 안전하지 않은 HTTP 메서드를 사용하여 요청이 발생할 때와 CSRF 토큰을 응답에 렌더링하는 모든 요청에서 필요하기 때문에 그 외 요청에는 지연로딩 하는 것이 권장된다
         */

        // 쿠키 저장 예제 (세션 저장은 기본 동작이라 예시 없음)
//        CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/csrf", "/csrfToken").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository));

        // 핸들러 사용 예제
        XorCsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new XorCsrfTokenRequestAttributeHandler();
        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null); // 지연된 토큰을 사용하지 않고 CsrfToken 을 모든 요청마다 로드한다. (기본은 성능 향상을 위해 지연 로딩 사용)

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/csrf", "/csrfToken").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(csrf -> csrf.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler));
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
