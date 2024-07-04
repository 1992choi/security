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
            - 예외 처리
              • 예외 처리는 필터 체인 내에서 발생하는 예외를 의미하며 크게 인증예외(AuthenticationException) 와 인가예외(AccessDeniedException)로 나눌 수 있다
              • 예외를 처리하는 필터로서 ExceptionTranslationFilter 가 사용 되며 사용자의 인증 및 인가 상태에 따라 로그인 재시도, 401, 403 코드 등으로 응답할 수 있다

            - 예외 처리 유형
              - AuthenticationException
                1. SecurityContext 에서 인증 정보 삭제 - 기존의 Authentication 이 더 이상 유효하지 않다고 판단하고 Authentication 을 초기화 한다
                2. AuthenticationEntryPoint 호출
                   • AuthenticationException 이 감지되면 필터는 authenticationEntryPoint 를 실행하고 이를 통해 인증 실패를 공통적으로 처리할 수 있으며 일반적으로 인증을 시도할 수 있는 화면으로 이동한다
                3. 인증 프로세스의 요청 정보를 저장하고 검색
                   • RequestCache & SavedRequest - 인증 프로세스 동안 전달되는 요청을 세션 혹은 쿠키에 저장
                   • 사용자가 인증을 완료한 후 요청을 검색하여 재 사용할 수 있다. 기본 구현은 HttpSessionRequestCache 이다

              - AccessDeniedException
                1. AccessDeniedHandler 호출
                   • AccessDeniedException 이 감지되면 필터는 사용자가 익명 사용자인지 여부를 판단하고 익명 사용자인 경우 인증예외처리가 실행되고 익명 사용자가 아닌 경우 필터는 AccessDeniedHandler 에게 위임한다

         */
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            // 커스텀하게 사용할 AuthenticationEntryPoint 를 설정한다
                            System.out.println(authException.getMessage());
                            response.sendRedirect("/login"); // 사용자 정의 EntryPoint가 구현되면, 기본 로그인 페이지 생성이 무시되므로 로그인 페이지를 만들어줘야한다. (컨트롤러에 RequestMapping 및 로그인 페이지 구현 필요)
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            // 커스텀하게 사용할 AccessDeniedHandler 를 설정한다
                            System.out.println(accessDeniedException.getMessage());
                            response.sendRedirect("/denied");
                        })
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
